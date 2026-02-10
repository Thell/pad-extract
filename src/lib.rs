use std::borrow::Cow;
use std::error::Error;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use bytemuck::allocation::pod_collect_to_vec;
use bytemuck::{Pod, Zeroable};
use byteorder::{LittleEndian, ReadBytesExt};
use encoding_rs::EUC_KR;
use icefast::Ice;
use memchr::memchr;
use rayon::prelude::*;
use rdst::{RadixKey, RadixSort};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_WRITE,
    FILE_SHARE_READ, WriteFile,
};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

struct OverlappedWorker {
    // We keep two buffers. While one is "Locked" by the OS for a write,
    // the other is "Active" for the next decompression.
    buf_a: Vec<u8>,
    buf_b: Vec<u8>,
    is_a_active: bool,
    pending_handle: HANDLE,
    overlapped: OVERLAPPED,
}

impl OverlappedWorker {
    fn new() -> Self {
        Self {
            buf_a: Vec::with_capacity(1024 * 1024),
            buf_b: Vec::with_capacity(1024 * 1024),
            is_a_active: true,
            pending_handle: INVALID_HANDLE_VALUE,
            overlapped: unsafe { std::mem::zeroed() },
        }
    }

    /// Waits for the previous asynchronous write to finish and closes the handle.
    fn wait_for_pending(&mut self) {
        if self.pending_handle != INVALID_HANDLE_VALUE {
            unsafe {
                let mut transferred = 0;
                // This blocks ONLY if the SSD hasn't finished the previous write yet.
                // In most cases, the CPU is slower than the SSD's cache, so this returns instantly.
                GetOverlappedResult(self.pending_handle, &self.overlapped, &mut transferred, 1);
                CloseHandle(self.pending_handle);
                self.pending_handle = INVALID_HANDLE_VALUE;
            }
        }
    }
}

// Ensure handles are closed if a thread panics
impl Drop for OverlappedWorker {
    fn drop(&mut self) {
        self.wait_for_pending();
    }
}

#[derive(PartialOrd, Ord, PartialEq, Eq)]
pub enum ReadLevel {
    Raw,
    Decrypt,
    Decompress,
}

enum BlockType {
    Packages,
    Metas,
    Paths,
    Files,
}

fn block_range(
    block: BlockType,
    reader: &mut Cursor<&mut [u8]>,
) -> Result<Range<usize>, Box<dyn Error>> {
    let count = reader.read_u32::<LittleEndian>()? as u64;
    let start = reader.position();
    let end = match block {
        BlockType::Packages => start + count * 12,
        BlockType::Metas => start + count * 28,
        BlockType::Paths => start + count,
        BlockType::Files => start + count,
    };
    reader.set_position(end);
    Ok(start as usize..end as usize)
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct PackageRecord {
    pub id: u32,
    pub hash: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct MetaRecord {
    pub hash: u32,
    pub path_id: u32,
    pub file_id: u32,
    pub package_id: u32,
    pub package_offset: u32,
    pub sz_compressed: u32,
    pub sz_original: u32,
}

impl RadixKey for MetaRecord {
    // 4 levels for a u32 (4 bytes)
    const LEVELS: usize = 4;

    #[inline]
    fn get_level(&self, level: usize) -> u8 {
        // This extracts each byte of the u32 for the radix passes
        // level 0 is the least significant byte, level 3 is the most
        (self.file_id >> (level * 8)) as u8
    }
}

#[derive(Debug)]
pub struct PathRecord<'a> {
    pub path: Cow<'a, str>,
    pub file_range: Range<usize>,
}

impl<'a> PathRecord<'a> {
    fn many_from_encrypted_le_bytes(bytes: &'a mut [u8], ice: &Ice) -> Vec<PathRecord<'a>> {
        ice.decrypt_auto(bytes);

        // SAFETY: Since the path string list is of null terminated strings
        //         we use +2 to account for the null terminator of the last string.
        let trimmed_len = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 2);
        let mut bytes = &bytes[..trimmed_len];

        let mut out = Vec::with_capacity(8192);

        // NOTE: There must be start (4), end (4), a path (1..), and a null terminator (1)
        while bytes.len() >= 10 {
            let (header, rest) = bytes.split_at(8);

            let start = u32::from_le_bytes(header[0..4].try_into().unwrap());
            let len = u32::from_le_bytes(header[4..8].try_into().unwrap());

            if let Some(end) = memchr(0, &rest) {
                let (path_bytes, after_path) = rest.split_at(end);
                let path_str = unsafe { std::str::from_utf8_unchecked(path_bytes) };
                out.push(PathRecord {
                    path: Cow::Borrowed(path_str),
                    file_range: start as usize..(start + len) as usize,
                });
                bytes = &after_path[1..];
            }
        }
        out
    }
}

struct FileRecord;

impl FileRecord {
    fn many_from_encrypted_le_bytes<'a>(bytes: &'a mut [u8], ice: &Ice) -> Vec<&'a str> {
        ice.decrypt_auto(bytes);

        // SAFETY: Since the path string list is of null terminated strings
        //         we would use +2 to account for the null terminator of the
        //         last string except that the split iterator will create an
        //         empty string at the end.
        let trimmed_len = bytes.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
        let bytes = &mut bytes[..trimmed_len];

        // NOTE: Less than 0.005% of the bytes are non-ASCII.
        // We can decode those rare cases into a leaked string
        // to maintain the &'a str return type.
        bytes
            .par_split(|&x| x == 0)
            .map(|chunk| {
                if encoding_rs::mem::is_ascii(chunk) {
                    // SAFETY: We just ensured all bytes are ASCII
                    unsafe { std::str::from_utf8_unchecked(chunk) }
                } else {
                    let cow_str = EUC_KR.decode_without_bom_handling(chunk).0;
                    Box::leak(cow_str.into_owned().into_boxed_str())
                }
            })
            .collect()
    }
}

pub struct MetaFile {
    #[allow(unused)]
    buf: Vec<u8>, // backing storage str
    pub ice: Ice,
    pub root: PathBuf,
    pub version: u32,
    pub package_table: Vec<PackageRecord>,
    pub meta_table: Vec<MetaRecord>,
    pub path_table: Vec<PathRecord<'static>>,
    pub file_table: Vec<&'static str>,
}

impl MetaFile {
    // The path table is organized such that each entry is a bucket of file indices.
    // The raw data is organized for hash lookups, but this library organizes it for
    // efficient filtering and extraction directly using the path table bucket indices
    // on the meta table records.
    // **In order to filter by bucket indices the meta table must be sorted by file index.**
    pub fn new(mut buf: Vec<u8>, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
        let ice = Ice::new(0, key);
        let root = PathBuf::new();

        let mut reader = Cursor::new(buf.as_mut_slice());
        let version = reader.read_u32::<LittleEndian>()?;
        let range_packages = block_range(BlockType::Packages, &mut reader)?;
        let range_metas = block_range(BlockType::Metas, &mut reader)?;
        let range_paths = block_range(BlockType::Paths, &mut reader)?;
        let range_files = block_range(BlockType::Files, &mut reader)?;

        drop(reader);

        // SAFETY: We just extracted the ranges, so we know that the ranges are valid
        //         unless the source material changes format in which case the whole
        //         extractor will fail.

        let (packages_slice, meta_slice, paths_slice, files_slice) = unsafe {
            let base = buf.as_mut_ptr();
            (
                std::slice::from_raw_parts_mut(
                    base.add(range_packages.start),
                    range_packages.len(),
                ),
                std::slice::from_raw_parts_mut(base.add(range_metas.start), range_metas.len()),
                std::slice::from_raw_parts_mut(base.add(range_paths.start), range_paths.len()),
                std::slice::from_raw_parts_mut(base.add(range_files.start), range_files.len()),
            )
        };

        let package_table: Vec<PackageRecord> = pod_collect_to_vec(packages_slice);
        let mut meta_table: Vec<MetaRecord> = pod_collect_to_vec(meta_slice);
        let path_table = PathRecord::many_from_encrypted_le_bytes(paths_slice, &ice);
        let file_table = FileRecord::many_from_encrypted_le_bytes(files_slice, &ice);

        meta_table.radix_sort_unstable();

        return Ok(MetaFile {
            buf,
            ice,
            root,
            version,
            package_table,
            meta_table,
            path_table,
            file_table,
        });
    }

    // pub fn new(mut buf: Vec<u8>, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
    //     let start_total = std::time::Instant::now();

    //     let ice = Ice::new(0, key);
    //     let root = PathBuf::new();

    //     let start_load = std::time::Instant::now();
    //     let mut reader = Cursor::new(buf.as_mut_slice());
    //     let version = reader.read_u32::<LittleEndian>()?;
    //     let range_packages = block_range(BlockType::Packages, &mut reader)?;
    //     let range_metas = block_range(BlockType::Metas, &mut reader)?;
    //     let range_paths = block_range(BlockType::Paths, &mut reader)?;
    //     let range_files = block_range(BlockType::Files, &mut reader)?;
    //     drop(reader);

    //     // SAFETY: We just extracted the ranges, so we know that the ranges are valid
    //     //         unless the source material changes format in which case the whole
    //     //         extractor will fail.
    //     let (packages_slice, meta_slice, paths_slice, files_slice) = unsafe {
    //         let base = buf.as_mut_ptr();
    //         (
    //             std::slice::from_raw_parts_mut(
    //                 base.add(range_packages.start),
    //                 range_packages.len(),
    //             ),
    //             std::slice::from_raw_parts_mut(base.add(range_metas.start), range_metas.len()),
    //             std::slice::from_raw_parts_mut(base.add(range_paths.start), range_paths.len()),
    //             std::slice::from_raw_parts_mut(base.add(range_files.start), range_files.len()),
    //         )
    //     };

    //     let dur_load = start_load.elapsed();

    //     let start_pkgs = std::time::Instant::now();
    //     let package_table: Vec<PackageRecord> = pod_collect_to_vec(packages_slice);
    //     let dur_pkgs = start_pkgs.elapsed();

    //     let start_metas = std::time::Instant::now();
    //     let mut meta_table: Vec<MetaRecord> = pod_collect_to_vec(meta_slice);
    //     let dur_metas = start_metas.elapsed();

    //     let start_paths = std::time::Instant::now();
    //     let path_table = PathRecord::many_from_encrypted_le_bytes(paths_slice, &ice);
    //     let dur_paths = start_paths.elapsed();

    //     let start_files = std::time::Instant::now();
    //     let file_table = FileRecord::many_from_encrypted_le_bytes(files_slice, &ice);
    //     let dur_files = start_files.elapsed();

    //     let start_sort = std::time::Instant::now();
    //     meta_table.radix_sort_unstable();
    //     let dur_sort = start_sort.elapsed();

    //     let dur_total = start_total.elapsed();

    //     println!(
    //         "\nParse timings (ns): total={:.1}, load={:.1}, packages-parse ({})={:.1}, metas-parse ({})={:.1}, metas-sort={:.1}, paths-parse ({})={:.1}, files-parse ({})={:.1}",
    //         dur_total.as_nanos() as f64 / 1000.0,
    //         dur_load.as_nanos() as f64 / 1000.0,
    //         package_table.len(),
    //         dur_pkgs.as_nanos() as f64 / 1000.0,
    //         meta_table.len(),
    //         dur_metas.as_nanos() as f64 / 1000.0,
    //         dur_sort.as_nanos() as f64 / 1000.0,
    //         path_table.len(),
    //         dur_paths.as_nanos() as f64 / 1000.0,
    //         file_table.len(),
    //         dur_files.as_nanos() as f64 / 1000.0,
    //     );

    //     return Ok(MetaFile {
    //         buf,
    //         ice,
    //         root,
    //         version,
    //         package_table,
    //         meta_table,
    //         path_table,
    //         file_table,
    //     });
    // }

    pub fn new_from_path(root: &Path, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
        let metafile = PathBuf::from("pad00000.meta");
        let buf = std::fs::read(root.join(metafile))?;
        let mut meta = Self::new(buf, key)?;
        meta.root = root.to_path_buf();
        Ok(meta)
    }

    pub fn extract(
        &self,
        record: &MetaRecord,
        level: &ReadLevel,
        out_path: &Path,
    ) -> Result<(), Box<dyn Error>> {
        let dir = self.path_table[record.path_id as usize].path.as_ref();
        let file = self.file_table[record.file_id as usize];
        let out = out_path.join(dir).join(file);

        let mut f = std::fs::File::create(out)?;
        let buf = self.read(record, level)?;
        f.write_all(&buf)?;
        Ok(())
    }

    fn build_path_cache(&self, out_path: &Path) -> nohash_hasher::IntMap<u32, PathBuf> {
        let mut path_cache = nohash_hasher::IntMap::default();
        for mr in &self.meta_table {
            path_cache.entry(mr.path_id).or_insert_with(|| {
                let dir = self.path_table[mr.path_id as usize].path.as_ref();
                let full_path = out_path.join(dir);
                let _ = std::fs::create_dir_all(&full_path);
                full_path
            });
        }
        path_cache
    }

    pub fn extract_many(&self, level: &ReadLevel, out_path: &Path) -> Result<(), Box<dyn Error>> {
        // 1. Pre-calculate joined paths using your existing IntMap logic
        let path_cache = self.build_path_cache(out_path);

        // 2. Parallel extraction with Double-Buffered Overlapped I/O
        self.meta_table.par_iter().for_each_init(
            || OverlappedWorker::new(),
            |worker, mr| {
                // A. Ensure the previous asynchronous write is finished before we reuse its buffer
                worker.wait_for_pending();

                // B. Toggle buffers (A -> B or B -> A)
                worker.is_a_active = !worker.is_a_active;

                // C. Perform the Read/Decrypt/Decompress.
                // We scope this so 'current_buf' (the borrow of worker) is dropped before
                // we update worker.pending_handle later.
                let (data_ptr, data_len) = {
                    let current_buf = if worker.is_a_active {
                        &mut worker.buf_a
                    } else {
                        &mut worker.buf_b
                    };
                    if let Err(e) = self.read_into(mr, level, current_buf) {
                        let p = self.path_table[mr.path_id as usize].path.as_ref();
                        let f = self.file_table[mr.file_id as usize];
                        eprintln!("Failed to read {}/{}: {}", p, f, e);
                        return;
                    }
                    (current_buf.as_ptr(), current_buf.len() as u32)
                };

                // D. Prepare Windows Wide-String Path
                let base_path = path_cache.get(&mr.path_id).unwrap();
                let file_name = self.file_table[mr.file_id as usize];
                let full_out = base_path.join(file_name);
                let wide_path: Vec<u16> =
                    full_out.as_os_str().encode_wide().chain(Some(0)).collect();

                // E. Fire the Overlapped Write
                unsafe {
                    let h = CreateFileW(
                        wide_path.as_ptr(),
                        FILE_GENERIC_WRITE,
                        FILE_SHARE_READ,
                        std::ptr::null(),
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                        std::ptr::null_mut(),
                    );

                    // On Windows, INVALID_HANDLE_VALUE is -1.
                    if h != INVALID_HANDLE_VALUE as _ && !h.is_null() {
                        worker.pending_handle = h;
                        worker.overlapped = std::mem::zeroed();

                        // Start the write. The OS will read from data_ptr in the background.
                        // This returns immediately.
                        WriteFile(
                            h,
                            data_ptr,
                            data_len,
                            std::ptr::null_mut(),
                            &mut worker.overlapped,
                        );
                    } else {
                        let p = self.path_table[mr.path_id as usize].path.as_ref();
                        let f = self.file_table[mr.file_id as usize];
                        eprintln!("Failed to create file {}/{}: Handle is invalid", p, f);
                    }
                }
            },
        );

        Ok(())
    }

    // pub fn extract_many(&self, level: &ReadLevel, out_path: &Path) -> Result<(), Box<dyn Error>> {
    //     // 1. Pre-calculate joined paths for ONLY the directories present in the (filtered) meta_table
    //     let mut path_cache: IntMap<u32, PathBuf> = IntMap::default();

    //     for mr in &self.meta_table {
    //         // Entry API avoids re-calculating/re-joining for the same path_id
    //         path_cache.entry(mr.path_id).or_insert_with(|| {
    //             let dir = self.path_table[mr.path_id as usize].path.as_ref();
    //             let full_path = out_path.join(dir);
    //             let _ = std::fs::create_dir_all(&full_path);
    //             full_path
    //         });
    //     }

    //     // Reuse the thead-safe scratch buffer for decompression
    //     self.meta_table.par_iter().for_each_init(
    //         || Vec::with_capacity(1024 * 1024),
    //         |scratch, mr| {
    //             let base_path = path_cache.get(&mr.path_id).unwrap();
    //             let file_name = self.file_table[mr.file_id as usize];
    //             let out = base_path.join(file_name);

    //             if let Err(e) = self.extract_with_buffer(mr, level, &out, scratch) {
    //                 let p = self.path_table[mr.path_id as usize].path.as_ref();
    //                 let f = self.file_table[mr.file_id as usize];
    //                 eprintln!("Failed {}/{}: {}", p, f, e);
    //             }
    //         },
    //     );

    //     Ok(())
    // }

    // fn extract_with_buffer(
    //     &self,
    //     record: &MetaRecord,
    //     level: &ReadLevel,
    //     out: &Path,
    //     scratch: &mut Vec<u8>,
    // ) -> Result<(), Box<dyn Error>> {
    //     self.read_into(record, level, scratch)?;
    //     std::fs::write(out, scratch)?;
    //     Ok(())
    // }

    fn read_into(
        &self,
        record: &MetaRecord,
        level: &ReadLevel,
        buf: &mut Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        let mut f = std::fs::File::open(self.package_path(record))?;
        f.seek(SeekFrom::Start(record.package_offset as u64))?;

        let sz = record.sz_compressed as usize;
        buf.clear();

        // Check if the scratch buffer already has enough room to avoid reallocation.
        if buf.capacity() < sz {
            buf.reserve(sz);
        }

        // SAFETY: We are immediately following this with read_exact, which fills
        // exactly 'sz' bytes. This avoids the zero-initialization cost of buf.resize(sz, 0).
        // This is safe because u8 has no drop glue and the next operation is a total overwrite.
        unsafe {
            buf.set_len(sz);
        }
        f.read_exact(buf)?;

        let file_name = self.file_table[record.file_id as usize];
        let is_dbss = file_name.ends_with(".dbss");

        if level >= &ReadLevel::Decrypt && !is_dbss && !buf.is_empty() {
            self.ice.decrypt_auto(buf);
        }

        if level >= &ReadLevel::Decompress {
            if record.sz_original > record.sz_compressed
                || (!is_dbss && !buf.is_empty() && buf[0] == 0x6E)
            {
                let mut r = Cursor::new(&buf);
                // quicklz allocates a new Vec; we transfer ownership to our scratch buffer.
                let decompressed = quicklz::decompress(&mut r, record.sz_original)?;
                *buf = decompressed;
            }
            if (buf.len() as u32) > record.sz_original {
                buf.truncate(record.sz_original as usize);
            }
        }
        Ok(())
    }

    pub fn read(&self, record: &MetaRecord, level: &ReadLevel) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut f = std::fs::File::open(self.package_path(record))?;
        f.seek(SeekFrom::Start(record.package_offset as u64))?;
        let mut buf = vec![0; record.sz_compressed as usize];
        f.read_exact(&mut buf)?;

        let file_name = self.file_table[record.file_id as usize];
        let is_dbss = file_name.ends_with(".dbss");

        if level >= &ReadLevel::Decrypt && !is_dbss {
            self.ice.decrypt_auto(&mut buf);
        }

        if level >= &ReadLevel::Decompress {
            if record.sz_original > record.sz_compressed
                || (!is_dbss && !buf.is_empty() && buf[0] == 0x6E)
            {
                let mut r = Cursor::new(&buf);
                buf = quicklz::decompress(&mut r, record.sz_original)?;
            }
            if record.sz_original < record.sz_compressed {
                buf.truncate(record.sz_original as usize);
            }
        }

        Ok(buf)
    }

    pub fn filter_by_file(&mut self, pattern: &str) -> Result<(), Box<dyn Error>> {
        let re = regex::Regex::new(pattern).unwrap();
        self.meta_table = self
            .meta_table
            .par_iter()
            .filter(|x| re.is_match(self.file_table[x.file_id as usize].as_ref()))
            .cloned()
            .collect();
        Ok(())
    }

    pub fn filter_by_path(&mut self, pattern: &str) -> Result<(), Box<dyn Error>> {
        let re = regex::Regex::new(pattern).unwrap();
        self.meta_table = self
            .path_table
            .par_iter()
            .filter(|x| re.is_match(x.path.as_ref()))
            .flat_map(|pr| self.meta_table[pr.file_range.clone()].to_vec())
            .collect();
        Ok(())
    }

    pub fn package_name(&self, record: &MetaRecord) -> PathBuf {
        PathBuf::from(format!("PAD{:05}.paz", record.package_id))
    }

    pub fn package_path(&self, record: &MetaRecord) -> PathBuf {
        self.root.join(self.package_name(record))
    }
}
