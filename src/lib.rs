use std::error::Error;
use std::io::prelude::*;
use std::io::{Cursor, SeekFrom};
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;

use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use fixedbitset::FixedBitSet;
use icefast::Ice;
use nohash_hasher::{BuildNoHashHasher, IntMap};
use rayon::prelude::*;

/// The level of processing to use on the data to read from the archive.
///
/// * `Raw` - The data is read but not decrypted or decompressed.
/// * `Decrypt` - The data is read and decrypted.
/// * `Decompress` - The data is read, decrypted and decompressed.
#[derive(PartialOrd, Ord, PartialEq, Eq)]
pub enum ReadLevel {
    #[allow(dead_code)]
    Raw,
    Decrypt,
    Decompress,
}

/// Type indicating the content within a block for a range of bytes.
///
/// See the individual type structs for specific layouts.
enum BlockType {
    Packages,
    Metas,
    Paths,
    Files,
}

/// Returns the range of bytes for the block and advances the cursor to the start of the next block.
///
/// SAFETY: The meta data is a fixed format and the caller must ensure the cursor
///         is positioned at the start of the appropriate block.
fn block_range(
    block: BlockType,
    reader: &mut Cursor<&Vec<u8>>,
) -> Result<std::ops::Range<usize>, Box<dyn Error>> {
    let count = reader.read_u32::<LittleEndian>()? as usize;
    let start = reader.position() as usize;
    let end = match block {
        BlockType::Packages => start + count * std::mem::size_of::<PackageRecord>(),
        BlockType::Metas => start + count * std::mem::size_of::<MetaRecord>(),
        BlockType::Paths => start + count,
        BlockType::Files => start + count,
    };
    reader.set_position(end as u64);
    Ok(start as usize..end as usize)
}

/// NOTE: Package records are not used internally by this library.
///
/// They can be utilized to validate the data archive or to differentiate
/// packages across versions.
#[derive(Debug, Clone, Copy)]
pub struct PackageRecord {
    pub id: u32,
    pub hash: u32,
    pub size: u32,
}

/// A meta record contains the meta data for a specific file.
///
/// The hash is not used internally by this library but can be used
/// to validate the data archive or to differentiate files across versions.
///
/// The `path_id`, `file_id` and `package_id` fields are indices into the
/// path table, file table and package table respectively.
///
/// NOTE: A file is generally compressed if the original size exceeds the compressed size.
///       However, some files (marked with a 0x6E header) are compressed via QuickLZ but,
///       due to byte alignment and padding, have a `sz_compressed` equal to or greater
///       than `sz_original` in which case the header is simply stripped.
///       This happens when a file blob was in a pre-compressed state.
#[derive(Debug, Clone, Copy)]
pub struct MetaRecord {
    pub hash: u32,
    pub path_id: u32,
    pub file_id: u32,
    pub package_id: u32,
    pub package_offset: u32,
    pub sz_compressed: u32,
    pub sz_original: u32,
}

/// A path record consists of the path string and the range of file indices
/// in that specific path's file bucket from the file table.
#[derive(Debug)]
pub struct PathRecord<'a> {
    pub path: &'a str,
    pub file_range: Range<usize>,
}

impl<'a> PathRecord<'a> {
    fn many_from_encrypted_le_bytes(bytes: &'a [u8]) -> Vec<PathRecord<'a>> {
        let mut out = Vec::with_capacity(8192);

        // NOTE: There must be start (4), end (4), a path (1..), and a null terminator (1)
        let mut pos = 0;
        while pos < bytes.len() - 9 {
            let bucket_start = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
            let bucket_len = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap());
            pos += 8;

            if let Some(end) = memchr::memchr(0, &bytes[pos..]) {
                // SAFETY: All path strings are ASCII
                let path_str = unsafe { std::str::from_utf8_unchecked(&bytes[pos..pos + end]) };
                pos += end + 1;
                out.push(PathRecord {
                    path: path_str,
                    file_range: bucket_start as usize..(bucket_start + bucket_len) as usize,
                });
            }
        }
        out
    }
}

struct FileRecord;

impl FileRecord {
    fn many_from_encrypted_le_bytes(bytes: &[u8]) -> Vec<&str> {
        let bytes = match bytes.iter().rposition(|&x| x != 0) {
            Some(len) => &bytes[..=len],
            None => return Vec::new(),
        };

        // NOTE: Of the approximately 900,000 file names in the meta file less than 0.005%
        //       are invalid ASCII/UTF-8 that require decoding.
        bytes
            .par_split(|&b| b == 0)
            .map(|chunk| {
                // NOTE: std::slice is_ascii is slightly faster than encoding_rs is_ascii.
                //       When it's not ASCII we end up double checking the initial ASCII bytes.
                if chunk.is_ascii() {
                    // SAFETY: is_ascii ensures valid UTF-8 for the slice.
                    unsafe { std::str::from_utf8_unchecked(chunk) }
                } else {
                    let cow_str = encoding_rs::EUC_KR.decode_without_bom_handling(chunk).0;
                    Box::leak(cow_str.into_owned().into_boxed_str())
                }
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct MetaFile {
    // SAFETY: This field must remain present and immutable for the lifetime of the struct.
    #[allow(unused)]
    buf: Vec<u8>,

    pub ice: Ice,
    pub root: PathBuf,
    pub version: u32,
    package_ptr: *const PackageRecord,
    package_len: usize,
    meta_ptr: *const MetaRecord,
    meta_len: usize,
    pub active_records: FixedBitSet,
    pub record_index: Vec<usize>,
    pub path_table: Vec<PathRecord<'static>>,
    pub file_table: Vec<&'static str>,
}

unsafe impl Sync for MetaFile {}

impl MetaFile {
    /// Creates a new meta file from the root directory containing the `pad00000.meta` file
    /// and using the provided encryption key.
    ///
    /// **SAFETY**: The pad00000.meta file is the read-only fixed format source of truth.
    ///             All unsafe operations are based on the assumption that the meta file is correct.
    pub fn new_from_path(root: &Path, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
        let metafile = PathBuf::from("pad00000.meta");
        let buf = std::fs::read(root.join(metafile))?;
        let mut meta = Self::new(buf, key)?;
        meta.root = root.to_path_buf();
        Ok(meta)
    }

    /// Creates a new meta file from the provided buffer and using the provided encryption key.
    ///
    /// The primary entry point is the `new_from_path` method which uses the `pad00000.meta` file.
    ///
    /// **SAFETY**: The pad00000.meta file is the read-only fixed format source of truth.
    ///             All unsafe operations are based on the assumption that the meta file is correct.
    #[cfg(not(feature = "instrumented"))]
    pub fn new(mut buf: Vec<u8>, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
        let ice = Ice::new(0, key);
        let root = PathBuf::new();

        let (version, package_range, meta_range, path_range, file_range) = {
            let mut reader = Cursor::new(&buf);

            let version = reader.read_u32::<LittleEndian>()?;

            let package_range = block_range(BlockType::Packages, &mut reader)?;
            let meta_range = block_range(BlockType::Metas, &mut reader)?;
            let path_range = block_range(BlockType::Paths, &mut reader)?;
            let file_range = block_range(BlockType::Files, &mut reader)?;

            (version, package_range, meta_range, path_range, file_range)
        };

        let (package_ptr, package_len) = {
            let bytes = &mut buf[package_range];
            let record_size = std::mem::size_of::<PackageRecord>();

            let num = bytes.len() / record_size;
            let ptr = bytes.as_mut_ptr() as *mut PackageRecord;

            (ptr as *const PackageRecord, num)
        };

        let (meta_ptr, meta_len, record_index, active_records) = {
            let bytes = &mut buf[meta_range];
            let record_size = std::mem::size_of::<MetaRecord>();

            let num = bytes.len() / record_size;
            let ptr = bytes.as_mut_ptr() as *mut MetaRecord;

            let mut active_records = FixedBitSet::with_capacity(num);
            active_records.insert_range(..);

            let mut record_index = vec![0_usize; num];
            unsafe {
                let metas = std::slice::from_raw_parts(ptr, num);
                let dst = record_index.as_mut_ptr();
                for (i, mr) in metas.iter().enumerate() {
                    dst.add(mr.file_id as usize).write(i);
                }
            }

            (ptr as *const MetaRecord, num, record_index, active_records)
        };

        let (paths_slice, files_slice) = unsafe {
            let base = buf.as_mut_ptr();
            (
                std::slice::from_raw_parts_mut(base.add(path_range.start), path_range.len()),
                std::slice::from_raw_parts_mut(base.add(file_range.start), file_range.len()),
            )
        };

        ice.decrypt_auto(paths_slice);
        let path_table = PathRecord::many_from_encrypted_le_bytes(paths_slice);

        ice.decrypt_auto(files_slice);
        let file_table = FileRecord::many_from_encrypted_le_bytes(files_slice);

        Ok(MetaFile {
            buf,
            ice,
            root,
            version,
            package_ptr,
            package_len,
            meta_ptr,
            meta_len,
            record_index,
            active_records,
            path_table,
            file_table,
        })
    }

    /// NOTE: This `new`` is instrumented to facilitate benchmarking during development using:
    ///       `cargo test --release --features=instrumented -- --nocapture --test-threads=1`
    ///
    #[cfg(feature = "instrumented")]
    pub fn new(mut buf: Vec<u8>, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
        let start_total = std::time::Instant::now();

        let ice = Ice::new(0, key);
        let root = PathBuf::new();

        let (version, package_range, meta_range, path_range, file_range) = {
            let mut reader = Cursor::new(&buf);

            let version = reader.read_u32::<LittleEndian>()?;

            let package_range = block_range(BlockType::Packages, &mut reader)?;
            let meta_range = block_range(BlockType::Metas, &mut reader)?;
            let path_range = block_range(BlockType::Paths, &mut reader)?;
            let file_range = block_range(BlockType::Files, &mut reader)?;

            (version, package_range, meta_range, path_range, file_range)
        };

        let (package_ptr, package_len, dur_pkgs) = {
            let start = std::time::Instant::now();
            let bytes = &mut buf[package_range];
            let num = bytes.len() / std::mem::size_of::<PackageRecord>();
            let ptr = bytes.as_mut_ptr() as *mut PackageRecord;
            let dur = start.elapsed();

            (ptr as *const PackageRecord, num, dur)
        };

        let (meta_ptr, meta_len, record_index, active_records, dur_metas, dur_sort) = {
            let start_parse = std::time::Instant::now();
            let bytes = &mut buf[meta_range];
            let record_size = std::mem::size_of::<MetaRecord>();
            let num = bytes.len() / record_size;
            let ptr = bytes.as_mut_ptr() as *mut MetaRecord;

            let mut active_records = FixedBitSet::with_capacity(num);
            active_records.insert_range(..);

            let mut record_index = vec![0_usize; num];
            unsafe {
                let metas = std::slice::from_raw_parts(ptr, num);
                let dst = record_index.as_mut_ptr();
                for (i, mr) in metas.iter().enumerate() {
                    dst.add(mr.file_id as usize).write(i);
                }
            }
            let dur_parse = start_parse.elapsed();

            let start_sort = std::time::Instant::now();
            // No sorting being done but keep this for consistency during experiments
            let dur_sort = start_sort.elapsed();

            (
                ptr as *const MetaRecord,
                num,
                record_index,
                active_records,
                dur_parse,
                dur_sort,
            )
        };

        let (paths_slice, files_slice) = unsafe {
            let base = buf.as_mut_ptr();
            (
                std::slice::from_raw_parts_mut(base.add(path_range.start), path_range.len()),
                std::slice::from_raw_parts_mut(base.add(file_range.start), file_range.len()),
            )
        };

        let start_paths = std::time::Instant::now();
        ice.decrypt_auto(paths_slice);
        let path_table = PathRecord::many_from_encrypted_le_bytes(paths_slice);
        let dur_paths = start_paths.elapsed();

        let start_files = std::time::Instant::now();
        ice.decrypt_auto(files_slice);
        let file_table = FileRecord::many_from_encrypted_le_bytes(files_slice);
        let dur_files = start_files.elapsed();

        let dur_total = start_total.elapsed();

        println!(
            "Parse timings (μs): total={}, packages-parse ({})={}, metas-parse ({})={}, metas-sort={}, paths-parse ({})={}, files-parse ({})={}",
            dur_total.as_micros() as f64,
            package_len,
            dur_pkgs.as_micros() as f64,
            meta_len,
            dur_metas.as_micros() as f64,
            dur_sort.as_micros() as f64,
            path_table.len(),
            dur_paths.as_micros() as f64,
            file_table.len(),
            dur_files.as_micros() as f64,
        );

        Ok(MetaFile {
            buf,
            ice,
            root,
            version,
            package_ptr,
            package_len,
            meta_ptr,
            meta_len,
            record_index,
            active_records,
            path_table,
            file_table,
        })
    }

    /// Extracts a single record from the archive.
    pub fn extract(
        &self,
        record: &MetaRecord,
        level: &ReadLevel,
        out_path: &Path,
    ) -> Result<(), Box<dyn Error>> {
        let dir = self.path_table[record.path_id as usize].path;
        let file = &self.file_table[record.file_id as usize];
        let out = out_path.join(dir).join(file);

        let mut buf = vec![0; record.sz_compressed as usize];
        self.extract_with_buffer(record, level, &out, &mut buf)?;
        Ok(std::fs::write(out, buf)?)
    }

    /// Reads and returns the bytes of a single record from the archive.
    pub fn read(&self, record: &MetaRecord, level: &ReadLevel) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut f = std::fs::File::open(self.package_path(record))?;
        f.seek(SeekFrom::Start(record.package_offset as u64))?;
        let mut buf = vec![0; record.sz_compressed as usize];
        f.read_exact(&mut buf)?;

        let is_dbss = self.file_table[record.file_id as usize].ends_with(".dbss");

        if level >= &ReadLevel::Decrypt && !is_dbss && !buf.is_empty() {
            self.ice.decrypt_auto(&mut buf);
        }

        if level >= &ReadLevel::Decompress {
            if record.sz_original > record.sz_compressed
                || (!is_dbss && !buf.is_empty() && buf[0] == 0x6E)
            {
                let mut r = Cursor::new(&buf);
                buf = quicklz::decompress(&mut r, record.sz_original)?;
                buf.truncate(record.sz_original as usize);
            }
        }

        Ok(buf)
    }

    /// Builds a path cache for the active records for use with `extract_many` ensuring
    /// that all directories are created.
    fn build_path_cache(&self, out_path: &Path) -> IntMap<u32, PathBuf> {
        let mut path_cache: IntMap<u32, PathBuf> =
            IntMap::with_capacity_and_hasher(self.path_table.len(), BuildNoHashHasher::default());

        for (i, pr) in self.path_table.iter().enumerate() {
            if self
                .active_records
                .contains_any_in_range(pr.file_range.clone())
            {
                let full_path = out_path.join(&pr.path);
                let _ = std::fs::create_dir_all(&full_path);
                path_cache.insert(i as u32, full_path);
            }
        }
        path_cache
    }

    /// Extracts all (remaining) records in the meta table.
    ///
    /// NOTE: This is normally called after filtering by path and/or file names.
    pub fn extract_many(&self, level: &ReadLevel, out_path: &Path) -> Result<(), Box<dyn Error>> {
        let path_cache = self.build_path_cache(out_path);

        self.active_records
            .ones()
            .collect::<Vec<_>>()
            .into_par_iter()
            .for_each_init(
                || Vec::with_capacity(8_192),
                |buf, mr_idx| {
                    let mr = self.meta_record_as_ref(mr_idx);
                    let base_path = path_cache.get(&mr.path_id).unwrap();
                    let file_name = self.file_table[mr.file_id as usize];
                    let out = base_path.join(file_name);

                    if let Err(e) = self.extract_with_buffer(mr, level, &out, buf) {
                        eprintln!("Failed extracting {}: {}", out.display(), e);
                    }
                },
            );
        Ok(())
    }

    fn extract_with_buffer(
        &self,
        record: &MetaRecord,
        level: &ReadLevel,
        out: &Path,
        buf: &mut Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        let mut f = std::fs::File::open(self.package_path(record))?;
        f.seek(SeekFrom::Start(record.package_offset as u64))?;

        // SAFETY: This is safe because reserve ensures that the buffer has enough space,
        //         and the next operation 'read_exact' is a total overwrite of the new len.
        //         If we could signal MaybeUninit during the thread init, we could use that instead
        //         if ICE and quicklz could handle that.
        unsafe {
            let sz_compressed = record.sz_compressed as usize;
            buf.reserve(sz_compressed.saturating_sub(buf.len()));
            #[allow(clippy::uninit_vec)]
            buf.set_len(sz_compressed);
            f.read_exact(buf)?;
        };

        if buf.is_empty() {
            return Ok(());
        }

        let is_dbss = self.file_table[record.file_id as usize].ends_with(".dbss");

        if level >= &ReadLevel::Decrypt && !is_dbss {
            self.ice.decrypt_auto(buf);
        }

        // NOTE: A file is generally compressed if the original size exceeds the compressed size.
        //       However, some files (marked with a 0x6E header) are compressed via QuickLZ but,
        //       due to byte alignment and padding, have a `sz_compressed` equal to or greater
        //       than `sz_original` in which case the header is simply stripped.
        //       This happens when a file blob was in a pre-compressed state.
        if level >= &ReadLevel::Decompress
            && (record.sz_original > record.sz_compressed || (!is_dbss && buf[0] == 0x6E))
        {
            let mut r = Cursor::new(buf);
            let mut decompressed = quicklz::decompress(&mut r, record.sz_original)?;
            decompressed.truncate(record.sz_original as usize);
            return Ok(std::fs::write(out, decompressed)?);
        }
        Ok(std::fs::write(out, buf)?)
    }

    /// Filters the current active records based on regex file name patterns.
    ///
    /// NOTE: Filter by path first for performance.
    pub fn filter_by_file(&mut self, pattern: &str) {
        let re = regex::Regex::new(pattern).expect("invalid file regex pattern");

        let matches: Vec<usize> = self
            .active_records
            .ones()
            .collect::<Vec<_>>()
            .into_par_iter()
            .filter(|&i| {
                let mr = self.meta_record_as_ref(i);
                let name = self.file_table[mr.file_id as usize];
                re.is_match(name)
            })
            .collect();

        self.active_records.clear();
        for i in matches {
            self.active_records.insert(i);
        }
    }

    /// Initializes the active records based on regex path patterns.
    ///
    /// NOTE: This overwrites any previous path or file filtering.
    pub fn filter_by_path(&mut self, pattern: &str) {
        let re = regex::Regex::new(pattern).expect("invalid path regex pattern");

        self.active_records.clear();
        self.path_table
            .iter()
            .filter(|pr| re.is_match(pr.path.as_ref()))
            .for_each(|pr| self.active_records.insert_range(pr.file_range.clone()));
    }

    /// Returns a reference to a meta record.
    #[inline(always)]
    pub fn meta_record_as_ref(&self, file_id: usize) -> &MetaRecord {
        assert!(file_id < self.record_index.len());
        unsafe { &*self.meta_ptr.add(*self.record_index.get_unchecked(file_id)) }
    }

    /// Returns a slice view of the meta table.
    pub fn meta_table_ref(&self) -> &[MetaRecord] {
        unsafe { std::slice::from_raw_parts(self.meta_ptr, self.meta_len) }
    }

    /// Returns an iterator over references to active meta records.
    pub fn active_meta_records_iter<'a>(&'a self) -> impl Iterator<Item = &'a MetaRecord> + 'a {
        self.active_records
            .ones()
            .map(move |file_id| self.meta_record_as_ref(file_id))
    }

    /// Returns a parallel iterator over references to active meta records.
    pub fn active_meta_records_par_iter<'a>(
        &'a self,
    ) -> impl ParallelIterator<Item = &'a MetaRecord> + 'a {
        self.active_records
            .ones()
            .collect::<Vec<_>>()
            .into_par_iter()
            .map(move |file_id| self.meta_record_as_ref(file_id))
    }

    /// Returns the name of the package file for use in file paths.
    pub fn package_name(&self, record: &MetaRecord) -> PathBuf {
        PathBuf::from(format!("PAD{:05}.paz", record.package_id))
    }

    /// Returns the path to the package file.
    pub fn package_path(&self, record: &MetaRecord) -> PathBuf {
        self.root.join(self.package_name(record))
    }

    /// Returns a slice view of the package table.
    pub fn package_table_ref(&self) -> &[PackageRecord] {
        unsafe { std::slice::from_raw_parts(self.package_ptr, self.package_len) }
    }

    /// Sets the active records to all records.
    pub fn reset_active_records(&mut self) {
        self.active_records.clear();
        self.active_records.insert_range(..);
    }

    /// Set the active records from the given Vec of file IDs.
    pub fn set_active_records_from_ids(&mut self, ids: &Vec<u32>) {
        self.active_records.clear();
        for &id in ids {
            self.active_records.insert(id as usize);
        }
    }
}
