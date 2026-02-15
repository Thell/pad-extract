use std::error::Error;
use std::io::prelude::*;
use std::io::{Cursor, SeekFrom};
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;

use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use icefast::Ice;
use rayon::prelude::*;

/// The level of processing to use on the data to read from the archive.
///
/// * `Raw` - The data is not processed at all.
/// * `Decrypt` - The data is decrypted.
/// * `Decompress` - The data is decrypted and decompressed.
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
    reader: &mut Cursor<&[u8]>,
) -> Result<std::ops::Range<usize>, Box<dyn Error>> {
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

/// NOTE: Package records are not used internally by this library.
///
/// They can be utilized to validate the data archive or to differentiate
/// packages across versions.
#[derive(Debug)]
pub struct PackageRecord {
    pub id: u32,
    pub hash: u32,
    pub size: u32,
}

impl PackageRecord {
    fn from_le_bytes(bytes: [u8; 12]) -> PackageRecord {
        let mut reader = Cursor::new(bytes);
        PackageRecord {
            id: reader.read_u32::<LittleEndian>().unwrap(),
            hash: reader.read_u32::<LittleEndian>().unwrap(),
            size: reader.read_u32::<LittleEndian>().unwrap(),
        }
    }

    fn many_from_le_bytes(bytes: &[u8]) -> Vec<PackageRecord> {
        bytes
            .par_chunks_exact(12)
            .map(|chunk| PackageRecord::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }
}

/// A meta record contains the meta data for a specific file.
///
/// The hash is not used internally by this library but can be used
/// to validate the data archive or to differentiate files across versions.
///
/// The `path_id`, `file_id` and `package_id` fields are indices into the
/// path table, file table and package table respectively.
///
/// sz_original accounts for both decryption and decompression.
#[derive(Debug, Clone)]
pub struct MetaRecord {
    pub hash: u32,
    pub path_id: u32,
    pub file_id: u32,
    pub package_id: u32,
    pub package_offset: u32,
    pub sz_compressed: u32,
    pub sz_original: u32,
}

impl MetaRecord {
    fn from_le_bytes(bytes: &[u8; 28]) -> MetaRecord {
        let mut reader = Cursor::new(bytes);
        MetaRecord {
            hash: reader.read_u32::<LittleEndian>().unwrap(),
            path_id: reader.read_u32::<LittleEndian>().unwrap(),
            file_id: reader.read_u32::<LittleEndian>().unwrap(),
            package_id: reader.read_u32::<LittleEndian>().unwrap(),
            package_offset: reader.read_u32::<LittleEndian>().unwrap(),
            sz_compressed: reader.read_u32::<LittleEndian>().unwrap(),
            sz_original: reader.read_u32::<LittleEndian>().unwrap(),
        }
    }

    fn many_from_le_bytes(bytes: &[u8]) -> Vec<MetaRecord> {
        bytes
            .par_chunks_exact(28)
            .map(|chunk| MetaRecord::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }
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
    fn many_from_encrypted_le_bytes<'a>(bytes: &'a [u8]) -> Vec<&'a str> {
        let bytes = match bytes.iter().rposition(|&x| x != 0) {
            Some(len) => &bytes[..=len],
            None => return Vec::new(),
        };

        // NOTE: Of the approximately 900,000 file names in the meta file less than 0.005%
        //       are invalid ASCII/UTF-8 that require decoding.
        bytes
            .par_split(|&b| b == 0)
            .map(|chunk| {
                // NOTE: std::slice is_ascii is slightly faster than encoding_rs is_ascii
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
    // SAFETY: This field must remain present and immutable for the lifetime of the struct,
    //         as `path_table` and `file_table` contain slices that borrow directly.
    #[allow(unused)]
    buf: Vec<u8>,

    pub ice: Ice,
    pub root: PathBuf,
    pub version: u32,
    pub package_table: Vec<PackageRecord>,
    pub meta_table: Vec<MetaRecord>,
    pub path_table: Vec<PathRecord<'static>>,
    pub file_table: Vec<&'static str>,
}

impl MetaFile {
    /// Creates a new meta file from the root directory containing the `pad00000.meta` file
    /// and using the provided encryption key.
    ///
    /// The `pad00000.meta`` path table is organized such that each entry is a bucket
    /// of file indices nad is organized for hash lookups, but this library organizes it for
    /// efficient filtering and extraction by directly using the path table bucket indices
    /// on the meta table records.
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
    /// **SAFETY**: The pad00000.meta file is the source of truth.
    /// All unsafe operations are based on the assumption that the meta file is correct.
    #[cfg(not(feature = "instrumented"))]
    pub fn new(mut buf: Vec<u8>, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
        // NOTE: ** To filter by bucket indices the meta table must be sorted by file index. **
        let ice = Ice::new(0, key);
        let root = PathBuf::new();

        let mut reader = Cursor::new(buf.as_slice());

        let version = reader.read_u32::<LittleEndian>().unwrap();

        let range = block_range(BlockType::Packages, &mut reader)?;
        let package_table = PackageRecord::many_from_le_bytes(&reader.get_ref()[range]);

        let range = block_range(BlockType::Metas, &mut reader)?;
        let mut meta_table = MetaRecord::many_from_le_bytes(&reader.get_ref()[range]);
        meta_table.par_sort_by_key(|x| x.file_id);

        let range_paths = block_range(BlockType::Paths, &mut reader)?;
        let range_files = block_range(BlockType::Files, &mut reader)?;

        // SAFETY: We just extracted the ranges, so we know that the ranges are valid
        //         unless the source material changes format in which case the whole
        //         extractor will fail.
        let (paths_slice, files_slice) = unsafe {
            let base = buf.as_mut_ptr();
            (
                std::slice::from_raw_parts_mut(base.add(range_paths.start), range_paths.len()),
                std::slice::from_raw_parts_mut(base.add(range_files.start), range_files.len()),
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
            package_table,
            meta_table,
            path_table,
            file_table,
        })
    }

    /// NOTE: This `new`` is instrumented to facilitate benchmarking during development using:
    ///       `cargo test --release --features=instrumented -- --nocapture --test-threads=1`
    ///
    #[cfg(feature = "instrumented")]
    pub fn new(mut buf: Vec<u8>, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
        // NOTE: ** To filter by bucket indices the meta table must be sorted by file index. **
        let start_total = std::time::Instant::now();

        let ice = Ice::new(0, key);
        let root = PathBuf::new();

        let mut reader = Cursor::new(buf.as_slice());

        let version = reader.read_u32::<LittleEndian>().unwrap();

        let start_pkgs = std::time::Instant::now();
        let range = block_range(BlockType::Packages, &mut reader)?;
        let package_table = PackageRecord::many_from_le_bytes(&reader.get_ref()[range]);
        let dur_pkgs = start_pkgs.elapsed();

        let start_metas = std::time::Instant::now();
        let range = block_range(BlockType::Metas, &mut reader)?;
        let mut meta_table = MetaRecord::many_from_le_bytes(&reader.get_ref()[range]);
        let dur_metas = start_metas.elapsed();

        let start_sort = std::time::Instant::now();
        meta_table.par_sort_by_key(|x| x.file_id);
        let dur_sort = start_sort.elapsed();

        let range_paths = block_range(BlockType::Paths, &mut reader)?;
        let range_files = block_range(BlockType::Files, &mut reader)?;

        // SAFETY: We just extracted the ranges, so we know that the ranges are valid
        //         unless the source material changes format in which case the whole
        //         extractor will fail.
        let (paths_slice, files_slice) = unsafe {
            let base = buf.as_mut_ptr();
            (
                std::slice::from_raw_parts_mut(base.add(range_paths.start), range_paths.len()),
                std::slice::from_raw_parts_mut(base.add(range_files.start), range_files.len()),
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
            package_table.len(),
            dur_pkgs.as_micros() as f64,
            meta_table.len(),
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
            package_table,
            meta_table,
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

        let mut f = std::fs::File::create(out)?;
        let buf = self.read(record, level)?;
        f.write_all(&buf)?;
        Ok(())
    }

    pub fn read(&self, record: &MetaRecord, level: &ReadLevel) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut f = std::fs::File::open(self.package_path(record))?;
        f.seek(SeekFrom::Start(record.package_offset as u64))?;
        let mut buf = vec![0; record.sz_compressed as usize];
        f.read_exact(&mut buf)?;

        let file_name = &self.file_table[record.file_id as usize];
        let is_dbss = file_name.ends_with(".dbss");

        if level >= &ReadLevel::Decrypt && !is_dbss && !buf.is_empty() {
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
                buf = buf[0..record.sz_original as usize].to_vec();
            }
        }

        Ok(buf)
    }
    pub fn extract_many(&self, level: &ReadLevel, out_path: &Path) -> Result<(), Box<dyn Error>> {
        self.meta_table
            .iter()
            .map(|mr| self.path_table[mr.path_id as usize].path)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .for_each(|p| std::fs::create_dir_all(out_path.join(p)).expect("create dir failed"));

        self.meta_table.par_iter().for_each(|mr| {
            if let Err(e) = self.extract(mr, level, out_path) {
                let base_path = self.path_table[mr.path_id as usize].path;
                let file_name = &self.file_table[mr.file_id as usize];
                let out = out_path.join(base_path).join(file_name);
                eprintln!("Failed extracting {}: {}", out.display(), e);
            }
        });
        Ok(())
    }

    /// This method filters the internal meta table based on regex file name patterns
    /// and can be called multiple times.
    pub fn filter_by_file(&mut self, pattern: &str) -> Result<(), Box<dyn Error>> {
        let re = regex::Regex::new(pattern).expect("invalid regex");
        self.meta_table = self
            .meta_table
            .par_iter()
            .filter(|mr| re.is_match(self.file_table[mr.file_id as usize].as_ref()))
            .cloned()
            .collect();
        Ok(())
    }

    /// This method filters the internal meta table based on regex path patterns.
    ///
    /// SAFETY: This operation is destructive and invalidates the `file_range` indices in the
    ///         `path_table`. This should only be called once as a pre-processing step before
    ///         extraction, as subsequent calls to `filter_by_path` will likely panic from
    ///         index out of bounds or return incorrect data.
    pub fn filter_by_path(&mut self, pattern: &str) -> Result<(), Box<dyn Error>> {
        let re = regex::Regex::new(pattern).expect("invalid regex");
        self.meta_table = self
            .path_table
            .iter()
            .filter(|pr| re.is_match(pr.path.as_ref()))
            .flat_map(|pr| self.meta_table[pr.file_range.clone()].to_vec())
            .collect();
        Ok(())
    }

    /// Returns the name of the package file for use in file paths.
    pub fn package_name(&self, record: &MetaRecord) -> PathBuf {
        PathBuf::from(format!("PAD{:05}.paz", record.package_id))
    }

    /// Returns the path to the package file.
    pub fn package_path(&self, record: &MetaRecord) -> PathBuf {
        self.root.join(self.package_name(record))
    }
}
