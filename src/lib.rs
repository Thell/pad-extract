use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use icefast::Ice;
use rayon::prelude::*;
use std::error::Error;
use std::io::Cursor;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;

#[derive(PartialOrd, Ord, PartialEq, Eq)]
pub enum ReadLevel {
    #[allow(dead_code)]
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
    reader: &mut Cursor<&mut Vec<u8>>,
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
    Ok(std::ops::Range {
        start: start as usize,
        end: end as usize,
    })
}

#[derive(Debug)]
pub struct MetaFile {
    pub ice: Ice,
    pub root: PathBuf,
    pub version: u32,
    pub package_table: Vec<PackageRecord>,
    pub meta_table: Vec<MetaRecord>,
    pub path_table: Vec<PathRecord>,
    pub file_table: Vec<PathBuf>,
}

impl MetaFile {
    // The path table is organized such that each entry is a bucket of file indices.
    // The raw data is organized for hash lookups, but this library organizes it for
    // efficient filtering and extraction directly using the path table bucket indices
    // on the meta table records.
    // In order to filter by bucket indices the meta table needs to be sorted by file index.
    pub fn new(buf: &mut Vec<u8>, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
        let ice = Ice::new(0, key);
        let root = PathBuf::new();

        let mut reader = Cursor::new(&mut *buf);

        let version = reader.read_u32::<LittleEndian>().unwrap();

        let range = block_range(BlockType::Packages, &mut reader)?;
        let package_table = PackageRecord::many_from_le_bytes(&reader.get_ref()[range]);

        let range = block_range(BlockType::Metas, &mut reader)?;
        let mut meta_table = MetaRecord::many_from_le_bytes(&reader.get_ref()[range]);
        meta_table.par_sort_by_key(|x| x.file_id);

        let range = block_range(BlockType::Paths, &mut reader)?;
        let path_table =
            PathRecord::many_from_encrypted_le_bytes(&mut reader.get_mut()[range], &ice);

        let range = block_range(BlockType::Files, &mut reader)?;
        let file_table =
            FileRecord::many_from_encrypted_le_bytes(&mut reader.get_mut()[range], &ice);

        let meta_file = MetaFile {
            ice,
            root,
            version,
            package_table,
            meta_table,
            path_table,
            file_table,
        };
        Ok(meta_file)
    }

    pub fn new_from_path(root: &Path, key: &[u8; 8]) -> Result<Self, Box<dyn Error>> {
        let metafile = PathBuf::from("pad00000.meta");
        let mut buf = std::fs::read(root.join(metafile))?;
        let mut meta = Self::new(&mut buf, key)?;
        meta.root = root.to_path_buf();
        Ok(meta)
    }

    pub fn extract(
        &self,
        record: &MetaRecord,
        level: &ReadLevel,
        out_path: &Path,
    ) -> Result<(), Box<dyn Error>> {
        let file_path = self.path_table[record.path_id as usize].path.clone();
        let file_name = &self.file_table[record.file_id as usize];
        let out_path = &out_path.join(file_path).join(file_name);
        let mut f = std::fs::File::create(out_path)?;
        let buf = &self.read(record, level)?;
        f.write_all(buf)?;
        Ok(())
    }

    pub fn extract_many(&self, level: &ReadLevel, out_path: &Path) -> Result<(), Box<dyn Error>> {
        self.meta_table
            .iter()
            .map(|mr| self.path_table[mr.path_id as usize].path.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .for_each(|p| std::fs::create_dir_all(out_path.join(p)).expect("create dir failed"));
        self.meta_table.par_iter().for_each(|mr| {
            if let Err(e) = self.extract(mr, level, out_path) {
                let path = self.path_table[mr.path_id as usize].path.clone();
                let file = &self.file_table[mr.file_id as usize];
                let out_path = path.join(file);
                println!(
                    "Failed {}\n metarecord: {:?}\n with error: {}\n",
                    out_path.display(),
                    mr,
                    e
                );
            }
        });
        Ok(())
    }

    pub fn filter_by_file(&mut self, pattern: &str) -> Result<(), Box<dyn Error>> {
        let re = regex::Regex::new(pattern).unwrap();
        self.meta_table = self
            .meta_table
            .par_iter()
            .filter(|x| re.is_match(self.file_table[x.file_id as usize].to_str().unwrap()))
            .cloned()
            .collect();
        Ok(())
    }

    pub fn filter_by_path(&mut self, re_pat: &str) -> Result<(), Box<dyn Error>> {
        let re = regex::Regex::new(re_pat).unwrap();
        self.meta_table = self
            .path_table
            .iter()
            .filter(|x| re.is_match(x.path.to_str().unwrap()))
            .flat_map(|pr| self.meta_table[pr.file_range.clone()].to_vec())
            .collect();
        Ok(())
    }

    pub fn read(&self, record: &MetaRecord, level: &ReadLevel) -> Result<Vec<u8>, Box<dyn Error>> {
        // ReadLevel::Raw
        let mut f = std::fs::File::open(self.package_path(record))?;
        f.seek(std::io::SeekFrom::Start(record.package_offset as u64))?;
        let mut buf = vec![0; record.sz_compressed as usize];
        f.read_exact(&mut buf)?;

        let file_name = &self.file_table[record.file_id as usize];
        let is_dbss = match file_name.to_str() {
            Some(s) => s.ends_with(".dbss"),
            None => false,
        };
        if level >= &ReadLevel::Decrypt && !is_dbss {
            buf.par_chunks_exact_mut(128)
                .for_each(|chunk| self.ice.decrypt_blocks_par::<16>(chunk));
            buf.chunks_exact_mut(128)
                .into_remainder()
                .chunks_exact_mut(8)
                .for_each(|chunk| {
                    self.ice.decrypt(chunk);
                });
        }

        if level >= &ReadLevel::Decompress {
            if record.sz_original > record.sz_compressed
                || (!is_dbss && !buf.is_empty() && buf[0] == 0x6E)
            {
                let mut buf_reader = Cursor::<&[u8]>::new(&buf);
                buf = quicklz::decompress(&mut buf_reader, record.sz_original)?;
            }
            if record.sz_original < record.sz_compressed {
                buf = buf[0..record.sz_original as usize].to_vec();
            }
        }
        Ok(buf)
    }

    pub fn package_name(&self, record: &MetaRecord) -> PathBuf {
        PathBuf::from(format!("PAD{:05}.paz", record.package_id))
    }

    pub fn package_path(&self, record: &MetaRecord) -> PathBuf {
        self.root.join(self.package_name(record))
    }
}

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

#[derive(Debug)]
pub struct PathRecord {
    pub path: PathBuf,
    pub file_range: std::ops::Range<usize>,
}

impl PathRecord {
    fn from_raw_parts(path: &str, start: usize, end: usize) -> PathRecord {
        PathRecord {
            path: PathBuf::from(path),
            file_range: std::ops::Range { start, end },
        }
    }

    fn many_from_encrypted_le_bytes(bytes: &mut [u8], ice: &Ice) -> Vec<PathRecord> {
        ice.decrypt_auto(bytes);
        let trimmed_len = bytes.len() - bytes.iter().rev().position(|x| *x != 0).unwrap() + 1;
        let bytes = &mut bytes[..trimmed_len];

        let mut path_table = Vec::new();
        let mut reader = Cursor::new(bytes);
        while (reader.position() as usize) < trimmed_len {
            let start = reader.read_u32::<LittleEndian>().unwrap();
            let end = start + reader.read_u32::<LittleEndian>().unwrap();
            let mut buf = Vec::new();
            reader.read_until(0, &mut buf).unwrap();
            buf.pop();
            let record = PathRecord::from_raw_parts(
                &encoding_rs::EUC_KR.decode_without_bom_handling(&buf).0,
                start as usize,
                end as usize,
            );
            path_table.push(record);
        }
        path_table
    }
}

struct FileRecord; // PathBuf
impl FileRecord {
    fn many_from_encrypted_le_bytes(bytes: &mut [u8], ice: &Ice) -> Vec<PathBuf> {
        ice.decrypt_auto(bytes);
        let trimmed_len = bytes.len() - bytes.iter().rev().position(|x| x != &0u8).unwrap();
        bytes[..trimmed_len]
            .par_split(|x| x == &0u8)
            .map(|x| encoding_rs::EUC_KR.decode_without_bom_handling(x).0)
            .map(|x| PathBuf::from(x.to_string()))
            .collect()
    }
}
