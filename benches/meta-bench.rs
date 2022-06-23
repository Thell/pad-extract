use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[macro_use]
extern crate bencher;
use bencher::Bencher;

use pad::MetaFile;
use pad::ReadLevel;
use rayon::prelude::*;
use std::path::PathBuf;

const ICE_KEY: &[u8; 8] = &[0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];

lazy_static::lazy_static! {
    static ref ROOT : PathBuf = [r"C:\", "Program Files (x86)", "BlackDesert", "Paz"].iter().collect();
}

const PATH_FILTER: &str = r"^gamecommondata/binary/$";
const FILE_FILTER: &str = r"bss$";

fn b1_parse(bench: &mut Bencher) {
    bench.iter(|| {
        let meta = MetaFile::new_from_path(&ROOT, ICE_KEY).expect("meta parsing error");
        bencher::black_box(meta);
    });
}

fn b2_filter_path(bench: &mut Bencher) {
    bench.iter(|| {
        let mut meta = MetaFile::new_from_path(&ROOT, ICE_KEY).expect("meta parsing error");
        meta.filter_by_path(PATH_FILTER).expect("path filter error");
        bencher::black_box(meta);
    });
}

fn b3_filter_file(bench: &mut Bencher) {
    bench.iter(|| {
        let mut meta = MetaFile::new_from_path(&ROOT, ICE_KEY).expect("meta parsing error");
        meta.filter_by_file(FILE_FILTER).expect("path filter error");
        bencher::black_box(meta);
    });
}

fn b4_filter_path_and_file(bench: &mut Bencher) {
    bench.iter(|| {
        let mut meta = MetaFile::new_from_path(&ROOT, ICE_KEY).expect("meta parsing error");
        meta.filter_by_path(PATH_FILTER).expect("path filter error");
        meta.filter_by_file(FILE_FILTER).expect("path filter error");
        bencher::black_box(meta);
    });
}

fn b5_read_raw(bench: &mut Bencher) {
    bench.iter(|| {
        let mut meta = MetaFile::new_from_path(&ROOT, ICE_KEY).expect("meta parsing error");
        meta.filter_by_path(PATH_FILTER).expect("path filter error");
        meta.filter_by_file(FILE_FILTER).expect("path filter error");
        meta.meta_table.par_iter().for_each(|mr| {
            let buf = meta.read(mr, &ReadLevel::Raw).expect("read failed");
            bencher::black_box(buf);
        });
    });
}

fn b6_read_decrypted(bench: &mut Bencher) {
    bench.iter(|| {
        let mut meta = MetaFile::new_from_path(&ROOT, ICE_KEY).expect("meta parsing error");
        meta.filter_by_path(PATH_FILTER).expect("path filter error");
        meta.filter_by_file(FILE_FILTER).expect("path filter error");
        meta.meta_table.par_iter().for_each(|mr| {
            let buf = meta.read(mr, &ReadLevel::Decrypt).expect("read failed");
            bencher::black_box(buf);
        });
    });
}

fn b7_read_decompressed(bench: &mut Bencher) {
    bench.iter(|| {
        let mut meta = MetaFile::new_from_path(&ROOT, ICE_KEY).expect("meta parsing error");
        meta.filter_by_path(PATH_FILTER).expect("path filter error");
        meta.filter_by_file(FILE_FILTER).expect("path filter error");
        meta.meta_table.par_iter().for_each(|mr| {
            let buf = meta.read(mr, &ReadLevel::Decompress).expect("read failed");
            bencher::black_box(buf);
        });
    });
}

fn b8_extract(bench: &mut Bencher) {
    bench.iter(|| {
        let out = PathBuf::from("./").canonicalize().unwrap().join("bench-out");
        let mut meta = MetaFile::new_from_path(&ROOT, ICE_KEY).expect("meta parsing error");
        meta.filter_by_path(PATH_FILTER).expect("path filter error");
        meta.filter_by_file(FILE_FILTER).expect("path filter error");
        meta.extract_many(&ReadLevel::Decompress, &out).expect("extract failed");
    });
}

benchmark_group!(
    bench_meta,
    b1_parse,
    b2_filter_path,
    b3_filter_file,
    b4_filter_path_and_file,
    b5_read_raw,
    b6_read_decrypted,
    b7_read_decompressed,
    b8_extract,
);
benchmark_main!(bench_meta);
