use pad::MetaFile;
use std::path::PathBuf;

lazy_static::lazy_static! {
    static ref ROOT : PathBuf = [r".", "test-data"].iter().collect();
}

const KEY: &[u8; 8] = &[0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];

#[test]
fn meta_parse() {
    // This is a rather monolithic test, but the structure of the meta file is
    // pretty simple and each block is interdependent. The only part that might
    // be 'different' is the string handling since it has dynamic length but
    // that isn't worth breaking up into multiple tests.
    let meta = MetaFile::new(&ROOT, KEY).expect("meta parsing error");

    // Version
    assert_eq!(meta.version, 1892, "version mismatch");

    // Package table
    assert_eq!(meta.package_table.len(), 7700, "package table len mismatch");

    let package_record = meta.package_table.first().unwrap();
    assert_eq!(package_record.id, 1, "package id mismatch");
    assert_eq!(package_record.hash, 879459305, "package hash mismatch");
    assert_eq!(package_record.size, 9863228, "package size mismatch");

    let package_record = meta.package_table.last().unwrap();
    assert_eq!(package_record.id, 7700, "package id mismatch");
    assert_eq!(package_record.hash, 4047003738, "package hash mismatch");
    assert_eq!(package_record.size, 174196, "package size mismatch");

    // Meta table
    assert_eq!(meta.meta_table.len(), 597589, "meta table len mismatch");

    let meta_record = meta.meta_table.first().unwrap();
    assert_eq!(meta_record.hash, 3751579307, "meta hash mismatch");
    assert_eq!(meta_record.path_id, 0, "meta path id mismatch");
    assert_eq!(meta_record.file_id, 0, "meta file id mismatch");
    assert_eq!(meta_record.package_id, 1, "meta package id mismatch");
    assert_eq!(meta_record.package_offset, 53372, "meta offset mismatch");
    assert_eq!(meta_record.sz_compressed, 22992, "meta compressed size mismatch");
    assert_eq!(meta_record.sz_original, 88220, "meta original size mismatch");

    let meta_record = meta.meta_table.last().unwrap();
    assert_eq!(meta_record.hash, 1207248531, "meta hash mismatch");
    assert_eq!(meta_record.path_id, 6320, "meta path id mismatch");
    assert_eq!(meta_record.file_id, 597588, "meta file id mismatch");
    assert_eq!(meta_record.package_id, 7697, "meta package id mismatch");
    assert_eq!(meta_record.package_offset, 5352580, "meta offset mismatch");
    assert_eq!(meta_record.sz_compressed, 2168784, "meta compressed size mismatch");
    assert_eq!(meta_record.sz_original, 19204210, "meta original size mismatch");

    // Path table
    assert_eq!(meta.path_table.len(), 6321, "path table len mismatch");

    let path_record = meta.path_table.first().unwrap();
    assert_eq!(path_record.path, PathBuf::from("character/"), "path mismatch");
    assert_eq!(path_record.file_range.start, 0, "path bucket start mismatch");
    assert_eq!(path_record.file_range.end, 53, "path bucket end mismatch");

    let path_record = meta.path_table.last().unwrap();
    assert_eq!(
        path_record.path,
        PathBuf::from("character/rebootbinaryactionchart/rebootpc/2_phw/"),
        "path mismatch"
    );
    assert_eq!(path_record.file_range.start, 597587, "path bucket start mismatch");
    assert_eq!(path_record.file_range.end, 597589, "path bucket end mismatch");

    // File table
    assert_eq!(meta.file_table.len(), 597589, "file table len mismatch");
    assert_eq!(
        meta.file_table.first().unwrap(),
        &PathBuf::from("ai 스크립트_메뉴얼.xml"),
        "file id mismatch"
    );
    assert_eq!(
        meta.file_table.last().unwrap(),
        &PathBuf::from("sorceressaction_noweapon_simple.paac"),
        "file id mismatch"
    );
}

#[test]
fn path_filter() {
    // path_filter should filter only the meta table leaving the package, path, and file tables
    // intact such that package_id, path_id, and file_id still act as indexes into the respective
    // tables.

    // Filters without qualifiers.
    let mut meta = MetaFile::new(&ROOT, KEY).expect("meta parsing error");
    let old_package_table_len = meta.package_table.len();
    let old_path_table_len = meta.path_table.len();
    let old_file_table_len = meta.file_table.len();
    meta.filter_by_path("character").expect("(w/ qualifiers)path filter error");
    assert_eq!(meta.package_table.len(), old_package_table_len, "(w/o qualifiers) package table len mismatch");
    assert_eq!(meta.path_table.len(), old_path_table_len, "(w/o qualifiers) path table len mismatch");
    assert_eq!(meta.file_table.len(), old_file_table_len, "(w/o qualifiers) file table len mismatch");
    assert_eq!(meta.meta_table.len(), 156958, "(w/o qualifiers)meta table len mismatch");

    // Filters with qualifiers.
    let mut meta = MetaFile::new(&ROOT, KEY).expect("meta parsing error");
    meta.filter_by_path("^character/ai_.*k/").expect("(w/ qualifiers) path filter error");
    assert_eq!(meta.package_table.len(), old_package_table_len, "(w/ qualifiers) package table len mismatch");
    assert_eq!(meta.path_table.len(), old_path_table_len, "(w/ qualifiers)path table len mismatch");
    assert_eq!(meta.file_table.len(), old_file_table_len, "(w/ qualifiers)file table len mismatch");
    assert_eq!(meta.meta_table.len(), 37, "(w/ qualifiers)meta table len mismatch");
}

#[test]
fn file_filter() {
    // path_filter should filter only the meta table leaving the package, path, and file tables
    // intact such that package_id, path_id, and file_id still act as indexes into the respective
    // tables.

    // Filters without qualifiers.
    let mut meta = MetaFile::new(&ROOT, KEY).expect("meta parsing error");
    let old_package_table_len = meta.package_table.len();
    let old_path_table_len = meta.path_table.len();
    let old_file_table_len = meta.file_table.len();
    meta.filter_by_file("cloud").expect("(w/ qualifiers)path filter error");
    assert_eq!(meta.package_table.len(), old_package_table_len, "(w/o qualifiers) package table len mismatch");
    assert_eq!(meta.path_table.len(), old_path_table_len, "(w/o qualifiers) path table len mismatch");
    assert_eq!(meta.file_table.len(), old_file_table_len, "(w/o qualifiers) file table len mismatch");
    assert_eq!(meta.meta_table.len(), 40, "(w/o qualifiers)meta table len mismatch");

    // Filters with qualifiers.
    let mut meta = MetaFile::new(&ROOT, KEY).expect("meta parsing error");
    meta.filter_by_file("^cloud.*fx").expect("(w/ qualifiers) path filter error");
    assert_eq!(meta.package_table.len(), old_package_table_len, "(w/ qualifiers) package table len mismatch");
    assert_eq!(meta.path_table.len(), old_path_table_len, "(w/ qualifiers)path table len mismatch");
    assert_eq!(meta.file_table.len(), old_file_table_len, "(w/ qualifiers)file table len mismatch");
    assert_eq!(meta.meta_table.len(), 4, "(w/ qualifiers)meta table len mismatch");
}
