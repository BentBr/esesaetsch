//! `hostkey::load_or_generate` — used by the `serve` subcommand on startup.

use esesaetsch_core::hostkey;

#[test]
fn generates_when_absent() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("host_key");
    assert!(!path.exists());
    let _key = hostkey::load_or_generate(&path).expect("load_or_generate");
    assert!(path.exists());
}

#[test]
fn loads_when_present() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("host_key");
    hostkey::generate(&path).expect("seed");
    let _key1 = hostkey::load_or_generate(&path).expect("load existing");
    let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
    let _key2 = hostkey::load_or_generate(&path).expect("load again");
    let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "load_or_generate must not rewrite an existing key"
    );
}
