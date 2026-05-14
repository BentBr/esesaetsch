//! Tests for `hostkey::generate` — writes a fresh Ed25519 key to disk
//! with restrictive permissions (0600 on Unix).

use esesaetsch_core::hostkey;
use std::fs;

#[test]
fn generate_writes_a_file_at_path() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("host_key");
    hostkey::generate(&path).expect("generate");
    let md = fs::metadata(&path).expect("file exists");
    assert!(md.len() > 0, "non-empty file written");
}

#[cfg(unix)]
#[test]
fn generated_file_has_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("host_key");
    hostkey::generate(&path).expect("generate");
    let perms = fs::metadata(&path).unwrap().permissions();
    let mode = perms.mode() & 0o777;
    assert_eq!(mode, 0o600, "host key must be 0600, got 0o{mode:o}");
}

#[test]
fn generated_key_is_loadable() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("host_key");
    hostkey::generate(&path).expect("generate");
    let _key = hostkey::load(&path).expect("load back");
}

#[test]
fn generate_errors_if_parent_dir_missing() {
    let path = std::path::Path::new("/tmp/esesaetsch-no-such-dir-xyzzy-2026/host_key");
    let res = hostkey::generate(path);
    assert!(res.is_err());
}
