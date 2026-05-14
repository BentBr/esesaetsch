//! Tests for `hostkey::load` — reads an existing PEM-encoded Ed25519 key
//! from disk and returns the parsed `russh_keys::key::KeyPair`.

use esesaetsch_core::error::HostKeyError;
use esesaetsch_core::hostkey;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn load_returns_error_for_missing_file() {
    let result = hostkey::load(std::path::Path::new("/definitely/does/not/exist/hostkey"));
    assert!(matches!(result, Err(HostKeyError::Io { .. })));
}

#[test]
fn load_returns_error_for_malformed_file() {
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"this is not an OpenSSH key").unwrap();
    let result = hostkey::load(tmp.path());
    assert!(matches!(result, Err(HostKeyError::Malformed { .. })));
}

#[test]
fn load_succeeds_for_freshly_generated_key() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("host_key");
    hostkey::generate(&path).expect("generate");
    let _key = hostkey::load(&path).expect("load");
}
