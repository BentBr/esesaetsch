//! End-to-end CLI tests via the compiled binary.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_lists_subcommands() {
    Command::cargo_bin("esesaetsch")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("gen-key"))
        .stdout(predicate::str::contains("serve"));
}

#[test]
fn gen_key_writes_a_host_key() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("host_key");
    Command::cargo_bin("esesaetsch")
        .unwrap()
        .args(["gen-key", "--host-key"])
        .arg(&path)
        .assert()
        .success();
    assert!(path.exists(), "gen-key should create the file");
}

#[test]
fn gen_key_refuses_to_overwrite() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("host_key");
    std::fs::write(&path, b"existing").unwrap();
    Command::cargo_bin("esesaetsch")
        .unwrap()
        .args(["gen-key", "--host-key"])
        .arg(&path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn serve_with_invalid_bind_fails_with_clear_message() {
    let tmp = tempfile::TempDir::new().unwrap();
    let toml = tmp.path().join("config.toml");
    std::fs::write(
        &toml,
        r#"
        [server]
        bind = "not-an-address"
        port = 2222
    "#,
    )
    .unwrap();
    Command::cargo_bin("esesaetsch")
        .unwrap()
        .args(["serve", "--config"])
        .arg(&toml)
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid bind address"));
}

#[test]
fn serve_with_no_auth_method_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let toml = tmp.path().join("config.toml");
    std::fs::write(
        &toml,
        r"
        [auth]
        pubkey_enabled = false
        password_enabled = false
        cert_enabled = false
    ",
    )
    .unwrap();
    Command::cargo_bin("esesaetsch")
        .unwrap()
        .args(["serve", "--config"])
        .arg(&toml)
        .assert()
        .failure()
        .stderr(predicate::str::contains("at least one"));
}

#[test]
fn serve_with_valid_config_prints_listen_message() {
    let tmp = tempfile::TempDir::new().unwrap();
    let toml = tmp.path().join("config.toml");
    std::fs::write(
        &toml,
        r"
        [server]
        port = 12345
    ",
    )
    .unwrap();
    Command::cargo_bin("esesaetsch")
        .unwrap()
        .args(["serve", "--config"])
        .arg(&toml)
        .assert()
        .success()
        .stdout(predicate::str::contains("12345"));
}
