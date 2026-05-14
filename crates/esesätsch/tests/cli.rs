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
fn serve_actually_listens_on_the_configured_port() {
    use std::io::Read;
    use std::net::{TcpStream, ToSocketAddrs};
    use std::thread;
    use std::time::{Duration, Instant};

    let tmp = tempfile::TempDir::new().unwrap();
    let host_key = tmp.path().join("host_key");

    // Pick a high port that's vanishingly unlikely to be in use. If the
    // bind fails, the binary exits with an error and the test fails
    // cleanly via the join check below.
    let port: u16 = 56_731;

    let bin = assert_cmd::cargo::cargo_bin("esesaetsch");
    let mut child = std::process::Command::new(&bin)
        .args(["serve", "--port"])
        .arg(port.to_string())
        .args(["--host-key"])
        .arg(&host_key)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn binary");

    // Poll for the server to actually be listening (TCP connect succeeds).
    let addr = ("127.0.0.1", port)
        .to_socket_addrs()
        .expect("resolve")
        .next()
        .expect("address");
    let deadline = Instant::now() + Duration::from_secs(5);
    let connected = loop {
        if Instant::now() > deadline {
            break false;
        }
        if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            // Read the SSH banner the server sends as a sanity check.
            let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buf = [0_u8; 32];
            let n = s.read(&mut buf).unwrap_or(0);
            if n > 0 && buf.starts_with(b"SSH-2.0-") {
                break true;
            }
        }
        thread::sleep(Duration::from_millis(100));
    };

    // Tear down the server before any assertion can poison the test.
    let _ = child.kill();
    let _ = child.wait();

    assert!(connected, "server did not start listening on port {port}");
}
