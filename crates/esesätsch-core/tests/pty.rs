//! Tests for the PTY trait surfaces and the in-tree Mock.

use esesaetsch_core::cert::CertGrants;
use esesaetsch_core::pty::{
    Command, MockChildConfig, MockPtySpawner, PtySpawner, SessionExitStatus, SpawnSpec,
    TerminalSize,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn shell_spawn_spec<'a>() -> SpawnSpec<'a> {
    SpawnSpec {
        user: "alice",
        term: "xterm-256color",
        size: TerminalSize {
            cols: 80,
            rows: 24,
            pixel_w: 0,
            pixel_h: 0,
        },
        env: &[],
        command: Command::Shell,
        interactive: true,
        grants: CertGrants::default(),
    }
}

#[tokio::test]
async fn mock_spawner_returns_a_child_with_scripted_stdout() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        stdout_bytes: b"hello\n".to_vec(),
        exit_status: Some(SessionExitStatus::success()),
        ..MockChildConfig::default()
    });

    let mut child = spawner.spawn(shell_spawn_spec()).expect("spawns");
    let mut buf = Vec::new();
    child
        .take_reader()
        .expect("reader")
        .read_to_end(&mut buf)
        .await
        .expect("reads");
    assert_eq!(buf, b"hello\n");
}

#[tokio::test]
async fn mock_stdin_is_captured_in_the_record() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        exit_status: Some(SessionExitStatus::success()),
        ..MockChildConfig::default()
    });

    let mut child = spawner.spawn(shell_spawn_spec()).expect("spawns");
    let mut w = child.take_writer().expect("writer");
    w.write_all(b"ls -la\n").await.expect("write");
    w.flush().await.expect("flush");

    let record = spawner.last_record().expect("has record");
    assert_eq!(record.stdin.lock().unwrap().as_slice(), b"ls -la\n");
}

#[tokio::test]
async fn mock_resize_is_recorded() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        exit_status: Some(SessionExitStatus::success()),
        ..MockChildConfig::default()
    });

    let mut child = spawner.spawn(shell_spawn_spec()).expect("spawns");
    child.resize(120, 40).unwrap();
    child.resize(80, 24).unwrap();

    let record = spawner.last_record().expect("has record");
    let resizes = record.resizes.lock().unwrap().clone();
    assert_eq!(resizes, vec![(120, 40), (80, 24)]);
}

#[tokio::test]
async fn mock_wait_resolves_to_scripted_exit_code() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        exit_status: Some(SessionExitStatus::from_code(42)),
        ..MockChildConfig::default()
    });

    let mut child = spawner.spawn(shell_spawn_spec()).expect("spawns");
    let status = child.take_wait().expect("wait").await.expect("waits");
    assert_eq!(status.code, Some(42));
}

#[tokio::test]
async fn mock_kill_marks_record_and_resolves_wait() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig::default()); // no scripted exit
    let mut child = spawner.spawn(shell_spawn_spec()).expect("spawns");

    child.kill().unwrap();
    let status = child.take_wait().expect("wait").await.expect("waits");
    assert_eq!(status.code, Some(137));

    let record = spawner.last_record().expect("has record");
    assert!(record.killed.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn interactive_mode_has_no_separate_stderr_reader() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        stderr_bytes: Some(b"this should not appear".to_vec()),
        exit_status: Some(SessionExitStatus::success()),
        ..MockChildConfig::default()
    });

    let mut spec = shell_spawn_spec();
    spec.interactive = true;
    let mut child = spawner.spawn(spec).expect("spawns");
    assert!(child.take_stderr().is_none(), "PTY merges stderr");
}

#[tokio::test]
async fn non_interactive_mode_exposes_stderr_separately() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        stderr_bytes: Some(b"error: boom\n".to_vec()),
        exit_status: Some(SessionExitStatus::from_code(1)),
        ..MockChildConfig::default()
    });

    let mut spec = shell_spawn_spec();
    spec.interactive = false;
    spec.command = Command::Exec("/bin/false".to_owned());

    let mut child = spawner.spawn(spec).expect("spawns");
    let mut e = child.take_stderr().expect("non-interactive has stderr");
    let mut buf = Vec::new();
    e.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, b"error: boom\n");
}

#[tokio::test]
async fn spawn_error_propagates() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        spawn_error: Some("permission denied".to_owned()),
        ..MockChildConfig::default()
    });

    let outcome = spawner.spawn(shell_spawn_spec());
    assert!(outcome.is_err());
}

#[tokio::test]
async fn force_command_overrides_requested_shell() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        exit_status: Some(SessionExitStatus::success()),
        ..MockChildConfig::default()
    });

    let spec = SpawnSpec {
        command: Command::Shell,
        grants: CertGrants {
            force_command: Some("/usr/bin/restricted".to_owned()),
        },
        ..shell_spawn_spec()
    };

    spawner.spawn(spec).expect("spawns");
    let observed = spawner.last_command().expect("has command");
    assert_eq!(observed, Command::Exec("/usr/bin/restricted".to_owned()));
}

#[tokio::test]
async fn force_command_overrides_requested_command() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        exit_status: Some(SessionExitStatus::success()),
        ..MockChildConfig::default()
    });

    let spec = SpawnSpec {
        command: Command::Exec("rm -rf /".to_owned()),
        grants: CertGrants {
            force_command: Some("/bin/echo locked".to_owned()),
        },
        ..shell_spawn_spec()
    };

    spawner.spawn(spec).expect("spawns");
    let observed = spawner.last_command().expect("has command");
    assert_eq!(observed, Command::Exec("/bin/echo locked".to_owned()));
}

#[tokio::test]
async fn spec_user_is_recorded() {
    let spawner = MockPtySpawner::new();
    spawner.set_config(MockChildConfig {
        exit_status: Some(SessionExitStatus::success()),
        ..MockChildConfig::default()
    });

    let spec = SpawnSpec {
        user: "bob",
        ..shell_spawn_spec()
    };
    spawner.spawn(spec).expect("spawns");
    assert_eq!(spawner.last_user().as_deref(), Some("bob"));
}
