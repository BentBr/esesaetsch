//! End-to-end session lifecycle tests.
//!
//! These boot the real server, connect a real russh client, open a
//! session channel, drive it through shell/command/pty/data/exit, and
//! assert observed behaviour. The PTY layer is a mock so we can
//! deterministically script stdout, exit codes, and inspect what the
//! server tried to spawn.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use esesaetsch_core::auth::{
    AllowlistPubkeyAuthenticator, PasswordAuthenticator, PubkeyAuthenticator,
};
use esesaetsch_core::config::Config;
use esesaetsch_core::pty::{
    Command, MockChildConfig, MockPtySpawner, PtySpawner, SessionExitStatus,
};
use russh::ChannelMsg;
use ssh_key::PrivateKey;
use tokio::time::timeout;

use common::{AcceptAnyClientHandler, MockPasswordAuthenticator, TestServer, client_config};

#[allow(clippy::expect_used)] // test helper
fn to_russh_pk(p: &PrivateKey) -> russh::keys::PrivateKeyWithHashAlg {
    let openssh = p
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("to_openssh")
        .to_string();
    let key = russh::keys::decode_secret_key(&openssh, None).expect("decode_secret_key");
    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None)
}

#[allow(clippy::unwrap_used)] // test helper
async fn server_with_spawner(spawner: Arc<dyn PtySpawner>) -> (TestServer, PrivateKey) {
    let user_key = common::random_ed25519_key();
    let user_pub = user_key.public_key().to_openssh().unwrap();

    let mut config = Config::defaults();
    config.pubkey_enabled = true;
    config.password_enabled = false;
    config.cert_enabled = false;
    config
        .authorized_keys
        .insert("alice".to_owned(), vec![user_pub.clone()]);

    let mut allow = BTreeMap::new();
    allow.insert("alice".to_owned(), vec![user_pub]);
    let pubkey_auth: Arc<dyn PubkeyAuthenticator> =
        Arc::new(AllowlistPubkeyAuthenticator::from_allowlist(&allow).unwrap());
    let password_auth: Arc<dyn PasswordAuthenticator> = Arc::new(MockPasswordAuthenticator::new());

    let server = TestServer::start_with_spawner(config, pubkey_auth, password_auth, spawner).await;
    (server, user_key)
}

#[allow(clippy::expect_used)] // test helper
async fn connect_and_auth(
    server: &TestServer,
    user_key: &PrivateKey,
) -> russh::client::Handle<AcceptAnyClientHandler> {
    let mut handle = timeout(
        Duration::from_secs(5),
        russh::client::connect(client_config(), server.bound_addr, AcceptAnyClientHandler),
    )
    .await
    .expect("connect timed out")
    .expect("connect");

    let kp = to_russh_pk(user_key);
    let ok = handle
        .authenticate_publickey("alice", kp)
        .await
        .expect("auth");
    assert!(ok.success(), "auth should succeed");
    handle
}

#[allow(clippy::expect_used)] // test helper
async fn drain_channel(
    channel: &mut russh::Channel<russh::client::Msg>,
) -> (Vec<u8>, Vec<u8>, Option<u32>) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut code = None;
    loop {
        let msg = timeout(Duration::from_secs(5), channel.wait())
            .await
            .expect("channel wait timed out");
        match msg {
            Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => stderr.extend_from_slice(&data),
            Some(ChannelMsg::ExitStatus { exit_status }) => code = Some(exit_status),
            Some(ChannelMsg::Close) | None => break,
            // Eof, RequestPty echoes, etc. — ignore.
            Some(_) => {}
        }
    }
    (stdout, stderr, code)
}

#[tokio::test]
async fn command_request_pumps_stdout_and_emits_exit_status() {
    let spawner = Arc::new(MockPtySpawner::new());
    spawner.set_config(MockChildConfig {
        stdout_bytes: b"hello from child\n".to_vec(),
        exit_status: Some(SessionExitStatus::from_code(42)),
        ..MockChildConfig::default()
    });

    let (server, user_key) = server_with_spawner(spawner.clone()).await;
    let handle = connect_and_auth(&server, &user_key).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("channel_open_session");
    channel.exec(true, "echo hello").await.expect("request");

    let (stdout, stderr, code) = drain_channel(&mut channel).await;
    assert_eq!(stdout, b"hello from child\n");
    assert!(stderr.is_empty());
    assert_eq!(code, Some(42));

    let observed = spawner.last_command().expect("spawned");
    assert_eq!(observed, Command::Exec("echo hello".to_owned()));
    let observed_user = spawner.last_user().expect("user");
    assert_eq!(observed_user, "alice");
}

#[tokio::test]
async fn shell_via_pty_pumps_output_and_propagates_exit() {
    let spawner = Arc::new(MockPtySpawner::new());
    spawner.set_config(MockChildConfig {
        stdout_bytes: b"$ ".to_vec(),
        exit_status: Some(SessionExitStatus::success()),
        ..MockChildConfig::default()
    });

    let (server, user_key) = server_with_spawner(spawner.clone()).await;
    let handle = connect_and_auth(&server, &user_key).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("channel_open_session");

    channel
        .request_pty(false, "xterm-256color", 80, 24, 0, 0, &[])
        .await
        .expect("pty");
    channel.request_shell(false).await.expect("shell");

    let (stdout, _stderr, code) = drain_channel(&mut channel).await;
    assert_eq!(stdout, b"$ ");
    assert_eq!(code, Some(0));

    let observed = spawner.last_command().expect("spawned");
    assert_eq!(observed, Command::Shell);
}

#[tokio::test]
async fn stdin_data_reaches_the_child() {
    let spawner = Arc::new(MockPtySpawner::new());
    spawner.set_config(MockChildConfig {
        stdout_bytes: Vec::new(),
        exit_status: None, // never exits — gives us time to send stdin
        ..MockChildConfig::default()
    });

    let (server, user_key) = server_with_spawner(spawner.clone()).await;
    let handle = connect_and_auth(&server, &user_key).await;
    let channel = handle
        .channel_open_session()
        .await
        .expect("channel_open_session");
    channel.exec(true, "/bin/cat").await.expect("request");

    let bytes = b"hello stdin!\n";
    channel.data(&bytes[..]).await.expect("send stdin");

    tokio::time::sleep(Duration::from_millis(150)).await;

    let record = spawner.last_record().expect("record");
    let captured = record.stdin.lock().unwrap().clone();
    assert!(
        captured.windows(bytes.len()).any(|w| w == bytes),
        "expected captured stdin to contain {bytes:?}, got {captured:?}",
    );

    drop(channel);
    drop(handle);
}

#[tokio::test]
async fn window_change_propagates_to_pty_resize() {
    let spawner = Arc::new(MockPtySpawner::new());
    spawner.set_config(MockChildConfig {
        exit_status: None,
        ..MockChildConfig::default()
    });

    let (server, user_key) = server_with_spawner(spawner.clone()).await;
    let handle = connect_and_auth(&server, &user_key).await;
    let channel = handle
        .channel_open_session()
        .await
        .expect("channel_open_session");
    channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("pty");
    channel.request_shell(false).await.expect("shell");

    channel
        .window_change(120, 40, 0, 0)
        .await
        .expect("window_change");

    tokio::time::sleep(Duration::from_millis(150)).await;

    let record = spawner.last_record().expect("record");
    let resizes = record.resizes.lock().unwrap().clone();
    assert!(
        resizes.contains(&(120, 40)),
        "expected resize(120,40) in {resizes:?}",
    );

    drop(channel);
    drop(handle);
}

#[tokio::test]
async fn client_disconnect_kills_the_child() {
    // When the client closes the channel / drops the connection, the
    // server-side session task calls `PtyChild::kill` so the child
    // doesn't outlive the session.
    let spawner = Arc::new(MockPtySpawner::new());
    spawner.set_config(MockChildConfig {
        // Long-running child that never exits on its own.
        exit_status: None,
        ..MockChildConfig::default()
    });

    let (server, user_key) = server_with_spawner(spawner.clone()).await;
    {
        let handle = connect_and_auth(&server, &user_key).await;
        let channel = handle
            .channel_open_session()
            .await
            .expect("channel_open_session");
        channel
            .exec(true, "/bin/sleep 9999")
            .await
            .expect("request");

        // Give the session task a moment to spawn the child.
        tokio::time::sleep(Duration::from_millis(150)).await;
        // Channel and handle drop here — connection torn down.
    }

    // Poll for the kill to land (the kill happens once the control_tx is
    // dropped server-side and the session loop sees `recv() -> None`).
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let killed = spawner
            .last_record()
            .expect("record")
            .killed
            .load(std::sync::atomic::Ordering::Relaxed);
        if killed {
            break;
        }
        assert!(
            std::time::Instant::now() <= deadline,
            "server did not kill child within 3s of client disconnect",
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn spawn_failure_emits_exit_status_one_with_no_stderr() {
    // When the spawner errors, the client sees `exit-status=1` and the
    // channel closes — no stderr description ever crosses the wire (the
    // operator-side reason is only in the server log).
    let spawner = Arc::new(MockPtySpawner::new());
    spawner.set_config(MockChildConfig {
        spawn_error: Some("simulated PrivilegeDenied".to_owned()),
        ..MockChildConfig::default()
    });

    let (server, user_key) = server_with_spawner(spawner).await;
    let handle = connect_and_auth(&server, &user_key).await;
    let mut channel = handle
        .channel_open_session()
        .await
        .expect("channel_open_session");
    channel.exec(true, "/bin/anything").await.expect("request");

    let (stdout, stderr, code) = drain_channel(&mut channel).await;
    assert!(stdout.is_empty());
    assert!(stderr.is_empty(), "no stderr leaked: {stderr:?}");
    assert_eq!(code, Some(1));
}
