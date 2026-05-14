//! SSH session loop.
//!
//! Once a client has authenticated and requested either `shell` or `exec`
//! on a channel, [`run`] takes ownership of the spawned `PtyChild` and
//! manages the lifetime of the session:
//!
//! - **stdout pump**: child's stdout → `Handle::data(channel_id, …)`.
//! - **stderr pump** (non-interactive only): child's stderr →
//!   `Handle::extended_data(channel_id, 1, …)`.
//! - **stdin pipe**: incoming `data` SSH messages are forwarded to the
//!   child's stdin via a control channel.
//! - **resize**: incoming `window-change` messages call
//!   `PtyChild::resize`.
//! - **exit**: when the child terminates, we send `exit-status` (or
//!   `exit-status = 1` on internal failure, with no diagnostic bytes) and close
//!   the channel.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::pty::PtyChild;

/// Control messages from the russh `Handler` callbacks into the running
/// session task.
#[derive(Debug)]
pub enum ControlMsg {
    /// Client sent stdin data.
    Stdin(Vec<u8>),
    /// Client requested a terminal resize.
    Resize { cols: u16, rows: u16 },
    /// Client closed the channel (peer disconnect).
    Close,
}

/// Run a session against `child` until either the child exits or the
/// control channel is closed.
///
/// `interactive` controls whether stderr is pumped as ext-data type 1
/// (false) or merged into stdout by the kernel/ConPTY (true).
pub async fn run(
    mut child: Box<dyn PtyChild>,
    mut control_rx: mpsc::Receiver<ControlMsg>,
    handle: russh::server::Handle,
    channel_id: russh::ChannelId,
    interactive: bool,
) {
    // Take the child's I/O halves into separate sub-tasks.
    let stdout_reader = child.take_reader();
    let stdin_writer = child.take_writer();
    let stderr_reader = if interactive {
        None
    } else {
        child.take_stderr()
    };
    let wait_future = child.take_wait();

    // Spawn the stdout → handle pump.
    let stdout_handle = handle.clone();
    let stdout_task = stdout_reader
        .map(|reader| tokio::spawn(pump_to_handle_data(reader, stdout_handle, channel_id)));

    // Spawn the stderr → handle ext-data pump (non-interactive only).
    let stderr_handle = handle.clone();
    let stderr_task = stderr_reader.map(|reader| {
        tokio::spawn(pump_to_handle_ext_data(
            reader,
            stderr_handle,
            channel_id,
            1,
        ))
    });

    // Spawn the stdin pump that pulls from control_rx and writes to stdin.
    let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>(32);
    let stdin_task = stdin_writer.map(|writer| tokio::spawn(pump_stdin(writer, stdin_rx)));

    // Control loop: dispatch messages, watch for exit.
    let mut wait_box = wait_future;
    let mut stdout_task = stdout_task;
    let mut stderr_task = stderr_task;
    loop {
        tokio::select! {
            // Wait for the child to exit. Drain the output pumps before
            // sending exit-status so the client sees all child output.
            res = async {
                if let Some(ref mut w) = wait_box {
                    w.as_mut().await
                } else {
                    std::future::pending().await
                }
            } => {
                // Internal error: surface to the client as an opaque exit
                // code 1 (no diagnostic bytes — see the information-disclosure
                // note at the crate root).
                let code = res.map_or(1, |status| {
                    u32::try_from(status.code.unwrap_or(0)).unwrap_or(0)
                });
                if let Some(t) = stdout_task.take() {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        t,
                    ).await;
                }
                if let Some(t) = stderr_task.take() {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        t,
                    ).await;
                }
                let _ = handle.exit_status_request(channel_id, code).await;
                let _ = handle.eof(channel_id).await;
                let _ = handle.close(channel_id).await;
                break;
            }

            cmd = control_rx.recv() => {
                match cmd {
                    Some(ControlMsg::Stdin(bytes)) => {
                        let _ = stdin_tx.send(bytes).await;
                    }
                    Some(ControlMsg::Resize { cols, rows }) => {
                        if let Err(e) = child.resize(cols, rows) {
                            tracing::warn!(
                                target: "esesaetsch_core::session",
                                ?e,
                                "resize failed",
                            );
                        }
                    }
                    Some(ControlMsg::Close) | None => {
                        let _ = child.kill();
                        break;
                    }
                }
            }
        }
    }

    drop(stdin_tx);
    if let Some(t) = stdout_task {
        t.abort();
    }
    if let Some(t) = stderr_task {
        t.abort();
    }
    if let Some(t) = stdin_task {
        t.abort();
    }
}

async fn pump_to_handle_data<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    handle: russh::server::Handle,
    channel_id: russh::ChannelId,
) {
    let mut buf = vec![0_u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let payload = russh::CryptoVec::from_slice(&buf[..n]);
                if handle.data(channel_id, payload).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn pump_to_handle_ext_data<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    handle: russh::server::Handle,
    channel_id: russh::ChannelId,
    ext_type: u32,
) {
    let mut buf = vec![0_u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let payload = russh::CryptoVec::from_slice(&buf[..n]);
                if handle
                    .extended_data(channel_id, ext_type, payload)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

async fn pump_stdin<W: tokio::io::AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(bytes) = rx.recv().await {
        if writer.write_all(&bytes).await.is_err() {
            break;
        }
        let _ = writer.flush().await;
    }
    let _ = writer.shutdown().await;
}
