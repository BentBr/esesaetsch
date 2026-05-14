//! Real `PtySpawner` implementation backed by `portable-pty`.
//!
//! Bridges `portable-pty`'s synchronous `Read`/`Write` master sides to the
//! core's async trait surface by running the I/O on dedicated
//! `spawn_blocking` tasks that feed tokio channels.
//!
//! ## Stderr handling
//!
//! `portable-pty` always merges stderr into the PTY's single output stream
//! (that's how kernel/ConPTY PTYs work). For non-interactive `exec`
//! requests this means the client sees stdout and stderr merged on the
//! main channel; future work will spawn non-interactive commands via
//! `tokio::process::Command` directly so stderr can flow as SSH
//! extended-data type 1.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Mutex;

use esesaetsch_core::error::SpawnError;
use esesaetsch_core::pty::{
    Command, PtyChild, PtySpawner, SessionExitStatus, SpawnSpec, TerminalSize,
};
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use tokio::io::{AsyncRead, AsyncWrite};

/// `PtySpawner` backed by `portable-pty`'s native PTY system (Unix PTY on
/// macOS/Linux, `ConPTY` on Windows).
pub struct RealPtySpawner;

impl RealPtySpawner {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RealPtySpawner {
    fn default() -> Self {
        Self::new()
    }
}

impl PtySpawner for RealPtySpawner {
    fn spawn(&self, spec: SpawnSpec<'_>) -> Result<Box<dyn PtyChild>, SpawnError> {
        let system = native_pty_system();
        let size = portable_size(spec.size);
        let pair = system
            .openpty(size)
            .map_err(|e| SpawnError::PtyAllocation(format!("{e}")))?;

        // Build the command. The effective command honours cert-grants
        // `force-command` overrides.
        let effective = spec.effective_command();
        let mut cmd = match effective {
            Command::Shell => default_shell_command(spec.user),
            Command::Exec(s) => CommandBuilder::from_argv(shell_argv(&s)),
        };
        cmd.env("TERM", spec.term);
        for (k, v) in spec.env {
            cmd.env(k, v);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| SpawnError::ProcessSpawn(format!("{e}")))?;
        let pid = child.process_id();

        // Reader: clone the master side and bridge to async.
        let reader_sync = pair
            .master
            .try_clone_reader()
            .map_err(|e| SpawnError::PtyAllocation(format!("cloning reader: {e}")))?;
        let reader = async_reader_from_sync(reader_sync);

        // Writer: take the master writer and bridge to async.
        let writer_sync = pair
            .master
            .take_writer()
            .map_err(|e| SpawnError::PtyAllocation(format!("taking writer: {e}")))?;
        let writer = async_writer_from_sync(writer_sync);

        // Wait: drive the blocking `wait` call on a spawn_blocking task.
        // We move the child into the task so kill works via pid signalling
        // (the Child handle is consumed here).
        let wait_handle = tokio::task::spawn_blocking({
            let mut child = child;
            move || {
                child
                    .wait()
                    .map(|status| convert_exit_status(&status))
                    .map_err(|e| io::Error::other(format!("waitpid: {e}")))
            }
        });

        let master = Mutex::new(pair.master);

        Ok(Box::new(RealPtyChild {
            master,
            reader: Some(reader),
            writer: Some(writer),
            wait_handle: Some(wait_handle),
            pid,
        }))
    }
}

const fn portable_size(s: TerminalSize) -> PtySize {
    PtySize {
        rows: s.rows,
        cols: s.cols,
        pixel_width: s.pixel_w,
        pixel_height: s.pixel_h,
    }
}

/// Build a `CommandBuilder` for the user's login shell. v1 hard-codes
/// `/bin/sh` on Unix and `cmd.exe` on Windows; later steps will resolve
/// the user's actual shell via `/etc/passwd` (Unix) or
/// `HKEY_USERS\<sid>\Environment\COMSPEC` (Windows).
fn default_shell_command(_user: &str) -> CommandBuilder {
    #[cfg(unix)]
    {
        let mut cb = CommandBuilder::new("/bin/sh");
        cb.arg("-i");
        cb
    }
    #[cfg(windows)]
    {
        CommandBuilder::new("cmd.exe")
    }
}

/// Parse an exec command string. For v1 we just split on whitespace; SSH
/// `exec` requests carry the command as a single string and the shell on
/// the other side is normally responsible for splitting. portable-pty's
/// `CommandBuilder::from_argv` takes argv directly.
fn shell_argv(s: &str) -> Vec<std::ffi::OsString> {
    if s.trim().is_empty() {
        return vec![std::ffi::OsString::from("/bin/sh")];
    }
    // Route through the shell so single-string command-lines like
    // "echo foo | grep f" behave as the user expects.
    #[cfg(unix)]
    {
        vec![
            std::ffi::OsString::from("/bin/sh"),
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(s),
        ]
    }
    #[cfg(windows)]
    {
        vec![
            std::ffi::OsString::from("cmd.exe"),
            std::ffi::OsString::from("/C"),
            std::ffi::OsString::from(s),
        ]
    }
}

fn convert_exit_status(status: &portable_pty::ExitStatus) -> SessionExitStatus {
    // portable_pty::ExitStatus::exit_code() returns u32 of process exit
    // code. We cap to i32 range; signals aren't exposed on the trait.
    let code = i32::try_from(status.exit_code()).unwrap_or(i32::MAX);
    SessionExitStatus {
        code: Some(code),
        signal: None,
    }
}

// =====================================================================
// Real PTY child
// =====================================================================

struct RealPtyChild {
    master: Mutex<Box<dyn MasterPty + Send>>,
    reader: Option<Box<dyn AsyncRead + Unpin + Send + 'static>>,
    writer: Option<Box<dyn AsyncWrite + Unpin + Send + 'static>>,
    wait_handle: Option<tokio::task::JoinHandle<io::Result<SessionExitStatus>>>,
    pid: Option<u32>,
}

impl PtyChild for RealPtyChild {
    fn take_reader(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send + 'static>> {
        self.reader.take()
    }

    fn take_writer(&mut self) -> Option<Box<dyn AsyncWrite + Unpin + Send + 'static>> {
        self.writer.take()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send + 'static>> {
        // PTY merges stderr into stdout — no separate stream.
        None
    }

    fn take_wait(
        &mut self,
    ) -> Option<Pin<Box<dyn Future<Output = io::Result<SessionExitStatus>> + Send + 'static>>> {
        let handle = self.wait_handle.take()?;
        Some(Box::pin(async move {
            match handle.await {
                Ok(inner) => inner,
                Err(join_err) => Err(io::Error::other(format!("wait task: {join_err}"))),
            }
        }))
    }

    fn resize(&mut self, cols: u16, rows: u16) -> Result<(), io::Error> {
        let guard = self
            .master
            .lock()
            .map_err(|_| io::Error::other("master pty lock poisoned"))?;
        guard
            .resize(PtySize {
                cols,
                rows,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| io::Error::other(format!("pty resize: {e}")))
    }

    fn kill(&mut self) -> io::Result<()> {
        let Some(pid) = self.pid else { return Ok(()) };
        kill_pid(pid)
    }
}

#[cfg(unix)]
fn kill_pid(pid: u32) -> io::Result<()> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    let p = Pid::from_raw(i32::try_from(pid).map_err(|_| io::Error::other("pid out of range"))?);
    kill(p, Signal::SIGHUP).map_err(|e| io::Error::other(format!("kill: {e}")))?;
    Ok(())
}

#[cfg(windows)]
// Signature mirrors the Unix `kill_pid` so callers don't need cfg branches.
// Will be wired through the `windows` crate's TerminateProcess in a follow-up;
// for now this is a best-effort no-op — the child will exit when the PTY's
// master closes.
#[allow(clippy::unnecessary_wraps)]
const fn kill_pid(_pid: u32) -> io::Result<()> {
    Ok(())
}

// =====================================================================
// Sync ↔ async I/O bridges
// =====================================================================

/// Wrap a synchronous `Read` in an `AsyncRead` by streaming chunks through
/// a tokio mpsc, with the actual blocking reads happening on a
/// `spawn_blocking` task.
fn async_reader_from_sync(
    reader: Box<dyn io::Read + Send>,
) -> Box<dyn AsyncRead + Unpin + Send + 'static> {
    let (tx, rx) = tokio::sync::mpsc::channel::<io::Result<Vec<u8>>>(8);
    tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        let mut buf = vec![0_u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(Ok(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.blocking_send(Err(e));
                    break;
                }
            }
        }
    });
    Box::new(ChannelReader {
        rx,
        leftover: Vec::new(),
    })
}

struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    leftover: Vec<u8>,
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::Poll;
        if !self.leftover.is_empty() {
            let take = self.leftover.len().min(buf.remaining());
            let drain: Vec<u8> = self.leftover.drain(..take).collect();
            buf.put_slice(&drain);
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                let take = bytes.len().min(buf.remaining());
                buf.put_slice(&bytes[..take]);
                if take < bytes.len() {
                    self.leftover.extend_from_slice(&bytes[take..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Wrap a synchronous `Write` in an `AsyncWrite` by funnelling bytes
/// through a tokio mpsc to a `spawn_blocking` write loop.
fn async_writer_from_sync(
    writer: Box<dyn io::Write + Send>,
) -> Box<dyn AsyncWrite + Unpin + Send + 'static> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    tokio::task::spawn_blocking(move || {
        let mut writer = writer;
        while let Some(chunk) = rx.blocking_recv() {
            if writer.write_all(&chunk).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });
    Box::new(ChannelWriter { tx })
}

struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // Best-effort non-blocking enqueue. If the channel is full we
        // accept the bytes but drop the rest of the write — the session
        // is already a write-back-pressure-aware protocol so this is rare.
        match self.tx.try_send(buf.to_vec()) {
            Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Tell tokio to come back later.
                std::task::Poll::Pending
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                std::task::Poll::Ready(Err(io::Error::other("pty writer closed")))
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
