//! PTY abstraction.
//!
//! The library defines abstract traits — `PtySpawner` + `PtyChild` — so the
//! protocol/session logic can be tested in `esesaetsch-core` without ever
//! touching the host OS. Real implementations using `portable-pty`,
//! `setuid`/`fork`, and `CreateProcessAsUserW` live in the `esesätsch`
//! binary crate.
//!
//! ## Interactive vs. non-interactive
//!
//! - **Interactive** (`pty_req` then `shell`/`exec`): the child's stdout
//!   and stderr are merged at the kernel-level TTY. `PtyChild::stderr`
//!   returns `None`; all child output flows through `reader`.
//! - **Non-interactive `exec`** (no `pty_req`): stdout and stderr are
//!   separate. `PtyChild::stderr` returns `Some(reader)` so the session
//!   can forward stderr as SSH extended-data type 1.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::cert::CertGrants;
use crate::error::SpawnError;

/// Terminal size in cells plus optional pixel dimensions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TerminalSize {
    pub cols: u16,
    pub rows: u16,
    pub pixel_w: u16,
    pub pixel_h: u16,
}

/// What to spawn for this session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// The user's default login shell.
    Shell,
    /// A specific command (from an `exec` channel request, or from a
    /// cert `force-command` override).
    Exec(String),
}

/// Exit status of a child, normalised across Unix and Windows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionExitStatus {
    /// Normal exit code (0–255 on Unix).
    pub code: Option<i32>,
    /// Signal that terminated the process (Unix only).
    pub signal: Option<i32>,
}

impl SessionExitStatus {
    /// A successful (code 0) exit.
    #[must_use]
    pub const fn success() -> Self {
        Self {
            code: Some(0),
            signal: None,
        }
    }

    /// A failed exit with the given code.
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        Self {
            code: Some(code),
            signal: None,
        }
    }
}

/// Parameters for `PtySpawner::spawn`.
#[derive(Debug)]
pub struct SpawnSpec<'a> {
    /// SSH username; mapped to an OS user by the real `PtySpawner` impl.
    pub user: &'a str,
    /// TERM env (e.g., `"xterm-256color"`); ignored if not interactive.
    pub term: &'a str,
    /// Terminal size when interactive.
    pub size: TerminalSize,
    /// Environment variables requested by the client (filtered by policy
    /// before being applied; v1 ignores client-supplied env entirely).
    pub env: &'a [(String, String)],
    /// What to run.
    pub command: Command,
    /// `true` if the client requested a PTY (`pty_req` channel message
    /// before `shell`/`exec`).
    pub interactive: bool,
    /// Grants conferred by cert auth (force-command overrides `command`
    /// when set).
    pub grants: CertGrants,
}

impl SpawnSpec<'_> {
    /// Apply cert-grants force-command, if any. Returns the effective
    /// command the spawner should actually execute.
    #[must_use]
    pub fn effective_command(&self) -> Command {
        self.grants
            .force_command
            .as_ref()
            .map_or_else(|| self.command.clone(), |fc| Command::Exec(fc.clone()))
    }
}

/// Spawn a child process in the target OS user's security context with an
/// allocated PTY (when interactive).
pub trait PtySpawner: Send + Sync {
    /// Spawn the child.
    ///
    /// # Errors
    ///
    /// See [`SpawnError`] for the catalogue.
    fn spawn(&self, spec: SpawnSpec<'_>) -> Result<Box<dyn PtyChild>, SpawnError>;
}

/// Handle to a running child + PTY.
///
/// I/O methods use `take_*` semantics: each returns `Some` once, then `None`.
/// This lets the session task move the readers/writer/wait-future into
/// separate sub-tasks while keeping the child alive for `resize`/`kill`.
pub trait PtyChild: Send {
    /// Take ownership of the child's stdout reader (merged with stderr in
    /// PTY mode). Returns `None` after the first call.
    fn take_reader(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send + 'static>>;
    /// Take ownership of the child's stdin writer. Returns `None` after
    /// the first call.
    fn take_writer(&mut self) -> Option<Box<dyn AsyncWrite + Unpin + Send + 'static>>;
    /// Take ownership of the child's stderr reader. Returns `None` in PTY
    /// mode (stderr is merged) or after the first call.
    fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send + 'static>>;
    /// Take the future that resolves when the child exits. Returns `None`
    /// after the first call.
    fn take_wait(
        &mut self,
    ) -> Option<Pin<Box<dyn Future<Output = io::Result<SessionExitStatus>> + Send + 'static>>>;
    /// Inform the PTY of a new size (sent on `window-change` SSH messages).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the underlying ioctl/ConPTY call fails.
    fn resize(&mut self, cols: u16, rows: u16) -> Result<(), io::Error>;
    /// Forcibly terminate the child (sent on client disconnect).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the kill/`TerminateProcess` call fails.
    fn kill(&mut self) -> io::Result<()>;
}

// =====================================================================
// In-process Mock for tests
// =====================================================================
//
// Lives in the public surface (rather than behind `#[cfg(test)]`) so
// integration tests in this crate AND in downstream crates can use it.
// Production code paths never construct it. The mock relies on `.expect`
// for mutex poisoning (a poisoned mutex in test code is itself a bug);
// the strict-lint deny on `expect_used`/`unwrap_used` is relaxed inside
// the `mock` submodule below.

pub use mock::{MockChildConfig, MockPtyRecord, MockPtySpawner};

#[allow(clippy::wildcard_imports)] // submodule inheriting parent's surface
mod mock {
    use super::*;

    /// Recording of activity on a `MockPtyChild`, shared between the test and
    /// the child via `Arc`.
    #[derive(Debug, Default)]
    pub struct MockPtyRecord {
        /// Bytes the session has written to stdin.
        pub stdin: Mutex<Vec<u8>>,
        /// `(cols, rows)` pairs received by `resize`.
        pub resizes: Mutex<Vec<(u16, u16)>>,
        /// True once `kill` has been called.
        pub killed: AtomicBool,
    }

    /// Scripted configuration for a [`MockPtyChild`] produced by
    /// [`MockPtySpawner`].
    #[derive(Debug, Clone, Default)]
    pub struct MockChildConfig {
        /// Bytes the child's stdout will produce, in order.
        pub stdout_bytes: Vec<u8>,
        /// Bytes the child's stderr will produce (only used when
        /// `interactive` is false on the spawn).
        pub stderr_bytes: Option<Vec<u8>>,
        /// Exit status that `wait` will resolve to. `None` means `wait`
        /// remains pending forever (test scenario for client disconnect).
        pub exit_status: Option<SessionExitStatus>,
        /// If `Some`, [`PtySpawner::spawn`] returns this error instead of a
        /// child. Used to exercise the spawn-failure path (client sees
        /// `exit-status = 1` with no diagnostic bytes).
        pub spawn_error: Option<String>,
    }

    /// Scriptable [`PtySpawner`] for tests.
    #[derive(Debug, Default)]
    pub struct MockPtySpawner {
        config: Mutex<MockChildConfig>,
        last_record: Mutex<Option<Arc<MockPtyRecord>>>,
        last_spec_command: Mutex<Option<Command>>,
        last_spec_user: Mutex<Option<String>>,
    }

    impl MockPtySpawner {
        /// New empty spawner.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Replace the next-child config used by `spawn`.
        pub fn set_config(&self, cfg: MockChildConfig) {
            *self
                .config
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = cfg;
        }

        /// Get a handle to the recording of the most recent child spawned by
        /// this spawner. Returns `None` if `spawn` has not been called yet.
        #[must_use]
        pub fn last_record(&self) -> Option<Arc<MockPtyRecord>> {
            self.last_record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        /// The `command` field that the last `spawn` call observed (after
        /// `effective_command` has applied any force-command override).
        #[must_use]
        pub fn last_command(&self) -> Option<Command> {
            self.last_spec_command
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        /// The `user` field that the last `spawn` call observed.
        #[must_use]
        pub fn last_user(&self) -> Option<String> {
            self.last_spec_user
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl PtySpawner for MockPtySpawner {
        fn spawn(&self, spec: SpawnSpec<'_>) -> Result<Box<dyn PtyChild>, SpawnError> {
            let cfg = self
                .config
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            *self
                .last_spec_command
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(spec.effective_command());
            *self
                .last_spec_user
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(spec.user.to_owned());

            if let Some(msg) = cfg.spawn_error {
                return Err(SpawnError::ProcessSpawn(msg));
            }

            let record = Arc::new(MockPtyRecord::default());
            *self
                .last_record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&record));

            Ok(Box::new(MockPtyChild::new(cfg, record, spec.interactive)))
        }
    }

    /// Mock child returned by [`MockPtySpawner`].
    struct MockPtyChild {
        stdout_buf: Option<Vec<u8>>,
        stderr_buf: Option<Vec<u8>>,
        interactive: bool,
        record: Arc<MockPtyRecord>,
        writer_taken: bool,
        wait_taken: bool,
        exit_notify: Arc<tokio::sync::Notify>,
        exit_status: Arc<AtomicI32>,
        exit_resolved: Arc<AtomicBool>,
    }

    impl MockPtyChild {
        fn new(cfg: MockChildConfig, record: Arc<MockPtyRecord>, interactive: bool) -> Self {
            let exit_notify = Arc::new(tokio::sync::Notify::new());
            let exit_status = Arc::new(AtomicI32::new(0));
            let exit_resolved = Arc::new(AtomicBool::new(false));
            if let Some(es) = cfg.exit_status {
                exit_status.store(es.code.unwrap_or(0), Ordering::Relaxed);
                exit_resolved.store(true, Ordering::Relaxed);
                exit_notify.notify_waiters();
            }
            Self {
                stdout_buf: Some(cfg.stdout_bytes),
                stderr_buf: cfg.stderr_bytes,
                interactive,
                record,
                writer_taken: false,
                wait_taken: false,
                exit_notify,
                exit_status,
                exit_resolved,
            }
        }
    }

    impl PtyChild for MockPtyChild {
        fn take_reader(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send + 'static>> {
            self.stdout_buf
                .take()
                .map(|b| -> Box<dyn AsyncRead + Unpin + Send + 'static> {
                    Box::new(std::io::Cursor::new(b))
                })
        }

        fn take_writer(&mut self) -> Option<Box<dyn AsyncWrite + Unpin + Send + 'static>> {
            if self.writer_taken {
                None
            } else {
                self.writer_taken = true;
                Some(Box::new(MockStdinWriter {
                    record: Arc::clone(&self.record),
                }))
            }
        }

        fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Unpin + Send + 'static>> {
            if self.interactive {
                return None;
            }
            self.stderr_buf
                .take()
                .map(|b| -> Box<dyn AsyncRead + Unpin + Send + 'static> {
                    Box::new(std::io::Cursor::new(b))
                })
        }

        fn take_wait(
            &mut self,
        ) -> Option<Pin<Box<dyn Future<Output = io::Result<SessionExitStatus>> + Send + 'static>>>
        {
            if self.wait_taken {
                return None;
            }
            self.wait_taken = true;
            let notify = Arc::clone(&self.exit_notify);
            let resolved = Arc::clone(&self.exit_resolved);
            let status = Arc::clone(&self.exit_status);
            Some(Box::pin(async move {
                if !resolved.load(Ordering::Relaxed) {
                    notify.notified().await;
                }
                Ok(SessionExitStatus::from_code(status.load(Ordering::Relaxed)))
            }))
        }

        fn resize(&mut self, cols: u16, rows: u16) -> Result<(), io::Error> {
            self.record
                .resizes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((cols, rows));
            Ok(())
        }

        fn kill(&mut self) -> io::Result<()> {
            self.record.killed.store(true, Ordering::Relaxed);
            self.exit_status.store(137, Ordering::Relaxed);
            self.exit_resolved.store(true, Ordering::Relaxed);
            self.exit_notify.notify_waiters();
            Ok(())
        }
    }

    /// Captures bytes that the session writes to "stdin" of the mock child.
    struct MockStdinWriter {
        record: Arc<MockPtyRecord>,
    }

    impl AsyncWrite for MockStdinWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            self.record
                .stdin
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
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
} // mod mock
