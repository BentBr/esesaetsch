//! Logging configuration for the core library.
//!
//! Two layers cooperate:
//! - a standard `tracing-subscriber` `fmt` layer writing to stderr (fd 2);
//! - a redaction helper applied to any text that contains sensitive fields
//!   before it reaches the formatter.
//!
//! Sensitive fields (per spec §6.4): `password=…`, raw key blobs.

use std::io::{self, Write};

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;

/// Server log verbosity controlled by CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    /// Default: info for our crates, warn for dependencies.
    Default,
    /// `--debug`: debug for our crates, info for dependencies.
    Debug,
    /// `--trace`: trace for our crates including the packet-dump layer.
    Trace,
}

impl Verbosity {
    /// Returns the `RUST_LOG`-style filter string to install.
    #[must_use]
    pub const fn env_filter(self) -> &'static str {
        match self {
            Self::Default => "info",
            Self::Debug => "info,esesaetsch_core=debug,esesaetsch=debug",
            Self::Trace => "info,esesaetsch_core=trace,esesaetsch=trace",
        }
    }
}

/// Install the global tracing subscriber for production / server use.
///
/// Wraps stderr with a [`RedactingWriter`] so any formatted log line
/// containing a `password="…"` field is redacted **before** it reaches
/// the operator's terminal — defence-in-depth on top of the per-call-site
/// careful logging in the rest of the crate (spec §6.4 rule 9).
///
/// Idempotent for production binaries: the second call returns `Err` but
/// callers may ignore it (binaries call this once at startup).
///
/// # Errors
///
/// Returns an error if a global subscriber was already set.
pub fn install(verbosity: Verbosity) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
    let filter = EnvFilter::new(verbosity.env_filter());
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(RedactingStderr));
    tracing::subscriber::set_global_default(subscriber)
}

/// `MakeWriter` that yields a [`RedactingWriter`] wrapping stderr per record.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedactingStderr;

impl MakeWriter<'_> for RedactingStderr {
    type Writer = RedactingWriter<io::Stderr>;
    fn make_writer(&self) -> Self::Writer {
        RedactingWriter::new(io::stderr())
    }
}

/// Adapter that filters writes through [`redact_sensitive`] before passing
/// them to the underlying writer. Non-UTF-8 chunks pass through unchanged.
///
/// Used by [`install`] to wrap stderr. Standalone-testable via any
/// inner writer.
#[derive(Debug)]
pub struct RedactingWriter<W: Write> {
    inner: W,
}

impl<W: Write> RedactingWriter<W> {
    /// Wrap `inner`.
    pub const fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(s) = std::str::from_utf8(buf) {
            let redacted = redact_sensitive(s);
            self.inner.write_all(redacted.as_bytes())?;
            // Even if we wrote fewer bytes than `buf.len()` (e.g.,
            // collapsing "hunter2" → "<REDACTED>"), we report `buf.len()`
            // so the tracing layer doesn't loop. Information leak risk
            // is none because we wrote the redacted form.
            Ok(buf.len())
        } else {
            self.inner.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Redact sensitive substrings before logging.
///
/// Currently handles the `password="…"` field pattern. Pubkey/cert blob
/// redaction lives in the trace layer (plan 2) where the value is bytes,
/// not a quoted string.
#[must_use]
pub fn redact_sensitive(input: &str) -> String {
    const PATTERN: &str = "password=\"";
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find(PATTERN) {
        out.push_str(&rest[..start]);
        out.push_str("password=\"<REDACTED>\"");
        let after = &rest[start + PATTERN.len()..];
        if let Some(end) = after.find('"') {
            rest = &after[end + 1..];
        } else {
            // Unbalanced quote: redact the rest and stop.
            return out;
        }
    }
    out.push_str(rest);
    out
}
