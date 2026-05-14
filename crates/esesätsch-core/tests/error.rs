//! Surface tests that the public error types exist, are `Send + Sync + 'static`,
//! and that their `Display` output is non-empty (never accidentally leaks
//! internal Debug output to operators).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use esesaetsch_core::error::{ConfigError, CryptoError, Error, HostKeyError};

const fn assert_send_sync_static<T: Send + Sync + 'static>() {}

#[test]
fn error_types_are_send_sync_static() {
    assert_send_sync_static::<Error>();
    assert_send_sync_static::<ConfigError>();
    assert_send_sync_static::<HostKeyError>();
    assert_send_sync_static::<CryptoError>();
}

#[test]
fn top_level_error_wraps_config_error() {
    let inner = ConfigError::InvalidPort(0);
    let wrapped: Error = inner.into();
    assert!(matches!(wrapped, Error::Config(_)));
    assert!(!format!("{wrapped}").is_empty());
    assert!(!format!("{wrapped:?}").is_empty());
}

#[test]
fn config_error_invalid_port_message_includes_port() {
    let e = ConfigError::InvalidPort(70_000);
    let msg = format!("{e}");
    assert!(
        msg.contains("70000"),
        "message {msg:?} should include the offending port"
    );
}
