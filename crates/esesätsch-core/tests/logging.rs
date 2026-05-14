//! Logging-subsystem tests. We verify two contracts:
//! 1. Verbosity levels produce the documented `EnvFilter` directive.
//! 2. The redaction helper replaces sensitive substrings before any log
//!    record could be emitted (so even TRACE-level packet dumps are safe).

use esesaetsch_core::logging::{Verbosity, redact_sensitive};

#[test]
fn redact_sensitive_replaces_password_field() {
    let raw = r#"method="password" password="hunter2" user="alice""#;
    let red = redact_sensitive(raw);
    assert!(
        !red.contains("hunter2"),
        "redacted output must not contain plaintext password: {red}"
    );
    assert!(
        red.contains("password=\"<REDACTED>\""),
        "redacted output: {red}"
    );
    assert!(
        red.contains("user=\"alice\""),
        "non-sensitive fields preserved: {red}"
    );
}

#[test]
fn redact_sensitive_passes_through_when_no_match() {
    let raw = "channel open succeeded, peer=10.0.0.5";
    assert_eq!(redact_sensitive(raw), raw);
}

#[test]
fn redact_sensitive_handles_multiple_passwords() {
    let raw = r#"a password="one" b password="two" c"#;
    let red = redact_sensitive(raw);
    assert!(!red.contains("one"));
    assert!(!red.contains("two"));
    assert_eq!(red.matches("<REDACTED>").count(), 2);
}

#[test]
fn redact_sensitive_handles_unbalanced_quote() {
    // A malformed input that opens a password field but never closes it
    // should still result in a redacted output that doesn't leak content.
    let raw = r#"password="never_closes"#;
    let red = redact_sensitive(raw);
    assert!(!red.contains("never_closes"));
}

#[test]
fn redacting_writer_strips_password_field_from_chunk() {
    use esesaetsch_core::logging::RedactingWriter;
    use std::io::Write;
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = RedactingWriter::new(&mut buf);
        w.write_all(b"method=\"password\" password=\"hunter2\" user=\"alice\"")
            .expect("write");
        w.flush().expect("flush");
    }
    let s = std::str::from_utf8(&buf).expect("utf8");
    assert!(
        !s.contains("hunter2"),
        "writer must redact plaintext password: {s}",
    );
    assert!(s.contains("password=\"<REDACTED>\""), "got {s}");
    assert!(
        s.contains("user=\"alice\""),
        "non-sensitive fields preserved: {s}"
    );
}

#[test]
fn redacting_writer_passes_through_non_utf8_unchanged() {
    use esesaetsch_core::logging::RedactingWriter;
    use std::io::Write;
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = RedactingWriter::new(&mut buf);
        w.write_all(&[0xff, 0xfe, 0xfd]).expect("write");
    }
    assert_eq!(buf, vec![0xff, 0xfe, 0xfd]);
}

#[test]
fn redacting_writer_handles_multiple_writes() {
    use esesaetsch_core::logging::RedactingWriter;
    use std::io::Write;
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut w = RedactingWriter::new(&mut buf);
        w.write_all(b"a password=\"one\" ").expect("w1");
        w.write_all(b"b password=\"two\"").expect("w2");
    }
    let s = std::str::from_utf8(&buf).expect("utf8");
    assert!(!s.contains("one"));
    assert!(!s.contains("two"));
    assert_eq!(s.matches("<REDACTED>").count(), 2);
}

#[test]
fn verbosity_levels_have_expected_filter_strings() {
    assert_eq!(Verbosity::Default.env_filter(), "info");
    assert_eq!(
        Verbosity::Debug.env_filter(),
        "info,esesaetsch_core=debug,esesaetsch=debug",
    );
    assert_eq!(
        Verbosity::Trace.env_filter(),
        "info,esesaetsch_core=trace,esesaetsch=trace",
    );
}
