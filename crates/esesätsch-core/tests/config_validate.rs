//! Validation rules from spec §5.4. Each test is a single rule.

use esesaetsch_core::config::Config;
use esesaetsch_core::error::ConfigError;
use std::path::PathBuf;

const VALID_ED25519: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDuiUkU0+nukC7q+TI0gMA0+jl3wQuRZ2u5GFOdjT2Cn alice@laptop";

fn base() -> Config {
    let mut c = Config::defaults();
    c.authorized_keys
        .insert("alice".to_owned(), vec![VALID_ED25519.to_owned()]);
    c
}

#[test]
fn defaults_validate_ok_when_keys_present() {
    let c = base();
    c.validate().expect("validates");
}

#[test]
fn empty_authorized_keys_validates_with_pubkey_enabled() {
    let mut c = Config::defaults();
    c.authorized_keys.clear();
    c.validate().expect("validates");
}

#[test]
fn no_auth_method_enabled_fails() {
    let mut c = base();
    c.pubkey_enabled = false;
    c.password_enabled = false;
    c.cert_enabled = false;
    assert!(matches!(
        c.validate(),
        Err(ConfigError::NoAuthMethodEnabled)
    ));
}

#[test]
fn malformed_authorized_key_fails() {
    let mut c = base();
    c.authorized_keys
        .insert("bob".to_owned(), vec!["NOT-A-KEY".to_owned()]);
    assert!(matches!(
        c.validate(),
        Err(ConfigError::InvalidAuthorizedKey { .. })
    ));
}

#[test]
fn host_key_path_with_dotdot_fails() {
    let mut c = base();
    c.host_key = PathBuf::from("../../etc/passwd");
    assert!(matches!(
        c.validate(),
        Err(ConfigError::InvalidHostKeyPath(_))
    ));
}

#[test]
fn cert_enabled_with_empty_trusted_fails() {
    let mut c = base();
    c.cert_enabled = true;
    c.ca_trusted.clear();
    assert!(matches!(
        c.validate(),
        Err(ConfigError::CertEnabledWithoutTrustedCa)
    ));
}

#[test]
fn cert_enabled_with_trusted_passes() {
    let mut c = base();
    c.cert_enabled = true;
    c.ca_trusted = vec![VALID_ED25519.to_owned()];
    c.validate().expect("validates");
}

#[test]
fn malformed_ca_key_fails() {
    let mut c = base();
    c.cert_enabled = true;
    c.ca_trusted = vec!["NOT-A-CA".to_owned()];
    assert!(matches!(
        c.validate(),
        Err(ConfigError::InvalidAuthorizedKey { .. })
    ));
}
