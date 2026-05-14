//! Host-key load/generate operations (spec §5.5, §6.1, subcommand `gen-key`).
//!
//! v1 generates Ed25519 keys. The `russh-keys` crate provides parsing of
//! the OpenSSH on-disk format.

use std::fs;
use std::path::Path;

use crate::error::HostKeyError;

/// Load an existing host key from `path`.
///
/// # Errors
///
/// - `HostKeyError::Io` if the file cannot be read.
/// - `HostKeyError::Malformed` if the contents are not a valid OpenSSH key.
pub fn load(path: &Path) -> Result<russh_keys::key::KeyPair, HostKeyError> {
    let pem = fs::read_to_string(path).map_err(|source| HostKeyError::Io {
        path: path.display().to_string(),
        source,
    })?;
    russh_keys::decode_secret_key(&pem, None).map_err(|e| HostKeyError::Malformed {
        path: path.display().to_string(),
        detail: format!("{e}"),
    })
}

/// Generate a fresh Ed25519 host key and write it to `path` in OpenSSH
/// PEM format with 0600 permissions on Unix.
///
/// # Errors
///
/// - `HostKeyError::Generation` if the underlying primitive fails (should
///   not happen except under exhausted entropy).
/// - `HostKeyError::Io` if the write fails or the parent directory does
///   not exist.
pub fn generate(path: &Path) -> Result<(), HostKeyError> {
    let key = russh_keys::key::KeyPair::generate_ed25519()
        .ok_or_else(|| HostKeyError::Generation("ed25519 generation returned None".to_owned()))?;

    let mut pem: Vec<u8> = Vec::new();
    russh_keys::encode_pkcs8_pem(&key, &mut pem)
        .map_err(|e| HostKeyError::Generation(format!("encode failed: {e}")))?;

    fs::write(path, &pem).map_err(|source| HostKeyError::Io {
        path: path.display().to_string(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            HostKeyError::Io {
                path: path.display().to_string(),
                source,
            }
        })?;
    }
    Ok(())
}

/// If `path` exists, load it; otherwise generate a new key and store it
/// at `path`.
///
/// # Errors
///
/// See `load` and `generate`.
pub fn load_or_generate(path: &Path) -> Result<russh_keys::key::KeyPair, HostKeyError> {
    if !path.exists() {
        generate(path)?;
    }
    load(path)
}
