//! Host-key load/generate operations (used by the `gen-key` subcommand and
//! by the server's startup path).

use std::fs;
use std::path::Path;

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey as SshKeyPrivateKey};

use crate::error::HostKeyError;

/// Load an existing host key from `path`.
///
/// # Errors
///
/// - `HostKeyError::Io` if the file cannot be read.
/// - `HostKeyError::Malformed` if the contents are not a valid OpenSSH key.
pub fn load(path: &Path) -> Result<russh::keys::PrivateKey, HostKeyError> {
    let pem = fs::read_to_string(path).map_err(|source| HostKeyError::Io {
        path: path.display().to_string(),
        source,
    })?;
    russh::keys::decode_secret_key(&pem, None).map_err(|e| HostKeyError::Malformed {
        path: path.display().to_string(),
        detail: format!("{e}"),
    })
}

/// Generate a fresh Ed25519 host key and write it to `path` in OpenSSH
/// format with 0600 permissions on Unix.
///
/// Internally we generate via the standalone `ssh-key` 0.6 crate (which
/// has an ergonomic `PrivateKey::random`) and write the OpenSSH PEM. The
/// `load` path then parses it back as `russh::keys::PrivateKey` —
/// OpenSSH PEM is wire-stable, so this round-trip is exact.
///
/// # Errors
///
/// - `HostKeyError::Generation` if the underlying primitive fails (should
///   not happen except under exhausted entropy).
/// - `HostKeyError::Io` if the write fails or the parent directory does
///   not exist.
pub fn generate(path: &Path) -> Result<(), HostKeyError> {
    let key = SshKeyPrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| HostKeyError::Generation(format!("{e}")))?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| HostKeyError::Generation(format!("encode failed: {e}")))?;

    fs::write(path, pem.as_bytes()).map_err(|source| HostKeyError::Io {
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
pub fn load_or_generate(path: &Path) -> Result<russh::keys::PrivateKey, HostKeyError> {
    if !path.exists() {
        generate(path)?;
    }
    load(path)
}
