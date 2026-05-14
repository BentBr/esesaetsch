//! OS-native password authentication.
//!
//! On Unix (with the `pam-auth` feature enabled) this dispatches to PAM
//! via the `pam` crate. On Windows it will dispatch to `LogonUserW` in
//! a follow-up task. Without the `pam-auth` feature, attempts to enable
//! password auth in the config are refused at startup by the binary.

use esesaetsch_core::auth::PasswordAuthenticator;
#[cfg(any(all(unix, feature = "pam-auth"), windows))]
use esesaetsch_core::error::AuthError;

/// PAM-backed `PasswordAuthenticator`. Each call to `verify` opens a fresh
/// PAM transaction against the configured service file (`/etc/pam.d/<service>`).
///
/// Recommended service names:
/// - `sshd` — piggyback on OpenSSH's existing PAM config.
/// - `esesaetsch` — install your own custom service file via the
///   `install-service` subcommand.
#[cfg(all(unix, feature = "pam-auth"))]
pub struct PamPasswordAuthenticator {
    service_name: String,
}

#[cfg(all(unix, feature = "pam-auth"))]
impl PamPasswordAuthenticator {
    /// Create a new authenticator against the given PAM service.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

#[cfg(all(unix, feature = "pam-auth"))]
impl PasswordAuthenticator for PamPasswordAuthenticator {
    fn verify(&self, user: &str, password: &str) -> Result<(), AuthError> {
        let mut client = pam::Client::with_password(&self.service_name)
            .map_err(|e| AuthError::Backend(format!("pam init: {e}")))?;
        client.conversation_mut().set_credentials(user, password);
        client
            .authenticate()
            .map_err(|_| AuthError::CredentialMismatch)?;
        client
            .open_session()
            .map_err(|_| AuthError::CredentialMismatch)?;
        Ok(())
    }
}

/// Windows-native `PasswordAuthenticator` backed by `LogonUserW`.
///
/// The token returned by `LogonUserW` is closed immediately; the
/// implementation only cares whether authentication succeeded. Process
/// spawning as the authenticated user (`CreateProcessAsUserW`) is a
/// separate concern and lives in `real_user`.
#[cfg(windows)]
pub struct LogonUserPasswordAuthenticator;

#[cfg(windows)]
impl LogonUserPasswordAuthenticator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(windows)]
impl Default for LogonUserPasswordAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl PasswordAuthenticator for LogonUserPasswordAuthenticator {
    fn verify(&self, user: &str, password: &str) -> Result<(), AuthError> {
        windows_impl::logon_user(user, password)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // thin FFI wrapper around LogonUserW + CloseHandle
mod windows_impl {
    use esesaetsch_core::error::AuthError;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::Authentication::Identity::{
        LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, LogonUserW,
    };
    use windows::core::PCWSTR;

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn logon_user(user: &str, password: &str) -> Result<(), AuthError> {
        let user_w = to_wide(user);
        let pass_w = to_wide(password);
        let mut token = HANDLE::default();
        let result = unsafe {
            LogonUserW(
                PCWSTR(user_w.as_ptr()),
                PCWSTR::null(),
                PCWSTR(pass_w.as_ptr()),
                LOGON32_LOGON_NETWORK,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        };
        match result {
            Ok(()) => {
                // Token is valid; we don't need it (yet). Close.
                if !token.is_invalid() {
                    let _ = unsafe { CloseHandle(token) };
                }
                Ok(())
            }
            Err(_) => Err(AuthError::CredentialMismatch),
        }
    }
}

/// Build the OS-native authenticator for the current target/feature set.
///
/// Returns `None` when no backend is available — the caller should refuse
/// to enable password auth in that case.
#[cfg(all(unix, feature = "pam-auth"))]
#[must_use]
pub fn build_native_password_auth(service_name: &str) -> Option<Box<dyn PasswordAuthenticator>> {
    Some(Box::new(PamPasswordAuthenticator::new(service_name)))
}

#[cfg(windows)]
#[must_use]
pub fn build_native_password_auth(_service_name: &str) -> Option<Box<dyn PasswordAuthenticator>> {
    Some(Box::new(LogonUserPasswordAuthenticator::new()))
}

#[cfg(not(any(all(unix, feature = "pam-auth"), windows)))]
#[must_use]
pub fn build_native_password_auth(_service_name: &str) -> Option<Box<dyn PasswordAuthenticator>> {
    None
}
