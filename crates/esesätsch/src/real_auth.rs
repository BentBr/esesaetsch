//! OS-native password authentication.
//!
//! On Unix this dispatches to PAM via the `pam` crate (which transitively
//! requires `libclang` at build time — see the binary `Cargo.toml` for
//! platform-specific install notes). On Windows it dispatches to
//! `LogonUserW` via the `windows` crate.

use esesaetsch_core::auth::PasswordAuthenticator;
#[cfg(any(unix, windows))]
use esesaetsch_core::error::AuthError;

/// PAM-backed `PasswordAuthenticator`. Each call to `verify` opens a fresh
/// PAM transaction against the configured service file (`/etc/pam.d/<service>`).
///
/// Recommended service names:
/// - `sshd` — piggyback on OpenSSH's existing PAM config.
/// - `esesaetsch` — install your own custom service file via the
///   `install-service` subcommand.
#[cfg(unix)]
pub struct PamPasswordAuthenticator {
    service_name: String,
}

#[cfg(unix)]
impl PamPasswordAuthenticator {
    /// Create a new authenticator against the given PAM service.
    #[must_use]
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

/// Minimal `nonstick` conversation handler. PAM modules call into this
/// to get the username (plain prompt) and the password (masked prompt).
/// We hand back the fixed credentials we already have, ignore info/error
/// messages, and refuse radio/binary prompts (no PAM module our use case
/// supports should issue those).
#[cfg(unix)]
struct FixedConv {
    username: String,
    password: String,
}

#[cfg(unix)]
impl nonstick::ConversationAdapter for FixedConv {
    fn prompt(
        &self,
        _request: impl AsRef<std::ffi::OsStr>,
    ) -> nonstick::Result<std::ffi::OsString> {
        Ok(self.username.clone().into())
    }

    fn masked_prompt(
        &self,
        _request: impl AsRef<std::ffi::OsStr>,
    ) -> nonstick::Result<std::ffi::OsString> {
        Ok(self.password.clone().into())
    }

    fn error_msg(&self, _message: impl AsRef<std::ffi::OsStr>) {}
    fn info_msg(&self, _message: impl AsRef<std::ffi::OsStr>) {}
}

#[cfg(unix)]
impl PasswordAuthenticator for PamPasswordAuthenticator {
    fn verify(&self, user: &str, password: &str) -> Result<(), AuthError> {
        use nonstick::{AuthnFlags, ConversationAdapter, Transaction, TransactionBuilder};

        let conv = FixedConv {
            username: user.to_owned(),
            password: password.to_owned(),
        };
        let mut txn = TransactionBuilder::new_with_service(&self.service_name)
            .username(user)
            .build(conv.into_conversation())
            .map_err(|e| AuthError::Backend(format!("pam txn: {e}")))?;
        txn.authenticate(AuthnFlags::empty())
            .map_err(|_| AuthError::CredentialMismatch)?;
        txn.account_management(AuthnFlags::empty())
            .map_err(|_| AuthError::CredentialMismatch)?;
        Ok(())
    }
}

/// Windows-native `PasswordAuthenticator` backed by `LogonUserW`.
///
/// The token returned by `LogonUserW` is closed immediately; the
/// implementation only cares whether authentication succeeded. Process
/// spawning as the authenticated user (`CreateProcessAsUserW`) is a
/// separate concern.
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
                if !token.is_invalid() {
                    let _ = unsafe { CloseHandle(token) };
                }
                Ok(())
            }
            Err(_) => Err(AuthError::CredentialMismatch),
        }
    }
}

/// Build the OS-native authenticator for the current target.
///
/// The `Option` is kept (rather than a hard `Box`) so the same call-site
/// in `main.rs` works on any future target where no backend exists; on
/// Unix and Windows the function unconditionally returns `Some(...)`.
#[cfg(unix)]
#[must_use]
#[allow(clippy::unnecessary_wraps)] // signature mirrors the no-backend fallback
pub fn build_native_password_auth(service_name: &str) -> Option<Box<dyn PasswordAuthenticator>> {
    Some(Box::new(PamPasswordAuthenticator::new(service_name)))
}

#[cfg(windows)]
#[must_use]
#[allow(clippy::unnecessary_wraps)]
pub fn build_native_password_auth(_service_name: &str) -> Option<Box<dyn PasswordAuthenticator>> {
    Some(Box::new(LogonUserPasswordAuthenticator::new()))
}

#[cfg(not(any(unix, windows)))]
#[must_use]
pub fn build_native_password_auth(_service_name: &str) -> Option<Box<dyn PasswordAuthenticator>> {
    None
}
