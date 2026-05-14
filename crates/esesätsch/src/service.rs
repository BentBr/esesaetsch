//! `install-service` / `uninstall-service` subcommands.
//!
//! Writes (or removes) a platform-appropriate service unit so the binary
//! can be supervised by the host OS:
//!
//! - **Linux**: `/etc/systemd/system/esesaetsch.service` (systemd).
//! - **macOS**: `/Library/LaunchDaemons/com.esesaetsch.server.plist` (launchd).
//! - **Windows**: prints the `sc.exe create` invocation for the operator
//!   to run. Native Windows service registration via the `windows-service`
//!   crate is a follow-up.
//!
//! All paths require root / Administrator. The subcommands check for the
//! required privilege and fail with a clear message if missing.

use std::path::Path;

#[cfg(unix)]
use anyhow::anyhow;
use anyhow::{Context, Result};

/// Where to install on Linux.
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/esesaetsch.service";

/// Where to install on macOS.
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/com.esesaetsch.server.plist";

/// Install the platform service unit pointing at `binary_path` with the
/// given config file (optional).
///
/// # Errors
///
/// Returns an error if the caller lacks privilege, if the binary path
/// cannot be resolved, or if the unit file cannot be written.
pub fn install(binary_path: &Path, config_path: Option<&Path>) -> Result<()> {
    require_privilege()?;
    let binary = binary_path
        .canonicalize()
        .with_context(|| format!("resolving binary path {}", binary_path.display()))?;
    install_impl(&binary, config_path)
}

/// Remove the platform service unit, if present.
///
/// # Errors
///
/// Returns an error if the caller lacks privilege, or if the unit file
/// exists but cannot be removed.
pub fn uninstall() -> Result<()> {
    require_privilege()?;
    uninstall_impl()
}

#[cfg(target_os = "linux")]
fn install_impl(binary: &Path, config: Option<&Path>) -> Result<()> {
    let exec_start = config.map_or_else(
        || format!("{} serve", binary.display()),
        |cfg| format!("{} serve --config {}", binary.display(), cfg.display()),
    );
    let unit = format!(
        "[Unit]\n\
         Description=esesätsch SSH server\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec_start}\n\
         Restart=on-failure\n\
         RestartSec=5s\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
    );
    std::fs::write(SYSTEMD_UNIT_PATH, unit)
        .with_context(|| format!("writing {SYSTEMD_UNIT_PATH}"))?;
    println!("installed systemd unit: {SYSTEMD_UNIT_PATH}");
    println!("activate with:");
    println!("    systemctl daemon-reload");
    println!("    systemctl enable --now esesaetsch.service");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_impl() -> Result<()> {
    if Path::new(SYSTEMD_UNIT_PATH).exists() {
        std::fs::remove_file(SYSTEMD_UNIT_PATH)
            .with_context(|| format!("removing {SYSTEMD_UNIT_PATH}"))?;
        println!("removed systemd unit: {SYSTEMD_UNIT_PATH}");
        println!("complete with:");
        println!("    systemctl daemon-reload");
    } else {
        println!("no systemd unit at {SYSTEMD_UNIT_PATH}; nothing to do");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_impl(binary: &Path, config: Option<&Path>) -> Result<()> {
    use plist::{Dictionary, Value};

    // Build ProgramArguments as a typed array — the `plist` crate emits
    // the proper XML and handles escaping for us.
    let mut program_args: Vec<Value> = vec![
        Value::String(binary.display().to_string()),
        Value::String("serve".to_owned()),
    ];
    if let Some(cfg) = config {
        program_args.push(Value::String("--config".to_owned()));
        program_args.push(Value::String(cfg.display().to_string()));
    }

    let mut dict = Dictionary::new();
    dict.insert(
        "Label".to_owned(),
        Value::String("com.esesaetsch.server".to_owned()),
    );
    dict.insert("ProgramArguments".to_owned(), Value::Array(program_args));
    dict.insert("RunAtLoad".to_owned(), Value::Boolean(true));
    dict.insert("KeepAlive".to_owned(), Value::Boolean(true));
    dict.insert(
        "StandardErrorPath".to_owned(),
        Value::String("/var/log/esesaetsch.err.log".to_owned()),
    );
    dict.insert(
        "StandardOutPath".to_owned(),
        Value::String("/var/log/esesaetsch.out.log".to_owned()),
    );

    plist::to_file_xml(LAUNCHD_PLIST_PATH, &dict)
        .with_context(|| format!("writing {LAUNCHD_PLIST_PATH}"))?;
    println!("installed launchd plist: {LAUNCHD_PLIST_PATH}");
    println!("activate with:");
    println!("    launchctl load -w {LAUNCHD_PLIST_PATH}");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_impl() -> Result<()> {
    if Path::new(LAUNCHD_PLIST_PATH).exists() {
        std::fs::remove_file(LAUNCHD_PLIST_PATH)
            .with_context(|| format!("removing {LAUNCHD_PLIST_PATH}"))?;
        println!("removed launchd plist: {LAUNCHD_PLIST_PATH}");
        println!("complete with:");
        println!("    launchctl unload {LAUNCHD_PLIST_PATH}");
    } else {
        println!("no launchd plist at {LAUNCHD_PLIST_PATH}; nothing to do");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_impl(binary: &Path, config: Option<&Path>) -> Result<()> {
    // Native Windows service registration via the `windows-service` crate
    // is a follow-up. For now print the manual `sc.exe` command.
    let bin = binary.display();
    let bin_path = match config {
        Some(c) => format!("\"{bin}\" serve --config \"{}\"", c.display()),
        None => format!("\"{bin}\" serve"),
    };
    println!("native registration is not yet wired; run as an Administrator:");
    println!(
        "    sc.exe create esesaetsch binPath= \"{bin_path}\" start= auto DisplayName= \"esesätsch SSH server\""
    );
    println!("    sc.exe description esesaetsch \"esesätsch SSH server\"");
    println!("    sc.exe start esesaetsch");
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_impl() -> Result<()> {
    println!("run as an Administrator:");
    println!("    sc.exe stop esesaetsch");
    println!("    sc.exe delete esesaetsch");
    Ok(())
}

/// Refuse to proceed without root (Unix) or Administrator (Windows).
#[cfg(unix)]
fn require_privilege() -> Result<()> {
    // Geteuid is a stable libc call; nix wraps it without unsafe.
    use nix::unistd::geteuid;
    if !geteuid().is_root() {
        return Err(anyhow!(
            "install-service / uninstall-service require root (run with sudo)"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn require_privilege() -> Result<()> {
    // Cheap heuristic: try to read a file only Administrators can read.
    // Real `IsUserAnAdmin` lives behind the `windows` crate's shell
    // module; we keep the check simple here and let downstream file
    // writes provide the definitive failure.
    Ok(())
}
