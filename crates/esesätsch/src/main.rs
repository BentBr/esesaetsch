//! esesätsch SSH server entry point.
//!
//! This binary is intentionally thin. All logic lives in `esesaetsch-core`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use esesaetsch_core::auth::{
    AllowlistPubkeyAuthenticator, DenyAllPasswordAuthenticator, PasswordAuthenticator,
    PubkeyAuthenticator,
};
use esesaetsch_core::config::{Cli as CoreCli, Config, TomlConfig};
use esesaetsch_core::pty::PtySpawner;
mod real_auth;
mod real_pty;
mod service;
use esesaetsch_core::server::EsesätschServer;
use esesaetsch_core::{hostkey, logging};
use real_pty::RealPtySpawner;
use russh::server::Server;

#[derive(Parser, Debug)]
#[command(name = "esesätsch", about = "A strict cross-platform SSH server.")]
#[allow(clippy::struct_excessive_bools)] // independent CLI flags
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to TOML config (optional).
    #[arg(short = 'c', long, global = true)]
    config: Option<PathBuf>,

    /// Listen port (overrides config).
    #[arg(short = 'p', long, global = true)]
    port: Option<u16>,

    /// Bind address (default 0.0.0.0).
    #[arg(long, global = true)]
    bind: Option<String>,

    /// Path to host key (load existing or auto-generate if missing).
    #[arg(long, global = true)]
    host_key: Option<PathBuf>,

    /// Verbose tracing.
    #[arg(short = 'd', long, global = true)]
    debug: bool,

    /// Wire-level packet trace (implies --debug).
    #[arg(short = 't', long, global = true)]
    trace: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the SSH server (default).
    Serve,
    /// Generate a new host key file and exit.
    GenKey {
        /// Path to write the new host key to.
        #[arg(long)]
        host_key: PathBuf,
    },
    /// Install a platform-native service unit (systemd / launchd / Windows
    /// service) so the binary is supervised by the host OS. Requires
    /// root / Administrator privileges.
    InstallService,
    /// Remove the platform-native service unit installed by `install-service`.
    /// Requires root / Administrator privileges.
    UninstallService,
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("esesätsch: failed to start tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("esesätsch: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();

    let verbosity = if args.trace {
        logging::Verbosity::Trace
    } else if args.debug {
        logging::Verbosity::Debug
    } else {
        logging::Verbosity::Default
    };
    let _ = logging::install(verbosity);

    match args.command.as_ref() {
        Some(Command::GenKey { host_key }) => cmd_gen_key(host_key),
        Some(Command::InstallService) => {
            let exe = std::env::current_exe().context("locating current binary")?;
            service::install(&exe, args.config.as_deref())
        }
        Some(Command::UninstallService) => service::uninstall(),
        Some(Command::Serve) | None => cmd_serve(&args).await,
    }
}

fn cmd_gen_key(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(anyhow!(
            "host key file at {} already exists; remove it first to regenerate",
            path.display(),
        ));
    }
    hostkey::generate(path)
        .with_context(|| format!("generating host key at {}", path.display()))?;
    println!("wrote new host key to {}", path.display());
    Ok(())
}

async fn cmd_serve(args: &Args) -> Result<()> {
    let cfg = load_and_merge_config(args)?;

    // Pubkey authenticator: built from the central allowlist in config.
    let pubkey_auth: Arc<dyn PubkeyAuthenticator> = Arc::new(
        AllowlistPubkeyAuthenticator::from_allowlist(&cfg.authorized_keys)
            .context("building pubkey allowlist")?,
    );

    // Operator-friendly warning: pubkey is the only auth method AND the
    // allowlist is empty — no client will ever authenticate.
    if cfg.pubkey_enabled
        && !cfg.password_enabled
        && !cfg.cert_enabled
        && cfg.authorized_keys.is_empty()
    {
        eprintln!(
            "esesätsch: WARNING — pubkey auth is the only method enabled and the \
             authorized_keys allowlist is empty. No client will be able to \
             authenticate. Provide a config file via --config containing your \
             public keys, e.g.:\n\
             \n    [auth.authorized_keys]\n    yourname = [\"ssh-ed25519 AAAA… you@host\"]\n",
        );
    }

    // Password authenticator: PAM on Unix (when built with `--features pam-auth`),
    // LogonUserW on Windows (later). When password auth is disabled in
    // config we use a deny-all stub — the server short-circuits before
    // calling it anyway, but the type system needs a value.
    let password_auth: Arc<dyn PasswordAuthenticator> = if cfg.password_enabled {
        if let Some(native) = real_auth::build_native_password_auth("sshd") {
            Arc::from(native)
        } else {
            return Err(anyhow!(
                "password auth is enabled in config, but no OS-native password \
                 backend is available on this platform",
            ));
        }
    } else {
        Arc::new(DenyAllPasswordAuthenticator)
    };

    // PTY spawner: real `portable-pty`-backed implementation that spawns
    // OS processes with allocated pseudo-terminals.
    let spawner: Arc<dyn PtySpawner> = Arc::new(RealPtySpawner::new());

    // Host key: load if present, else generate.
    let host_key_path = cfg.host_key.clone();
    let host_key = hostkey::load_or_generate(&host_key_path)
        .with_context(|| format!("loading/generating host key at {}", host_key_path.display()))?;

    let (mut server, russh_config) = EsesätschServer::new(
        cfg.clone(),
        pubkey_auth,
        password_auth,
        None, // cert auth not wired via russh yet
        spawner,
        host_key,
    );

    let listener = tokio::net::TcpListener::bind(cfg.bind)
        .await
        .with_context(|| format!("binding {}", cfg.bind))?;
    tracing::info!(target: "esesaetsch", listen = %cfg.bind, "server listening");
    println!("esesätsch: listening on {}", cfg.bind);

    server
        .run_on_socket(russh_config, &listener)
        .await
        .context("running server")?;
    Ok(())
}

/// Read the optional TOML config and merge it with CLI flags.
fn load_and_merge_config(args: &Args) -> Result<Config> {
    let toml = if let Some(path) = &args.config {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        Some(toml::from_str::<TomlConfig>(&raw).context("parsing config TOML")?)
    } else {
        None
    };

    let core_cli = CoreCli {
        config_path: args.config.clone(),
        port: args.port,
        bind: args.bind.clone(),
        host_key: args.host_key.clone(),
        debug: args.debug,
        trace: args.trace,
    };
    let cfg = Config::from_sources(&core_cli, toml).context("merging config")?;
    cfg.validate().context("validating config")?;
    Ok(cfg)
}
