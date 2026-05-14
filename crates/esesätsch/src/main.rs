//! esesätsch SSH server entry point.
//!
//! This binary is intentionally thin. All logic lives in `esesaetsch-core`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use esesaetsch_core::hostkey;

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
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("esesätsch: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    let verbosity = if args.trace {
        esesaetsch_core::logging::Verbosity::Trace
    } else if args.debug {
        esesaetsch_core::logging::Verbosity::Debug
    } else {
        esesaetsch_core::logging::Verbosity::Default
    };
    // Errors from install are non-fatal (e.g., subscriber already set in tests).
    let _ = esesaetsch_core::logging::install(verbosity);

    match args.command.as_ref() {
        Some(Command::GenKey { host_key }) => cmd_gen_key(host_key),
        Some(Command::Serve) | None => cmd_serve(&args),
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

fn cmd_serve(args: &Args) -> Result<()> {
    use esesaetsch_core::config::{Cli as CoreCli, Config, TomlConfig};
    use std::fs;

    let toml = if let Some(path) = &args.config {
        let raw = fs::read_to_string(path)
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

    println!(
        "serve: would listen on {} (full server wiring not yet hooked in this binary)",
        cfg.bind,
    );
    Ok(())
}
