use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use agentslam::core::config::Config;
use agentslam::hook::{self, HookKind};

#[derive(Parser)]
#[command(
    name = "agentslam",
    version,
    about = "SSO-authorized MCP rooms for coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (MCP at /mcp, OAuth AS, web UI).
    Serve {
        /// TOML config file; provider secrets come from the env vars it names.
        #[arg(
            long,
            short,
            env = "AGENTSLAM_CONFIG",
            default_value = "agentslam.toml"
        )]
        config: PathBuf,
    },
    /// Validate a config file (and that the referenced secret env vars are set).
    CheckConfig {
        #[arg(
            long,
            short,
            env = "AGENTSLAM_CONFIG",
            default_value = "agentslam.toml"
        )]
        config: PathBuf,
    },
    /// Host hook: `session-start` (SessionStart: prints the agentslam session id),
    /// `prompt` (UserPromptSubmit) or `stop` (Stop, never blocks).
    Hook {
        #[arg(value_enum)]
        kind: HookArg,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum HookArg {
    SessionStart,
    Prompt,
    Stop,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Hook { kind } => {
            let kind = match kind {
                HookArg::SessionStart => HookKind::SessionStart,
                HookArg::Prompt => HookKind::Prompt,
                HookArg::Stop => HookKind::Stop,
            };
            ExitCode::from(hook::run(kind).await as u8)
        }
        Command::CheckConfig { config } => match Config::load(&config) {
            Ok(_) => {
                println!("config ok: {}", config.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("config error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Command::Serve { config } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            let cfg = match Config::load(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e:#}");
                    return ExitCode::FAILURE;
                }
            };
            let running = match agentslam::core::app::serve(cfg, None).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("startup failed: {e:#}");
                    return ExitCode::FAILURE;
                }
            };
            println!("agentslam listening on {}", running.url());
            let stop = tokio::signal::ctrl_c();
            if let Err(e) = stop.await {
                eprintln!("signal handler failed: {e}");
            }
            running.stop().await;
            ExitCode::SUCCESS
        }
    }
}
