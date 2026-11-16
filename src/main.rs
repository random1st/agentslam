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
    /// Instance operator commands that run against the server database.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Host hook: `session-start` (SessionStart: prints the agentslam session id),
    /// `prompt` (UserPromptSubmit) or `stop` (Stop, never blocks).
    Hook {
        #[arg(value_enum)]
        kind: HookArg,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Mint a headless token for agent <service>/<agent> of organization
    /// <org>, creating the service account if missing. Prints only the token.
    ServiceToken {
        #[arg(
            long,
            short,
            env = "AGENTSLAM_CONFIG",
            default_value = "agentslam.toml"
        )]
        config: PathBuf,
        /// Organization name or key (e.g. the Workspace domain).
        #[arg(long)]
        org: String,
        /// Service account name.
        #[arg(long)]
        service: String,
        /// Agent label.
        #[arg(long)]
        agent: String,
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
        Command::Admin {
            command:
                AdminCommand::ServiceToken {
                    config,
                    org,
                    service,
                    agent,
                },
        } => match service_token(&config, &org, &service, &agent).await {
            Ok(token) => {
                println!("{token}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
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

/// `agentslam admin service-token`: open the configured database (applying
/// pending migrations, as the server does) and mint the token.
async fn service_token(
    config: &std::path::Path,
    org: &str,
    service: &str,
    agent: &str,
) -> anyhow::Result<String> {
    let cfg = Config::load(config)?;
    // An operator command must act on the server's database: a mistyped path
    // would otherwise create an empty database and mint a token nobody serves.
    if !std::path::Path::new(&cfg.database).is_file() {
        anyhow::bail!(
            "database {} does not exist: point `database` in {} at the server's database",
            cfg.database,
            config.display()
        );
    }
    let db = agentslam::core::db::Db::open(&cfg.database)?;
    let now = agentslam::core::clock::Clock::default().now();
    let resource = cfg.mcp_resource();
    let (org, service, agent) = (org.to_string(), service.to_string(), agent.to_string());
    let token = db
        .call(move |c| {
            agentslam::identity::people::operator_service_token(
                c, &org, &service, &agent, &resource, now,
            )
        })
        .await?;
    Ok(token)
}
