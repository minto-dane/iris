use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::api::{IrisRequest, OperationOptions};
use crate::error::{IrisError, Result};

#[derive(Debug, Parser)]
#[command(name = "iris", version, about = "Iris package manager")]
pub struct Cli {
    #[arg(long, global = true, default_value = "/var/iris")]
    pub root: PathBuf,
    #[arg(long, global = true, value_enum, default_value_t = Transport::Direct)]
    pub transport: Transport,
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,
    #[arg(long, global = true)]
    pub dry_run: bool,
    #[arg(long, global = true)]
    pub yes: bool,
    #[arg(long, global = true)]
    pub batch: bool,
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Install(PackagesArgs),
    Remove(PackagesArgs),
    Purge(PackagesArgs),
    Update(PackagesArgs),
    #[command(name = "self", subcommand)]
    SelfCmd(SelfCommand),
    Search(SearchArgs),
    Info(PackageArgs),
    Verify(VerifyArgs),
    Repair(PackagesArgs),
    Audit,
    #[command(subcommand)]
    Generation(GenerationCommand),
    #[command(subcommand)]
    Orphan(OrphanCommand),
    #[command(subcommand)]
    Repo(RepoCommand),
    History,
    Pin(PackageArgs),
    Why(PackageArgs),
    #[command(subcommand)]
    Daemon(DaemonCommand),
}

#[derive(Debug, Args)]
pub struct PackagesArgs {
    pub packages: Vec<String>,
}

#[derive(Debug, Args)]
pub struct PackageArgs {
    pub package: String,
}

#[derive(Debug, Args)]
pub struct SearchArgs {
    pub query: String,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[arg(long)]
    pub full: bool,
    pub packages: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum GenerationCommand {
    List,
    Switch(GenerationSwitchArgs),
    Rollback,
    Diff(GenerationDiffArgs),
    Gc,
}

#[derive(Debug, Subcommand)]
pub enum SelfCommand {
    /// Show managed iris package status, schema version, and staged bootstrap state.
    Status,
    /// Stage a bootstrap-required iris self-upgrade plan without applying the migration.
    Stage,
    /// Apply a previously staged bootstrap self-upgrade and state-schema migration.
    Bootstrap,
    /// Update iris through the ordinary managed-package path when bootstrap is not required.
    Update,
}

#[derive(Debug, Args)]
pub struct GenerationSwitchArgs {
    pub generation: i64,
}

#[derive(Debug, Args)]
pub struct GenerationDiffArgs {
    pub from: i64,
    pub to: i64,
}

#[derive(Debug, Subcommand)]
pub enum OrphanCommand {
    List,
    Show(PackageArgs),
    Purge(OrphanPurgeArgs),
}

#[derive(Debug, Args)]
pub struct OrphanPurgeArgs {
    pub package: Option<String>,
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Subcommand)]
pub enum RepoCommand {
    Add(RepoAddArgs),
    Sync,
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    Status,
    Log(DaemonLogArgs),
}

#[derive(Debug, Args)]
pub struct DaemonLogArgs {
    #[arg(long, default_value_t = 20, value_parser = parse_positive_usize)]
    pub lines: usize,
}

#[derive(Debug, Args)]
pub struct RepoAddArgs {
    pub url: String,
    pub key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Transport {
    Direct,
    Daemon,
}

#[derive(Debug, Clone, Copy)]
pub struct RenderOptions {
    pub batch: bool,
    pub json: bool,
}

#[derive(Debug, Clone)]
pub struct FrontendRequest {
    pub root: PathBuf,
    pub transport: Transport,
    pub socket: Option<PathBuf>,
    pub request: IrisRequest,
    pub render: RenderOptions,
}

fn parse_positive_usize(value: &str) -> std::result::Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid positive integer: {value}"))?;
    if parsed == 0 {
        return Err("value must be at least 1".into());
    }
    Ok(parsed)
}

impl Cli {
    pub fn render_options(&self) -> RenderOptions {
        RenderOptions {
            batch: self.batch,
            json: self.json,
        }
    }

    pub fn into_frontend_request(self) -> Result<FrontendRequest> {
        let Cli {
            root,
            transport,
            socket,
            dry_run,
            yes,
            batch,
            json,
            command,
        } = self;

        if transport == Transport::Direct && socket.is_some() {
            return Err(IrisError::InvalidInput(
                "--socket requires --transport daemon".into(),
            ));
        }

        let render = RenderOptions { batch, json };
        let options = OperationOptions { dry_run, yes };
        let request = match command {
            Command::Install(args) => IrisRequest::Install {
                packages: args.packages,
                options,
            },
            Command::Remove(args) => IrisRequest::Remove {
                packages: args.packages,
                options,
            },
            Command::Purge(args) => IrisRequest::Purge {
                packages: args.packages,
                options,
            },
            Command::Update(args) => IrisRequest::Update {
                packages: args.packages,
                options,
            },
            Command::SelfCmd(command) => match command {
                SelfCommand::Status => IrisRequest::SelfStatus,
                SelfCommand::Stage => IrisRequest::SelfStage { options },
                SelfCommand::Bootstrap => IrisRequest::SelfBootstrap { options },
                SelfCommand::Update => IrisRequest::SelfUpdate { options },
            },
            Command::Search(args) => IrisRequest::Search { query: args.query },
            Command::Info(args) => IrisRequest::Info {
                package: args.package,
            },
            Command::Verify(args) => IrisRequest::Verify {
                packages: args.packages,
                full: args.full,
            },
            Command::Repair(args) => IrisRequest::Repair {
                packages: args.packages,
                options,
            },
            Command::Audit => IrisRequest::Audit,
            Command::Generation(command) => match command {
                GenerationCommand::List => IrisRequest::GenerationList,
                GenerationCommand::Switch(args) => IrisRequest::GenerationSwitch {
                    generation: args.generation,
                },
                GenerationCommand::Rollback => IrisRequest::GenerationRollback,
                GenerationCommand::Diff(args) => IrisRequest::GenerationDiff {
                    from: args.from,
                    to: args.to,
                },
                GenerationCommand::Gc => IrisRequest::GenerationGc,
            },
            Command::Orphan(command) => match command {
                OrphanCommand::List => IrisRequest::OrphanList,
                OrphanCommand::Show(args) => IrisRequest::OrphanShow {
                    package: args.package,
                },
                OrphanCommand::Purge(args) => IrisRequest::OrphanPurge {
                    package: if args.all { None } else { args.package },
                    force: args.force,
                    options,
                },
            },
            Command::Repo(command) => match command {
                RepoCommand::Add(args) => IrisRequest::RepoAdd {
                    url: args.url,
                    key: args.key,
                },
                RepoCommand::Sync => IrisRequest::RepoSync,
            },
            Command::History => IrisRequest::History,
            Command::Pin(args) => IrisRequest::Pin {
                package: args.package,
            },
            Command::Why(args) => IrisRequest::Why {
                package: args.package,
            },
            Command::Daemon(command) => match command {
                DaemonCommand::Status => IrisRequest::DaemonStatus,
                DaemonCommand::Log(args) => IrisRequest::DaemonLog { lines: args.lines },
            },
        };

        Ok(FrontendRequest {
            root,
            transport,
            socket,
            request,
            render,
        })
    }
}
