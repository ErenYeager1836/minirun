mod cgroups;
mod cli;
mod container;
mod doctor;
mod rootfs;

use clap::Parser;
use cli::{Cli, Commands};
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .init();

    match cli.command {
        Commands::Doctor => {
            doctor::run_doctor()?;
        }
        Commands::Run(args) => {
            let runtime = container::ContainerRuntime::new(args);
            let exit_code = runtime.run()?;
            std::process::exit(exit_code);
        }
    }

    Ok(())
}
