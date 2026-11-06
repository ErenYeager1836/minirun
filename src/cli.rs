use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "minirun",
    about = "A lightweight OCI-style Linux container runtime from scratch in Rust",
    version = "0.1.0"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Verbose debug logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a command inside an isolated container
    Run(RunArgs),
    /// Inspect the Linux environment and container capabilities
    Doctor,
}

#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    /// Path to root filesystem (rootfs) directory
    #[arg(short, long)]
    pub rootfs: Option<PathBuf>,

    /// Hostname inside the container
    #[arg(long, default_value = "minirun-container")]
    pub hostname: String,

    /// Memory limit (e.g. 128M, 512M, 1G)
    #[arg(short, long)]
    pub memory: Option<String>,

    /// CPU quota in cores (e.g. 0.5, 1.0, 2.0)
    #[arg(short, long)]
    pub cpus: Option<f64>,

    /// Maximum number of processes (PIDs limit, anti-forkbomb)
    #[arg(short, long)]
    pub pids: Option<u64>,

    /// Run in rootless mode using User Namespaces (CLONE_NEWUSER)
    #[arg(long)]
    pub rootless: bool,

    /// Command to execute inside the container
    #[arg(required = true)]
    pub command: String,

    /// Arguments for the command
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
}
