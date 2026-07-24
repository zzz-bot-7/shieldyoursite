use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "shield",
    version,
    about = "Security-header scanner.",
    long_about = None,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Scan one website.
    Scan {
        /// Domain or HTTP(S) URL.
        target: String,
        /// Print JSON only.
        #[arg(long, conflicts_with = "quiet")]
        json: bool,
        /// Print nothing.
        #[arg(long, conflicts_with = "json")]
        quiet: bool,
    },
    /// Write the latest scan as HTML.
    Report {
        /// Output file.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}
