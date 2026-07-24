use std::env;
use std::path::PathBuf;

use shield_scanner_core::{ScanError, Scanner};
use shield_scanner_report::{default_report_filename, render_html};

use crate::atomic_file::write_atomic;
use crate::cli::{Cli, Command};
use crate::output;
use crate::state::ScanStore;

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Scan(#[from] ScanError),
    #[error("State unavailable.")]
    State,
    #[error("No scan found.")]
    NoScan,
    #[error("Write failed.")]
    Write,
    #[error("Output failed.")]
    Output,
}

/// Executes one parsed CLI command.
///
/// # Errors
///
/// Returns [`CliError`] when scanning, state persistence, report generation, or
/// terminal output fails.
pub async fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Scan {
            target,
            json,
            quiet,
        } => run_scan(&target, json, quiet).await,
        Command::Report { output } => run_report(output),
    }
}

async fn run_scan(target: &str, json: bool, quiet: bool) -> Result<(), CliError> {
    let scanner = Scanner::new()?;
    let scan = scanner.scan(target).await?;
    ScanStore::discover()?.save(&scan)?;
    output::scan(&scan, json, quiet)
}

fn run_report(output_path: Option<PathBuf>) -> Result<(), CliError> {
    let scan = ScanStore::discover()?.load()?;
    let path = match output_path {
        Some(path) => path,
        None => env::current_dir()
            .map_err(|_| CliError::Write)?
            .join(default_report_filename(&scan)),
    };
    write_atomic(&path, render_html(&scan).as_bytes())?;
    output::report(&path)
}
