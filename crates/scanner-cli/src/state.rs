use std::env;
use std::fs;
use std::path::PathBuf;

use directories::ProjectDirs;
use shield_scanner_core::ScanResult;

use crate::atomic_file::write_atomic;
use crate::commands::CliError;

const LATEST_SCAN_FILE: &str = "latest-scan.json";

pub(crate) struct ScanStore {
    directory: PathBuf,
}

impl ScanStore {
    pub(crate) fn discover() -> Result<Self, CliError> {
        if let Some(directory) = env::var_os("SHIELD_DATA_DIR").filter(|value| !value.is_empty()) {
            return Ok(Self {
                directory: PathBuf::from(directory),
            });
        }

        let project = ProjectDirs::from("com", "JDRV", "Shield").ok_or(CliError::State)?;
        Ok(Self {
            directory: project.data_local_dir().to_owned(),
        })
    }

    pub(crate) fn save(&self, scan: &ScanResult) -> Result<(), CliError> {
        let json = serde_json::to_vec(scan).map_err(|_| CliError::State)?;
        write_atomic(&self.path(), &json)
    }

    pub(crate) fn load(&self) -> Result<ScanResult, CliError> {
        let json = fs::read(self.path()).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                CliError::NoScan
            } else {
                CliError::State
            }
        })?;
        serde_json::from_slice(&json).map_err(|_| CliError::State)
    }

    fn path(&self) -> PathBuf {
        self.directory.join(LATEST_SCAN_FILE)
    }
}
