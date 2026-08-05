use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::commands::CliError;

pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent).map_err(|_| CliError::Write)?;
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(CliError::Write)?;
    let temporary_name = format!(".{file_name}.{}.tmp", std::process::id());
    let temporary_path = path.with_file_name(temporary_name);

    let write_result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary_path).map_err(|_| CliError::Write)?;
        file.write_all(contents).map_err(|_| CliError::Write)?;
        file.sync_all().map_err(|_| CliError::Write)?;
        fs::rename(&temporary_path, path).map_err(|_| CliError::Write)
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    write_result
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn replaces_file_without_leaving_temporary_file() {
        let directory = tempdir().expect("temp directory should be created");
        let path = directory.path().join("result.txt");

        write_atomic(&path, b"first").expect("first write should succeed");
        write_atomic(&path, b"second").expect("replacement should succeed");

        assert_eq!(
            fs::read_to_string(path).expect("result should be readable"),
            "second"
        );
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("directory should be readable")
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn creates_owner_only_files() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().expect("temp directory should be created");
        let path = directory.path().join("result.txt");

        write_atomic(&path, b"sensitive").expect("write should succeed");

        let mode = fs::metadata(path)
            .expect("result metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
