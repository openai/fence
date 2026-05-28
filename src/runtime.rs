use crate::config::MAX_REPORT_BYTES;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const RESIDENT_EVIDENCE_STATUS: &str = "resident_lifecycle_test_only";
pub const TEST_READY_STATUS: &str = "test_only_ready_no_protection";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeError {
    pub code: &'static str,
    pub message: String,
}

impl RuntimeError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TestRuntimeStore {
    pub directory: PathBuf,
    pub state: PathBuf,
    pub report: PathBuf,
    pub ready: PathBuf,
}

impl TestRuntimeStore {
    pub fn create(root: &Path, invocation_id: &str) -> Result<Self, RuntimeError> {
        validate_slug(invocation_id)?;
        if root == Path::new("/run/fence") || root.starts_with("/run/fence/") {
            return Err(RuntimeError::new(
                "production_runtime_not_activated",
                "test-only lifecycle evidence cannot write the production runtime root",
            ));
        }
        create_owned_reportable_directory_root(root)?;
        let directory = root.join(invocation_id);
        fs::create_dir(&directory).map_err(|error| io_error("runtime_create_failed", error))?;
        set_directory_mode(&directory, 0o755)?;
        require_real_directory(&directory)?;
        Ok(Self {
            state: directory.join("state.json"),
            report: directory.join("report.json"),
            ready: directory.join("ready.json"),
            directory,
        })
    }

    pub fn write_state_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        write_json_exclusive(&self.state, value, 0o600)
    }

    pub fn write_ready_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        write_json_exclusive(&self.ready, value, 0o644)
    }

    pub fn replace_report(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        let bytes = bounded_json(value)?;
        let pending = self.directory.join("report.json.next");
        write_bytes_exclusive(&pending, &bytes, 0o644)?;
        fs::rename(&pending, &self.report)
            .map_err(|error| io_error("runtime_atomic_write_failed", error))
    }
}

fn create_owned_reportable_directory_root(root: &Path) -> Result<(), RuntimeError> {
    if root.exists() {
        require_real_directory(root)?;
    } else {
        fs::create_dir_all(root).map_err(|error| io_error("runtime_create_failed", error))?;
    }
    set_directory_mode(root, 0o755)?;
    require_real_directory(root)
}

fn require_real_directory(path: &Path) -> Result<(), RuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("runtime_metadata_failed", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(RuntimeError::new(
            "unsafe_runtime_directory",
            "runtime storage must be a real root-owned directory",
        ));
    }
    Ok(())
}

fn validate_slug(value: &str) -> Result<(), RuntimeError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-');
    if valid {
        Ok(())
    } else {
        Err(RuntimeError::new(
            "invalid_runtime_identifier",
            "runtime invocation identifier must be a bounded lowercase slug",
        ))
    }
}

fn write_json_exclusive(
    path: &Path,
    value: &impl Serialize,
    mode: u32,
) -> Result<(), RuntimeError> {
    let bytes = bounded_json(value)?;
    write_bytes_exclusive(path, &bytes, mode)
}

fn bounded_json(value: &impl Serialize) -> Result<Vec<u8>, RuntimeError> {
    let bytes = serde_json::to_vec(value).map_err(|_| {
        RuntimeError::new(
            "runtime_serialization_failed",
            "failed to serialize lifecycle evidence",
        )
    })?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(RuntimeError::new(
            "runtime_document_too_large",
            "lifecycle evidence exceeds the fixed report limit",
        ));
    }
    Ok(bytes)
}

fn write_bytes_exclusive(path: &Path, bytes: &[u8], mode: u32) -> Result<(), RuntimeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .mode(mode)
        .open(path)
        .map_err(|error| io_error("runtime_write_failed", error))?;
    file.write_all(bytes)
        .map_err(|error| io_error("runtime_write_failed", error))?;
    file.sync_all()
        .map_err(|error| io_error("runtime_write_failed", error))
}

fn set_directory_mode(path: &Path, mode: u32) -> Result<(), RuntimeError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| io_error("runtime_permissions_failed", error))
}

fn io_error(code: &'static str, error: std::io::Error) -> RuntimeError {
    RuntimeError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_INDEX: AtomicUsize = AtomicUsize::new(0);

    #[derive(Serialize)]
    struct Document {
        value: String,
    }

    fn root() -> PathBuf {
        PathBuf::from(format!(
            "target/tmp/runtime-unit-{}",
            TEST_INDEX.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn creates_root_owned_readable_evidence_storage_and_atomically_replaces_reports() {
        let root = root();
        let _ = fs::remove_dir_all(&root);
        let store = TestRuntimeStore::create(&root, "resident-proof").unwrap();
        store
            .write_state_exclusive(&Document {
                value: "state".to_owned(),
            })
            .unwrap();
        store
            .replace_report(&Document {
                value: "first".to_owned(),
            })
            .unwrap();
        store
            .replace_report(&Document {
                value: "second".to_owned(),
            })
            .unwrap();
        store
            .write_ready_exclusive(&Document {
                value: TEST_READY_STATUS.to_owned(),
            })
            .unwrap();

        assert_eq!(
            fs::read_to_string(&store.report).unwrap(),
            r#"{"value":"second"}"#
        );
        assert!(!store.directory.join("report.json.next").exists());
        assert_eq!(
            fs::metadata(&store.directory).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&store.state).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&store.report).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_production_roots_symlinks_duplicate_state_and_large_documents() {
        assert_eq!(
            TestRuntimeStore::create(Path::new("/run/fence"), "bad")
                .unwrap_err()
                .code,
            "production_runtime_not_activated"
        );
        assert_eq!(
            TestRuntimeStore::create(Path::new("target/tmp/runtime-bad"), "../bad")
                .unwrap_err()
                .code,
            "invalid_runtime_identifier"
        );

        let symlink_root = root();
        let target = symlink_root.with_extension("target");
        let _ = fs::remove_file(&symlink_root);
        let _ = fs::remove_dir_all(&target);
        fs::create_dir_all(&target).unwrap();
        symlink(fs::canonicalize(&target).unwrap(), &symlink_root).unwrap();
        assert_eq!(
            TestRuntimeStore::create(&symlink_root, "resident-proof")
                .unwrap_err()
                .code,
            "unsafe_runtime_directory"
        );
        fs::remove_file(&symlink_root).unwrap();
        fs::remove_dir_all(target).unwrap();

        let root = root();
        let store = TestRuntimeStore::create(&root, "resident-proof").unwrap();
        let state = Document {
            value: "state".to_owned(),
        };
        store.write_state_exclusive(&state).unwrap();
        assert_eq!(
            store.write_state_exclusive(&state).unwrap_err().code,
            "runtime_write_failed"
        );
        assert_eq!(
            store
                .replace_report(&Document {
                    value: "x".repeat(MAX_REPORT_BYTES),
                })
                .unwrap_err()
                .code,
            "runtime_document_too_large"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
