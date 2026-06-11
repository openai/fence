use crate::config::{MAX_CONFIG_BYTES, MAX_REPORT_BYTES};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

pub const RESIDENT_EVIDENCE_STATUS: &str = "resident_lifecycle_test_only";
pub const TEST_READY_STATUS: &str = "test_only_ready_no_protection";
pub const PRODUCTION_RUNTIME_ROOT: &str = "/run/fence";

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

pub trait RuntimeDocumentStore {
    fn directory(&self) -> &Path;
    fn write_state_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError>;
    fn write_ready_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError>;
    fn replace_report(&self, value: &impl Serialize) -> Result<(), RuntimeError>;
    fn verify_evidence_persistence(&self, require_ready: bool) -> Result<(), RuntimeError>;
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
        replace_report(&self.directory, &self.report, value)
    }

    pub fn verify_evidence_persistence(&self, require_ready: bool) -> Result<(), RuntimeError> {
        require_evidence_file(&self.state, None, 0o600)?;
        require_evidence_file(&self.report, None, 0o644)?;
        if require_ready {
            require_evidence_file(&self.ready, None, 0o644)?;
        }
        Ok(())
    }
}

impl RuntimeDocumentStore for TestRuntimeStore {
    fn directory(&self) -> &Path {
        &self.directory
    }

    fn write_state_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        self.write_state_exclusive(value)
    }

    fn write_ready_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        self.write_ready_exclusive(value)
    }

    fn replace_report(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        self.replace_report(value)
    }

    fn verify_evidence_persistence(&self, require_ready: bool) -> Result<(), RuntimeError> {
        self.verify_evidence_persistence(require_ready)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProductionRuntimeStore {
    pub invocation_id: String,
    pub directory: PathBuf,
    pub config: PathBuf,
    pub state: PathBuf,
    pub report: PathBuf,
    pub ready: PathBuf,
    expected_uid: u32,
}

impl ProductionRuntimeStore {
    pub fn open(config: &Path) -> Result<Self, RuntimeError> {
        Self::open_under(Path::new(PRODUCTION_RUNTIME_ROOT), config, 0)
    }

    fn open_under(root: &Path, config: &Path, expected_uid: u32) -> Result<Self, RuntimeError> {
        let invocation_id = production_invocation_id(root, config)?;
        let directory = root.join(&invocation_id);
        require_owned_directory(root, expected_uid, 0o755)?;
        require_owned_directory(&directory, expected_uid, 0o755)?;
        require_owned_file(config, expected_uid, 0o600)?;
        require_initial_production_directory(&directory)?;
        Ok(Self {
            state: directory.join("state.json"),
            report: directory.join("report.json"),
            ready: directory.join("ready.json"),
            invocation_id,
            directory,
            config: config.to_path_buf(),
            expected_uid,
        })
    }

    pub fn read_config_bounded(&self) -> Result<Vec<u8>, RuntimeError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.config)
            .map_err(|error| io_error("trusted_config_read_failed", error))?;
        require_owned_file_metadata(
            &file
                .metadata()
                .map_err(|error| io_error("trusted_config_metadata_failed", error))?,
            self.expected_uid,
            0o600,
        )?;
        let mut bytes = Vec::new();
        file.take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("trusted_config_read_failed", error))?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(RuntimeError::new(
                "trusted_config_too_large",
                "trusted launcher configuration exceeds the fixed input limit",
            ));
        }
        Ok(bytes)
    }

    pub fn write_state_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        write_json_exclusive(&self.state, value, 0o600)
    }

    pub fn write_ready_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        write_json_exclusive(&self.ready, value, 0o644)
    }

    pub fn replace_report(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        replace_report(&self.directory, &self.report, value)
    }

    pub fn verify_evidence_persistence(&self, require_ready: bool) -> Result<(), RuntimeError> {
        require_evidence_file(&self.state, Some(self.expected_uid), 0o600)?;
        require_evidence_file(&self.report, Some(self.expected_uid), 0o644)?;
        if require_ready {
            require_evidence_file(&self.ready, Some(self.expected_uid), 0o644)?;
        }
        Ok(())
    }
}

impl RuntimeDocumentStore for ProductionRuntimeStore {
    fn directory(&self) -> &Path {
        &self.directory
    }

    fn write_state_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        self.write_state_exclusive(value)
    }

    fn write_ready_exclusive(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        self.write_ready_exclusive(value)
    }

    fn replace_report(&self, value: &impl Serialize) -> Result<(), RuntimeError> {
        self.replace_report(value)
    }

    fn verify_evidence_persistence(&self, require_ready: bool) -> Result<(), RuntimeError> {
        self.verify_evidence_persistence(require_ready)
    }
}

fn require_evidence_file(
    path: &Path,
    expected_uid: Option<u32>,
    mode: u32,
) -> Result<(), RuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("runtime_evidence_missing", error))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || expected_uid.is_some_and(|uid| metadata.uid() != uid)
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(RuntimeError::new(
            "unsafe_runtime_evidence",
            "resident lifecycle evidence is missing or has unsafe ownership, type, or permissions",
        ));
    }
    Ok(())
}

fn production_invocation_id(root: &Path, config: &Path) -> Result<String, RuntimeError> {
    let relative = config.strip_prefix(root).map_err(|_| {
        RuntimeError::new(
            "unsafe_runtime_config_path",
            "trusted launcher configuration must be below the fixed runtime root",
        )
    })?;
    let mut components = relative.components();
    let invocation_id = match components.next() {
        Some(Component::Normal(value)) => value.to_str().unwrap_or_default(),
        _ => "",
    };
    if components.next() != Some(Component::Normal("config.json".as_ref()))
        || components.next().is_some()
    {
        return Err(RuntimeError::new(
            "unsafe_runtime_config_path",
            "trusted launcher configuration must use the fixed invocation config path",
        ));
    }
    validate_slug(invocation_id)?;
    Ok(invocation_id.to_owned())
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

fn require_owned_directory(path: &Path, expected_uid: u32, mode: u32) -> Result<(), RuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("runtime_metadata_failed", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(RuntimeError::new(
            "unsafe_runtime_directory",
            "trusted launcher runtime storage must be a pinned root-owned directory",
        ));
    }
    Ok(())
}

fn require_owned_file(path: &Path, expected_uid: u32, mode: u32) -> Result<(), RuntimeError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("runtime_metadata_failed", error))?;
    require_owned_file_metadata(&metadata, expected_uid, mode)
}

fn require_owned_file_metadata(
    metadata: &fs::Metadata,
    expected_uid: u32,
    mode: u32,
) -> Result<(), RuntimeError> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(RuntimeError::new(
            "unsafe_runtime_config",
            "trusted launcher configuration must be a pinned root-owned regular file",
        ));
    }
    Ok(())
}

fn require_initial_production_directory(directory: &Path) -> Result<(), RuntimeError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| io_error("runtime_metadata_failed", error))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| io_error("runtime_metadata_failed", error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    if entries == ["config.json"] {
        Ok(())
    } else {
        Err(RuntimeError::new(
            "unsafe_runtime_state",
            "trusted launcher runtime directory must initially contain only config.json",
        ))
    }
}

fn validate_slug(value: &str) -> Result<(), RuntimeError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.as_bytes().windows(2).any(|pair| pair == b"--");
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

fn replace_report(
    directory: &Path,
    report: &Path,
    value: &impl Serialize,
) -> Result<(), RuntimeError> {
    let bytes = bounded_json(value)?;
    let pending = directory.join("report.json.next");
    write_bytes_exclusive(&pending, &bytes, 0o644)?;
    fs::rename(&pending, report).map_err(|error| io_error("runtime_atomic_write_failed", error))
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

    fn production_fixture(config: &[u8]) -> (PathBuf, PathBuf, u32) {
        let root = root();
        let directory = root.join("trusted-run");
        let config_path = directory.join("config.json");
        fs::create_dir_all(&directory).unwrap();
        set_directory_mode(&root, 0o755).unwrap();
        set_directory_mode(&directory, 0o755).unwrap();
        fs::write(&config_path, config).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = fs::metadata(&root).unwrap().uid();
        (root, config_path, uid)
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
        store.verify_evidence_persistence(false).unwrap();
        assert_eq!(
            store.verify_evidence_persistence(true).unwrap_err().code,
            "runtime_evidence_missing"
        );
        store
            .write_ready_exclusive(&Document {
                value: TEST_READY_STATUS.to_owned(),
            })
            .unwrap();
        store.verify_evidence_persistence(true).unwrap();

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
        assert_eq!(
            TestRuntimeStore::create(Path::new("target/tmp/runtime-bad"), "bad--slug")
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

    #[test]
    fn opens_pinned_production_runtime_and_reads_bounded_trusted_config() {
        let (root, config, uid) = production_fixture(b"{\"schema_version\":1}");
        let store = ProductionRuntimeStore::open_under(&root, &config, uid).unwrap();

        assert_eq!(store.invocation_id, "trusted-run");
        assert_eq!(store.directory, root.join("trusted-run"));
        assert_eq!(
            store.read_config_bounded().unwrap(),
            b"{\"schema_version\":1}"
        );
        store
            .write_state_exclusive(&Document {
                value: "state".to_owned(),
            })
            .unwrap();
        store
            .replace_report(&Document {
                value: "report".to_owned(),
            })
            .unwrap();
        store
            .write_ready_exclusive(&Document {
                value: "ready".to_owned(),
            })
            .unwrap();
        store.verify_evidence_persistence(true).unwrap();

        assert_eq!(
            fs::metadata(&store.state).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&store.report).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(&store.ready).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_missing_symlinked_and_mode_changed_resident_evidence() {
        let root = root();
        let store = TestRuntimeStore::create(&root, "resident-proof").unwrap();
        store
            .write_state_exclusive(&Document {
                value: "state".to_owned(),
            })
            .unwrap();
        store
            .replace_report(&Document {
                value: "report".to_owned(),
            })
            .unwrap();
        store
            .write_ready_exclusive(&Document {
                value: "ready".to_owned(),
            })
            .unwrap();
        store.verify_evidence_persistence(true).unwrap();

        fs::set_permissions(&store.report, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            store.verify_evidence_persistence(true).unwrap_err().code,
            "unsafe_runtime_evidence"
        );
        fs::remove_file(&store.report).unwrap();
        symlink(&store.ready, &store.report).unwrap();
        assert_eq!(
            store.verify_evidence_persistence(true).unwrap_err().code,
            "unsafe_runtime_evidence"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_untrusted_production_config_paths_modes_ownership_and_size() {
        let (root, config, uid) = production_fixture(b"{}");
        assert_eq!(
            ProductionRuntimeStore::open_under(&root, &root.join("config.json"), uid)
                .unwrap_err()
                .code,
            "unsafe_runtime_config_path"
        );
        assert_eq!(
            ProductionRuntimeStore::open_under(&root, &config, uid.saturating_add(1))
                .unwrap_err()
                .code,
            "unsafe_runtime_directory"
        );

        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            ProductionRuntimeStore::open_under(&root, &config, uid)
                .unwrap_err()
                .code,
            "unsafe_runtime_config"
        );
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(root.join("trusted-run").join("stale.json"), b"{}").unwrap();
        assert_eq!(
            ProductionRuntimeStore::open_under(&root, &config, uid)
                .unwrap_err()
                .code,
            "unsafe_runtime_state"
        );
        fs::remove_file(root.join("trusted-run").join("stale.json")).unwrap();
        fs::write(&config, vec![b'x'; MAX_CONFIG_BYTES + 1]).unwrap();
        assert_eq!(
            ProductionRuntimeStore::open_under(&root, &config, uid)
                .unwrap()
                .read_config_bounded()
                .unwrap_err()
                .code,
            "trusted_config_too_large"
        );

        fs::remove_file(&config).unwrap();
        let target = root.join("config-target.json");
        fs::write(&target, b"{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &config).unwrap();
        assert_eq!(
            ProductionRuntimeStore::open_under(&root, &config, uid)
                .unwrap_err()
                .code,
            "unsafe_runtime_config"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
