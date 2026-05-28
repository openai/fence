use crate::hosted_runner::hosted_runner_fingerprint_requirement;
use crate::lifecycle::validate_test_service_context;
use crate::runtime::{RuntimeError, TestRuntimeStore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const LOCKDOWN_EVIDENCE_STATUS: &str = "lockdown_evidence_test_only";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_COMMAND_OUTPUT_BYTES: usize = 8 * 1024;
const MAX_POLICY_SOURCE_BYTES: u64 = 256 * 1024;
const SUDOERS_PATH: &str = "/etc/sudoers";
const SUDOERS_DROP_IN_ROOT: &str = "/etc/sudoers.d";
const RUNNER_DROP_IN_PATH: &str = "/etc/sudoers.d/runner";
const CONTAINER_UNITS: [&str; 3] = ["docker.socket", "docker.service", "containerd.service"];

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LockdownError {
    pub code: &'static str,
    pub message: String,
}

impl LockdownError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<RuntimeError> for LockdownError {
    fn from(error: RuntimeError) -> Self {
        Self::new(error.code, error.message)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockdownPosture {
    StandardBlock,
    UnsafePreserve,
    Audit,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct LockdownEvidence {
    pub status: &'static str,
    pub posture: LockdownPosture,
    pub assurance_status: &'static str,
    pub setup_status: &'static str,
    pub sudo_status: &'static str,
    pub container_status: &'static str,
    pub rollback_status: &'static str,
    pub readiness_status: &'static str,
    pub protection_available: bool,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct UnitObservation {
    load_state: String,
    active_state: String,
    unit_file_state: String,
}

#[derive(Debug, Serialize)]
struct LockdownState {
    status: &'static str,
    posture: LockdownPosture,
    setup_status: &'static str,
    readiness_status: &'static str,
}

pub trait LockdownControl {
    fn verify_supported_host(&mut self) -> Result<(), LockdownError>;
    fn verify_sudo_available(&mut self) -> Result<(), LockdownError>;
    fn verify_containers_available(&mut self) -> Result<(), LockdownError>;
    fn disable_sudo(&mut self) -> Result<(), LockdownError>;
    fn disable_containers(&mut self) -> Result<(), LockdownError>;
    fn verify_sudo_disabled(&mut self) -> Result<(), LockdownError>;
    fn verify_containers_disabled(&mut self) -> Result<(), LockdownError>;
    fn rollback_pre_ready(&mut self) -> Result<bool, LockdownError>;
}

pub struct LockdownSession<C: LockdownControl> {
    pub evidence: LockdownEvidence,
    pub runtime: TestRuntimeStore,
    control: C,
}

impl<C: LockdownControl> LockdownSession<C> {
    pub fn establish_test_only(
        runtime: TestRuntimeStore,
        posture: LockdownPosture,
        mut control: C,
        inject_pre_ready_failure: bool,
    ) -> Result<Self, LockdownError> {
        let mut evidence = initial_evidence(posture);
        runtime.write_state_exclusive(&LockdownState {
            status: LOCKDOWN_EVIDENCE_STATUS,
            posture,
            setup_status: "setting_up",
            readiness_status: "not_emitted",
        })?;
        runtime.replace_report(&evidence)?;

        let result = establish_controls(&mut evidence, posture, &mut control).and_then(|()| {
            if inject_pre_ready_failure {
                Err(LockdownError::new(
                    "injected_pre_ready_lockdown_failure",
                    "test injected a failure after provisional lockdown state",
                ))
            } else {
                Ok(())
            }
        });
        if let Err(error) = result {
            record_pre_ready_rollback(&runtime, &mut evidence, &mut control);
            return Err(error);
        }

        evidence.setup_status = "verified_test_only_no_ready";
        if let Err(error) = runtime.replace_report(&evidence) {
            record_pre_ready_rollback(&runtime, &mut evidence, &mut control);
            return Err(error.into());
        }
        Ok(Self {
            evidence,
            runtime,
            control,
        })
    }

    #[doc(hidden)]
    pub fn control_for_test(&self) -> &C {
        &self.control
    }
}

fn record_pre_ready_rollback(
    runtime: &TestRuntimeStore,
    evidence: &mut LockdownEvidence,
    control: &mut impl LockdownControl,
) {
    evidence.setup_status = "failed_pre_ready";
    evidence.rollback_status = match control.rollback_pre_ready() {
        Ok(true) => "rolled_back_pre_ready",
        Ok(false) => "nothing_to_rollback",
        Err(_) => "rollback_failed",
    };
    let _ = runtime.replace_report(evidence);
}

fn establish_controls(
    evidence: &mut LockdownEvidence,
    posture: LockdownPosture,
    control: &mut impl LockdownControl,
) -> Result<(), LockdownError> {
    control.verify_supported_host()?;
    control.verify_sudo_available()?;
    control.verify_containers_available()?;
    match posture {
        LockdownPosture::Audit => {
            evidence.sudo_status = "preserved";
            evidence.container_status = "preserved";
        }
        LockdownPosture::UnsafePreserve => {
            control.disable_sudo()?;
            control.verify_sudo_disabled()?;
            control.verify_containers_available()?;
            evidence.sudo_status = "disabled_verified";
            evidence.container_status = "preserved_unsafe";
        }
        LockdownPosture::StandardBlock => {
            control.disable_sudo()?;
            control.disable_containers()?;
            control.verify_sudo_disabled()?;
            control.verify_containers_disabled()?;
            evidence.sudo_status = "disabled_verified";
            evidence.container_status = "disabled_verified";
        }
    }
    Ok(())
}

fn initial_evidence(posture: LockdownPosture) -> LockdownEvidence {
    let (assurance_status, limitations) = match posture {
        LockdownPosture::StandardBlock => (
            "lockdown_controls_verified_test_only",
            vec![
                "lockdown_evidence_test_only_no_public_activation",
                "network_and_lockdown_not_composed_on_host",
                "readiness_not_emitted",
            ],
        ),
        LockdownPosture::UnsafePreserve => (
            "degraded_container_control_preserved",
            vec![
                "lockdown_evidence_test_only_no_public_activation",
                "container_control_preserved_invalidates_containment",
                "readiness_not_emitted",
            ],
        ),
        LockdownPosture::Audit => (
            "audit_observation_only",
            vec![
                "lockdown_evidence_test_only_no_public_activation",
                "sudo_and_container_control_preserved",
                "readiness_not_emitted",
            ],
        ),
    };
    LockdownEvidence {
        status: LOCKDOWN_EVIDENCE_STATUS,
        posture,
        assurance_status,
        setup_status: "setting_up",
        sudo_status: "not_checked",
        container_status: "not_checked",
        rollback_status: "not_required",
        readiness_status: "not_emitted",
        protection_available: false,
        limitations,
    }
}

pub struct SystemLockdownControl {
    quarantine_path: PathBuf,
    sudo_mode: Option<u32>,
    sudo_relocated: bool,
    containers_masked: bool,
}

impl SystemLockdownControl {
    pub fn new(runtime_directory: &Path) -> Self {
        Self {
            quarantine_path: runtime_directory.join("sudo-runner.provisional"),
            sudo_mode: None,
            sudo_relocated: false,
            containers_masked: false,
        }
    }
}

impl LockdownControl for SystemLockdownControl {
    fn verify_supported_host(&mut self) -> Result<(), LockdownError> {
        verify_fixed_fingerprint()
    }

    fn verify_sudo_available(&mut self) -> Result<(), LockdownError> {
        if runner_sudo_true()?.status.success() {
            Ok(())
        } else {
            Err(LockdownError::new(
                "sudo_shape_unsupported",
                "the accepted runner passwordless sudo path is unavailable",
            ))
        }
    }

    fn verify_containers_available(&mut self) -> Result<(), LockdownError> {
        if runner_docker_ps()?.status.success() {
            Ok(())
        } else {
            Err(LockdownError::new(
                "container_shape_unsupported",
                "the accepted runner Docker control path is unavailable",
            ))
        }
    }

    fn disable_sudo(&mut self) -> Result<(), LockdownError> {
        let bytes = read_bounded_policy_file(Path::new(RUNNER_DROP_IN_PATH))?;
        let mode = fs::metadata(RUNNER_DROP_IN_PATH)
            .map_err(|_| unsupported_fingerprint())?
            .permissions()
            .mode()
            & 0o777;
        write_policy_exclusive(
            &self.quarantine_path,
            &bytes,
            0o600,
            "sudo_lockdown_failed",
            "failed to create bounded provisional sudo policy state",
        )?;
        if fs::remove_file(RUNNER_DROP_IN_PATH).is_err() {
            let _ = fs::remove_file(&self.quarantine_path);
            return Err(LockdownError::new(
                "sudo_lockdown_failed",
                "failed to remove the accepted runner sudo policy source after quarantine",
            ));
        }
        self.sudo_mode = Some(mode);
        self.sudo_relocated = true;
        require_success(
            fixed_command("/usr/sbin/visudo", &["--check"])?,
            "sudo_lockdown_failed",
            "relocated sudo policy did not validate",
        )
    }

    fn disable_containers(&mut self) -> Result<(), LockdownError> {
        self.containers_masked = true;
        require_success(
            fixed_command(
                "/usr/bin/systemctl",
                &[
                    "mask",
                    "--runtime",
                    "--now",
                    CONTAINER_UNITS[0],
                    CONTAINER_UNITS[1],
                    CONTAINER_UNITS[2],
                ],
            )?,
            "container_lockdown_failed",
            "failed to stop and runtime-mask accepted container units",
        )
    }

    fn verify_sudo_disabled(&mut self) -> Result<(), LockdownError> {
        if runner_sudo_true()?.status.success() {
            Err(LockdownError::new(
                "sudo_lockdown_failed",
                "runner passwordless sudo remains usable after lockdown",
            ))
        } else {
            Ok(())
        }
    }

    fn verify_containers_disabled(&mut self) -> Result<(), LockdownError> {
        if runner_docker_ps()?.status.success() {
            return Err(LockdownError::new(
                "container_lockdown_failed",
                "runner Docker access remains usable after lockdown",
            ));
        }
        for unit in CONTAINER_UNITS {
            let state = observe_unit(unit)?;
            if state.active_state == "active"
                || !matches!(state.unit_file_state.as_str(), "masked" | "masked-runtime")
            {
                return Err(LockdownError::new(
                    "container_lockdown_failed",
                    "an accepted container unit is not stopped and runtime-masked",
                ));
            }
        }
        for path in [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/run/containerd/containerd.sock",
        ] {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(LockdownError::new(
                    "container_lockdown_failed",
                    "a container runtime socket remains connectable after lockdown",
                ));
            }
        }
        Ok(())
    }

    fn rollback_pre_ready(&mut self) -> Result<bool, LockdownError> {
        let changed = self.containers_masked || self.sudo_relocated;
        if self.containers_masked {
            require_success(
                fixed_command(
                    "/usr/bin/systemctl",
                    &[
                        "unmask",
                        "--runtime",
                        CONTAINER_UNITS[0],
                        CONTAINER_UNITS[1],
                        CONTAINER_UNITS[2],
                    ],
                )?,
                "lockdown_rollback_failed",
                "failed to unmask provisional container state",
            )?;
            require_success(
                fixed_command(
                    "/usr/bin/systemctl",
                    &[
                        "start",
                        "containerd.service",
                        "docker.socket",
                        "docker.service",
                    ],
                )?,
                "lockdown_rollback_failed",
                "failed to restore provisional container state",
            )?;
            self.containers_masked = false;
        }
        if self.sudo_relocated {
            let bytes = read_bounded_policy_file(&self.quarantine_path).map_err(|_| {
                LockdownError::new(
                    "lockdown_rollback_failed",
                    "failed to read bounded provisional sudo policy state",
                )
            })?;
            write_policy_exclusive(
                Path::new(RUNNER_DROP_IN_PATH),
                &bytes,
                self.sudo_mode.unwrap_or(0o440),
                "lockdown_rollback_failed",
                "failed to restore bounded provisional sudo policy state",
            )?;
            fs::remove_file(&self.quarantine_path).map_err(|_| {
                LockdownError::new(
                    "lockdown_rollback_failed",
                    "failed to remove sudo quarantine",
                )
            })?;
            require_success(
                fixed_command("/usr/sbin/visudo", &["--check"])?,
                "lockdown_rollback_failed",
                "restored sudo policy did not validate",
            )?;
            self.sudo_relocated = false;
            self.sudo_mode = None;
        }
        Ok(changed)
    }
}

pub fn run_lockdown_test_service(
    unit_name: &str,
    runtime_root: &Path,
    invocation_id: &str,
    posture: LockdownPosture,
    inject_pre_ready_failure: bool,
) -> Result<LockdownEvidence, LockdownError> {
    validate_test_service_context(unit_name)
        .map_err(|error| LockdownError::new(error.code, error.message))?;
    let runtime = TestRuntimeStore::create(runtime_root, invocation_id)?;
    let control = SystemLockdownControl::new(&runtime.directory);
    LockdownSession::establish_test_only(runtime, posture, control, inject_pre_ready_failure)
        .map(|session| session.evidence)
}

fn verify_fixed_fingerprint() -> Result<(), LockdownError> {
    let accepted = hosted_runner_fingerprint_requirement().accepted;
    if std::env::consts::ARCH != accepted.architecture {
        return Err(unsupported_fingerprint());
    }
    let os_release =
        fs::read_to_string("/etc/os-release").map_err(|_| unsupported_fingerprint())?;
    if !os_release.lines().any(|line| line == "ID=ubuntu")
        || !os_release
            .lines()
            .any(|line| line == "VERSION_ID=\"24.04\"")
    {
        return Err(unsupported_fingerprint());
    }
    for executable in accepted.executable_paths {
        if !fs::metadata(executable)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        {
            return Err(unsupported_fingerprint());
        }
    }
    let groups = fixed_command(
        "/usr/bin/id",
        &["--groups", "--name", accepted.expected_principal],
    )?;
    if !groups.status.success() {
        return Err(unsupported_fingerprint());
    }
    let groups_text = String::from_utf8_lossy(&groups.stdout);
    let observed_groups = groups_text.split_whitespace().collect::<BTreeSet<_>>();
    if observed_groups
        != accepted
            .required_runner_groups
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    {
        return Err(unsupported_fingerprint());
    }
    verify_sudo_sources(&accepted.sudo_policy_sources)?;
    for expected in &accepted.container_units {
        if observe_unit(expected.name)?
            != (UnitObservation {
                load_state: expected.load_state.to_owned(),
                active_state: expected.active_state.to_owned(),
                unit_file_state: expected.unit_file_state.to_owned(),
            })
        {
            return Err(unsupported_fingerprint());
        }
    }
    verify_socket_fingerprint()?;
    let docker = runner_docker_ps()?;
    if !docker.status.success() || !docker.stdout.is_empty() {
        return Err(unsupported_fingerprint());
    }
    Ok(())
}

fn verify_sudo_sources(
    expected: &[crate::hosted_runner::AcceptedSudoPolicySourceV1],
) -> Result<(), LockdownError> {
    let mut observed_drop_ins = Vec::new();
    for entry in fs::read_dir(SUDOERS_DROP_IN_ROOT).map_err(|_| unsupported_fingerprint())? {
        let entry = entry.map_err(|_| unsupported_fingerprint())?;
        if !entry
            .file_type()
            .is_ok_and(|kind| kind.is_file() && !kind.is_symlink())
        {
            return Err(unsupported_fingerprint());
        }
        observed_drop_ins.push(entry.file_name().to_string_lossy().into_owned());
    }
    observed_drop_ins.sort();
    let mut expected_drop_ins = expected
        .iter()
        .filter(|source| source.path_class == "drop_in")
        .map(|source| source.name.to_owned())
        .collect::<Vec<_>>();
    expected_drop_ins.sort();
    if observed_drop_ins != expected_drop_ins {
        return Err(unsupported_fingerprint());
    }
    for source in expected {
        let path = if source.path_class == "main_policy" {
            PathBuf::from(SUDOERS_PATH)
        } else {
            Path::new(SUDOERS_DROP_IN_ROOT).join(source.name)
        };
        if sha256_bounded_file(&path)? != source.sha256 {
            return Err(unsupported_fingerprint());
        }
    }
    Ok(())
}

fn verify_socket_fingerprint() -> Result<(), LockdownError> {
    let accepted = hosted_runner_fingerprint_requirement().accepted;
    for expected in accepted.container_sockets {
        let metadata = fs::metadata(expected.path).map_err(|_| unsupported_fingerprint())?;
        if !expected.present
            || !metadata.file_type().is_socket()
            || metadata.permissions().mode() & 0o777 != 0o660
            || metadata.uid() != 0
        {
            return Err(unsupported_fingerprint());
        }
        let ownership = fixed_command("/usr/bin/stat", &["--format=%U:%G:%a:%F", expected.path])?;
        let expected_ownership = format!(
            "{}:{}:{}:socket\n",
            expected.owner,
            expected.group,
            expected.mode.trim_start_matches('0')
        );
        if !ownership.status.success() || ownership.stdout != expected_ownership.as_bytes() {
            return Err(unsupported_fingerprint());
        }
    }
    Ok(())
}

fn sha256_bounded_file(path: &Path) -> Result<String, LockdownError> {
    let bytes = read_bounded_policy_file(path)?;
    let mut hexadecimal = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut hexadecimal, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(hexadecimal)
}

fn read_bounded_policy_file(path: &Path) -> Result<Vec<u8>, LockdownError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| unsupported_fingerprint())?;
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unsupported_fingerprint())?;
    if bytes.len() as u64 > MAX_POLICY_SOURCE_BYTES {
        return Err(unsupported_fingerprint());
    }
    Ok(bytes)
}

fn write_policy_exclusive(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    code: &'static str,
    message: &'static str,
) -> Result<(), LockdownError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .mode(mode)
        .open(path)
        .map_err(|_| LockdownError::new(code, message))?;
    file.write_all(bytes)
        .map_err(|_| LockdownError::new(code, message))?;
    file.sync_all()
        .map_err(|_| LockdownError::new(code, message))
}

fn runner_sudo_true() -> Result<Output, LockdownError> {
    fixed_command(
        "/usr/bin/sudo",
        &[
            "--non-interactive",
            "--user",
            "runner",
            "--",
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/true",
        ],
    )
}

fn runner_docker_ps() -> Result<Output, LockdownError> {
    fixed_command(
        "/usr/bin/sudo",
        &[
            "--non-interactive",
            "--user",
            "runner",
            "--",
            "/usr/bin/docker",
            "ps",
            "--quiet",
        ],
    )
}

fn observe_unit(name: &str) -> Result<UnitObservation, LockdownError> {
    let output = fixed_command(
        "/usr/bin/systemctl",
        &[
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=UnitFileState",
            name,
        ],
    )?;
    if !output.status.success() {
        return Err(unsupported_fingerprint());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap_or("")
            .to_owned()
    };
    let load_state = value("LoadState=");
    let active_state = value("ActiveState=");
    let unit_file_state = value("UnitFileState=");
    Ok(UnitObservation {
        load_state,
        active_state,
        unit_file_state,
    })
}

fn fixed_command(program: &str, arguments: &[&str]) -> Result<Output, LockdownError> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| unsupported_fingerprint())?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|_| unsupported_fingerprint())?;
                if output.stdout.len() + output.stderr.len() > MAX_COMMAND_OUTPUT_BYTES {
                    return Err(LockdownError::new(
                        "lockdown_command_output_too_large",
                        "fixed lockdown command output exceeded its bound",
                    ));
                }
                return Ok(output);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LockdownError::new(
                    "lockdown_command_timeout",
                    "fixed lockdown command exceeded its deadline",
                ));
            }
            Err(_) => return Err(unsupported_fingerprint()),
        }
    }
}

fn require_success(
    output: Output,
    code: &'static str,
    message: &'static str,
) -> Result<(), LockdownError> {
    if output.status.success() {
        Ok(())
    } else {
        Err(LockdownError::new(code, message))
    }
}

fn unsupported_fingerprint() -> LockdownError {
    LockdownError::new(
        "unsupported_host_fingerprint",
        "host state does not match the reviewed lockdown evidence fingerprint",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_INDEX: AtomicUsize = AtomicUsize::new(0);

    struct FakeControl {
        operations: RefCell<Vec<&'static str>>,
    }

    impl FakeControl {
        fn new() -> Self {
            Self {
                operations: RefCell::new(Vec::new()),
            }
        }
    }

    impl LockdownControl for FakeControl {
        fn verify_supported_host(&mut self) -> Result<(), LockdownError> {
            self.operations.borrow_mut().push("fingerprint");
            Ok(())
        }

        fn verify_sudo_available(&mut self) -> Result<(), LockdownError> {
            self.operations.borrow_mut().push("sudo_available");
            Ok(())
        }

        fn verify_containers_available(&mut self) -> Result<(), LockdownError> {
            self.operations.borrow_mut().push("containers_available");
            Ok(())
        }

        fn disable_sudo(&mut self) -> Result<(), LockdownError> {
            self.operations.borrow_mut().push("disable_sudo");
            Ok(())
        }

        fn disable_containers(&mut self) -> Result<(), LockdownError> {
            self.operations.borrow_mut().push("disable_containers");
            Ok(())
        }

        fn verify_sudo_disabled(&mut self) -> Result<(), LockdownError> {
            self.operations.borrow_mut().push("sudo_disabled");
            Ok(())
        }

        fn verify_containers_disabled(&mut self) -> Result<(), LockdownError> {
            self.operations.borrow_mut().push("containers_disabled");
            Ok(())
        }

        fn rollback_pre_ready(&mut self) -> Result<bool, LockdownError> {
            self.operations.borrow_mut().push("rollback");
            Ok(true)
        }
    }

    fn runtime(invocation: &str) -> TestRuntimeStore {
        let root = PathBuf::from(format!(
            "target/tmp/lockdown-unit-{}",
            TEST_INDEX.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        TestRuntimeStore::create(&root, invocation).unwrap()
    }

    #[test]
    fn standard_block_orders_lockdown_without_emitting_readiness() {
        let session = LockdownSession::establish_test_only(
            runtime("standard-proof"),
            LockdownPosture::StandardBlock,
            FakeControl::new(),
            false,
        )
        .unwrap();
        assert_eq!(
            *session.control_for_test().operations.borrow(),
            vec![
                "fingerprint",
                "sudo_available",
                "containers_available",
                "disable_sudo",
                "disable_containers",
                "sudo_disabled",
                "containers_disabled"
            ]
        );
        assert_eq!(session.evidence.sudo_status, "disabled_verified");
        assert_eq!(session.evidence.container_status, "disabled_verified");
        assert!(!session.runtime.ready.exists());
        fs::remove_dir_all(session.runtime.directory.parent().unwrap()).unwrap();
    }

    #[test]
    fn audit_preserves_controls_and_unsafe_preserve_is_degraded() {
        let audit = LockdownSession::establish_test_only(
            runtime("audit-proof"),
            LockdownPosture::Audit,
            FakeControl::new(),
            false,
        )
        .unwrap();
        assert_eq!(audit.evidence.assurance_status, "audit_observation_only");
        assert_eq!(audit.evidence.sudo_status, "preserved");
        assert_eq!(audit.evidence.container_status, "preserved");

        let degraded = LockdownSession::establish_test_only(
            runtime("unsafe-proof"),
            LockdownPosture::UnsafePreserve,
            FakeControl::new(),
            false,
        )
        .unwrap();
        assert_eq!(
            degraded.evidence.assurance_status,
            "degraded_container_control_preserved"
        );
        assert_eq!(degraded.evidence.sudo_status, "disabled_verified");
        assert_eq!(degraded.evidence.container_status, "preserved_unsafe");
        fs::remove_dir_all(audit.runtime.directory.parent().unwrap()).unwrap();
        fs::remove_dir_all(degraded.runtime.directory.parent().unwrap()).unwrap();
    }

    #[test]
    fn pre_ready_failure_rolls_back_provisional_controls() {
        let runtime = runtime("rollback-proof");
        let report = runtime.report.clone();
        let error = LockdownSession::establish_test_only(
            runtime,
            LockdownPosture::StandardBlock,
            FakeControl::new(),
            true,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "injected_pre_ready_lockdown_failure");
        let serialized = fs::read_to_string(&report).unwrap();
        assert!(serialized.contains("\"rollback_status\":\"rolled_back_pre_ready\""));
        assert!(serialized.contains("\"readiness_status\":\"not_emitted\""));
        fs::remove_dir_all(report.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn policy_source_hashing_refuses_symlinks_and_oversized_inputs() {
        let root = PathBuf::from(format!(
            "target/tmp/lockdown-policy-unit-{}",
            TEST_INDEX.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let policy = root.join("policy");
        fs::write(&policy, b"accepted policy bytes").unwrap();
        assert_eq!(sha256_bounded_file(&policy).unwrap().len(), 64);

        let linked = root.join("linked");
        symlink(fs::canonicalize(&policy).unwrap(), &linked).unwrap();
        assert_eq!(
            sha256_bounded_file(&linked).unwrap_err().code,
            "unsupported_host_fingerprint"
        );

        let oversized = root.join("oversized");
        fs::write(&oversized, vec![b'x'; MAX_POLICY_SOURCE_BYTES as usize + 1]).unwrap();
        assert_eq!(
            sha256_bounded_file(&oversized).unwrap_err().code,
            "unsupported_host_fingerprint"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
