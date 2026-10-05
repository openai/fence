use crate::hosted_runner::{
    AcceptedHostedRunnerFactsV3, AcceptedPermissionAncestorV2, AcceptedTrustedExecutableV2,
    hosted_runner_fingerprint_requirement, reviewed_ubuntu_os_release,
};
use crate::lifecycle::validate_test_service_context;
use crate::local_control::{
    NoCurrentFenceOwner, OBSERVATION_TIMEOUT, PinnedCurrentFenceOwner, SOCKET_PROBE_TIMEOUT,
    SystemUnixSocketAccess, observe_local_control_inventory,
    verify_reviewed_local_control_observation,
};
use crate::runtime::{RuntimeError, TestRuntimeStore};
use crate::trusted_executable::{TrustedExecutable, TrustedExecutableSet};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const LOCKDOWN_EVIDENCE_STATUS: &str = "lockdown_evidence_test_only";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const CONTAINER_RESTART_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_COMMAND_OUTPUT_BYTES: usize = 8 * 1024;
const MAX_POLICY_SOURCE_BYTES: u64 = 256 * 1024;
const MAX_SUDO_POLICY_SOURCES: usize = 64;
const SUDOERS_PATH: &str = "/etc/sudoers";
const SUDOERS_DROP_IN_ROOT: &str = "/etc/sudoers.d";
const RESTORED_SUDO_VISUDO_ARGUMENTS: [&str; 3] = ["--check", "--file", SUDOERS_PATH];
const RUNNER_SUDO_VALIDATION_ARGUMENTS: [&str; 3] =
    ["--non-interactive", "--reset-timestamp", "--validate"];
const RUNNER_SUDO_POLICY_LIST_ARGUMENTS: [&str; 4] =
    ["--non-interactive", "--list", "--other-user", "runner"];
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_error_code: Option<&'static str>,
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

#[derive(Debug, Clone, Eq, PartialEq)]
struct SudoPolicySourcePin {
    path_class: &'static str,
    name: String,
    mode: u32,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
    sha256: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ReviewedPathKind {
    RegularFile,
    Directory,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ReviewedPathIdentity {
    mode: u32,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
    kind: ReviewedPathKind,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RunnerAccessProbe {
    NotWritable,
    Executable,
    NotExecutable,
}

impl RunnerAccessProbe {
    fn arguments(self, path: &str) -> Vec<&str> {
        match self {
            Self::NotWritable => vec!["!", "-w", path],
            Self::Executable => vec!["-x", path],
            Self::NotExecutable => vec!["!", "-x", path],
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RunnerProbeTarget<'a> {
    TrustedExecutable(&'a AcceptedTrustedExecutableV2),
    PermissionAncestor(&'a AcceptedPermissionAncestorV2),
}

impl RunnerProbeTarget<'_> {
    fn path(self) -> &'static str {
        match self {
            Self::TrustedExecutable(expected) => expected.path,
            Self::PermissionAncestor(expected) => expected.path,
        }
    }

    fn observe(self) -> Result<RunnerProbeIdentity, LockdownError> {
        match self {
            Self::TrustedExecutable(expected) => observe_reviewed_path(
                Path::new(expected.path),
                expected.canonical_target,
                expected.mode,
                ReviewedPathKind::RegularFile,
            )
            .map(RunnerProbeIdentity::Path),
            Self::PermissionAncestor(expected) => observe_reviewed_path(
                Path::new(expected.path),
                expected.canonical_target,
                expected.mode,
                ReviewedPathKind::Directory,
            )
            .map(RunnerProbeIdentity::Path),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RunnerAccessProbeSpec<'a> {
    target: RunnerProbeTarget<'a>,
    probe: RunnerAccessProbe,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum RunnerProbeIdentity {
    Path(ReviewedPathIdentity),
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
    fn commit_no_restore(&mut self);
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
        control.commit_no_restore();
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
        Err(error) => {
            evidence.rollback_error_code = Some(error.code);
            "rollback_failed"
        }
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
    match posture {
        LockdownPosture::Audit => {
            match control.verify_containers_available() {
                Ok(()) => {}
                Err(error) if error.code == "container_shape_unsupported" => {}
                Err(error) => return Err(error),
            }
            evidence.sudo_status = "preserved";
            evidence.container_status = "preserved";
        }
        LockdownPosture::UnsafePreserve => {
            control.verify_containers_available()?;
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
        rollback_error_code: None,
        readiness_status: "not_emitted",
        protection_available: false,
        limitations,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct SudoRollbackSource {
    name: String,
    bytes: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
    sha256: String,
}

#[derive(Debug)]
enum SudoRollbackState {
    Unchanged,
    RollbackAvailable(Vec<SudoRollbackSource>),
    CommittedNoRestore,
}

pub struct SystemLockdownControl {
    executables: Arc<TrustedExecutableSet>,
    sudo_rollback: SudoRollbackState,
    sudo_source_pins: Option<Vec<SudoPolicySourcePin>>,
    removed_sudo_source_names: Vec<String>,
    containers_masked: bool,
}

impl SystemLockdownControl {
    pub(crate) fn new(executables: Arc<TrustedExecutableSet>) -> Self {
        Self {
            executables,
            sudo_rollback: SudoRollbackState::Unchanged,
            sudo_source_pins: None,
            removed_sudo_source_names: Vec::new(),
            containers_masked: false,
        }
    }
}

impl LockdownControl for SystemLockdownControl {
    fn verify_supported_host(&mut self) -> Result<(), LockdownError> {
        let executables = &self.executables;
        executables
            .verify_all()
            .map_err(|_| unsupported_fingerprint())?;
        self.sudo_source_pins = Some(verify_host_capabilities(executables)?);
        Ok(())
    }

    fn verify_sudo_available(&mut self) -> Result<(), LockdownError> {
        let executables = &self.executables;
        executables
            .verify_all()
            .map_err(|_| unsupported_fingerprint())?;
        self.verify_sudo_baseline()?;
        let sudo_available = runner_sudo_validate(executables)?.status.success();
        let root_can_list_policy = fixed_command(
            executables,
            TrustedExecutable::Sudo,
            &RUNNER_SUDO_POLICY_LIST_ARGUMENTS,
        )?
        .status
        .success();
        self.verify_sudo_baseline()?;
        if sudo_available && root_can_list_policy {
            Ok(())
        } else {
            Err(LockdownError::new(
                "sudo_shape_unsupported",
                "the accepted runner passwordless sudo path is unavailable",
            ))
        }
    }

    fn verify_containers_available(&mut self) -> Result<(), LockdownError> {
        let executables = &self.executables;
        executables
            .verify_all()
            .map_err(|_| unsupported_fingerprint())?;
        if runner_docker_available(executables)? {
            Ok(())
        } else {
            Err(LockdownError::new(
                "container_shape_unsupported",
                "the accepted runner Docker control path is unavailable",
            ))
        }
    }

    fn disable_sudo(&mut self) -> Result<(), LockdownError> {
        if !matches!(self.sudo_rollback, SudoRollbackState::Unchanged) {
            return Err(LockdownError::new(
                "sudo_lockdown_failed",
                "sudo lockdown state does not permit another disable operation",
            ));
        }
        let source_pins = self
            .sudo_source_pins
            .as_ref()
            .ok_or_else(unsupported_fingerprint)?;
        let source_names = discover_runner_sudo_source_names(&self.executables, source_pins)?;
        if source_names.is_empty() {
            return Err(unsupported_fingerprint());
        }
        for name in source_names {
            let source = capture_runner_sudo_source(&name)?;
            let source_pin = source_pins
                .iter()
                .find(|pin| pin.path_class == "drop_in" && pin.name == name)
                .ok_or_else(unsupported_fingerprint)?;
            if !rollback_source_matches_pin(&source, source_pin) {
                return Err(unsupported_fingerprint());
            }
            remove_captured_runner_sudo_source(&source)?;
            self.removed_sudo_source_names.push(name);
            match &mut self.sudo_rollback {
                SudoRollbackState::Unchanged => {
                    self.sudo_rollback = SudoRollbackState::RollbackAvailable(vec![source]);
                }
                SudoRollbackState::RollbackAvailable(sources) => sources.push(source),
                SudoRollbackState::CommittedNoRestore => unreachable!("checked above"),
            }
        }
        require_success(
            fixed_command(&self.executables, TrustedExecutable::Visudo, &["--check"])?,
            "sudo_lockdown_failed",
            "sudo policy did not validate after removing the accepted runner source",
        )
    }

    fn disable_containers(&mut self) -> Result<(), LockdownError> {
        if !runner_docker_available(&self.executables)? {
            return Ok(());
        }
        self.containers_masked = true;
        require_success(
            fixed_command(
                &self.executables,
                TrustedExecutable::Systemctl,
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
        let executables = &self.executables;
        executables
            .verify_all()
            .map_err(|_| unsupported_fingerprint())?;
        let source_pins = self
            .sudo_source_pins
            .as_deref()
            .ok_or_else(unsupported_fingerprint)?;
        verify_locked_sudo_sources(executables, source_pins, &self.removed_sudo_source_names)?;
        let sudo_available = runner_sudo_validate(executables)?.status.success();
        let policy_listing = fixed_command(
            executables,
            TrustedExecutable::Sudo,
            &RUNNER_SUDO_POLICY_LIST_ARGUMENTS,
        )?;
        verify_locked_sudo_sources(executables, source_pins, &self.removed_sudo_source_names)?;
        if !sudo_privileges_disabled(sudo_available, &policy_listing) {
            Err(LockdownError::new(
                "sudo_lockdown_failed",
                "runner retains sudo privileges after lockdown",
            ))
        } else {
            Ok(())
        }
    }

    fn verify_containers_disabled(&mut self) -> Result<(), LockdownError> {
        let executables = &self.executables;
        executables
            .verify_all()
            .map_err(|_| unsupported_fingerprint())?;
        let docker_available = if self.containers_masked {
            if executables.contains(TrustedExecutable::Docker) {
                let output = runner_docker_ps(executables)?;
                if output.status.code().is_none() {
                    return Err(unsupported_fingerprint());
                }
                output.status.success()
            } else {
                false
            }
        } else {
            runner_docker_available(executables)?
        };
        if docker_available {
            return Err(LockdownError::new(
                "container_lockdown_failed",
                "runner Docker access remains usable after lockdown",
            ));
        }
        for unit in CONTAINER_UNITS {
            let state = observe_unit(executables, unit)?;
            if state.active_state == "active"
                || self.containers_masked
                    && !matches!(state.unit_file_state.as_str(), "masked" | "masked-runtime")
            {
                return Err(LockdownError::new(
                    "container_lockdown_failed",
                    "an accepted container unit remains active or was not runtime-masked",
                ));
            }
        }
        verify_container_sockets_unavailable(executables)
    }

    fn commit_no_restore(&mut self) {
        commit_no_restore_state(&mut self.sudo_rollback);
    }

    fn rollback_pre_ready(&mut self) -> Result<bool, LockdownError> {
        let executables = Arc::clone(&self.executables);
        let sudo_executables = Arc::clone(&executables);
        rollback_pre_ready_components(
            &mut self.sudo_rollback,
            &mut self.containers_masked,
            move |sources| {
                for source in sources {
                    restore_runner_sudo_source(&sudo_executables, source)?;
                }
                Ok(())
            },
            move || restore_container_controls(&executables),
        )
    }
}

impl SystemLockdownControl {
    fn verify_sudo_baseline(&self) -> Result<(), LockdownError> {
        let expected = self
            .sudo_source_pins
            .as_deref()
            .ok_or_else(unsupported_fingerprint)?;
        let observed = capture_sudo_sources(&self.executables)?;
        if observed == expected {
            Ok(())
        } else {
            Err(unsupported_fingerprint())
        }
    }
}

fn commit_no_restore_state(sudo_rollback: &mut SudoRollbackState) {
    *sudo_rollback = SudoRollbackState::CommittedNoRestore;
}

fn rollback_pre_ready_components<RestoreSudo, RestoreContainers>(
    sudo_rollback: &mut SudoRollbackState,
    containers_masked: &mut bool,
    mut restore_sudo: RestoreSudo,
    mut restore_containers: RestoreContainers,
) -> Result<bool, LockdownError>
where
    RestoreSudo: FnMut(&[SudoRollbackSource]) -> Result<(), LockdownError>,
    RestoreContainers: FnMut() -> Result<(), LockdownError>,
{
    if matches!(sudo_rollback, SudoRollbackState::CommittedNoRestore) {
        return Err(LockdownError::new(
            "lockdown_rollback_after_commit",
            "lockdown controls cannot be restored after the success boundary",
        ));
    }

    let sudo_restore_required = matches!(sudo_rollback, SudoRollbackState::RollbackAvailable(_));
    let container_restore_required = *containers_masked;
    let changed = sudo_restore_required || container_restore_required;

    let sudo_result = match sudo_rollback {
        SudoRollbackState::RollbackAvailable(sources) => restore_sudo(sources),
        SudoRollbackState::Unchanged => Ok(()),
        SudoRollbackState::CommittedNoRestore => unreachable!("checked above"),
    };
    if sudo_restore_required && sudo_result.is_ok() {
        *sudo_rollback = SudoRollbackState::Unchanged;
    }

    let container_result = if container_restore_required {
        restore_containers()
    } else {
        Ok(())
    };
    if container_restore_required && container_result.is_ok() {
        *containers_masked = false;
    }

    match (sudo_result, container_result) {
        (Ok(()), Ok(())) => Ok(changed),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(sudo_error), Err(container_error)) => Err(LockdownError::new(
            "lockdown_rollback_failed",
            format!(
                "sudo rollback failed with {}; container rollback failed with {}",
                sudo_error.code, container_error.code
            ),
        )),
    }
}

fn restore_container_controls(executables: &TrustedExecutableSet) -> Result<(), LockdownError> {
    require_success(
        fixed_command(
            executables,
            TrustedExecutable::Systemctl,
            &[
                "unmask",
                "--runtime",
                CONTAINER_UNITS[0],
                CONTAINER_UNITS[1],
                CONTAINER_UNITS[2],
            ],
        )?,
        "container_unmask_rollback_failed",
        "failed to unmask provisional container state",
    )?;
    require_success(
        fixed_command_with_timeout(
            executables,
            TrustedExecutable::Systemctl,
            &[
                "start",
                "containerd.service",
                "docker.socket",
                "docker.service",
            ],
            CONTAINER_RESTART_TIMEOUT,
        )
        .map_err(|_| {
            LockdownError::new(
                "container_restart_rollback_failed",
                "bounded container restoration command could not complete",
            )
        })?,
        "container_restart_rollback_failed",
        "failed to restore provisional container state",
    )
}

pub fn run_lockdown_test_service(
    unit_name: &str,
    runtime_root: &Path,
    invocation_id: &str,
    posture: LockdownPosture,
    inject_pre_ready_failure: bool,
) -> Result<LockdownEvidence, LockdownError> {
    let executables = Arc::new(
        TrustedExecutableSet::capture_reviewed_hosted()
            .map_err(|error| LockdownError::new(error.code, error.message))?,
    );
    validate_test_service_context(unit_name, &executables)
        .map_err(|error| LockdownError::new(error.code, error.message))?;
    verify_test_local_control_inventory(&executables)?;
    let runtime = TestRuntimeStore::create(runtime_root, invocation_id)?;
    let control = SystemLockdownControl::new(executables);
    LockdownSession::establish_test_only(runtime, posture, control, inject_pre_ready_failure)
        .map(|session| session.evidence)
}

#[doc(hidden)]
pub fn run_lockdown_acl_rejection_test_service(
    unit_name: &str,
    fixture: &Path,
) -> Result<(), LockdownError> {
    let executables = TrustedExecutableSet::capture_reviewed_hosted()
        .map_err(|error| LockdownError::new(error.code, error.message))?;
    validate_test_service_context(unit_name, &executables)
        .map_err(|error| LockdownError::new(error.code, error.message))?;
    let canonical = fixture
        .to_str()
        .filter(|path| Path::new(path) == fixture)
        .ok_or_else(unsupported_fingerprint)?;
    let expected = observe_reviewed_path(fixture, canonical, "0750", ReviewedPathKind::Directory)?;
    verify_identity_bound_probe(
        &expected,
        || observe_reviewed_path(fixture, canonical, "0750", ReviewedPathKind::Directory),
        |probe| run_runner_access_probe(&executables, probe, canonical),
        RunnerAccessProbe::NotExecutable,
    )
}

fn verify_test_local_control_inventory(
    executables: &TrustedExecutableSet,
) -> Result<(), LockdownError> {
    let deadline = Instant::now() + OBSERVATION_TIMEOUT;
    let socket_access = SystemUnixSocketAccess::new(|path: &OsStr| {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let timeout = remaining.min(SOCKET_PROBE_TIMEOUT);
        if timeout.is_zero() {
            None
        } else {
            runner_path_writable(executables, path, timeout).ok()
        }
    });
    let observed =
        observe_local_control_inventory(Path::new("/proc"), &socket_access, &NoCurrentFenceOwner);
    verify_reviewed_local_control_observation(
        &hosted_runner_fingerprint_requirement()
            .accepted
            .local_control_inventory,
        &observed,
    )
    .map_err(|error| LockdownError::new(error.code, error.message))
}

fn runner_access_probe_plan<'a>(
    accepted: &'a AcceptedHostedRunnerFactsV3,
    docker_present: bool,
) -> Vec<RunnerAccessProbeSpec<'a>> {
    let mut plan = Vec::with_capacity(
        accepted.trusted_executables.len() * 2 + accepted.permission_ancestor_directories.len() * 2,
    );
    for executable in &accepted.trusted_executables {
        if executable.path == TrustedExecutable::Docker.path() && !docker_present {
            continue;
        }
        let target = RunnerProbeTarget::TrustedExecutable(executable);
        plan.push(RunnerAccessProbeSpec {
            target,
            probe: RunnerAccessProbe::NotWritable,
        });
        plan.push(RunnerAccessProbeSpec {
            target,
            probe: RunnerAccessProbe::Executable,
        });
    }
    for ancestor in &accepted.permission_ancestor_directories {
        let target = RunnerProbeTarget::PermissionAncestor(ancestor);
        plan.push(RunnerAccessProbeSpec {
            target,
            probe: RunnerAccessProbe::NotWritable,
        });
        plan.push(RunnerAccessProbeSpec {
            target,
            probe: if ancestor.runner_searchable {
                RunnerAccessProbe::Executable
            } else {
                RunnerAccessProbe::NotExecutable
            },
        });
    }
    plan
}

fn collect_runner_probe_baselines<'a>(
    plan: &[RunnerAccessProbeSpec<'a>],
) -> Result<BTreeMap<&'static str, RunnerProbeIdentity>, LockdownError> {
    let mut baselines = BTreeMap::new();
    for spec in plan {
        let path = spec.target.path();
        let observed = spec.target.observe()?;
        if let Some(baseline) = baselines.get(path) {
            if baseline != &observed {
                return Err(unsupported_fingerprint());
            }
        } else {
            baselines.insert(path, observed);
        }
    }
    let expected_target_count = plan
        .iter()
        .map(|spec| spec.target.path())
        .collect::<BTreeSet<_>>()
        .len();
    if baselines.len() != expected_target_count {
        return Err(unsupported_fingerprint());
    }
    Ok(baselines)
}

fn verify_runner_access_probes(
    executables: &TrustedExecutableSet,
    accepted: &AcceptedHostedRunnerFactsV3,
) -> Result<(), LockdownError> {
    let plan = runner_access_probe_plan(accepted, executables.contains(TrustedExecutable::Docker));
    let baselines = collect_runner_probe_baselines(&plan)?;
    for spec in plan {
        let expected = baselines
            .get(spec.target.path())
            .ok_or_else(unsupported_fingerprint)?;
        verify_identity_bound_probe(
            expected,
            || spec.target.observe(),
            |probe| run_runner_access_probe(executables, probe, spec.target.path()),
            spec.probe,
        )?;
    }
    Ok(())
}

fn verify_identity_bound_probe<Identity, Observe, Probe>(
    expected: &Identity,
    mut observe: Observe,
    mut run_probe: Probe,
    probe: RunnerAccessProbe,
) -> Result<(), LockdownError>
where
    Identity: Eq,
    Observe: FnMut() -> Result<Identity, LockdownError>,
    Probe: FnMut(RunnerAccessProbe) -> Result<bool, LockdownError>,
{
    if &observe()? != expected {
        return Err(unsupported_fingerprint());
    }
    if !run_probe(probe)? {
        return Err(unsupported_fingerprint());
    }
    if &observe()? != expected {
        return Err(unsupported_fingerprint());
    }
    Ok(())
}

fn run_runner_access_probe(
    executables: &TrustedExecutableSet,
    probe: RunnerAccessProbe,
    path: &str,
) -> Result<bool, LockdownError> {
    let arguments = probe.arguments(path);
    runner_command(executables, TrustedExecutable::Test, &arguments)
        .map(|output| output.status.success())
}

fn observe_reviewed_path(
    path: &Path,
    canonical_target: &str,
    expected_mode: &str,
    kind: ReviewedPathKind,
) -> Result<ReviewedPathIdentity, LockdownError> {
    let mode = parse_reviewed_mode(expected_mode)?;
    if !path.is_absolute()
        || path.to_str() != Some(canonical_target)
        || fs::canonicalize(path).ok().as_deref() != Some(Path::new(canonical_target))
    {
        return Err(unsupported_fingerprint());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| unsupported_fingerprint())?;
    let kind_matches = match kind {
        ReviewedPathKind::RegularFile => metadata.file_type().is_file(),
        ReviewedPathKind::Directory => metadata.file_type().is_dir(),
    };
    if !kind_matches
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Err(unsupported_fingerprint());
    }
    Ok(ReviewedPathIdentity {
        mode,
        uid: metadata.uid(),
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        kind,
    })
}

fn parse_reviewed_mode(value: &str) -> Result<u32, LockdownError> {
    let mode = u32::from_str_radix(value, 8).map_err(|_| unsupported_fingerprint())?;
    if format!("{mode:04o}") != value || mode & !0o7777 != 0 {
        return Err(unsupported_fingerprint());
    }
    Ok(mode)
}

fn verify_host_identity(accepted: &AcceptedHostedRunnerFactsV3) -> Result<(), LockdownError> {
    if std::env::consts::ARCH != accepted.architecture {
        return Err(unsupported_fingerprint());
    }
    let os_release =
        fs::read_to_string("/etc/os-release").map_err(|_| unsupported_fingerprint())?;
    if accepted.os_id != "ubuntu" || !reviewed_ubuntu_os_release(&os_release) {
        return Err(unsupported_fingerprint());
    }
    Ok(())
}

fn verify_runner_identity(
    executables: &TrustedExecutableSet,
    accepted: &AcceptedHostedRunnerFactsV3,
) -> Result<(), LockdownError> {
    let username = fixed_command(
        executables,
        TrustedExecutable::Id,
        &["--user", "--name", accepted.expected_principal],
    )?;
    let uid = fixed_command(
        executables,
        TrustedExecutable::Id,
        &["--user", accepted.expected_principal],
    )?;
    let expected_username = format!("{}\n", accepted.expected_principal);
    let valid_uid = std::str::from_utf8(&uid.stdout)
        .ok()
        .and_then(|value| value.trim_end_matches('\n').parse::<u32>().ok())
        .is_some_and(|value| value != 0);
    if !username.status.success()
        || username.stdout != expected_username.as_bytes()
        || !uid.status.success()
        || !valid_uid
    {
        return Err(unsupported_fingerprint());
    }
    Ok(())
}

fn verify_host_capabilities(
    executables: &TrustedExecutableSet,
) -> Result<Vec<SudoPolicySourcePin>, LockdownError> {
    let accepted = hosted_runner_fingerprint_requirement().accepted;
    verify_host_identity(&accepted)?;
    executables
        .verify_all()
        .map_err(|_| unsupported_fingerprint())?;
    verify_runner_identity(executables, &accepted)?;
    let docker_available = runner_docker_available(executables)?;
    if docker_available {
        let workloads = runner_docker_ps(executables)?;
        if !workloads.status.success() || !workloads.stdout.is_empty() {
            return Err(unsupported_fingerprint());
        }
    }
    verify_reviewed_runner_groups(executables, &accepted, docker_available)?;
    verify_runner_access_probes(executables, &accepted)?;
    let sudo_source_pins = capture_sudo_sources(executables).map_err(unsupported_sudo_policy)?;
    if discover_runner_sudo_source_names(executables, &sudo_source_pins)
        .map_err(unsupported_sudo_policy)?
        .is_empty()
    {
        return Err(unsupported_sudo_policy(unsupported_fingerprint()));
    }
    let sudo_syntax = fixed_command(
        executables,
        TrustedExecutable::Visudo,
        &RESTORED_SUDO_VISUDO_ARGUMENTS,
    )?;
    if !sudo_syntax.status.success() {
        return Err(unsupported_sudo_policy(unsupported_fingerprint()));
    }
    if capture_sudo_sources(executables).map_err(unsupported_sudo_policy)? != sudo_source_pins {
        return Err(unsupported_sudo_policy(unsupported_fingerprint()));
    }
    Ok(sudo_source_pins)
}

fn verify_reviewed_runner_groups(
    executables: &TrustedExecutableSet,
    accepted: &AcceptedHostedRunnerFactsV3,
    docker_available: bool,
) -> Result<(), LockdownError> {
    let groups = fixed_command(
        executables,
        TrustedExecutable::Id,
        &["--groups", "--name", accepted.expected_principal],
    )?;
    if !groups.status.success() {
        return Err(unsupported_runner_groups());
    }
    let groups_text =
        std::str::from_utf8(&groups.stdout).map_err(|_| unsupported_runner_groups())?;
    let observed = groups_text.split_whitespace().collect::<BTreeSet<_>>();
    let reviewed = accepted
        .required_runner_groups
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if !observed.contains("runner")
        || docker_available && !observed.contains("docker")
        || !observed.is_subset(&reviewed)
    {
        return Err(unsupported_runner_groups());
    }
    Ok(())
}

fn capture_sudo_sources(
    executables: &TrustedExecutableSet,
) -> Result<Vec<SudoPolicySourcePin>, LockdownError> {
    capture_sudo_sources_at(
        Path::new(SUDOERS_PATH),
        Path::new(SUDOERS_DROP_IN_ROOT),
        |path| run_runner_access_probe(executables, RunnerAccessProbe::NotWritable, path),
    )
}

fn capture_sudo_sources_at<Probe>(
    main_policy: &Path,
    drop_in_root: &Path,
    mut runner_cannot_write: Probe,
) -> Result<Vec<SudoPolicySourcePin>, LockdownError>
where
    Probe: FnMut(&str) -> Result<bool, LockdownError>,
{
    let root = fs::symlink_metadata(drop_in_root).map_err(|_| unsupported_fingerprint())?;
    if !root.file_type().is_dir()
        || root.uid() != 0
        || root.gid() != 0
        || root.permissions().mode() & 0o022 != 0
        || fs::canonicalize(drop_in_root).ok().as_deref() != Some(drop_in_root)
    {
        return Err(unsupported_fingerprint());
    }
    let root_path = drop_in_root.to_str().ok_or_else(unsupported_fingerprint)?;
    if !runner_cannot_write(root_path)? {
        return Err(unsupported_fingerprint());
    }

    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(drop_in_root)
        .map_err(|_| unsupported_fingerprint())?
        .enumerate()
    {
        if index >= MAX_SUDO_POLICY_SOURCES * 2 {
            return Err(unsupported_fingerprint());
        }
        let entry = entry.map_err(|_| unsupported_fingerprint())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| unsupported_fingerprint())?;
        if !active_sudo_drop_in(&name) {
            continue;
        }
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !entry
                .file_type()
                .is_ok_and(|kind| kind.is_file() && !kind.is_symlink())
        {
            return Err(unsupported_fingerprint());
        }
        paths.push((name, entry.path()));
        if paths.len() >= MAX_SUDO_POLICY_SOURCES {
            return Err(unsupported_fingerprint());
        }
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0));

    let mut pins = Vec::with_capacity(paths.len() + 2);
    pins.push(SudoPolicySourcePin {
        path_class: "drop_in_root",
        name: "sudoers.d".to_owned(),
        mode: root.permissions().mode() & 0o7777,
        uid: root.uid(),
        gid: root.gid(),
        device: root.dev(),
        inode: root.ino(),
        sha256: String::new(),
    });
    pins.push(capture_dynamic_sudo_policy_source(
        main_policy,
        "main_policy",
        "sudoers",
        true,
        &mut runner_cannot_write,
    )?);
    for (name, path) in paths {
        pins.push(capture_dynamic_sudo_policy_source(
            &path,
            "drop_in",
            &name,
            false,
            &mut runner_cannot_write,
        )?);
    }
    let final_root = fs::symlink_metadata(drop_in_root).map_err(|_| unsupported_fingerprint())?;
    if !final_root.file_type().is_dir()
        || final_root.uid() != root.uid()
        || final_root.gid() != root.gid()
        || final_root.permissions().mode() & 0o7777 != root.permissions().mode() & 0o7777
        || final_root.dev() != root.dev()
        || final_root.ino() != root.ino()
    {
        return Err(unsupported_fingerprint());
    }
    Ok(pins)
}

fn active_sudo_drop_in(name: &str) -> bool {
    !name.contains('.') && !name.ends_with('~')
}

fn capture_dynamic_sudo_policy_source<Probe>(
    path: &Path,
    path_class: &'static str,
    name: &str,
    allow_drop_in_directory_include: bool,
    runner_cannot_write: &mut Probe,
) -> Result<SudoPolicySourcePin, LockdownError>
where
    Probe: FnMut(&str) -> Result<bool, LockdownError>,
{
    let (bytes, metadata) = read_bounded_policy_file_with_metadata(path)?;
    let path_text = path.to_str().ok_or_else(unsupported_fingerprint)?;
    if fs::canonicalize(path).ok().as_deref() != Some(path)
        || !policy_source_metadata_is_safe(&metadata)
        || !sudo_includes_are_bounded(&bytes, allow_drop_in_directory_include)
        || !sudo_authentication_defaults_are_safe(&bytes)
    {
        return Err(unsupported_fingerprint());
    }
    if !runner_cannot_write(path_text)? {
        return Err(unsupported_fingerprint());
    }
    Ok(SudoPolicySourcePin {
        path_class,
        name: name.to_owned(),
        mode: metadata.permissions().mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        sha256: sha256_bytes(&bytes),
    })
}

fn sudo_includes_are_bounded(bytes: &[u8], allow_drop_in_directory_include: bool) -> bool {
    bytes.split(|byte| *byte == b'\n').all(|line| {
        let Some(trimmed) = effective_sudo_policy_line(line) else {
            return false;
        };
        if !(trimmed.starts_with(b"#include") || trimmed.starts_with(b"@include")) {
            return true;
        }
        let tokens = trimmed
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|token| !token.is_empty())
            .collect::<Vec<_>>();
        allow_drop_in_directory_include
            && tokens.len() == 2
            && matches!(tokens[0], b"#includedir" | b"@includedir")
            && tokens[1] == SUDOERS_DROP_IN_ROOT.as_bytes()
    })
}

fn sudo_authentication_defaults_are_safe(bytes: &[u8]) -> bool {
    bytes.split(|byte| *byte == b'\n').all(|line| {
        let Some(line) = effective_sudo_policy_line(line) else {
            return false;
        };
        let Some((directive, settings)) = line
            .iter()
            .position(u8::is_ascii_whitespace)
            .map(|index| (&line[..index], &line[index + 1..]))
        else {
            return !line.starts_with(b"Defaults");
        };
        if !directive.starts_with(b"Defaults") {
            return true;
        }
        let mut quoted = false;
        let mut start = 0;
        for (index, byte) in settings.iter().copied().enumerate() {
            if byte == b'"' {
                quoted = !quoted;
            }
            if byte == b',' && !quoted {
                if forbidden_sudo_authentication_setting(&settings[start..index]) {
                    return false;
                }
                start = index + 1;
            }
        }
        !quoted && !forbidden_sudo_authentication_setting(&settings[start..])
    })
}

fn effective_sudo_policy_line(line: &[u8]) -> Option<&[u8]> {
    let line = trim_ascii_whitespace(line);
    if line.starts_with(b"#")
        && !line.starts_with(b"#include")
        && line.get(1).is_none_or(|byte| !byte.is_ascii_digit())
    {
        let keyword = line
            .split(|byte| byte.is_ascii_whitespace())
            .next()
            .unwrap_or_default();
        let unescaped = keyword
            .iter()
            .copied()
            .filter(|byte| *byte != b'\\')
            .collect::<Vec<_>>();
        if unescaped.starts_with(b"#include")
            || keyword.ends_with(b"\\") && b"#include".starts_with(&unescaped)
        {
            return None;
        }
        return Some(&[]);
    }

    let mut quoted = false;
    for (index, byte) in line.iter().copied().enumerate() {
        match byte {
            b'\\' => return None,
            b'"' => quoted = !quoted,
            b'#' if !quoted
                && index != 0
                && line
                    .get(index + 1)
                    .is_none_or(|next| !next.is_ascii_digit()) =>
            {
                return Some(trim_ascii_whitespace(&line[..index]));
            }
            _ => {}
        }
    }
    (!quoted).then_some(line)
}

fn forbidden_sudo_authentication_setting(option: &[u8]) -> bool {
    let option = trim_ascii_whitespace(option);
    let option = option.strip_prefix(b"!").unwrap_or(option);
    let name_end = option
        .iter()
        .position(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        .unwrap_or(option.len());
    matches!(
        &option[..name_end],
        b"root_sudo"
            | b"verifypw"
            | b"listpw"
            | b"rootpw"
            | b"targetpw"
            | b"runaspw"
            | b"authenticate"
    )
}

#[cfg(test)]
fn reviewed_runner_sudo_policy(bytes: &[u8]) -> bool {
    reviewed_runner_sudo_policy_for_principals(bytes, &["runner".to_owned()])
}

fn reviewed_runner_sudo_policy_for_principals(bytes: &[u8], principals: &[String]) -> bool {
    let mut effective = None;
    for raw in bytes.split(|byte| *byte == b'\n') {
        let Some(line) = effective_sudo_policy_line(raw) else {
            return false;
        };
        if line.starts_with(b"Defaults")
            && line.get(b"Defaults".len()).is_some_and(|separator| {
                separator.is_ascii_whitespace() || matches!(separator, b':' | b'@' | b'>' | b'!')
            })
        {
            if !sudo_authentication_defaults_are_safe(line) {
                return false;
            }
            continue;
        }
        if !line.is_empty() && effective.replace(line).is_some() {
            return false;
        }
    }
    let Some(line) = effective else {
        return false;
    };
    let fields = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let Some(principal) = fields.first() else {
        return false;
    };
    let policy = fields[1..].concat();
    principals
        .iter()
        .any(|candidate| principal == &candidate.as_bytes())
        && matches!(
            policy.as_slice(),
            b"ALL=(ALL)NOPASSWD:ALL" | b"ALL=(ALL:ALL)NOPASSWD:ALL"
        )
}

fn discover_runner_sudo_source_names(
    executables: &TrustedExecutableSet,
    pins: &[SudoPolicySourcePin],
) -> Result<Vec<String>, LockdownError> {
    let groups = fixed_command(
        executables,
        TrustedExecutable::Id,
        &["--groups", "--name", "runner"],
    )?;
    let uid = fixed_command(executables, TrustedExecutable::Id, &["--user", "runner"])?;
    if !groups.status.success() || !uid.status.success() {
        return Err(unsupported_fingerprint());
    }
    let group_names = std::str::from_utf8(&groups.stdout).map_err(|_| unsupported_fingerprint())?;
    let uid = std::str::from_utf8(&uid.stdout)
        .ok()
        .and_then(|value| value.trim_end_matches('\n').parse::<u32>().ok())
        .filter(|uid| *uid != 0)
        .ok_or_else(unsupported_fingerprint)?;
    let mut principals = vec!["runner".to_owned(), format!("#{uid}")];
    principals.extend(
        group_names
            .split_whitespace()
            .map(|group| format!("%{group}")),
    );

    let mut matches = Vec::new();
    for pin in pins.iter().filter(|pin| pin.path_class == "drop_in") {
        let path = sudo_drop_in_path(&pin.name)?;
        let (bytes, metadata) = read_bounded_policy_file_with_metadata(&path)?;
        if metadata.dev() != pin.device
            || metadata.ino() != pin.inode
            || metadata.uid() != pin.uid
            || metadata.gid() != pin.gid
            || metadata.permissions().mode() & 0o7777 != pin.mode
            || sha256_bytes(&bytes) != pin.sha256
        {
            return Err(unsupported_fingerprint());
        }
        if reviewed_runner_sudo_policy_for_principals(&bytes, &principals) {
            matches.push(pin.name.clone());
        }
    }
    Ok(matches)
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn verify_locked_sudo_sources(
    executables: &TrustedExecutableSet,
    pinned: &[SudoPolicySourcePin],
    removed: &[String],
) -> Result<(), LockdownError> {
    if removed.is_empty() {
        return Err(unsupported_fingerprint());
    }
    for name in removed {
        require_policy_source_absent(&sudo_drop_in_path(name)?)?;
    }
    let observed = capture_sudo_sources(executables)?;
    if !remaining_sudo_source_pins_match(&observed, pinned, removed) {
        return Err(unsupported_fingerprint());
    }
    for name in removed {
        require_policy_source_absent(&sudo_drop_in_path(name)?)?;
    }
    Ok(())
}

fn remaining_sudo_source_pins_match(
    observed: &[SudoPolicySourcePin],
    pinned: &[SudoPolicySourcePin],
    removed: &[String],
) -> bool {
    observed.iter().eq(pinned
        .iter()
        .filter(|pin| pin.path_class != "drop_in" || !removed.iter().any(|name| name == &pin.name)))
}

fn policy_source_metadata_is_safe(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.permissions().mode() & 0o022 == 0
}

fn require_policy_source_absent(path: &Path) -> Result<(), LockdownError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(LockdownError::new(
            "sudo_lockdown_failed",
            "the accepted runner sudo policy source is present or could not be checked",
        )),
    }
}

fn sudo_privileges_disabled(validation_succeeded: bool, policy_listing: &Output) -> bool {
    let Ok(message) = std::str::from_utf8(&policy_listing.stdout) else {
        return false;
    };
    let message = message.trim_end_matches(['\r', '\n']);
    if message.is_empty()
        || !message.is_ascii()
        || message
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b':' | b'(' | b')' | b'='))
    {
        return false;
    }
    let words = message.split_ascii_whitespace().collect::<Vec<_>>();
    let denied = words
        .windows(2)
        .any(|pair| pair == ["not", "allowed"] || pair == ["not", "permitted"])
        || words.iter().any(|word| {
            matches!(
                word.trim_matches(|character: char| !character.is_ascii_alphanumeric()),
                "cannot" | "denied"
            )
        });
    !validation_succeeded
        && policy_listing.status.success()
        && policy_listing.stderr.is_empty()
        && words.starts_with(&["User", "runner"])
        && words.iter().any(|word| word.trim_matches('.').eq("sudo"))
        && denied
}

fn sudo_drop_in_path(name: &str) -> Result<PathBuf, LockdownError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(unsupported_fingerprint());
    }
    Ok(Path::new(SUDOERS_DROP_IN_ROOT).join(name))
}

fn capture_runner_sudo_source(name: &str) -> Result<SudoRollbackSource, LockdownError> {
    let path = sudo_drop_in_path(name)?;
    let (bytes, metadata) = read_bounded_policy_file_with_metadata(&path)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let raw_sha256 = sha256_bytes(&bytes);
    if fs::canonicalize(&path).ok().as_deref() != Some(path.as_path())
        || !policy_source_metadata_is_safe(&metadata)
        || !sudo_includes_are_bounded(&bytes, false)
    {
        return Err(unsupported_fingerprint());
    }
    Ok(SudoRollbackSource {
        name: name.to_owned(),
        bytes,
        mode,
        uid: metadata.uid(),
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        sha256: raw_sha256,
    })
}

fn rollback_source_matches_pin(source: &SudoRollbackSource, pin: &SudoPolicySourcePin) -> bool {
    pin.path_class == "drop_in"
        && pin.name == source.name
        && source.mode == pin.mode
        && source.uid == pin.uid
        && source.gid == pin.gid
        && source.device == pin.device
        && source.inode == pin.inode
        && source.sha256 == pin.sha256
}

fn remove_captured_runner_sudo_source(captured: &SudoRollbackSource) -> Result<(), LockdownError> {
    let current = capture_runner_sudo_source(&captured.name)?;
    if current != *captured {
        return Err(LockdownError::new(
            "sudo_lockdown_failed",
            "accepted runner sudo policy source changed before removal",
        ));
    }
    fs::remove_file(sudo_drop_in_path(&captured.name)?).map_err(|_| {
        LockdownError::new(
            "sudo_lockdown_failed",
            "failed to remove the accepted runner sudo policy source",
        )
    })?;
    Ok(())
}

fn restore_runner_sudo_source(
    executables: &TrustedExecutableSet,
    source: &SudoRollbackSource,
) -> Result<(), LockdownError> {
    write_policy_exclusive(
        &sudo_drop_in_path(&source.name)?,
        &source.bytes,
        source.mode,
        "sudo_source_write_rollback_failed",
        "failed to restore bounded in-memory sudo policy state",
    )?;
    verify_restored_runner_sudo_source(executables, source)
}

fn verify_restored_runner_sudo_source(
    executables: &TrustedExecutableSet,
    expected: &SudoRollbackSource,
) -> Result<(), LockdownError> {
    let restored = capture_runner_sudo_source(&expected.name).map_err(|_| {
        LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "restored sudo policy source is unavailable or no longer accepted",
        )
    })?;
    if restored.bytes != expected.bytes
        || restored.mode != expected.mode
        || restored.uid != expected.uid
        || restored.gid != expected.gid
        || restored.sha256 != expected.sha256
    {
        return Err(LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "restored sudo policy metadata or digest does not match captured state",
        ));
    }
    executables.verify_all().map_err(|_| {
        LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "trusted executable state changed before restored sudo verification",
        )
    })?;
    let restored_sources = capture_sudo_sources(executables).map_err(|_| {
        LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "restored sudo policy inventory is unavailable or unsafe",
        )
    })?;
    require_success(
        fixed_command(
            executables,
            TrustedExecutable::Visudo,
            &RESTORED_SUDO_VISUDO_ARGUMENTS,
        )
        .map_err(|_| {
            LockdownError::new(
                "sudo_restore_verification_rollback_failed",
                "restored sudo policy syntax could not be verified",
            )
        })?,
        "sudo_restore_verification_rollback_failed",
        "restored sudo policy syntax is invalid",
    )?;
    let sudo_available = runner_sudo_validate(executables)
        .map_err(|_| {
            LockdownError::new(
                "sudo_restore_verification_rollback_failed",
                "restored sudo policy capability could not be verified",
            )
        })?
        .status
        .success();
    if !sudo_available {
        return Err(LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "restored sudo policy did not restore the accepted runner capability",
        ));
    }
    executables.verify_all().map_err(|_| {
        LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "trusted executable state changed during restored sudo verification",
        )
    })?;
    let final_sources = capture_sudo_sources(executables).map_err(|_| {
        LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "restored sudo policy inventory could not be verified again",
        )
    })?;
    if final_sources != restored_sources {
        return Err(LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "restored sudo policy inventory changed during capability verification",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn sha256_bounded_file(path: &Path) -> Result<String, LockdownError> {
    let bytes = read_bounded_policy_file(path)?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let mut hexadecimal = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut hexadecimal, "{byte:02x}").expect("writing to a string cannot fail");
    }
    hexadecimal
}

#[cfg(test)]
fn read_bounded_policy_file(path: &Path) -> Result<Vec<u8>, LockdownError> {
    read_bounded_policy_file_with_metadata(path).map(|(bytes, _)| bytes)
}

fn read_bounded_policy_file_with_metadata(
    path: &Path,
) -> Result<(Vec<u8>, fs::Metadata), LockdownError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| unsupported_fingerprint())?;
    let metadata = file.metadata().map_err(|_| unsupported_fingerprint())?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_POLICY_SOURCE_BYTES {
        return Err(unsupported_fingerprint());
    }
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unsupported_fingerprint())?;
    if bytes.len() as u64 > MAX_POLICY_SOURCE_BYTES || bytes.len() as u64 != metadata.len() {
        return Err(unsupported_fingerprint());
    }
    let path_metadata = fs::symlink_metadata(path).map_err(|_| unsupported_fingerprint())?;
    if !path_metadata.file_type().is_file()
        || path_metadata.uid() != metadata.uid()
        || path_metadata.gid() != metadata.gid()
        || path_metadata.permissions().mode() & 0o7777 != metadata.permissions().mode() & 0o7777
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
        || path_metadata.len() != metadata.len()
    {
        return Err(unsupported_fingerprint());
    }
    Ok((bytes, metadata))
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
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|_| LockdownError::new(code, message))?;
    file.write_all(bytes)
        .map_err(|_| LockdownError::new(code, message))?;
    file.sync_all()
        .map_err(|_| LockdownError::new(code, message))
}

fn runner_sudo_validate(executables: &TrustedExecutableSet) -> Result<Output, LockdownError> {
    runner_command(
        executables,
        TrustedExecutable::Sudo,
        &RUNNER_SUDO_VALIDATION_ARGUMENTS,
    )
}

fn runner_docker_ps(executables: &TrustedExecutableSet) -> Result<Output, LockdownError> {
    runner_command(executables, TrustedExecutable::Docker, &["ps", "--quiet"])
}

pub(crate) fn runner_docker_available(
    executables: &TrustedExecutableSet,
) -> Result<bool, LockdownError> {
    if executables.contains(TrustedExecutable::Docker) {
        let output = runner_docker_ps(executables)?;
        if output.status.success() {
            return Ok(true);
        }
        if output.status.code().is_none() {
            return Err(unsupported_fingerprint());
        }
    }
    verify_container_runtime_unavailable(executables)?;
    Ok(false)
}

fn verify_container_runtime_unavailable(
    executables: &TrustedExecutableSet,
) -> Result<(), LockdownError> {
    for unit in CONTAINER_UNITS {
        let state = observe_unit(executables, unit)?;
        if state.active_state == "active" {
            return Err(LockdownError::new(
                "container_lockdown_failed",
                "a container service remains active without verified runner access",
            ));
        }
    }
    verify_container_sockets_unavailable(executables)?;
    let deadline = Instant::now() + OBSERVATION_TIMEOUT;
    let socket_access = SystemUnixSocketAccess::new(|path: &OsStr| {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let timeout = remaining.min(SOCKET_PROBE_TIMEOUT);
        if timeout.is_zero() {
            None
        } else {
            runner_path_writable(executables, path, timeout).ok()
        }
    });
    let fence_owner = PinnedCurrentFenceOwner::capture(Path::new("/proc"))
        .map_err(|error| LockdownError::new(error.code, error.message))?;
    let observed =
        observe_local_control_inventory(Path::new("/proc"), &socket_access, &fence_owner);
    verify_reviewed_local_control_observation(
        &hosted_runner_fingerprint_requirement()
            .accepted
            .local_control_inventory,
        &observed,
    )
    .map_err(|error| LockdownError::new(error.code, error.message))?;
    if !observed.snapshot.root_container_processes.is_empty() {
        return Err(LockdownError::new(
            "container_lockdown_failed",
            "root-owned container runtime processes remain available",
        ));
    }
    Ok(())
}

fn verify_container_sockets_unavailable(
    executables: &TrustedExecutableSet,
) -> Result<(), LockdownError> {
    for path in [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
    ] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Ok(metadata) if metadata.file_type().is_socket() => {
                if unix_socket_has_listener(Path::new(path))?
                    && runner_path_writable(executables, OsStr::new(path), SOCKET_PROBE_TIMEOUT)?
                {
                    return Err(LockdownError::new(
                        "container_lockdown_failed",
                        "a container runtime socket remains accessible to the runner",
                    ));
                }
            }
            Ok(_) | Err(_) => return Err(unsupported_fingerprint()),
        }
    }
    Ok(())
}

fn unix_socket_has_listener(path: &Path) -> Result<bool, LockdownError> {
    match UnixStream::connect(path) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::NotFound
            ) =>
        {
            Ok(false)
        }
        Err(_) => Err(unsupported_fingerprint()),
    }
}

pub(crate) fn runner_path_writable(
    executables: &TrustedExecutableSet,
    path: &OsStr,
    timeout: Duration,
) -> Result<bool, LockdownError> {
    if timeout.is_zero() {
        return Err(unsupported_fingerprint());
    }
    let mut command = executables
        .runner_command(TrustedExecutable::Test, &[])
        .map_err(|_| unsupported_fingerprint())?;
    command.arg("-w").arg(path);
    let output = run_fixed_command_with_timeout(
        command,
        &[],
        timeout,
        TrustedExecutable::Test,
        CommandPrincipal::Runner,
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(unsupported_fingerprint()),
    }
}

fn observe_unit(
    executables: &TrustedExecutableSet,
    name: &str,
) -> Result<UnitObservation, LockdownError> {
    let output = fixed_command(
        executables,
        TrustedExecutable::Systemctl,
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

pub(crate) fn fixed_command(
    executables: &TrustedExecutableSet,
    executable: TrustedExecutable,
    arguments: &[&str],
) -> Result<Output, LockdownError> {
    fixed_command_with_timeout(executables, executable, arguments, COMMAND_TIMEOUT)
}

fn fixed_command_with_timeout(
    executables: &TrustedExecutableSet,
    executable: TrustedExecutable,
    arguments: &[&str],
    timeout: Duration,
) -> Result<Output, LockdownError> {
    let command = executables
        .command(executable)
        .map_err(|_| unsupported_fingerprint())?;
    run_fixed_command_with_timeout(
        command,
        arguments,
        timeout,
        executable,
        CommandPrincipal::Root,
    )
}

fn runner_command(
    executables: &TrustedExecutableSet,
    executable: TrustedExecutable,
    arguments: &[&str],
) -> Result<Output, LockdownError> {
    let command = executables
        .runner_command(executable, arguments)
        .map_err(|_| unsupported_fingerprint())?;
    run_fixed_command_with_timeout(
        command,
        &[],
        COMMAND_TIMEOUT,
        executable,
        CommandPrincipal::Runner,
    )
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CommandPrincipal {
    Root,
    Runner,
}

fn run_fixed_command_with_timeout(
    mut command: Command,
    arguments: &[&str],
    timeout: Duration,
    executable: TrustedExecutable,
    principal: CommandPrincipal,
) -> Result<Output, LockdownError> {
    // Nonblocking sockets let us bound both capture and elapsed time, including when
    // a descendant retains stdout after the direct child exits. Blocking reader
    // threads or wait_with_output could otherwise outlive the deadline.
    let (mut stdout, child_stdout) = UnixStream::pair().map_err(|_| unsupported_fingerprint())?;
    let (mut stderr, child_stderr) = UnixStream::pair().map_err(|_| unsupported_fingerprint())?;
    stdout
        .set_nonblocking(true)
        .map_err(|_| unsupported_fingerprint())?;
    stderr
        .set_nonblocking(true)
        .map_err(|_| unsupported_fingerprint())?;
    let mut child = command
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdout(Stdio::from(OwnedFd::from(child_stdout)))
        .stderr(Stdio::from(OwnedFd::from(child_stderr)))
        .spawn()
        .map_err(|_| unsupported_fingerprint())?;
    // Command retains its configured descriptors after spawn; close those copies.
    drop(command);
    let deadline = Instant::now() + timeout;
    let result = (|| {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let (mut out_eof, mut err_eof) = (false, false);
        loop {
            if Instant::now() >= deadline {
                return Err(LockdownError::new(
                    "lockdown_command_timeout",
                    "fixed lockdown command exceeded its deadline",
                ));
            }
            let previous_size = out.len() + err.len();
            drain_command_stream(&mut stdout, &mut out, err.len(), &mut out_eof)?;
            drain_command_stream(&mut stderr, &mut err, out.len(), &mut err_eof)?;
            if let Some(status) = child.try_wait().map_err(|_| unsupported_fingerprint())?
                && out_eof
                && err_eof
            {
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
            if previous_size == out.len() + err.len() {
                thread::sleep(Duration::from_millis(10));
            }
        }
    })();
    if let Err(error) = &result {
        let _ = child.kill();
        let _ = child.wait();
        if matches!(
            error.code,
            "lockdown_command_timeout" | "lockdown_command_output_too_large"
        ) {
            // Never emit args, paths, output, or environment: they may contain job data.
            eprintln!(
                "{}",
                serde_json::json!({
                    "fence_lockdown_command": {
                        "executable": executable,
                        "principal": principal,
                        "code": error.code,
                        "timeout_ms": timeout.as_millis(),
                    }
                })
            );
        }
    }
    result
}

fn drain_command_stream(
    stream: &mut UnixStream,
    captured: &mut Vec<u8>,
    other_size: usize,
    eof: &mut bool,
) -> Result<(), LockdownError> {
    if *eof {
        return Ok(());
    }
    let mut buffer = [0; 4096];
    let limit = buffer
        .len()
        .min(MAX_COMMAND_OUTPUT_BYTES - captured.len() - other_size + 1);
    match stream.read(&mut buffer[..limit]) {
        Ok(0) => *eof = true,
        Ok(size) => {
            if captured.len() + other_size + size > MAX_COMMAND_OUTPUT_BYTES {
                return Err(LockdownError::new(
                    "lockdown_command_output_too_large",
                    "fixed lockdown command output exceeded its bound",
                ));
            }
            captured.extend_from_slice(&buffer[..size]);
        }
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
        Err(_) => return Err(unsupported_fingerprint()),
    }
    Ok(())
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
        "host security controls do not meet Fence's lockdown requirements",
    )
}

fn unsupported_runner_groups() -> LockdownError {
    LockdownError::new(
        "unsupported_host_fingerprint",
        "runner groups are missing required membership or include an unreviewed group",
    )
}

fn unsupported_sudo_policy(error: LockdownError) -> LockdownError {
    if error.code == "unsupported_host_fingerprint" {
        LockdownError::new(
            error.code,
            "sudo policy is unsafe, invalid, changed, or lacks a reviewed runner grant",
        )
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_INDEX: AtomicUsize = AtomicUsize::new(0);

    // Synthetic subprocesses exercise the IO boundary without requiring root or
    // weakening the production trusted-executable boundary.
    fn synthetic_command(script: &str, timeout: Duration) -> Result<Output, LockdownError> {
        run_fixed_command_with_timeout(
            Command::new("/bin/sh"),
            &["-c", script],
            timeout,
            TrustedExecutable::Test,
            CommandPrincipal::Runner,
        )
    }

    #[test]
    fn fixed_command_preserves_status_and_both_streams_at_combined_bound() {
        let output = synthetic_command(
            "printf '%4096s' out; printf '%4096s' err >&2; exit 7",
            COMMAND_TIMEOUT,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout.len(), 4096);
        assert_eq!(output.stderr.len(), 4096);
        assert!(output.stdout.ends_with(b"out"));
        assert!(output.stderr.ends_with(b"err"));
    }

    #[test]
    fn fixed_command_rejects_combined_overflow_and_large_writes_without_timing_out() {
        for script in [
            "printf '%4096s' out; printf '%4097s' err >&2",
            "printf '%1048576s' out",
            "printf '%1048576s' err >&2",
        ] {
            assert_eq!(
                synthetic_command(script, COMMAND_TIMEOUT).unwrap_err().code,
                "lockdown_command_output_too_large",
                "{script}"
            );
        }
    }

    #[test]
    fn fixed_command_bounds_wait_after_direct_child_exits_with_streams_still_open() {
        // sleep inherits both streams; waiting for EOF must obey the same deadline.
        assert_eq!(
            synthetic_command("sleep 2 & exit 0", Duration::from_millis(100))
                .unwrap_err()
                .code,
            "lockdown_command_timeout"
        );
    }

    #[test]
    fn fixed_command_times_out_and_reaps_a_running_child() {
        assert_eq!(
            synthetic_command("exec /bin/sleep 2", Duration::from_millis(100))
                .unwrap_err()
                .code,
            "lockdown_command_timeout"
        );
    }

    struct FakeControl {
        operations: Rc<RefCell<Vec<&'static str>>>,
        rollback_result: Result<bool, LockdownError>,
        containers_result: Result<(), LockdownError>,
    }

    impl FakeControl {
        fn new() -> Self {
            Self {
                operations: Rc::new(RefCell::new(Vec::new())),
                rollback_result: Ok(true),
                containers_result: Ok(()),
            }
        }

        fn with_rollback_error(error: LockdownError) -> Self {
            Self {
                operations: Rc::new(RefCell::new(Vec::new())),
                rollback_result: Err(error),
                containers_result: Ok(()),
            }
        }

        fn without_containers() -> Self {
            Self {
                containers_result: Err(LockdownError::new(
                    "container_shape_unsupported",
                    "the accepted runner Docker control path is unavailable",
                )),
                ..Self::new()
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
            self.containers_result.clone()
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

        fn commit_no_restore(&mut self) {
            self.operations.borrow_mut().push("commit_no_restore");
        }

        fn rollback_pre_ready(&mut self) -> Result<bool, LockdownError> {
            self.operations.borrow_mut().push("rollback");
            self.rollback_result.clone()
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

    fn test_rollback_source() -> SudoRollbackSource {
        SudoRollbackSource {
            name: "runner".to_owned(),
            bytes: b"captured policy".to_vec(),
            mode: 0o440,
            uid: 0,
            gid: 0,
            device: 1,
            inode: 2,
            sha256: sha256_bytes(b"captured policy"),
        }
    }

    fn test_policy_pin(path_class: &'static str, name: &'static str) -> SudoPolicySourcePin {
        SudoPolicySourcePin {
            path_class,
            name: name.to_owned(),
            mode: 0o440,
            uid: 0,
            gid: 0,
            device: 1,
            inode: 2,
            sha256: format!("digest-{name}"),
        }
    }

    #[test]
    fn fingerprint_v3_builds_the_exact_runner_access_probe_plan() {
        let accepted = hosted_runner_fingerprint_requirement().accepted;
        let plan = runner_access_probe_plan(&accepted, true);
        assert_eq!(
            plan.len(),
            accepted.trusted_executables.len() * 2
                + accepted.permission_ancestor_directories.len() * 2
        );

        let mut by_path = BTreeMap::<&str, Vec<RunnerAccessProbe>>::new();
        for spec in plan {
            by_path
                .entry(spec.target.path())
                .or_default()
                .push(spec.probe);
        }
        assert_eq!(
            by_path.len(),
            accepted.trusted_executables.len() + accepted.permission_ancestor_directories.len()
        );
        for executable in &accepted.trusted_executables {
            assert_eq!(
                by_path.get(executable.path).unwrap(),
                &vec![
                    RunnerAccessProbe::NotWritable,
                    RunnerAccessProbe::Executable
                ]
            );
        }
        for ancestor in &accepted.permission_ancestor_directories {
            assert_eq!(
                by_path.get(ancestor.path).unwrap(),
                &vec![
                    RunnerAccessProbe::NotWritable,
                    if ancestor.runner_searchable {
                        RunnerAccessProbe::Executable
                    } else {
                        RunnerAccessProbe::NotExecutable
                    }
                ]
            );
        }
        assert_eq!(
            by_path.get(SUDOERS_DROP_IN_ROOT).unwrap(),
            &vec![
                RunnerAccessProbe::NotWritable,
                RunnerAccessProbe::NotExecutable
            ]
        );
        let without_docker = runner_access_probe_plan(&accepted, false);
        assert!(
            without_docker
                .iter()
                .all(|spec| spec.target.path() != "/usr/bin/docker")
        );

        assert_eq!(
            RunnerAccessProbe::NotWritable.arguments("/fixed/path"),
            vec!["!", "-w", "/fixed/path"]
        );
        assert_eq!(
            RunnerAccessProbe::Executable.arguments("/fixed/path"),
            vec!["-x", "/fixed/path"]
        );
        assert_eq!(
            RunnerAccessProbe::NotExecutable.arguments("/fixed/path"),
            vec!["!", "-x", "/fixed/path"]
        );
        assert_eq!(
            RUNNER_SUDO_VALIDATION_ARGUMENTS,
            ["--non-interactive", "--reset-timestamp", "--validate"]
        );
        assert_eq!(
            RUNNER_SUDO_POLICY_LIST_ARGUMENTS,
            ["--non-interactive", "--list", "--other-user", "runner"]
        );
        assert_eq!(
            RESTORED_SUDO_VISUDO_ARGUMENTS,
            ["--check", "--file", "/etc/sudoers"]
        );
    }

    #[test]
    fn identity_bound_runner_probe_fails_closed_on_outcome_and_identity_drift() {
        let mut observations = [7_u64, 7].into_iter();
        verify_identity_bound_probe(
            &7,
            || Ok(observations.next().unwrap()),
            |probe| {
                assert_eq!(probe, RunnerAccessProbe::NotWritable);
                Ok(true)
            },
            RunnerAccessProbe::NotWritable,
        )
        .unwrap();

        let mut observations = [7_u64, 7].into_iter();
        assert_eq!(
            verify_identity_bound_probe(
                &7,
                || Ok(observations.next().unwrap()),
                |_| Ok(false),
                RunnerAccessProbe::Executable,
            )
            .unwrap_err()
            .code,
            "unsupported_host_fingerprint"
        );

        let mut observations = [7_u64, 7].into_iter();
        assert_eq!(
            verify_identity_bound_probe(
                &7,
                || Ok(observations.next().unwrap()),
                |_| {
                    Err(LockdownError::new(
                        "runner_probe_spawn_failed",
                        "injected runner probe failure",
                    ))
                },
                RunnerAccessProbe::Executable,
            )
            .unwrap_err()
            .code,
            "runner_probe_spawn_failed"
        );

        let mut before_drift = [8_u64].into_iter();
        let probe_ran = Rc::new(RefCell::new(false));
        let probe_ran_for_closure = Rc::clone(&probe_ran);
        assert_eq!(
            verify_identity_bound_probe(
                &7,
                || Ok(before_drift.next().unwrap()),
                move |_| {
                    *probe_ran_for_closure.borrow_mut() = true;
                    Ok(true)
                },
                RunnerAccessProbe::Executable,
            )
            .unwrap_err()
            .code,
            "unsupported_host_fingerprint"
        );
        assert!(!*probe_ran.borrow());

        let mut after_drift = [7_u64, 8].into_iter();
        assert_eq!(
            verify_identity_bound_probe(
                &7,
                || Ok(after_drift.next().unwrap()),
                |_| Ok(true),
                RunnerAccessProbe::Executable,
            )
            .unwrap_err()
            .code,
            "unsupported_host_fingerprint"
        );
    }

    #[test]
    fn reviewed_modes_require_the_exact_four_digit_octal_form() {
        assert_eq!(parse_reviewed_mode("0755").unwrap(), 0o755);
        assert_eq!(parse_reviewed_mode("4755").unwrap(), 0o4755);
        for invalid in ["755", "00755", "0855", "10000", "mode"] {
            assert_eq!(
                parse_reviewed_mode(invalid).unwrap_err().code,
                "unsupported_host_fingerprint"
            );
        }
    }

    #[test]
    fn unsupported_host_errors_identify_groups_and_sudo_policy() {
        let groups = unsupported_runner_groups();
        assert_eq!(groups.code, "unsupported_host_fingerprint");
        assert!(groups.message.contains("runner groups"));

        let sudo = unsupported_sudo_policy(unsupported_fingerprint());
        assert_eq!(sudo.code, "unsupported_host_fingerprint");
        assert!(sudo.message.contains("sudo policy"));

        let original = LockdownError::new("runner_probe_failed", "probe unavailable");
        assert_eq!(unsupported_sudo_policy(original.clone()), original);
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
                "disable_sudo",
                "disable_containers",
                "sudo_disabled",
                "containers_disabled",
                "commit_no_restore"
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
        assert_eq!(
            *audit.control_for_test().operations.borrow(),
            vec![
                "fingerprint",
                "sudo_available",
                "containers_available",
                "commit_no_restore"
            ]
        );

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
    fn missing_containers_are_safe_for_audit_and_standard_but_not_unsafe_preserve() {
        let audit = LockdownSession::establish_test_only(
            runtime("audit-no-containers"),
            LockdownPosture::Audit,
            FakeControl::without_containers(),
            false,
        )
        .unwrap();
        assert_eq!(audit.evidence.container_status, "preserved");

        let standard = LockdownSession::establish_test_only(
            runtime("standard-no-containers"),
            LockdownPosture::StandardBlock,
            FakeControl::without_containers(),
            false,
        )
        .unwrap();
        assert_eq!(standard.evidence.container_status, "disabled_verified");

        let unsafe_runtime = runtime("unsafe-no-containers");
        let unsafe_root = unsafe_runtime.directory.parent().unwrap().to_path_buf();
        let error = LockdownSession::establish_test_only(
            unsafe_runtime,
            LockdownPosture::UnsafePreserve,
            FakeControl::without_containers(),
            false,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "container_shape_unsupported");

        fs::remove_dir_all(audit.runtime.directory.parent().unwrap()).unwrap();
        fs::remove_dir_all(standard.runtime.directory.parent().unwrap()).unwrap();
        fs::remove_dir_all(unsafe_root).unwrap();
    }

    #[test]
    fn audit_rejects_container_failures_other_than_proven_absence() {
        let mut control = FakeControl::new();
        control.containers_result = Err(LockdownError::new(
            "container_lockdown_failed",
            "a container runtime socket remains accessible to the runner",
        ));
        let runtime = runtime("audit-dangerous-containers");
        let root = runtime.directory.parent().unwrap().to_path_buf();
        let error =
            LockdownSession::establish_test_only(runtime, LockdownPosture::Audit, control, false)
                .err()
                .unwrap();
        assert_eq!(error.code, "container_lockdown_failed");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pre_ready_failure_rolls_back_provisional_controls() {
        let runtime = runtime("rollback-proof");
        let report = runtime.report.clone();
        let control = FakeControl::new();
        let operations = Rc::clone(&control.operations);
        let error = LockdownSession::establish_test_only(
            runtime,
            LockdownPosture::StandardBlock,
            control,
            true,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "injected_pre_ready_lockdown_failure");
        let serialized = fs::read_to_string(&report).unwrap();
        assert!(serialized.contains("\"rollback_status\":\"rolled_back_pre_ready\""));
        assert!(serialized.contains("\"readiness_status\":\"not_emitted\""));
        assert_eq!(
            *operations.borrow(),
            vec![
                "fingerprint",
                "sudo_available",
                "disable_sudo",
                "disable_containers",
                "sudo_disabled",
                "containers_disabled",
                "rollback"
            ]
        );
        fs::remove_dir_all(report.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn pre_ready_rollback_failure_is_recorded_without_committing() {
        let runtime = runtime("rollback-failure-proof");
        let report = runtime.report.clone();
        let control = FakeControl::with_rollback_error(LockdownError::new(
            "sudo_source_write_rollback_failed",
            "injected rollback failure",
        ));
        let operations = Rc::clone(&control.operations);

        let error = LockdownSession::establish_test_only(
            runtime,
            LockdownPosture::StandardBlock,
            control,
            true,
        )
        .err()
        .unwrap();

        assert_eq!(error.code, "injected_pre_ready_lockdown_failure");
        let serialized = fs::read_to_string(&report).unwrap();
        assert!(serialized.contains("\"rollback_status\":\"rollback_failed\""));
        assert!(
            serialized.contains("\"rollback_error_code\":\"sudo_source_write_rollback_failed\"")
        );
        assert!(serialized.contains("\"readiness_status\":\"not_emitted\""));
        assert_eq!(operations.borrow().last(), Some(&"rollback"));
        assert!(!operations.borrow().contains(&"commit_no_restore"));
        fs::remove_dir_all(report.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn container_rollback_failure_does_not_skip_sudo_restoration() {
        let mut sudo_rollback = SudoRollbackState::RollbackAvailable(vec![test_rollback_source()]);
        let mut containers_masked = true;
        let operations = Rc::new(RefCell::new(Vec::new()));
        let sudo_operations = Rc::clone(&operations);
        let container_operations = Rc::clone(&operations);

        let error = rollback_pre_ready_components(
            &mut sudo_rollback,
            &mut containers_masked,
            move |_| {
                sudo_operations.borrow_mut().push("restore_sudo");
                Ok(())
            },
            move || {
                container_operations.borrow_mut().push("restore_containers");
                Err(LockdownError::new(
                    "container_restart_rollback_failed",
                    "injected container rollback failure",
                ))
            },
        )
        .unwrap_err();

        assert_eq!(error.code, "container_restart_rollback_failed");
        assert_eq!(
            *operations.borrow(),
            vec!["restore_sudo", "restore_containers"]
        );
        assert!(matches!(sudo_rollback, SudoRollbackState::Unchanged));
        assert!(containers_masked);
    }

    #[test]
    fn rollback_preserves_each_failed_component_state_and_aggregates_errors() {
        let mut sudo_rollback = SudoRollbackState::RollbackAvailable(vec![test_rollback_source()]);
        let mut containers_masked = true;

        let error = rollback_pre_ready_components(
            &mut sudo_rollback,
            &mut containers_masked,
            |_| {
                Err(LockdownError::new(
                    "sudo_source_write_rollback_failed",
                    "injected sudo rollback failure",
                ))
            },
            || {
                Err(LockdownError::new(
                    "container_restart_rollback_failed",
                    "injected container rollback failure",
                ))
            },
        )
        .unwrap_err();

        assert_eq!(error.code, "lockdown_rollback_failed");
        assert!(error.message.contains("sudo_source_write_rollback_failed"));
        assert!(error.message.contains("container_restart_rollback_failed"));
        assert!(matches!(
            sudo_rollback,
            SudoRollbackState::RollbackAvailable(_)
        ));
        assert!(containers_masked);

        let mut sudo_rollback = SudoRollbackState::RollbackAvailable(vec![test_rollback_source()]);
        let mut containers_masked = true;
        let error = rollback_pre_ready_components(
            &mut sudo_rollback,
            &mut containers_masked,
            |_| {
                Err(LockdownError::new(
                    "sudo_source_write_rollback_failed",
                    "injected sudo rollback failure",
                ))
            },
            || Ok(()),
        )
        .unwrap_err();

        assert_eq!(error.code, "sudo_source_write_rollback_failed");
        assert!(matches!(
            sudo_rollback,
            SudoRollbackState::RollbackAvailable(_)
        ));
        assert!(!containers_masked);
    }

    #[test]
    fn committed_lockdown_discards_rollback_state_and_rejects_restore() {
        let mut sudo_rollback = SudoRollbackState::RollbackAvailable(vec![test_rollback_source()]);
        let mut containers_masked = true;
        commit_no_restore_state(&mut sudo_rollback);
        assert!(matches!(
            sudo_rollback,
            SudoRollbackState::CommittedNoRestore
        ));
        assert_eq!(
            rollback_pre_ready_components(
                &mut sudo_rollback,
                &mut containers_masked,
                |_| panic!("sudo restore must not run after commit"),
                || panic!("container restore must not run after commit"),
            )
            .unwrap_err()
            .code,
            "lockdown_rollback_after_commit"
        );
        assert!(containers_masked);

        commit_no_restore_state(&mut sudo_rollback);
        assert!(matches!(
            sudo_rollback,
            SudoRollbackState::CommittedNoRestore
        ));
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

        let directory = root.join("directory");
        fs::create_dir(&directory).unwrap();
        assert_eq!(
            sha256_bounded_file(&directory).unwrap_err().code,
            "unsupported_host_fingerprint"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sudo_drop_in_names_follow_sudo_backup_file_rules() {
        for name in ["runner", "90-cloud-init-users", "policy_1"] {
            assert!(active_sudo_drop_in(name));
        }
        for name in ["runner.bak", ".runner", "runner~", "runner.old~"] {
            assert!(!active_sudo_drop_in(name));
        }
    }

    #[test]
    fn sudo_policy_rejects_external_nested_and_continued_include_directives() {
        assert!(sudo_includes_are_bounded(
            b"Defaults env_reset\n@includedir /etc/sudoers.d\n",
            true,
        ));
        assert!(sudo_includes_are_bounded(
            b"runner ALL=(ALL) NOPASSWD:ALL\n# documentation\n",
            false,
        ));
        assert!(sudo_includes_are_bounded(
            b"# Windows path C:\\Users\\runner\\notes\n# docs C:\\temp\\\n",
            false,
        ));
        assert!(sudo_includes_are_bounded(
            b"#1001 ALL=(ALL) NOPASSWD:ALL # Windows C:\\Users\\runner\n",
            false,
        ));
        for (policy, allow_root_include) in [
            (b"@include /tmp/unsafe\n".as_slice(), true),
            (b"#include /tmp/unsafe\n".as_slice(), true),
            (b"@includedir /tmp/unsafe\n".as_slice(), true),
            (b"@includedir /etc/sudoers.d extra\n".as_slice(), true),
            (b"@includedir /etc/sudoers.d\n".as_slice(), false),
            (b"@incl\\\nude /tmp/unsafe\n".as_slice(), true),
            (b"#incl\\\nude /tmp/unsafe\n".as_slice(), true),
            (b"#inc\\lude /tmp/unsafe\n".as_slice(), true),
            (b"#1001 ALL=(ALL) NOPASSWD:ALL\\\n".as_slice(), false),
            (b"Defaults env_keep += \"unterminated\n".as_slice(), false),
        ] {
            assert!(!sudo_includes_are_bounded(policy, allow_root_include));
        }
    }

    #[test]
    fn sudo_policy_rejects_authentication_default_overrides() {
        assert!(sudo_authentication_defaults_are_safe(
            b"Defaults env_reset\nDefaults use_pty # listpw is documented here\n"
        ));
        assert!(sudo_authentication_defaults_are_safe(
            b"# Windows C:\\Users\\runner\\docs\nDefaults env_keep += \"authenticate, listpw\"\nDefaults authenticate_extra, listpw_extra\n"
        ));
        assert!(sudo_authentication_defaults_are_safe(
            b"Defaults env_keep += \"# authenticate\" # rootpw C:\\Users\\runner\n"
        ));
        for policy in [
            b"Defaults !root_sudo\n".as_slice(),
            b"Defaults verifypw=always\n".as_slice(),
            b"Defaults:runner listpw=always\n".as_slice(),
            b"Defaults rootpw\n".as_slice(),
            b"Defaults targetpw\n".as_slice(),
            b"Defaults runaspw\n".as_slice(),
            b"Defaults !authenticate\n".as_slice(),
            b"Defaults env_reset, !authenticate\n".as_slice(),
            b"Defaults env_keep += \"harmless\", listpw=always\n".as_slice(),
            b"Defaults env_keep += \"unterminated\n".as_slice(),
            b"Defaults env_reset\\\n!authenticate\n".as_slice(),
            b"Defaults !root_sudo\nDefaults verifypw=always\nrunner ALL=(ALL) NOPASSWD:/bin/sh\n",
        ] {
            assert!(!sudo_authentication_defaults_are_safe(policy));
        }
    }

    #[test]
    fn runner_sudo_policy_contains_only_one_reviewed_grant() {
        for policy in [
            b"runner ALL=(ALL) NOPASSWD:ALL\n".as_slice(),
            b"# image metadata\n  runner\tALL=(ALL:ALL)\tNOPASSWD:ALL  \n# note\n",
            b"runner ALL=(ALL:ALL) NOPASSWD: ALL\n",
            b"runner ALL=(ALL) NOPASSWD:ALL # Windows C:\\Users\\runner\n",
            b"Defaults env_reset\nrunner ALL=(ALL) NOPASSWD:ALL\nDefaults use_pty\n",
            b"Defaults:runner env_keep += \"authenticate, # listpw\"\nrunner ALL=(ALL) NOPASSWD:ALL\n",
        ] {
            assert!(reviewed_runner_sudo_policy(policy));
        }
        for (principal, policy) in [
            ("%runner", b"%runner ALL=(ALL) NOPASSWD: ALL\n".as_slice()),
            ("#1001", b"#1001 ALL=(ALL:ALL) NOPASSWD:ALL\n".as_slice()),
        ] {
            assert!(reviewed_runner_sudo_policy_for_principals(
                policy,
                &[principal.to_owned()]
            ));
        }
        for policy in [
            b"runner ALL=(ALL) NOPASSWD:/bin/sh\n".as_slice(),
            b"runner ALL=(ALL) NOPASSWD:ALL\nDefaults !root_sudo\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\nDefaults env_reset, !authenticate\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\nDefaults:runner listpw=always\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\nDefaults env_keep += \"unterminated\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\nDefaultsTypo env_reset\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\nroot ALL=(ALL) NOPASSWD:ALL\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\n#1001 ALL=(ALL) NOPASSWD:ALL\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\nUser_Alias ADMINS = runner\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\n@includedir /etc/sudoers.d\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\nDefaults env_reset\\\n!authenticate\n",
            b"runner ALL=(ALL) NOPASSWD:ALL\n#incl\\\nude /tmp/unsafe\n",
            b"ubuntu ALL=(ALL) NOPASSWD:ALL\n",
        ] {
            assert!(!reviewed_runner_sudo_policy(policy));
        }
    }

    #[test]
    fn sudo_lockdown_rejects_command_specific_grants_and_listing_errors() {
        use std::os::unix::process::ExitStatusExt;

        let listing = |status, stdout: &[u8], stderr: &[u8]| Output {
            status: std::process::ExitStatus::from_raw(status),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        };
        let denied = b"User runner is not allowed to run sudo on fv-az123-45.\n";
        assert!(sudo_privileges_disabled(false, &listing(0, denied, b"")));
        assert!(sudo_privileges_disabled(
            false,
            &listing(0, b"User runner cannot invoke sudo here.\n", b"")
        ));
        assert!(sudo_privileges_disabled(
            false,
            &listing(
                0,
                b"User runner is not allowed to run sudo on image_host.\n",
                b""
            )
        ));
        assert!(!sudo_privileges_disabled(true, &listing(0, denied, b"")));
        assert!(!sudo_privileges_disabled(false, &listing(256, denied, b"")));
        assert!(!sudo_privileges_disabled(false, &listing(9, denied, b"")));
        for (stdout, stderr) in [
            (
                b"User runner may run the following commands on host:\n".as_slice(),
                b"".as_slice(),
            ),
            (b"User runner is allowed to run sudo.\n", b""),
            (b"User runner can run sudo with no password.\n", b""),
            (
                b"User runner is not allowed to run sudo on host.\nextra\n",
                b"",
            ),
            (denied.as_slice(), b"sudo: root is not allowed\n"),
        ] {
            assert!(!sudo_privileges_disabled(
                false,
                &listing(0, stdout, stderr)
            ));
        }
    }

    #[test]
    fn locked_sudo_inventory_requires_runner_absence() {
        let root = PathBuf::from(format!(
            "target/tmp/lockdown-inventory-unit-{}",
            TEST_INDEX.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let runner = root.join("runner");
        require_policy_source_absent(&runner).unwrap();

        fs::write(&runner, b"runner grant").unwrap();
        assert_eq!(
            require_policy_source_absent(&runner).unwrap_err().code,
            "sudo_lockdown_failed"
        );
        fs::remove_file(&runner).unwrap();

        let target = root.join("target");
        fs::write(&target, b"target").unwrap();
        symlink(fs::canonicalize(&target).unwrap(), &runner).unwrap();
        assert_eq!(
            require_policy_source_absent(&runner).unwrap_err().code,
            "sudo_lockdown_failed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn locked_sudo_pins_reject_metadata_digest_and_identity_drift() {
        let pinned = vec![
            test_policy_pin("main_policy", "sudoers"),
            test_policy_pin("drop_in", "90-cloud-init-users"),
            test_policy_pin("drop_in", "runner"),
        ];
        let mut observed = vec![
            test_policy_pin("main_policy", "sudoers"),
            test_policy_pin("drop_in", "90-cloud-init-users"),
        ];
        let removed = vec!["runner".to_owned()];
        assert!(remaining_sudo_source_pins_match(
            &observed, &pinned, &removed
        ));

        let mut renamed = pinned.clone();
        renamed[2].name = "90-hosted-grant".to_owned();
        assert!(remaining_sudo_source_pins_match(
            &observed,
            &renamed,
            &["90-hosted-grant".to_owned()]
        ));

        let mut multiple = pinned.clone();
        multiple.push(test_policy_pin("drop_in", "runner-extra"));
        assert!(remaining_sudo_source_pins_match(
            &observed,
            &multiple,
            &["runner".to_owned(), "runner-extra".to_owned()]
        ));

        observed[1].inode += 1;
        assert!(!remaining_sudo_source_pins_match(
            &observed, &pinned, &removed
        ));
        observed[1].inode -= 1;
        observed[1].mode = 0o400;
        assert!(!remaining_sudo_source_pins_match(
            &observed, &pinned, &removed
        ));
        observed[1].mode = 0o440;
        observed[1].sha256 = "different-digest".to_owned();
        assert!(!remaining_sudo_source_pins_match(
            &observed, &pinned, &removed
        ));
    }

    #[test]
    fn policy_restore_writer_is_exclusive_no_follow_and_preserves_bytes_and_mode() {
        let root = PathBuf::from(format!(
            "target/tmp/lockdown-writer-unit-{}",
            TEST_INDEX.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let restored = root.join("restored");
        write_policy_exclusive(
            &restored,
            b"exact restored policy\n",
            0o440,
            "test_write_failed",
            "test write failed",
        )
        .unwrap();
        assert_eq!(fs::read(&restored).unwrap(), b"exact restored policy\n");
        assert_eq!(
            fs::metadata(&restored).unwrap().permissions().mode() & 0o777,
            0o440
        );

        let existing = root.join("existing");
        fs::write(&existing, b"existing policy").unwrap();
        assert_eq!(
            write_policy_exclusive(
                &existing,
                b"replacement",
                0o440,
                "test_write_failed",
                "test write failed",
            )
            .unwrap_err()
            .code,
            "test_write_failed"
        );
        assert_eq!(fs::read(&existing).unwrap(), b"existing policy");

        let target = root.join("target");
        fs::write(&target, b"symlink target").unwrap();
        let linked = root.join("linked");
        symlink(fs::canonicalize(&target).unwrap(), &linked).unwrap();
        assert_eq!(
            write_policy_exclusive(
                &linked,
                b"replacement",
                0o440,
                "test_write_failed",
                "test write failed",
            )
            .unwrap_err()
            .code,
            "test_write_failed"
        );
        assert_eq!(fs::read(&target).unwrap(), b"symlink target");

        fs::remove_dir_all(root).unwrap();
    }
}
