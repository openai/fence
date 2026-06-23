use crate::hosted_runner::{
    AcceptedHostedRunnerFactsV2, AcceptedPermissionAncestorV2, AcceptedSudoPolicySourceV2,
    AcceptedTrustedExecutableV2, hosted_runner_fingerprint_requirement,
};
use crate::lifecycle::validate_test_service_context;
use crate::local_control::{
    NoCurrentFenceOwner, OBSERVATION_TIMEOUT, SOCKET_PROBE_TIMEOUT, SystemUnixSocketAccess,
    accepted_local_control_snapshot, observe_local_control_inventory,
    verify_local_control_observation,
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
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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
const SUDOERS_PATH: &str = "/etc/sudoers";
const SUDOERS_DROP_IN_ROOT: &str = "/etc/sudoers.d";
const RUNNER_DROP_IN_PATH: &str = "/etc/sudoers.d/runner";
const RUNNER_SUDO_VALIDATION_ARGUMENTS: [&str; 3] =
    ["--non-interactive", "--reset-timestamp", "--validate"];
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
    name: &'static str,
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
    SudoPolicySource(&'a AcceptedSudoPolicySourceV2),
}

impl RunnerProbeTarget<'_> {
    fn path(self) -> &'static str {
        match self {
            Self::TrustedExecutable(expected) => expected.path,
            Self::PermissionAncestor(expected) => expected.path,
            Self::SudoPolicySource(expected) => expected.canonical_target,
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
            Self::SudoPolicySource(expected) => {
                verify_policy_source(Path::new(expected.canonical_target), expected)
                    .map(RunnerProbeIdentity::PolicySource)
            }
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
    PolicySource(SudoPolicySourcePin),
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
        rollback_error_code: None,
        readiness_status: "not_emitted",
        protection_available: false,
        limitations,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct SudoRollbackSource {
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
    RollbackAvailable(SudoRollbackSource),
    CommittedNoRestore,
}

pub struct SystemLockdownControl {
    executables: Arc<TrustedExecutableSet>,
    sudo_rollback: SudoRollbackState,
    sudo_source_pins: Option<Vec<SudoPolicySourcePin>>,
    containers_masked: bool,
}

impl SystemLockdownControl {
    pub(crate) fn new(executables: Arc<TrustedExecutableSet>) -> Self {
        Self {
            executables,
            sudo_rollback: SudoRollbackState::Unchanged,
            sudo_source_pins: None,
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
        self.sudo_source_pins = Some(verify_fixed_fingerprint(executables)?);
        Ok(())
    }

    fn verify_sudo_available(&mut self) -> Result<(), LockdownError> {
        let executables = &self.executables;
        executables
            .verify_all()
            .map_err(|_| unsupported_fingerprint())?;
        if runner_sudo_validate(executables)?.status.success() {
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
        if runner_docker_ps(executables)?.status.success() {
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
        let source = capture_runner_sudo_source()?;
        let source_pin = self
            .sudo_source_pins
            .as_ref()
            .and_then(|pins| {
                pins.iter()
                    .find(|pin| pin.path_class == "drop_in" && pin.name == "runner")
            })
            .ok_or_else(unsupported_fingerprint)?;
        if !rollback_source_matches_pin(&source, source_pin) {
            return Err(unsupported_fingerprint());
        }
        remove_captured_runner_sudo_source(&source)?;
        self.sudo_rollback = SudoRollbackState::RollbackAvailable(source);
        require_success(
            fixed_command(&self.executables, TrustedExecutable::Visudo, &["--check"])?,
            "sudo_lockdown_failed",
            "sudo policy did not validate after removing the accepted runner source",
        )
    }

    fn disable_containers(&mut self) -> Result<(), LockdownError> {
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
        verify_locked_sudo_sources(source_pins)?;
        let sudo_available = runner_sudo_validate(executables)?.status.success();
        verify_locked_sudo_sources(source_pins)?;
        if sudo_available {
            Err(LockdownError::new(
                "sudo_lockdown_failed",
                "runner passwordless sudo remains usable after lockdown",
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
        if runner_docker_ps(executables)?.status.success() {
            return Err(LockdownError::new(
                "container_lockdown_failed",
                "runner Docker access remains usable after lockdown",
            ));
        }
        for unit in CONTAINER_UNITS {
            let state = observe_unit(executables, unit)?;
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

    fn commit_no_restore(&mut self) {
        commit_no_restore_state(&mut self.sudo_rollback);
    }

    fn rollback_pre_ready(&mut self) -> Result<bool, LockdownError> {
        let executables = Arc::clone(&self.executables);
        let sudo_executables = Arc::clone(&executables);
        rollback_pre_ready_components(
            &mut self.sudo_rollback,
            &mut self.containers_masked,
            move |source| restore_runner_sudo_source(&sudo_executables, source),
            move || restore_container_controls(&executables),
        )
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
    RestoreSudo: FnMut(&SudoRollbackSource) -> Result<(), LockdownError>,
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
        SudoRollbackState::RollbackAvailable(source) => restore_sudo(source),
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
    let accepted = accepted_local_control_snapshot(
        &hosted_runner_fingerprint_requirement()
            .accepted
            .local_control_inventory,
    )
    .map_err(|error| LockdownError::new(error.code, error.message))?;
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
    verify_local_control_observation(&accepted, &observed)
        .map_err(|error| LockdownError::new(error.code, error.message))
}

fn runner_access_probe_plan(
    accepted: &AcceptedHostedRunnerFactsV2,
) -> Vec<RunnerAccessProbeSpec<'_>> {
    let mut plan = Vec::with_capacity(
        accepted.trusted_executables.len() * 2
            + accepted.permission_ancestor_directories.len() * 2
            + accepted.sudo_policy_sources.len(),
    );
    for executable in &accepted.trusted_executables {
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
    for source in &accepted.sudo_policy_sources {
        plan.push(RunnerAccessProbeSpec {
            target: RunnerProbeTarget::SudoPolicySource(source),
            probe: RunnerAccessProbe::NotWritable,
        });
    }
    plan
}

fn collect_runner_probe_baselines<'a>(
    accepted: &'a AcceptedHostedRunnerFactsV2,
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
    let expected_target_count = accepted.trusted_executables.len()
        + accepted.permission_ancestor_directories.len()
        + accepted.sudo_policy_sources.len();
    if baselines.len() != expected_target_count {
        return Err(unsupported_fingerprint());
    }
    Ok(baselines)
}

fn verify_runner_access_probes(
    executables: &TrustedExecutableSet,
    accepted: &AcceptedHostedRunnerFactsV2,
) -> Result<(), LockdownError> {
    let plan = runner_access_probe_plan(accepted);
    let baselines = collect_runner_probe_baselines(accepted, &plan)?;
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

fn verify_fixed_fingerprint(
    executables: &TrustedExecutableSet,
) -> Result<Vec<SudoPolicySourcePin>, LockdownError> {
    let accepted = hosted_runner_fingerprint_requirement().accepted;
    if std::env::consts::ARCH != accepted.architecture {
        return Err(unsupported_fingerprint());
    }
    let os_release =
        fs::read_to_string("/etc/os-release").map_err(|_| unsupported_fingerprint())?;
    let expected_os_id = format!("ID={}", accepted.os_id);
    let expected_os_version = format!("VERSION_ID=\"{}\"", accepted.os_version_id);
    if !os_release.lines().any(|line| line == expected_os_id)
        || !os_release.lines().any(|line| line == expected_os_version)
    {
        return Err(unsupported_fingerprint());
    }
    executables
        .verify_all()
        .map_err(|_| unsupported_fingerprint())?;
    let groups = fixed_command(
        executables,
        TrustedExecutable::Id,
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
    let sudo_source_pins = verify_sudo_sources(&accepted.sudo_policy_sources)?;
    verify_runner_access_probes(executables, &accepted)?;
    executables
        .verify_all()
        .map_err(|_| unsupported_fingerprint())?;
    if verify_sudo_sources(&accepted.sudo_policy_sources)? != sudo_source_pins {
        return Err(unsupported_fingerprint());
    }
    for expected in &accepted.container_units {
        if observe_unit(executables, expected.name)?
            != (UnitObservation {
                load_state: expected.load_state.to_owned(),
                active_state: expected.active_state.to_owned(),
                unit_file_state: expected.unit_file_state.to_owned(),
            })
        {
            return Err(unsupported_fingerprint());
        }
    }
    verify_socket_fingerprint(executables)?;
    let docker = runner_docker_ps(executables)?;
    if !docker.status.success() || !docker.stdout.is_empty() {
        return Err(unsupported_fingerprint());
    }
    Ok(sudo_source_pins)
}

fn verify_sudo_sources(
    expected: &[AcceptedSudoPolicySourceV2],
) -> Result<Vec<SudoPolicySourcePin>, LockdownError> {
    verify_sudo_sources_with_runner_state(expected, true)
}

fn verify_locked_sudo_sources(pinned: &[SudoPolicySourcePin]) -> Result<(), LockdownError> {
    let expected = hosted_runner_fingerprint_requirement()
        .accepted
        .sudo_policy_sources;
    require_policy_source_absent(Path::new(RUNNER_DROP_IN_PATH))?;
    let observed = verify_sudo_sources_with_runner_state(&expected, false)?;
    if !remaining_sudo_source_pins_match(&observed, pinned) {
        return Err(unsupported_fingerprint());
    }
    require_policy_source_absent(Path::new(RUNNER_DROP_IN_PATH))
}

fn remaining_sudo_source_pins_match(
    observed: &[SudoPolicySourcePin],
    pinned: &[SudoPolicySourcePin],
) -> bool {
    observed.iter().eq(pinned
        .iter()
        .filter(|pin| pin.path_class != "drop_in" || pin.name != "runner"))
}

fn verify_sudo_sources_with_runner_state(
    expected: &[AcceptedSudoPolicySourceV2],
    runner_source_present: bool,
) -> Result<Vec<SudoPolicySourcePin>, LockdownError> {
    let expected_sources = expected
        .iter()
        .filter(|source| {
            runner_source_present || source.path_class != "drop_in" || source.name != "runner"
        })
        .collect::<Vec<_>>();
    let expected_drop_ins = expected_sources
        .iter()
        .filter(|source| source.path_class == "drop_in")
        .map(|source| source.name)
        .collect::<Vec<_>>();
    verify_drop_in_inventory(Path::new(SUDOERS_DROP_IN_ROOT), &expected_drop_ins)?;

    let mut observed = Vec::with_capacity(expected_sources.len());
    for source in expected_sources {
        let path = if source.path_class == "main_policy" {
            PathBuf::from(SUDOERS_PATH)
        } else {
            Path::new(SUDOERS_DROP_IN_ROOT).join(source.name)
        };
        observed.push(verify_policy_source(&path, source)?);
    }
    Ok(observed)
}

fn verify_drop_in_inventory(root: &Path, expected: &[&str]) -> Result<(), LockdownError> {
    let mut observed_drop_ins = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| unsupported_fingerprint())? {
        let entry = entry.map_err(|_| unsupported_fingerprint())?;
        if !entry
            .file_type()
            .is_ok_and(|kind| kind.is_file() && !kind.is_symlink())
        {
            return Err(unsupported_fingerprint());
        }
        observed_drop_ins.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| unsupported_fingerprint())?,
        );
    }
    observed_drop_ins.sort();
    let mut expected_drop_ins = expected
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    expected_drop_ins.sort();
    if observed_drop_ins != expected_drop_ins {
        return Err(unsupported_fingerprint());
    }
    Ok(())
}

fn verify_policy_source(
    path: &Path,
    expected: &AcceptedSudoPolicySourceV2,
) -> Result<SudoPolicySourcePin, LockdownError> {
    let (bytes, metadata) = read_bounded_policy_file_with_metadata(path)?;
    let expected_mode = parse_reviewed_mode(expected.mode)?;
    let sha256 = sha256_bytes(&bytes);
    if path.to_str() != Some(expected.canonical_target)
        || fs::canonicalize(path).ok().as_deref() != Some(Path::new(expected.canonical_target))
        || !policy_source_metadata_is_safe(&metadata)
        || metadata.permissions().mode() & 0o7777 != expected_mode
        || !source_accepts_sha256(expected, &sha256)
    {
        return Err(unsupported_fingerprint());
    }
    Ok(SudoPolicySourcePin {
        path_class: expected.path_class,
        name: expected.name,
        mode: metadata.permissions().mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        sha256,
    })
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

fn source_accepts_sha256(source: &AcceptedSudoPolicySourceV2, observed_sha256: &str) -> bool {
    observed_sha256 == source.sha256 || source.alternate_sha256.contains(&observed_sha256)
}

fn verify_socket_fingerprint(executables: &TrustedExecutableSet) -> Result<(), LockdownError> {
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
        let ownership = fixed_command(
            executables,
            TrustedExecutable::Stat,
            &["--format=%U:%G:%a:%F", expected.path],
        )?;
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

fn capture_runner_sudo_source() -> Result<SudoRollbackSource, LockdownError> {
    let accepted = hosted_runner_fingerprint_requirement()
        .accepted
        .sudo_policy_sources
        .into_iter()
        .find(|source| source.path_class == "drop_in" && source.name == "runner")
        .ok_or_else(|| {
            LockdownError::new(
                "unsupported_host_fingerprint",
                "accepted runner sudo source is not represented in the fingerprint",
            )
        })?;
    let (bytes, metadata) = read_bounded_policy_file_with_metadata(Path::new(RUNNER_DROP_IN_PATH))?;
    let mode = metadata.permissions().mode() & 0o7777;
    let sha256 = sha256_bytes(&bytes);
    if accepted.canonical_target != RUNNER_DROP_IN_PATH
        || fs::canonicalize(RUNNER_DROP_IN_PATH).ok().as_deref()
            != Some(Path::new(accepted.canonical_target))
        || mode != parse_reviewed_mode(accepted.mode)?
        || !policy_source_metadata_is_safe(&metadata)
        || !source_accepts_sha256(&accepted, &sha256)
    {
        return Err(unsupported_fingerprint());
    }
    Ok(SudoRollbackSource {
        bytes,
        mode,
        uid: metadata.uid(),
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        sha256,
    })
}

fn rollback_source_matches_pin(source: &SudoRollbackSource, pin: &SudoPolicySourcePin) -> bool {
    pin.path_class == "drop_in"
        && pin.name == "runner"
        && source.mode == pin.mode
        && source.uid == pin.uid
        && source.gid == pin.gid
        && source.device == pin.device
        && source.inode == pin.inode
        && source.sha256 == pin.sha256
}

fn remove_captured_runner_sudo_source(captured: &SudoRollbackSource) -> Result<(), LockdownError> {
    let current = capture_runner_sudo_source()?;
    if current != *captured {
        return Err(LockdownError::new(
            "sudo_lockdown_failed",
            "accepted runner sudo policy source changed before removal",
        ));
    }
    fs::remove_file(RUNNER_DROP_IN_PATH).map_err(|_| {
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
        Path::new(RUNNER_DROP_IN_PATH),
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
    let restored = capture_runner_sudo_source().map_err(|_| {
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
    let accepted_sources = hosted_runner_fingerprint_requirement()
        .accepted
        .sudo_policy_sources;
    verify_sudo_sources(&accepted_sources).map_err(|_| {
        LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "restored sudo policy inventory no longer matches the accepted state",
        )
    })?;
    require_success(
        fixed_command(executables, TrustedExecutable::Visudo, &["--check"]).map_err(|_| {
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
    verify_sudo_sources(&accepted_sources).map_err(|_| {
        LockdownError::new(
            "sudo_restore_verification_rollback_failed",
            "restored sudo policy inventory changed during capability verification",
        )
    })?;
    Ok(())
}

#[cfg(test)]
fn sha256_bounded_file(path: &Path) -> Result<String, LockdownError> {
    let bytes = read_bounded_policy_file(path)?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hexadecimal = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
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
    let output = run_fixed_command_with_timeout(command, &[], timeout)?;
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

fn fixed_command(
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
    run_fixed_command_with_timeout(command, arguments, timeout)
}

fn runner_command(
    executables: &TrustedExecutableSet,
    executable: TrustedExecutable,
    arguments: &[&str],
) -> Result<Output, LockdownError> {
    let command = executables
        .runner_command(executable, arguments)
        .map_err(|_| unsupported_fingerprint())?;
    run_fixed_command_with_timeout(command, &[], COMMAND_TIMEOUT)
}

fn run_fixed_command_with_timeout(
    mut command: Command,
    arguments: &[&str],
    timeout: Duration,
) -> Result<Output, LockdownError> {
    let mut child = command
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| unsupported_fingerprint())?;
    let deadline = Instant::now() + timeout;
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
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_INDEX: AtomicUsize = AtomicUsize::new(0);

    struct FakeControl {
        operations: Rc<RefCell<Vec<&'static str>>>,
        rollback_result: Result<bool, LockdownError>,
    }

    impl FakeControl {
        fn new() -> Self {
            Self {
                operations: Rc::new(RefCell::new(Vec::new())),
                rollback_result: Ok(true),
            }
        }

        fn with_rollback_error(error: LockdownError) -> Self {
            Self {
                operations: Rc::new(RefCell::new(Vec::new())),
                rollback_result: Err(error),
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
            name,
            mode: 0o440,
            uid: 0,
            gid: 0,
            device: 1,
            inode: 2,
            sha256: format!("digest-{name}"),
        }
    }

    #[test]
    fn fingerprint_v2_builds_the_exact_runner_access_probe_plan() {
        let accepted = hosted_runner_fingerprint_requirement().accepted;
        let plan = runner_access_probe_plan(&accepted);
        assert_eq!(
            plan.len(),
            accepted.trusted_executables.len() * 2
                + accepted.permission_ancestor_directories.len() * 2
                + accepted.sudo_policy_sources.len()
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
            accepted.trusted_executables.len()
                + accepted.permission_ancestor_directories.len()
                + accepted.sudo_policy_sources.len()
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
        for source in &accepted.sudo_policy_sources {
            assert_eq!(
                by_path.get(source.canonical_target).unwrap(),
                &vec![RunnerAccessProbe::NotWritable]
            );
        }
        assert_eq!(
            by_path.get(SUDOERS_DROP_IN_ROOT).unwrap(),
            &vec![
                RunnerAccessProbe::NotWritable,
                RunnerAccessProbe::NotExecutable
            ]
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
                "containers_available",
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
        let mut sudo_rollback = SudoRollbackState::RollbackAvailable(test_rollback_source());
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
        let mut sudo_rollback = SudoRollbackState::RollbackAvailable(test_rollback_source());
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

        let mut sudo_rollback = SudoRollbackState::RollbackAvailable(test_rollback_source());
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
        let mut sudo_rollback = SudoRollbackState::RollbackAvailable(test_rollback_source());
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
    fn locked_sudo_inventory_requires_exact_files_and_runner_absence() {
        let root = PathBuf::from(format!(
            "target/tmp/lockdown-inventory-unit-{}",
            TEST_INDEX.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("README"), b"readme").unwrap();
        fs::write(root.join("90-cloud-init-users"), b"cloud init").unwrap();

        verify_drop_in_inventory(&root, &["90-cloud-init-users", "README"]).unwrap();
        let runner = root.join("runner");
        require_policy_source_absent(&runner).unwrap();

        fs::write(&runner, b"runner grant").unwrap();
        assert_eq!(
            require_policy_source_absent(&runner).unwrap_err().code,
            "sudo_lockdown_failed"
        );
        assert_eq!(
            verify_drop_in_inventory(&root, &["90-cloud-init-users", "README"])
                .unwrap_err()
                .code,
            "unsupported_host_fingerprint"
        );
        fs::remove_file(&runner).unwrap();

        let target = root.join("target");
        fs::write(&target, b"target").unwrap();
        symlink(fs::canonicalize(&target).unwrap(), &runner).unwrap();
        assert_eq!(
            require_policy_source_absent(&runner).unwrap_err().code,
            "sudo_lockdown_failed"
        );
        assert_eq!(
            verify_drop_in_inventory(&root, &["90-cloud-init-users", "README", "target"])
                .unwrap_err()
                .code,
            "unsupported_host_fingerprint"
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
        assert!(remaining_sudo_source_pins_match(&observed, &pinned));

        observed[1].inode += 1;
        assert!(!remaining_sudo_source_pins_match(&observed, &pinned));
        observed[1].inode -= 1;
        observed[1].mode = 0o400;
        assert!(!remaining_sudo_source_pins_match(&observed, &pinned));
        observed[1].mode = 0o440;
        observed[1].sha256 = "different-digest".to_owned();
        assert!(!remaining_sudo_source_pins_match(&observed, &pinned));
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
