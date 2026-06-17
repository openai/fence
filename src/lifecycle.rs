use crate::config::Mode;
use crate::findings::{ConnectionFinding, FindingCollection, bounded_timestamp_now};
use crate::nflog::{NflogError, NflogReader};
use crate::nft::{NetworkEvidenceCounters, OwnedNftState, expected_dns_mediated_owned_state};
use crate::nft_backend::{BackendError, NativeNftBackend, SystemNftExecutor};
use crate::plan::{AssuranceStatus, PlanData};
use crate::runtime::{RESIDENT_EVIDENCE_STATUS, RuntimeError, TEST_READY_STATUS, TestRuntimeStore};
use serde::Serialize;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const RESIDENT_VERIFICATION_INTERVAL: Duration = Duration::from_secs(5);
pub const PRODUCTION_SERVICE_PREFIX: &str = "fence-";
const FINDING_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_CRITICAL_FINDINGS: usize = 64;
const SYSTEMD_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LifecycleError {
    pub code: &'static str,
    pub message: String,
}

impl LifecycleError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<BackendError> for LifecycleError {
    fn from(error: BackendError) -> Self {
        Self::new(error.code, error.message)
    }
}

impl From<NflogError> for LifecycleError {
    fn from(error: NflogError) -> Self {
        Self::new(error.code, error.message)
    }
}

impl From<RuntimeError> for LifecycleError {
    fn from(error: RuntimeError) -> Self {
        Self::new(error.code, error.message)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct CriticalFinding {
    pub timestamp: String,
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ResidentEvidence {
    pub status: &'static str,
    pub mode: Mode,
    pub assurance_status: AssuranceStatus,
    pub policy_hash: String,
    pub ruleset_hash: String,
    pub setup_status: &'static str,
    pub application_status: &'static str,
    pub verification_status: &'static str,
    pub readiness_status: &'static str,
    pub rollback_status: &'static str,
    pub verification_interval_seconds: u64,
    pub counters: NetworkEvidenceCounters,
    pub findings: Vec<ConnectionFinding>,
    pub findings_truncated: bool,
    pub critical_findings: Vec<CriticalFinding>,
    pub critical_findings_truncated: bool,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct ResidentState<'a> {
    status: &'static str,
    mode: Mode,
    policy_hash: &'a str,
    ruleset_hash: &'a str,
    planned_owned_state: &'a OwnedNftState,
}

#[derive(Debug, Serialize)]
struct TestOnlyReady<'a> {
    status: &'static str,
    mode: Mode,
    assurance_status: AssuranceStatus,
    policy_hash: &'a str,
    ruleset_hash: &'a str,
    protection_available: bool,
    limitations: Vec<&'static str>,
}

pub trait ResidentNetwork {
    fn bind_findings(&mut self, mode: Mode) -> Result<(), LifecycleError>;
    fn preflight(&mut self, ruleset: &str) -> Result<(), LifecycleError>;
    fn apply_provisional(&mut self, ruleset: &str) -> Result<(), LifecycleError>;
    fn verify_owned_state(&mut self, expected: &OwnedNftState) -> Result<(), LifecycleError>;
    fn total_violation_packets(&mut self) -> Result<u64, LifecycleError>;
    fn next_finding(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ConnectionFinding>, LifecycleError>;
    fn rollback_pre_ready(&mut self) -> Result<bool, LifecycleError>;
}

pub struct NativeResidentNetwork {
    backend: NativeNftBackend<SystemNftExecutor>,
    reader: Option<NflogReader>,
}

impl NativeResidentNetwork {
    pub fn in_current_namespace() -> Self {
        Self {
            backend: NativeNftBackend::new(SystemNftExecutor::host()),
            reader: None,
        }
    }
}

impl ResidentNetwork for NativeResidentNetwork {
    fn bind_findings(&mut self, mode: Mode) -> Result<(), LifecycleError> {
        self.reader = Some(NflogReader::bind(mode)?);
        Ok(())
    }

    fn preflight(&mut self, ruleset: &str) -> Result<(), LifecycleError> {
        self.backend.preflight(ruleset).map_err(Into::into)
    }

    fn apply_provisional(&mut self, ruleset: &str) -> Result<(), LifecycleError> {
        self.backend.apply_provisional(ruleset).map_err(Into::into)
    }

    fn verify_owned_state(&mut self, expected: &OwnedNftState) -> Result<(), LifecycleError> {
        self.backend
            .verify_owned_state(expected)
            .map_err(Into::into)
    }

    fn total_violation_packets(&mut self) -> Result<u64, LifecycleError> {
        self.backend.total_violation_packets().map_err(Into::into)
    }

    fn next_finding(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ConnectionFinding>, LifecycleError> {
        let reader = self.reader.as_ref().ok_or_else(|| {
            LifecycleError::new(
                "nflog_not_bound",
                "resident evidence must bind NFLOG before activation",
            )
        })?;
        reader.next_finding(timeout).map_err(Into::into)
    }

    fn rollback_pre_ready(&mut self) -> Result<bool, LifecycleError> {
        self.backend.rollback_pre_activation().map_err(Into::into)
    }
}

pub struct ResidentSession<N: ResidentNetwork> {
    network: N,
    runtime: TestRuntimeStore,
    expected_state: OwnedNftState,
    evidence: ResidentEvidence,
    findings: FindingCollection,
    next_verification: Duration,
}

impl<N: ResidentNetwork> ResidentSession<N> {
    pub fn establish_test_only(
        runtime: TestRuntimeStore,
        plan: &PlanData,
        network: N,
    ) -> Result<Self, LifecycleError> {
        let expected_state =
            expected_dns_mediated_owned_state(plan.selected_mode, &plan.effective_policy);
        Self::establish_test_only_with_expected(runtime, plan, network, expected_state)
    }

    pub fn establish_test_only_with_expected(
        runtime: TestRuntimeStore,
        plan: &PlanData,
        network: N,
        expected_state: OwnedNftState,
    ) -> Result<Self, LifecycleError> {
        let evidence = ResidentEvidence {
            status: RESIDENT_EVIDENCE_STATUS,
            mode: plan.selected_mode,
            assurance_status: plan.assurance_status,
            policy_hash: plan.policy_hash.clone(),
            ruleset_hash: plan.ruleset_hash.clone(),
            setup_status: "setting_up",
            application_status: "not_applied",
            verification_status: "not_verified",
            readiness_status: "not_emitted",
            rollback_status: "not_required",
            verification_interval_seconds: RESIDENT_VERIFICATION_INTERVAL.as_secs(),
            counters: NetworkEvidenceCounters {
                total_violations: 0,
                sampled_violations: 0,
            },
            findings: Vec::new(),
            findings_truncated: false,
            critical_findings: Vec::new(),
            critical_findings_truncated: false,
            limitations: vec![
                "resident_lifecycle_test_only_no_public_activation",
                "test_ready_is_not_a_protection_assertion",
                "sudo_lockdown_not_implemented",
                "container_lockdown_not_implemented",
                "packet_prefixes_transiently_inspected_in_memory_not_serialized",
            ],
        };
        runtime.write_state_exclusive(&ResidentState {
            status: RESIDENT_EVIDENCE_STATUS,
            mode: plan.selected_mode,
            policy_hash: &plan.policy_hash,
            ruleset_hash: &plan.ruleset_hash,
            planned_owned_state: &expected_state,
        })?;
        runtime.replace_report(&evidence)?;

        let mut session = Self {
            network,
            runtime,
            expected_state,
            evidence,
            findings: FindingCollection::empty(),
            next_verification: RESIDENT_VERIFICATION_INTERVAL,
        };
        if let Err(error) = session.activate_network(plan) {
            session.rollback_failed_setup();
            return Err(error);
        }

        session.evidence.setup_status = "verified_before_test_ready";
        if let Err(error) = session.runtime.replace_report(&session.evidence) {
            session.rollback_failed_setup();
            return Err(error.into());
        }
        if let Err(error) = session.runtime.write_ready_exclusive(&TestOnlyReady {
            status: TEST_READY_STATUS,
            mode: plan.selected_mode,
            assurance_status: plan.assurance_status,
            policy_hash: &plan.policy_hash,
            ruleset_hash: &plan.ruleset_hash,
            protection_available: false,
            limitations: vec![
                "resident_lifecycle_test_only_no_public_activation",
                "sudo_lockdown_not_implemented",
                "container_lockdown_not_implemented",
            ],
        }) {
            session.rollback_failed_setup();
            return Err(error.into());
        }
        session.evidence.setup_status = "resident_test_only";
        session.evidence.readiness_status = TEST_READY_STATUS;
        session.runtime.replace_report(&session.evidence)?;
        Ok(session)
    }

    fn activate_network(&mut self, plan: &PlanData) -> Result<(), LifecycleError> {
        self.network.bind_findings(plan.selected_mode)?;
        self.network
            .preflight(&plan.network_enforcement_preview.ruleset)?;
        self.network
            .apply_provisional(&plan.network_enforcement_preview.ruleset)?;
        self.evidence.application_status = "applied";
        self.network.verify_owned_state(&self.expected_state)?;
        self.evidence.verification_status = "verified";
        self.evidence.counters.total_violations = self.network.total_violation_packets()?;
        Ok(())
    }

    fn rollback_failed_setup(&mut self) {
        self.evidence.setup_status = "failed_pre_ready";
        self.evidence.verification_status = "failed_pre_ready";
        self.evidence.readiness_status = "not_emitted";
        self.evidence.rollback_status = match self.network.rollback_pre_ready() {
            Ok(true) => "rolled_back_pre_ready",
            Ok(false) => "nothing_to_rollback",
            Err(_) => "rollback_failed",
        };
        let _ = self.runtime.replace_report(&self.evidence);
    }

    pub fn poll_once(
        &mut self,
        elapsed: Duration,
        finding_timeout: Duration,
    ) -> Result<(), LifecycleError> {
        let mut changed = false;
        let mut finding_received = false;
        match self.network.next_finding(finding_timeout) {
            Ok(Some(finding)) => {
                self.findings.record_finding(finding);
                finding_received = true;
                changed = true;
            }
            Ok(None) => {}
            Err(_) => {
                self.record_critical(
                    "resident_nflog_failure",
                    "resident NFLOG collection failed after test readiness",
                );
                changed = true;
            }
        }
        let verification_due = elapsed >= self.next_verification;
        if verification_due {
            match self.network.verify_owned_state(&self.expected_state) {
                Ok(()) => {
                    self.evidence.verification_status = "verified";
                }
                Err(_) => {
                    self.evidence.verification_status = "critical_drift";
                    self.record_critical(
                        "resident_network_drift",
                        "owned nftables state drifted after test readiness",
                    );
                }
            }
            match self.network.total_violation_packets() {
                Ok(total) => self.evidence.counters.total_violations = total,
                Err(_) => self.record_critical(
                    "resident_counter_read_failed",
                    "owned violation counter could not be read after test readiness",
                ),
            }
            self.next_verification = elapsed + RESIDENT_VERIFICATION_INTERVAL;
            changed = true;
        } else if finding_received {
            match self.network.total_violation_packets() {
                Ok(total) => self.evidence.counters.total_violations = total,
                Err(_) => self.record_critical(
                    "resident_counter_read_failed",
                    "owned violation counter could not be read after a sampled finding",
                ),
            }
        }
        if changed {
            self.evidence.findings = self.findings.retained.clone();
            self.evidence.findings_truncated = self.findings.truncated;
            self.evidence.counters.sampled_violations = self.findings.sampled_total;
            self.runtime.replace_report(&self.evidence)?;
        }
        Ok(())
    }

    fn record_critical(&mut self, code: &'static str, message: &'static str) {
        if self.evidence.critical_findings.len() == MAX_CRITICAL_FINDINGS {
            self.evidence.critical_findings_truncated = true;
            return;
        }
        self.evidence.critical_findings.push(CriticalFinding {
            timestamp: bounded_timestamp_now(),
            code,
            message,
        });
    }
}

pub fn validate_test_service_context(unit_name: &str) -> Result<(), LifecycleError> {
    if !valid_test_service_name(unit_name) {
        return Err(LifecycleError::new(
            "invalid_test_service_name",
            "resident test service name must use the bounded Fence evidence prefix",
        ));
    }
    validate_service_main_pid(
        query_service_main_pid(unit_name)?,
        std::process::id(),
        "trusted_test_service_required",
        "resident test lifecycle must execute as the matching transient service main process",
    )
}

pub fn validate_production_service_context(invocation_id: &str) -> Result<(), LifecycleError> {
    let unit_name = production_service_name(invocation_id)?;
    let effective_uid = production_effective_uid()?;
    validate_production_service_identity(
        invocation_id,
        effective_uid,
        query_service_main_pid(&unit_name)?,
        std::process::id(),
    )
}

pub fn require_production_root_process() -> Result<(), LifecycleError> {
    if production_effective_uid()? == 0 {
        Ok(())
    } else {
        Err(LifecycleError::new(
            "trusted_launcher_required",
            "protected lifecycle must execute as root inside its matching transient service",
        ))
    }
}

fn production_effective_uid() -> Result<u32, LifecycleError> {
    fs::metadata("/proc/self")
        .map_err(|error| LifecycleError::new("trusted_launcher_required", error.to_string()))
        .map(|metadata| metadata.uid())
}

fn query_service_main_pid(unit_name: &str) -> Result<Option<u32>, LifecycleError> {
    let mut child = Command::new("/usr/bin/systemctl")
        .args(["show", "--property=MainPID", "--value", unit_name])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| LifecycleError::new("systemd_query_failed", error.to_string()))?;
    let deadline = Instant::now() + SYSTEMD_QUERY_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LifecycleError::new(
                    "systemd_query_timeout",
                    "resident service identity query exceeded its deadline",
                ));
            }
            Err(error) => {
                return Err(LifecycleError::new(
                    "systemd_query_failed",
                    error.to_string(),
                ));
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| LifecycleError::new("systemd_query_failed", error.to_string()))?;
    if !output.status.success() || output.stdout.len() > 64 {
        return Err(LifecycleError::new(
            "systemd_query_failed",
            "unable to observe bounded resident service identity",
        ));
    }
    let observed = std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    Ok(observed)
}

fn valid_test_service_name(name: &str) -> bool {
    let Some(slug) = name
        .strip_prefix("fence-evidence-")
        .and_then(|name| name.strip_suffix(".service"))
    else {
        return false;
    };
    !slug.is_empty()
        && slug.len() <= 48
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.as_bytes().windows(2).any(|pair| pair == b"--")
}

fn production_service_name(invocation_id: &str) -> Result<String, LifecycleError> {
    if !valid_service_slug(invocation_id, 64) {
        return Err(LifecycleError::new(
            "invalid_runtime_identifier",
            "trusted launcher invocation identifier must use the bounded lowercase slug format",
        ));
    }
    Ok(format!(
        "{PRODUCTION_SERVICE_PREFIX}{invocation_id}.service"
    ))
}

fn valid_service_slug(value: &str, maximum_length: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.as_bytes().windows(2).any(|pair| pair == b"--")
}

fn validate_production_service_identity(
    invocation_id: &str,
    effective_uid: u32,
    observed: Option<u32>,
    current: u32,
) -> Result<(), LifecycleError> {
    production_service_name(invocation_id)?;
    if effective_uid != 0 {
        return Err(LifecycleError::new(
            "trusted_launcher_required",
            "protected lifecycle must execute as root inside its matching transient service",
        ));
    }
    validate_service_main_pid(
        observed,
        current,
        "trusted_launcher_required",
        "protected lifecycle must execute as root inside its matching transient service",
    )
}

fn validate_service_main_pid(
    observed: Option<u32>,
    current: u32,
    code: &'static str,
    message: &'static str,
) -> Result<(), LifecycleError> {
    if observed == Some(current) {
        Ok(())
    } else {
        Err(LifecycleError::new(code, message))
    }
}

pub fn run_resident_test_service(
    unit_name: &str,
    runtime_root: &Path,
    plan: &PlanData,
    expected_state: Option<OwnedNftState>,
) -> Result<(), LifecycleError> {
    validate_test_service_context(unit_name)?;
    let runtime = TestRuntimeStore::create(runtime_root, &plan.invocation_id)?;
    let network = NativeResidentNetwork::in_current_namespace();
    let mut session = match expected_state {
        Some(expected) => {
            ResidentSession::establish_test_only_with_expected(runtime, plan, network, expected)?
        }
        None => ResidentSession::establish_test_only(runtime, plan, network)?,
    };
    let start = Instant::now();
    loop {
        session.poll_once(start.elapsed(), FINDING_POLL_INTERVAL)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_and_normalize;
    use crate::findings::finding_from_prefix;
    use crate::plan::build_plan;
    use crate::resolver::{Resolution, ResolveError, Resolver};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_INDEX: AtomicUsize = AtomicUsize::new(0);

    struct LiteralResolver;

    impl Resolver for LiteralResolver {
        fn resolve(&self, _hostname: &str, _timeout: Duration) -> Result<Resolution, ResolveError> {
            panic!("unit lifecycle fixtures contain literal destinations only");
        }
    }

    struct FakeNetwork {
        operations: RefCell<Vec<&'static str>>,
        verify: VecDeque<Result<(), LifecycleError>>,
        findings: VecDeque<Result<Option<ConnectionFinding>, LifecycleError>>,
        total: VecDeque<Result<u64, LifecycleError>>,
        rollback: Result<bool, LifecycleError>,
    }

    impl FakeNetwork {
        fn healthy() -> Self {
            Self {
                operations: RefCell::new(Vec::new()),
                verify: VecDeque::from([Ok(()), Ok(())]),
                findings: VecDeque::from([Ok(None), Ok(None)]),
                total: VecDeque::from([Ok(0), Ok(0)]),
                rollback: Ok(true),
            }
        }
    }

    impl ResidentNetwork for FakeNetwork {
        fn bind_findings(&mut self, _mode: Mode) -> Result<(), LifecycleError> {
            self.operations.borrow_mut().push("bind");
            Ok(())
        }

        fn preflight(&mut self, _ruleset: &str) -> Result<(), LifecycleError> {
            self.operations.borrow_mut().push("preflight");
            Ok(())
        }

        fn apply_provisional(&mut self, _ruleset: &str) -> Result<(), LifecycleError> {
            self.operations.borrow_mut().push("apply");
            Ok(())
        }

        fn verify_owned_state(&mut self, _expected: &OwnedNftState) -> Result<(), LifecycleError> {
            self.operations.borrow_mut().push("verify");
            self.verify.pop_front().unwrap_or(Ok(()))
        }

        fn total_violation_packets(&mut self) -> Result<u64, LifecycleError> {
            self.operations.borrow_mut().push("counter");
            self.total.pop_front().unwrap_or(Ok(0))
        }

        fn next_finding(
            &mut self,
            _timeout: Duration,
        ) -> Result<Option<ConnectionFinding>, LifecycleError> {
            self.operations.borrow_mut().push("finding");
            self.findings.pop_front().unwrap_or(Ok(None))
        }

        fn rollback_pre_ready(&mut self) -> Result<bool, LifecycleError> {
            self.operations.borrow_mut().push("rollback");
            self.rollback.clone()
        }
    }

    fn plan(invocation: &str) -> PlanData {
        let json = format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"{invocation}","allowlist":[]}}"#
        );
        build_plan(
            parse_and_normalize(json.as_bytes()).unwrap(),
            &LiteralResolver,
        )
        .unwrap()
    }

    fn root() -> std::path::PathBuf {
        std::path::PathBuf::from(format!(
            "target/tmp/lifecycle-unit-{}",
            TEST_INDEX.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn establishes_only_test_readiness_in_required_order_and_records_drift() {
        let root = root();
        let plan = plan("resident-proof");
        let runtime = TestRuntimeStore::create(&root, "resident-proof").unwrap();
        let mut network = FakeNetwork::healthy();
        network.verify = VecDeque::from([
            Ok(()),
            Err(LifecycleError::new("drift", "test injected drift")),
        ]);
        network.findings = VecDeque::from([
            Ok(Some(finding_from_prefix(Mode::Block, "t".to_owned(), &[0]))),
            Ok(None),
        ]);
        network.total = VecDeque::from([Ok(0), Ok(1), Ok(1)]);
        let mut session = ResidentSession::establish_test_only(runtime, &plan, network).unwrap();
        assert_eq!(
            session.expected_state,
            expected_dns_mediated_owned_state(plan.selected_mode, &plan.effective_policy)
        );
        assert_eq!(
            *session.network.operations.borrow(),
            vec!["bind", "preflight", "apply", "verify", "counter"]
        );
        session
            .poll_once(Duration::from_secs(4), Duration::ZERO)
            .unwrap();
        assert_eq!(session.evidence.verification_status, "verified");
        assert_eq!(session.evidence.counters.sampled_violations, 1);
        assert_eq!(session.evidence.counters.total_violations, 1);
        session
            .poll_once(Duration::from_secs(5), Duration::ZERO)
            .unwrap();
        assert_eq!(session.evidence.verification_status, "critical_drift");
        assert_eq!(session.evidence.critical_findings.len(), 1);
        assert_eq!(session.evidence.readiness_status, TEST_READY_STATUS);
        assert!(session.runtime.ready.exists());
        assert!(
            fs::read_to_string(&session.runtime.ready)
                .unwrap()
                .contains("\"protection_available\":false")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pre_ready_verification_failure_rolls_back_without_ready_evidence() {
        let root = root();
        let plan = plan("setup-failure");
        let runtime = TestRuntimeStore::create(&root, "setup-failure").unwrap();
        let mut network = FakeNetwork::healthy();
        network.verify = VecDeque::from([Err(LifecycleError::new("mismatch", "mismatch"))]);
        let error = ResidentSession::establish_test_only(runtime.clone(), &plan, network)
            .err()
            .unwrap();
        assert_eq!(error.code, "mismatch");
        assert!(!runtime.ready.exists());
        let report = fs::read_to_string(&runtime.report).unwrap();
        assert!(report.contains("\"rollback_status\":\"rolled_back_pre_ready\""));
        assert!(report.contains("\"readiness_status\":\"not_emitted\""));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pre_ready_ready_file_failure_rolls_back_applied_network_state() {
        let root = root();
        let plan = plan("ready-failure");
        let runtime = TestRuntimeStore::create(&root, "ready-failure").unwrap();
        runtime
            .write_ready_exclusive(&serde_json::json!({"occupied": true}))
            .unwrap();
        let error =
            ResidentSession::establish_test_only(runtime.clone(), &plan, FakeNetwork::healthy())
                .err()
                .unwrap();
        assert_eq!(error.code, "runtime_write_failed");
        let report = fs::read_to_string(&runtime.report).unwrap();
        assert!(report.contains("\"rollback_status\":\"rolled_back_pre_ready\""));
        assert!(report.contains("\"readiness_status\":\"not_emitted\""));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounds_critical_findings_and_checks_transient_service_identity() {
        assert!(valid_test_service_name("fence-evidence-proof-1.service"));
        assert!(!valid_test_service_name("fence.service"));
        assert!(!valid_test_service_name("fence-evidence-proof--1.service"));
        assert!(
            validate_service_main_pid(
                Some(12),
                12,
                "trusted_test_service_required",
                "test message",
            )
            .is_ok()
        );
        assert_eq!(
            validate_service_main_pid(
                Some(13),
                12,
                "trusted_test_service_required",
                "test message",
            )
            .unwrap_err()
            .code,
            "trusted_test_service_required"
        );
        assert_eq!(
            production_service_name("protected-run").unwrap(),
            "fence-protected-run.service"
        );
        assert_eq!(
            production_service_name("protected--run").unwrap_err().code,
            "invalid_runtime_identifier"
        );
        assert!(validate_production_service_identity("protected-run", 0, Some(12), 12).is_ok());
        assert_eq!(
            validate_production_service_identity("protected-run", 501, Some(12), 12)
                .unwrap_err()
                .code,
            "trusted_launcher_required"
        );
        assert_eq!(
            validate_production_service_identity("protected-run", 0, Some(13), 12)
                .unwrap_err()
                .code,
            "trusted_launcher_required"
        );
        assert_eq!(
            validate_production_service_identity("../bad", 0, Some(12), 12)
                .unwrap_err()
                .code,
            "invalid_runtime_identifier"
        );

        let root = root();
        let plan = plan("critical-bounds");
        let runtime = TestRuntimeStore::create(&root, "critical-bounds").unwrap();
        let mut session =
            ResidentSession::establish_test_only(runtime, &plan, FakeNetwork::healthy()).unwrap();
        for _ in 0..=MAX_CRITICAL_FINDINGS {
            session.record_critical("drift", "drift");
        }
        assert_eq!(
            session.evidence.critical_findings.len(),
            MAX_CRITICAL_FINDINGS
        );
        assert!(session.evidence.critical_findings_truncated);
        fs::remove_dir_all(root).unwrap();
    }
}
