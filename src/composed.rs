use crate::config::{ContainerPolicy, DestinationType, Mode, Protocol};
use crate::findings::{ConnectionFinding, FindingCollection, bounded_timestamp_now};
use crate::lifecycle::{
    CriticalFinding, LifecycleError, NativeResidentNetwork, RESIDENT_VERIFICATION_INTERVAL,
    ResidentNetwork, validate_test_service_context,
};
use crate::lockdown::{LockdownControl, LockdownError, SystemLockdownControl};
use crate::nft::{NetworkEvidenceCounters, OwnedNftState, expected_owned_state};
use crate::plan::{AssuranceStatus, PlanData};
use crate::runtime::{RuntimeError, TestRuntimeStore};
use serde::Serialize;
use std::path::Path;
use std::time::{Duration, Instant};

pub const COMPOSED_EVIDENCE_STATUS: &str = "composed_lifecycle_test_only";
pub const COMPOSED_READY_STATUS: &str = "composed_test_only_ready_no_protection";
pub const HOST_BLOCK_CANDIDATE_EVIDENCE_STATUS: &str = "host_block_candidate_test_only";
pub const HOST_BLOCK_CANDIDATE_READY_STATUS: &str =
    "host_block_candidate_ready_no_public_activation";
const FINDING_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_CRITICAL_FINDINGS: usize = 64;
const DOCUMENTED_RESULTS_RECEIVER: &str = "results-receiver.actions.githubusercontent.com";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum EvidenceScope {
    NamespaceComposition,
    HostBlockCandidate,
}

impl EvidenceScope {
    fn status(self) -> &'static str {
        match self {
            Self::NamespaceComposition => COMPOSED_EVIDENCE_STATUS,
            Self::HostBlockCandidate => HOST_BLOCK_CANDIDATE_EVIDENCE_STATUS,
        }
    }

    fn ready_status(self) -> &'static str {
        match self {
            Self::NamespaceComposition => COMPOSED_READY_STATUS,
            Self::HostBlockCandidate => HOST_BLOCK_CANDIDATE_READY_STATUS,
        }
    }

    fn assurance_status(self) -> &'static str {
        match self {
            Self::NamespaceComposition => "composed_controls_verified_test_only",
            Self::HostBlockCandidate => "host_block_candidate_verified_test_only",
        }
    }

    fn resident_setup_status(self) -> &'static str {
        match self {
            Self::NamespaceComposition => "resident_composed_test_only",
            Self::HostBlockCandidate => "resident_host_block_candidate_test_only",
        }
    }

    fn limitations(self) -> Vec<&'static str> {
        match self {
            Self::NamespaceComposition => vec![
                "composed_lifecycle_test_only_no_public_activation",
                "network_policy_is_namespace_isolated_not_host_protection",
                "no_platform_profile_or_host_finalization_proof",
                "packet_prefixes_transiently_inspected_in_memory_not_serialized",
            ],
            Self::HostBlockCandidate => vec![
                "host_block_candidate_test_only_no_public_activation",
                "documented_results_receiver_encoded_as_test_allowance_not_selected_profile",
                "permitted_candidate_destination_is_available_to_later_code",
                "minimal_finalization_candidate_not_general_compatibility",
                "no_action_wrapper_or_supported_agent_release",
                "packet_prefixes_transiently_inspected_in_memory_not_serialized",
            ],
        }
    }

    fn ready_limitations(self) -> Vec<&'static str> {
        match self {
            Self::NamespaceComposition => vec![
                "composed_lifecycle_test_only_no_public_activation",
                "network_policy_is_namespace_isolated_not_host_protection",
                "test_ready_is_not_a_protection_assertion",
            ],
            Self::HostBlockCandidate => vec![
                "host_block_candidate_test_only_no_public_activation",
                "documented_results_receiver_encoded_as_test_allowance_not_selected_profile",
                "permitted_candidate_destination_is_available_to_later_code",
                "minimal_finalization_candidate_not_general_compatibility",
                "test_ready_is_not_a_public_protection_assertion",
            ],
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ComposedError {
    pub code: &'static str,
    pub message: String,
}

impl ComposedError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<LifecycleError> for ComposedError {
    fn from(error: LifecycleError) -> Self {
        Self::new(error.code, error.message)
    }
}

impl From<LockdownError> for ComposedError {
    fn from(error: LockdownError) -> Self {
        Self::new(error.code, error.message)
    }
}

impl From<RuntimeError> for ComposedError {
    fn from(error: RuntimeError) -> Self {
        Self::new(error.code, error.message)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ComposedEvidence {
    pub status: &'static str,
    pub mode: Mode,
    pub assurance_status: &'static str,
    pub policy_hash: String,
    pub ruleset_hash: String,
    pub setup_status: &'static str,
    pub network_application_status: &'static str,
    pub network_verification_status: &'static str,
    pub sudo_status: &'static str,
    pub container_status: &'static str,
    pub readiness_status: &'static str,
    pub rollback_status: &'static str,
    pub verification_interval_seconds: u64,
    pub counters: NetworkEvidenceCounters,
    pub findings: Vec<ConnectionFinding>,
    pub findings_truncated: bool,
    pub critical_findings: Vec<CriticalFinding>,
    pub critical_findings_truncated: bool,
    pub protection_available: bool,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct ComposedState<'a> {
    status: &'static str,
    mode: Mode,
    policy_hash: &'a str,
    ruleset_hash: &'a str,
    planned_owned_state: &'a OwnedNftState,
    readiness_status: &'static str,
}

#[derive(Debug, Serialize)]
struct ComposedReady<'a> {
    status: &'static str,
    mode: Mode,
    policy_hash: &'a str,
    ruleset_hash: &'a str,
    protection_available: bool,
    limitations: Vec<&'static str>,
}

pub struct ComposedSession<N: ResidentNetwork, C: LockdownControl> {
    network: N,
    lockdown: C,
    runtime: TestRuntimeStore,
    expected_state: OwnedNftState,
    evidence: ComposedEvidence,
    findings: FindingCollection,
    next_verification: Duration,
    scope: EvidenceScope,
}

impl<N: ResidentNetwork, C: LockdownControl> ComposedSession<N, C> {
    pub fn establish_test_only(
        runtime: TestRuntimeStore,
        plan: &PlanData,
        network: N,
        lockdown: C,
    ) -> Result<Self, ComposedError> {
        Self::establish_with_scope(
            runtime,
            plan,
            network,
            lockdown,
            EvidenceScope::NamespaceComposition,
        )
    }

    fn establish_with_scope(
        runtime: TestRuntimeStore,
        plan: &PlanData,
        network: N,
        lockdown: C,
        scope: EvidenceScope,
    ) -> Result<Self, ComposedError> {
        validate_standard_block_plan(plan)?;
        let expected_state = expected_owned_state(plan.selected_mode, &plan.effective_policy);
        let evidence = initial_evidence(plan, scope);
        runtime.write_state_exclusive(&ComposedState {
            status: scope.status(),
            mode: plan.selected_mode,
            policy_hash: &plan.policy_hash,
            ruleset_hash: &plan.ruleset_hash,
            planned_owned_state: &expected_state,
            readiness_status: "not_emitted",
        })?;
        runtime.replace_report(&evidence)?;

        let mut session = Self {
            network,
            lockdown,
            runtime,
            expected_state,
            evidence,
            findings: FindingCollection::empty(),
            next_verification: RESIDENT_VERIFICATION_INTERVAL,
            scope,
        };
        if let Err(error) = session.establish_controls(plan) {
            session.rollback_failed_setup();
            return Err(error);
        }

        session.evidence.setup_status = "verified_before_test_ready";
        if let Err(error) = session.runtime.replace_report(&session.evidence) {
            session.rollback_failed_setup();
            return Err(error.into());
        }
        if let Err(error) = session.runtime.write_ready_exclusive(&ComposedReady {
            status: scope.ready_status(),
            mode: plan.selected_mode,
            policy_hash: &plan.policy_hash,
            ruleset_hash: &plan.ruleset_hash,
            protection_available: false,
            limitations: scope.ready_limitations(),
        }) {
            session.rollback_failed_setup();
            return Err(error.into());
        }
        session.evidence.setup_status = scope.resident_setup_status();
        session.evidence.readiness_status = scope.ready_status();
        session.runtime.replace_report(&session.evidence)?;
        Ok(session)
    }

    fn establish_controls(&mut self, plan: &PlanData) -> Result<(), ComposedError> {
        self.lockdown.verify_supported_host()?;
        self.lockdown.verify_sudo_available()?;
        self.lockdown.verify_containers_available()?;
        self.network.bind_findings(plan.selected_mode)?;
        self.network
            .preflight(&plan.network_enforcement_preview.ruleset)?;
        self.network
            .apply_provisional(&plan.network_enforcement_preview.ruleset)?;
        self.evidence.network_application_status = "applied";
        self.network.verify_owned_state(&self.expected_state)?;
        self.evidence.network_verification_status = "verified";
        self.evidence.counters.total_violations = self.network.total_violation_packets()?;
        self.lockdown.disable_sudo()?;
        self.lockdown.disable_containers()?;
        self.lockdown.verify_sudo_disabled()?;
        self.lockdown.verify_containers_disabled()?;
        self.evidence.sudo_status = "disabled_verified";
        self.evidence.container_status = "disabled_verified";
        Ok(())
    }

    fn rollback_failed_setup(&mut self) {
        self.evidence.setup_status = "failed_pre_ready";
        self.evidence.readiness_status = "not_emitted";
        let lockdown = self.lockdown.rollback_pre_ready();
        let network = self.network.rollback_pre_ready();
        self.evidence.rollback_status = match (lockdown, network) {
            (Ok(lockdown_changed), Ok(network_changed)) if lockdown_changed || network_changed => {
                "rolled_back_pre_ready"
            }
            (Ok(_), Ok(_)) => "nothing_to_rollback",
            _ => "rollback_failed",
        };
        let _ = self.runtime.replace_report(&self.evidence);
    }

    pub fn poll_once(
        &mut self,
        elapsed: Duration,
        finding_timeout: Duration,
    ) -> Result<(), ComposedError> {
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
                    "composed_nflog_failure",
                    "composed test NFLOG collection failed after test readiness",
                );
                changed = true;
            }
        }
        if elapsed >= self.next_verification {
            if self
                .network
                .verify_owned_state(&self.expected_state)
                .is_err()
            {
                self.evidence.network_verification_status = "critical_drift";
                self.record_critical(
                    "composed_network_drift",
                    match self.scope {
                        EvidenceScope::NamespaceComposition => {
                            "namespace-isolated owned nftables state drifted after test readiness"
                        }
                        EvidenceScope::HostBlockCandidate => {
                            "host owned nftables state drifted after candidate test readiness"
                        }
                    },
                );
            }
            if self.lockdown.verify_sudo_disabled().is_err() {
                self.evidence.sudo_status = "critical_drift";
                self.record_critical(
                    "composed_sudo_drift",
                    "measured passwordless sudo state drifted after test readiness",
                );
            }
            if self.lockdown.verify_containers_disabled().is_err() {
                self.evidence.container_status = "critical_drift";
                self.record_critical(
                    "composed_container_drift",
                    "measured container control state drifted after test readiness",
                );
            }
            match self.network.total_violation_packets() {
                Ok(total) => self.evidence.counters.total_violations = total,
                Err(_) => self.record_critical(
                    "composed_counter_read_failed",
                    "owned violation counter could not be read after test readiness",
                ),
            }
            self.next_verification = elapsed + RESIDENT_VERIFICATION_INTERVAL;
            changed = true;
        } else if finding_received {
            match self.network.total_violation_packets() {
                Ok(total) => self.evidence.counters.total_violations = total,
                Err(_) => self.record_critical(
                    "composed_counter_read_failed",
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

fn initial_evidence(plan: &PlanData, scope: EvidenceScope) -> ComposedEvidence {
    ComposedEvidence {
        status: scope.status(),
        mode: plan.selected_mode,
        assurance_status: scope.assurance_status(),
        policy_hash: plan.policy_hash.clone(),
        ruleset_hash: plan.ruleset_hash.clone(),
        setup_status: "setting_up",
        network_application_status: "not_applied",
        network_verification_status: "not_verified",
        sudo_status: "not_checked",
        container_status: "not_checked",
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
        protection_available: false,
        limitations: scope.limitations(),
    }
}

fn validate_standard_block_plan(plan: &PlanData) -> Result<(), ComposedError> {
    if plan.selected_mode != Mode::Block
        || plan.container_policy != Some(ContainerPolicy::Disable)
        || plan.assurance_status != AssuranceStatus::PlannedBlockContainment
    {
        return Err(ComposedError::new(
            "invalid_composed_test_posture",
            "composed lifecycle evidence accepts only standard block policy",
        ));
    }
    Ok(())
}

fn validate_host_block_candidate_plan(plan: &PlanData) -> Result<(), ComposedError> {
    validate_standard_block_plan(plan)?;
    let is_results_receiver_candidate = matches!(
        plan.requested_policy.as_slice(),
        [allowance]
            if allowance.destination_type == DestinationType::Hostname
                && allowance.destination == DOCUMENTED_RESULTS_RECEIVER
                && allowance.protocol == Protocol::Tcp
                && allowance.port == 443
    );
    if plan.platform_profile != "none" || !is_results_receiver_candidate {
        return Err(ComposedError::new(
            "invalid_host_block_candidate_policy",
            "host block candidate accepts only the documented results-receiver test allowance",
        ));
    }
    Ok(())
}

pub fn run_composed_standard_test_service(
    unit_name: &str,
    runtime_root: &Path,
    plan: &PlanData,
) -> Result<(), ComposedError> {
    validate_test_service_context(unit_name)?;
    let runtime = TestRuntimeStore::create(runtime_root, &plan.invocation_id)?;
    let network = NativeResidentNetwork::in_current_namespace();
    let lockdown = SystemLockdownControl::new(&runtime.directory);
    let mut session = ComposedSession::establish_test_only(runtime, plan, network, lockdown)?;
    let start = Instant::now();
    loop {
        session.poll_once(start.elapsed(), FINDING_POLL_INTERVAL)?;
    }
}

pub fn run_host_block_candidate_test_service(
    unit_name: &str,
    runtime_root: &Path,
    plan: &PlanData,
) -> Result<(), ComposedError> {
    validate_test_service_context(unit_name)?;
    validate_host_block_candidate_plan(plan)?;
    let runtime = TestRuntimeStore::create(runtime_root, &plan.invocation_id)?;
    let network = NativeResidentNetwork::in_current_namespace();
    let lockdown = SystemLockdownControl::new(&runtime.directory);
    let mut session = ComposedSession::establish_with_scope(
        runtime,
        plan,
        network,
        lockdown,
        EvidenceScope::HostBlockCandidate,
    )?;
    let start = Instant::now();
    loop {
        session.poll_once(start.elapsed(), FINDING_POLL_INTERVAL)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_and_normalize;
    use crate::plan::build_plan;
    use crate::resolver::{Resolution, ResolveError, Resolver};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_INDEX: AtomicUsize = AtomicUsize::new(0);

    struct LiteralResolver;

    impl Resolver for LiteralResolver {
        fn resolve(&self, _hostname: &str, _timeout: Duration) -> Result<Resolution, ResolveError> {
            panic!("composed lifecycle fixtures contain literal destinations only");
        }
    }

    struct DocumentedReceiverResolver;

    impl Resolver for DocumentedReceiverResolver {
        fn resolve(&self, hostname: &str, _timeout: Duration) -> Result<Resolution, ResolveError> {
            assert_eq!(hostname, DOCUMENTED_RESULTS_RECEIVER);
            Ok(Resolution {
                addresses: vec!["192.0.2.10".parse().unwrap()],
                elapsed: Duration::from_millis(1),
            })
        }
    }

    type Operations = Rc<RefCell<Vec<&'static str>>>;

    struct FakeNetwork {
        operations: Operations,
        verify: VecDeque<Result<(), LifecycleError>>,
        findings: VecDeque<Result<Option<ConnectionFinding>, LifecycleError>>,
        total: VecDeque<Result<u64, LifecycleError>>,
    }

    impl ResidentNetwork for FakeNetwork {
        fn bind_findings(&mut self, _mode: Mode) -> Result<(), LifecycleError> {
            self.operations.borrow_mut().push("network_bind");
            Ok(())
        }

        fn preflight(&mut self, _ruleset: &str) -> Result<(), LifecycleError> {
            self.operations.borrow_mut().push("network_preflight");
            Ok(())
        }

        fn apply_provisional(&mut self, _ruleset: &str) -> Result<(), LifecycleError> {
            self.operations.borrow_mut().push("network_apply");
            Ok(())
        }

        fn verify_owned_state(&mut self, _expected: &OwnedNftState) -> Result<(), LifecycleError> {
            self.operations.borrow_mut().push("network_verify");
            self.verify.pop_front().unwrap_or(Ok(()))
        }

        fn total_violation_packets(&mut self) -> Result<u64, LifecycleError> {
            self.operations.borrow_mut().push("network_counter");
            self.total.pop_front().unwrap_or(Ok(0))
        }

        fn next_finding(
            &mut self,
            _timeout: Duration,
        ) -> Result<Option<ConnectionFinding>, LifecycleError> {
            self.operations.borrow_mut().push("network_finding");
            self.findings.pop_front().unwrap_or(Ok(None))
        }

        fn rollback_pre_ready(&mut self) -> Result<bool, LifecycleError> {
            self.operations.borrow_mut().push("network_rollback");
            Ok(true)
        }
    }

    struct FakeLockdown {
        operations: Operations,
        container_verify: VecDeque<Result<(), LockdownError>>,
    }

    impl LockdownControl for FakeLockdown {
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
            self.container_verify.pop_front().unwrap_or(Ok(()))
        }

        fn rollback_pre_ready(&mut self) -> Result<bool, LockdownError> {
            self.operations.borrow_mut().push("lockdown_rollback");
            Ok(true)
        }
    }

    fn plan(invocation: &str) -> PlanData {
        let json = format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"{invocation}","container_policy":"disable","allowances":[]}}"#
        );
        build_plan(
            parse_and_normalize(json.as_bytes()).unwrap(),
            &LiteralResolver,
        )
        .unwrap()
    }

    fn runtime(invocation: &str) -> TestRuntimeStore {
        let root = std::path::PathBuf::from(format!(
            "target/tmp/composed-unit-{}",
            TEST_INDEX.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        TestRuntimeStore::create(&root, invocation).unwrap()
    }

    fn fakes(operations: &Operations) -> (FakeNetwork, FakeLockdown) {
        (
            FakeNetwork {
                operations: Rc::clone(operations),
                verify: VecDeque::from([Ok(()), Ok(())]),
                findings: VecDeque::from([Ok(None)]),
                total: VecDeque::from([Ok(0), Ok(0)]),
            },
            FakeLockdown {
                operations: Rc::clone(operations),
                container_verify: VecDeque::from([Ok(()), Ok(())]),
            },
        )
    }

    #[test]
    fn emits_test_readiness_only_after_network_and_lockdown_verification() {
        let operations = Rc::new(RefCell::new(Vec::new()));
        let (network, lockdown) = fakes(&operations);
        let runtime = runtime("composed-order");
        let ready = runtime.ready.clone();
        let root = runtime.directory.parent().unwrap().to_path_buf();
        let session = ComposedSession::establish_test_only(
            runtime,
            &plan("composed-order"),
            network,
            lockdown,
        )
        .unwrap();
        assert_eq!(
            *operations.borrow(),
            vec![
                "fingerprint",
                "sudo_available",
                "containers_available",
                "network_bind",
                "network_preflight",
                "network_apply",
                "network_verify",
                "network_counter",
                "disable_sudo",
                "disable_containers",
                "sudo_disabled",
                "containers_disabled",
            ]
        );
        assert_eq!(session.evidence.readiness_status, COMPOSED_READY_STATUS);
        assert!(
            fs::read_to_string(ready)
                .unwrap()
                .contains("\"protection_available\":false")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn labels_host_block_candidate_without_a_public_protection_assertion() {
        let operations = Rc::new(RefCell::new(Vec::new()));
        let (network, lockdown) = fakes(&operations);
        let runtime = runtime("host-candidate");
        let ready = runtime.ready.clone();
        let root = runtime.directory.parent().unwrap().to_path_buf();
        let session = ComposedSession::establish_with_scope(
            runtime,
            &plan("host-candidate"),
            network,
            lockdown,
            EvidenceScope::HostBlockCandidate,
        )
        .unwrap();
        assert_eq!(
            session.evidence.status,
            HOST_BLOCK_CANDIDATE_EVIDENCE_STATUS
        );
        assert_eq!(
            session.evidence.readiness_status,
            HOST_BLOCK_CANDIDATE_READY_STATUS
        );
        assert_eq!(
            session.evidence.setup_status,
            "resident_host_block_candidate_test_only"
        );
        assert!(session.evidence.limitations.contains(
            &"documented_results_receiver_encoded_as_test_allowance_not_selected_profile"
        ));
        let serialized = fs::read_to_string(ready).unwrap();
        assert!(serialized.contains(HOST_BLOCK_CANDIDATE_READY_STATUS));
        assert!(serialized.contains("\"protection_available\":false"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unreviewed_allowances_for_host_block_candidate() {
        let json = r#"{"schema_version":1,"mode":"block","invocation_id":"candidate-rule","platform_profile":"none","container_policy":"disable","allowances":[{"destination_type":"ip","destination":"192.0.2.10","protocol":"tcp","port":443}]}"#;
        let plan = build_plan(
            parse_and_normalize(json.as_bytes()).unwrap(),
            &LiteralResolver,
        )
        .unwrap();
        let error = validate_host_block_candidate_plan(&plan).unwrap_err();
        assert_eq!(error.code, "invalid_host_block_candidate_policy");
    }

    #[test]
    fn accepts_only_the_documented_receiver_candidate() {
        let json = format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"candidate-receiver","platform_profile":"none","container_policy":"disable","allowances":[{{"destination_type":"hostname","destination":"{DOCUMENTED_RESULTS_RECEIVER}","protocol":"tcp","port":443}}]}}"#
        );
        let plan = build_plan(
            parse_and_normalize(json.as_bytes()).unwrap(),
            &DocumentedReceiverResolver,
        )
        .unwrap();
        validate_host_block_candidate_plan(&plan).unwrap();
    }

    #[test]
    fn rolls_back_lockdown_then_network_on_pre_ready_failure() {
        let operations = Rc::new(RefCell::new(Vec::new()));
        let (network, mut lockdown) = fakes(&operations);
        lockdown.container_verify = VecDeque::from([Err(LockdownError {
            code: "injected_lockdown_failure",
            message: "test injected failure".to_owned(),
        })]);
        let runtime = runtime("composed-rollback");
        let ready = runtime.ready.clone();
        let report = runtime.report.clone();
        let root = runtime.directory.parent().unwrap().to_path_buf();
        let error = ComposedSession::establish_test_only(
            runtime,
            &plan("composed-rollback"),
            network,
            lockdown,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "injected_lockdown_failure");
        assert!(!ready.exists());
        assert!(
            fs::read_to_string(report)
                .unwrap()
                .contains("\"rollback_status\":\"rolled_back_pre_ready\"")
        );
        let operations = operations.borrow();
        assert_eq!(
            operations[operations.len() - 2..],
            ["lockdown_rollback", "network_rollback"]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn records_post_ready_lockdown_drift_without_rollback() {
        let operations = Rc::new(RefCell::new(Vec::new()));
        let (network, mut lockdown) = fakes(&operations);
        lockdown.container_verify = VecDeque::from([
            Ok(()),
            Err(LockdownError {
                code: "injected_drift",
                message: "test drift".to_owned(),
            }),
        ]);
        let runtime = runtime("composed-drift");
        let root = runtime.directory.parent().unwrap().to_path_buf();
        let mut session = ComposedSession::establish_test_only(
            runtime,
            &plan("composed-drift"),
            network,
            lockdown,
        )
        .unwrap();
        session
            .poll_once(Duration::from_secs(5), Duration::ZERO)
            .unwrap();
        assert_eq!(session.evidence.container_status, "critical_drift");
        assert_eq!(session.evidence.critical_findings.len(), 1);
        assert!(!operations.borrow().contains(&"lockdown_rollback"));
        fs::remove_dir_all(root).unwrap();
    }
}
