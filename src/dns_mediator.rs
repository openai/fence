use crate::config::{DestinationType, MAX_REPORT_BYTES, Mode, Protocol};
use crate::findings::{ConnectionFinding, FindingCollection, bounded_timestamp_now};
use crate::lifecycle::{
    CriticalFinding, NativeResidentNetwork, RESIDENT_VERIFICATION_INTERVAL, ResidentSession,
    validate_test_service_context,
};
use crate::lockdown::{LockdownControl, SystemLockdownControl};
use crate::nflog::NflogReader;
use crate::nft::{
    NetworkEvidenceCounters, OwnedNftState, expected_dns_mediated_owned_state,
    render_dns_mediated_replacement_ruleset, render_dns_mediated_ruleset,
};
use crate::nft_backend::{NativeNftBackend, SystemNftExecutor};
use crate::plan::{AssuranceStatus, EffectiveAllowance, PlanData};
use crate::runtime::{RuntimeError, TestRuntimeStore};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const DNS_MEDIATION_EVIDENCE_STATUS: &str = "dns_mediation_audit_test_only";
pub const DNS_MEDIATED_GITHUB_CANDIDATE_ID: &str = "github_hosted_dns_mediated_candidate_v1";
pub const DNS_MEDIATED_EXACT_STATUS_CANDIDATE_ID: &str =
    "github_hosted_dns_mediated_exact_status_candidate_v1";
pub const DNS_MEDIATED_BLOCK_EVIDENCE_STATUS: &str = "dns_mediated_host_block_candidate_test_only";
pub const DNS_MEDIATED_BLOCK_READY_STATUS: &str =
    "dns_mediated_host_block_candidate_ready_no_public_activation";
pub const DNS_CANDIDATE_PATTERNS: [&str; 4] = [
    "*.actions.githubusercontent.com",
    "codeload.github.com",
    "actions-results-receiver-production.githubapp.com",
    "productionresultssa*.blob.core.windows.net",
];
pub const DNS_BLOCK_CANDIDATE_HOSTNAMES: [&str; 2] = [
    "pipelines.actions.githubusercontent.com",
    "results-receiver.actions.githubusercontent.com",
];
const MAX_RETAINED_DNS_OBSERVATIONS: usize = 256;
const MAX_RETAINED_ADDRESSES_PER_OBSERVATION: usize = 32;
const MAX_DYNAMIC_MATERIALIZATIONS: usize = 128;
const MAX_DYNAMIC_TTL_SECONDS: u32 = 300;
const MAX_CRITICAL_FINDINGS: usize = 64;
const MAX_DNS_PACKET_BYTES: usize = 4096;
const UPSTREAM_DNS: &str = "168.63.129.16:53";
const HOST_DNS_BIND: &str = "127.0.0.1:53";
const DOCKER_DNS_BIND: &str = "172.17.0.1:53";
const RESOLVED_DROP_IN_DIR: &str = "/etc/systemd/resolved.conf.d";
const RESOLVED_DROP_IN_PATH: &str = "/etc/systemd/resolved.conf.d/90-fence-evidence.conf";
const DOCKER_DAEMON_PATH: &str = "/etc/docker/daemon.json";
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsEvidenceScope {
    Audit,
    HostBlockCandidate,
}

impl DnsEvidenceScope {
    fn mode(self) -> Mode {
        match self {
            Self::Audit => Mode::Audit,
            Self::HostBlockCandidate => Mode::Block,
        }
    }

    fn forward_query(self, hostname: &str) -> bool {
        match self {
            Self::Audit => true,
            Self::HostBlockCandidate => matches_exact_block_candidate_hostname(hostname),
        }
    }

    fn status(self) -> &'static str {
        match self {
            Self::Audit => DNS_MEDIATION_EVIDENCE_STATUS,
            Self::HostBlockCandidate => DNS_MEDIATED_BLOCK_EVIDENCE_STATUS,
        }
    }

    fn candidate_profile_id(self) -> &'static str {
        match self {
            Self::Audit => DNS_MEDIATED_GITHUB_CANDIDATE_ID,
            Self::HostBlockCandidate => DNS_MEDIATED_EXACT_STATUS_CANDIDATE_ID,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsMediationError {
    pub code: &'static str,
    pub message: String,
}

impl DnsMediationError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsObservation {
    pub hostname: String,
    pub query_type: String,
    pub candidate_classification: &'static str,
    pub occurrences: u64,
    pub resolved_addresses: Vec<String>,
    pub minimum_observed_ttl_seconds: Option<u32>,
    pub addresses_truncated: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsMediationEvidence {
    pub status: &'static str,
    pub candidate_profile_id: &'static str,
    pub candidate_domain_patterns: Vec<&'static str>,
    pub candidate_hostnames: Vec<&'static str>,
    pub mode: Mode,
    pub protection_available: bool,
    pub routing_status: &'static str,
    pub host_dns_routing: &'static str,
    pub docker_dns_routing: &'static str,
    pub answer_attribution_status: &'static str,
    pub proxy_policy_status: &'static str,
    pub observations: Vec<DnsObservation>,
    pub observations_truncated: bool,
    pub excluded_non_github_query_count: u64,
    pub blocked_non_candidate_query_count: u64,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsMaterializedHttpsAllowance {
    pub hostname: String,
    pub address: String,
    pub protocol: &'static str,
    pub port: u16,
    pub observed_ttl_seconds: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsMediatedBlockEvidence {
    pub status: &'static str,
    pub mode: Mode,
    pub candidate_profile_id: &'static str,
    pub candidate_hostnames: Vec<&'static str>,
    pub setup_status: &'static str,
    pub network_application_status: &'static str,
    pub network_verification_status: &'static str,
    pub sudo_status: &'static str,
    pub container_status: &'static str,
    pub readiness_status: &'static str,
    pub rollback_status: &'static str,
    pub ruleset_hash: String,
    pub dns_upstream_policy: &'static str,
    pub materialization_status: &'static str,
    pub materialized_https_allowances: Vec<DnsMaterializedHttpsAllowance>,
    pub materializations_truncated: bool,
    pub expired_materializations: u64,
    pub counters: NetworkEvidenceCounters,
    pub findings: Vec<ConnectionFinding>,
    pub findings_truncated: bool,
    pub critical_findings: Vec<CriticalFinding>,
    pub critical_findings_truncated: bool,
    pub protection_available: bool,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct DnsMediatedBlockState<'a> {
    status: &'static str,
    mode: Mode,
    candidate_profile_id: &'static str,
    ruleset_hash: &'a str,
    planned_owned_state: &'a OwnedNftState,
    readiness_status: &'static str,
}

#[derive(Debug, Serialize)]
struct DnsMediatedBlockReady<'a> {
    status: &'static str,
    mode: Mode,
    candidate_profile_id: &'static str,
    ruleset_hash: &'a str,
    protection_available: bool,
    limitations: Vec<&'static str>,
}

#[derive(Debug, Default)]
struct ObservationState {
    retained: BTreeMap<(String, u16, &'static str), RetainedObservation>,
    truncated: bool,
    excluded_non_github_query_count: u64,
    blocked_non_candidate_query_count: u64,
}

#[derive(Debug, Default)]
struct RetainedObservation {
    occurrences: u64,
    resolved_addresses: BTreeSet<IpAddr>,
    minimum_observed_ttl_seconds: Option<u32>,
    addresses_truncated: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DnsAddressAnswer {
    address: IpAddr,
    ttl_seconds: u32,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct PendingMaterialization {
    hostname: String,
    address: IpAddr,
    ttl_seconds: u32,
}

#[derive(Debug, Default)]
struct MaterializationQueue {
    pending: BTreeSet<PendingMaterialization>,
    truncated: bool,
}

#[derive(Clone)]
struct ActiveMaterialization {
    hostname: String,
    address: IpAddr,
    observed_ttl_seconds: u32,
    expires_at: Instant,
}

#[derive(Clone)]
struct ObservationRecorder {
    state: Arc<Mutex<ObservationState>>,
    report_path: PathBuf,
    scope: DnsEvidenceScope,
    materializations: Option<Arc<Mutex<MaterializationQueue>>>,
}

impl ObservationRecorder {
    fn record_query(&self, hostname: &str, query_type: u16) {
        let normalized = normalize_hostname(hostname);
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        if let Some(hostname) = normalized
            .as_ref()
            .filter(|name| reportable_github_hostname(name))
            .cloned()
        {
            let classification = candidate_classification(self.scope, &hostname);
            let key = (hostname, query_type, classification);
            if let Some(observation) = state.retained.get_mut(&key) {
                observation.occurrences = observation.occurrences.saturating_add(1);
            } else if state.retained.len() < MAX_RETAINED_DNS_OBSERVATIONS {
                state.retained.insert(
                    key,
                    RetainedObservation {
                        occurrences: 1,
                        ..RetainedObservation::default()
                    },
                );
            } else {
                state.truncated = true;
            }
        } else {
            state.excluded_non_github_query_count =
                state.excluded_non_github_query_count.saturating_add(1);
        }
        if self.scope == DnsEvidenceScope::HostBlockCandidate
            && normalized
                .as_deref()
                .is_some_and(|hostname| !self.scope.forward_query(hostname))
        {
            state.blocked_non_candidate_query_count =
                state.blocked_non_candidate_query_count.saturating_add(1);
        }
        let evidence = evidence_from_state(&state, "active_test_only", self.scope);
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        let _ = write_result;
    }

    fn record_response(&self, hostname: &str, query_type: u16, packet: &[u8]) {
        let Some(hostname) =
            normalize_hostname(hostname).filter(|name| reportable_github_hostname(name))
        else {
            return;
        };
        let answers = parse_dns_address_answers(packet);
        if answers.is_empty() {
            return;
        }
        let classification = candidate_classification(self.scope, &hostname);
        let key = (hostname.clone(), query_type, classification);
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        let Some(observation) = state.retained.get_mut(&key) else {
            return;
        };
        retain_address_answers(observation, answers);
        if self.scope == DnsEvidenceScope::HostBlockCandidate
            && matches_exact_block_candidate_hostname(&hostname)
            && let Some(queue) = &self.materializations
        {
            let mut queue = queue.lock().expect("DNS materialization lock poisoned");
            for answer in parse_dns_address_answers(packet) {
                if answer.ttl_seconds == 0 {
                    continue;
                }
                if queue.pending.len() >= MAX_DYNAMIC_MATERIALIZATIONS {
                    queue.truncated = true;
                    break;
                }
                queue.pending.insert(PendingMaterialization {
                    hostname: hostname.clone(),
                    address: answer.address,
                    ttl_seconds: answer.ttl_seconds.min(MAX_DYNAMIC_TTL_SECONDS),
                });
            }
        }
        let evidence = evidence_from_state(&state, "active_test_only", self.scope);
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        let _ = write_result;
    }

    fn reset_after_activation(&self) -> Result<(), DnsMediationError> {
        let mut state = self.state.lock().map_err(|_| {
            DnsMediationError::new(
                "dns_observation_state_failed",
                "DNS observation state could not be reset after setup",
            )
        })?;
        *state = ObservationState::default();
        let evidence = evidence_from_state(&state, "active_test_only", self.scope);
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        write_result
    }
}

struct DnsRouting {
    docker_original: Option<Vec<u8>>,
    resolved_drop_in_created: bool,
    docker_changed: bool,
}

impl DnsRouting {
    fn activate() -> Result<Self, DnsMediationError> {
        let mut routing = Self {
            docker_original: None,
            resolved_drop_in_created: false,
            docker_changed: false,
        };
        let result = routing.activate_inner();
        if result.is_err() {
            let _ = routing.rollback();
        }
        result.map(|()| routing)
    }

    fn activate_inner(&mut self) -> Result<(), DnsMediationError> {
        if Path::new(RESOLVED_DROP_IN_PATH).exists() {
            return Err(DnsMediationError::new(
                "dns_routing_conflict",
                "test DNS routing refuses a preexisting owned resolver drop-in",
            ));
        }
        fs::create_dir_all(RESOLVED_DROP_IN_DIR).map_err(|_| {
            DnsMediationError::new(
                "dns_routing_setup_failed",
                "failed to prepare resolver drop-in directory",
            )
        })?;
        write_new_file(
            Path::new(RESOLVED_DROP_IN_PATH),
            b"[Resolve]\nDNS=127.0.0.1\nDomains=~.\n",
            0o644,
        )?;
        self.resolved_drop_in_created = true;
        fixed_command("/usr/bin/systemctl", &["restart", "systemd-resolved"])?;
        let _ = fixed_command("/usr/bin/resolvectl", &["flush-caches"]);

        let docker_path = Path::new(DOCKER_DAEMON_PATH);
        self.docker_original = match fs::read(docker_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(_) => {
                return Err(DnsMediationError::new(
                    "dns_routing_setup_failed",
                    "failed to read bounded Docker DNS configuration input",
                ));
            }
        };
        let mut docker_config = match self.docker_original.as_deref() {
            Some(bytes) => serde_json::from_slice::<Value>(bytes).map_err(|_| {
                DnsMediationError::new(
                    "dns_routing_setup_failed",
                    "Docker DNS configuration is not structured JSON",
                )
            })?,
            None => Value::Object(Map::new()),
        };
        let Some(object) = docker_config.as_object_mut() else {
            return Err(DnsMediationError::new(
                "dns_routing_setup_failed",
                "Docker DNS configuration is not a JSON object",
            ));
        };
        object.insert(
            "dns".to_owned(),
            Value::Array(vec![Value::String("172.17.0.1".to_owned())]),
        );
        let docker_bytes = serde_json::to_vec(&docker_config).map_err(|_| {
            DnsMediationError::new(
                "dns_routing_setup_failed",
                "failed to serialize Docker DNS configuration",
            )
        })?;
        replace_external_file(docker_path, &docker_bytes)?;
        self.docker_changed = true;
        fixed_command("/usr/bin/systemctl", &["restart", "docker.service"])
    }

    fn rollback(&mut self) -> Result<bool, DnsMediationError> {
        let changed = self.resolved_drop_in_created || self.docker_changed;
        if self.docker_changed {
            match self.docker_original.as_deref() {
                Some(bytes) => replace_external_file(Path::new(DOCKER_DAEMON_PATH), bytes)?,
                None => {
                    let _ = fs::remove_file(DOCKER_DAEMON_PATH);
                }
            }
            fixed_command("/usr/bin/systemctl", &["restart", "docker.service"])?;
            self.docker_changed = false;
        }
        if self.resolved_drop_in_created {
            fs::remove_file(RESOLVED_DROP_IN_PATH).map_err(|_| {
                DnsMediationError::new(
                    "dns_routing_rollback_failed",
                    "failed to remove provisional resolver routing",
                )
            })?;
            fixed_command("/usr/bin/systemctl", &["restart", "systemd-resolved"])?;
            self.resolved_drop_in_created = false;
        }
        Ok(changed)
    }
}

pub struct DnsMediationSession {
    routing: DnsRouting,
    _threads: Vec<JoinHandle<()>>,
}

impl DnsMediationSession {
    fn establish(
        runtime_directory: &Path,
        scope: DnsEvidenceScope,
        materializations: Option<Arc<Mutex<MaterializationQueue>>>,
    ) -> Result<Self, DnsMediationError> {
        let report_path = runtime_directory.join("dns-report.json");
        let recorder = ObservationRecorder {
            state: Arc::new(Mutex::new(ObservationState::default())),
            report_path,
            scope,
            materializations,
        };
        write_report(
            &recorder.report_path,
            &evidence_from_state(
                &recorder
                    .state
                    .lock()
                    .expect("DNS observation lock poisoned"),
                "setting_up",
                scope,
            ),
        )?;
        let threads = start_dns_proxy(recorder.clone())?;
        let routing = DnsRouting::activate()?;
        if let Err(error) = recorder.reset_after_activation() {
            let mut routing = routing;
            let _ = routing.rollback();
            return Err(error);
        }
        Ok(Self {
            routing,
            _threads: threads,
        })
    }
}

pub fn run_dns_mediation_audit_test_service(
    unit_name: &str,
    runtime_root: &Path,
    plan: &PlanData,
) -> Result<(), DnsMediationError> {
    validate_test_service_context(unit_name)
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    if plan.selected_mode != Mode::Audit || plan.platform_profile.id != "none" {
        return Err(DnsMediationError::new(
            "invalid_dns_measurement_policy",
            "DNS mediation measurement accepts only audit mode without a selected profile",
        ));
    }
    let runtime = TestRuntimeStore::create(runtime_root, &plan.invocation_id)
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    let directory = runtime.directory.clone();
    let mut mediation = DnsMediationSession::establish(&directory, DnsEvidenceScope::Audit, None)?;
    let network = NativeResidentNetwork::in_current_namespace();
    let mut resident = match ResidentSession::establish_test_only(runtime, plan, network) {
        Ok(session) => session,
        Err(error) => {
            let _ = mediation.routing.rollback();
            return Err(DnsMediationError::new(error.code, error.message));
        }
    };
    let start = Instant::now();
    loop {
        resident
            .poll_once(start.elapsed(), POLL_INTERVAL)
            .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    }
}

struct DnsMediatedBlockSession {
    _mediation: DnsMediationSession,
    queue: Arc<Mutex<MaterializationQueue>>,
    backend: NativeNftBackend<SystemNftExecutor>,
    lockdown: SystemLockdownControl,
    reader: NflogReader,
    runtime: TestRuntimeStore,
    active: BTreeMap<(String, IpAddr), ActiveMaterialization>,
    expected_state: OwnedNftState,
    evidence: DnsMediatedBlockEvidence,
    findings: FindingCollection,
    next_verification: Duration,
}

impl DnsMediatedBlockSession {
    fn establish(
        runtime: TestRuntimeStore,
        mut mediation: DnsMediationSession,
        queue: Arc<Mutex<MaterializationQueue>>,
    ) -> Result<Self, DnsMediationError> {
        if let Err(error) = prehydrate_candidate_names() {
            let _ = mediation.routing.rollback();
            return Err(error);
        }
        let mut active = BTreeMap::new();
        let (changed, materializations_truncated, _) =
            merge_pending_materializations(&mut active, &queue, Instant::now());
        if !changed || active.is_empty() {
            let _ = mediation.routing.rollback();
            return Err(DnsMediationError::new(
                "dns_candidate_prehydration_failed",
                "DNS-mediated block candidate did not materialize fixed bootstrap names",
            ));
        }
        let allowances = materialized_effective_allowances(&active);
        let ruleset = render_dns_mediated_ruleset(Mode::Block, &allowances);
        let ruleset_hash = sha256_hex(ruleset.as_bytes());
        let expected_state = expected_dns_mediated_owned_state(Mode::Block, &allowances);
        let mut evidence =
            initial_dns_block_evidence(&active, materializations_truncated, ruleset_hash.clone());
        if let Err(error) = runtime.write_state_exclusive(&DnsMediatedBlockState {
            status: DNS_MEDIATED_BLOCK_EVIDENCE_STATUS,
            mode: Mode::Block,
            candidate_profile_id: DNS_MEDIATED_EXACT_STATUS_CANDIDATE_ID,
            ruleset_hash: &ruleset_hash,
            planned_owned_state: &expected_state,
            readiness_status: "not_emitted",
        }) {
            let _ = mediation.routing.rollback();
            return Err(runtime_error(error));
        }
        if let Err(error) = runtime.replace_report(&evidence) {
            let _ = mediation.routing.rollback();
            return Err(runtime_error(error));
        }

        let mut backend = NativeNftBackend::new(SystemNftExecutor::host());
        let mut lockdown = SystemLockdownControl::new(&runtime.directory);
        let reader = match NflogReader::bind(Mode::Block) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = mediation.routing.rollback();
                return Err(DnsMediationError::new(error.code, error.message));
            }
        };
        let setup_result = (|| {
            lockdown.verify_supported_host().map_err(lockdown_error)?;
            lockdown.verify_sudo_available().map_err(lockdown_error)?;
            lockdown
                .verify_containers_available()
                .map_err(lockdown_error)?;
            backend.preflight(&ruleset).map_err(backend_error)?;
            backend.apply_provisional(&ruleset).map_err(backend_error)?;
            evidence.network_application_status = "applied";
            backend
                .verify_owned_state(&expected_state)
                .map_err(backend_error)?;
            evidence.network_verification_status = "verified";
            lockdown.disable_sudo().map_err(lockdown_error)?;
            lockdown.disable_containers().map_err(lockdown_error)?;
            lockdown.verify_sudo_disabled().map_err(lockdown_error)?;
            lockdown
                .verify_containers_disabled()
                .map_err(lockdown_error)?;
            evidence.sudo_status = "disabled_verified";
            evidence.container_status = "disabled_verified";
            Ok(())
        })();
        if let Err(error) = setup_result {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(error);
        }

        evidence.setup_status = "verified_before_test_ready";
        if let Err(error) = runtime.replace_report(&evidence) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(runtime_error(error));
        }
        if let Err(error) = runtime.write_ready_exclusive(&DnsMediatedBlockReady {
            status: DNS_MEDIATED_BLOCK_READY_STATUS,
            mode: Mode::Block,
            candidate_profile_id: DNS_MEDIATED_EXACT_STATUS_CANDIDATE_ID,
            ruleset_hash: &ruleset_hash,
            protection_available: false,
            limitations: dns_block_limitations(),
        }) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(runtime_error(error));
        }
        evidence.setup_status = "resident_dns_mediated_host_block_candidate_test_only";
        evidence.readiness_status = DNS_MEDIATED_BLOCK_READY_STATUS;
        runtime.replace_report(&evidence).map_err(runtime_error)?;
        Ok(Self {
            _mediation: mediation,
            queue,
            backend,
            lockdown,
            reader,
            runtime,
            active,
            expected_state,
            evidence,
            findings: FindingCollection::empty(),
            next_verification: RESIDENT_VERIFICATION_INTERVAL,
        })
    }

    fn poll_once(
        &mut self,
        elapsed: Duration,
        finding_timeout: Duration,
    ) -> Result<(), DnsMediationError> {
        let mut changed = false;
        match self.reader.next_finding(finding_timeout) {
            Ok(Some(finding)) => {
                self.findings.record_finding(finding);
                changed = true;
            }
            Ok(None) => {}
            Err(_) => {
                self.record_critical(
                    "dns_candidate_nflog_failure",
                    "DNS-mediated block candidate NFLOG collection failed after test readiness",
                );
                changed = true;
            }
        }

        let mut proposed = self.active.clone();
        let (materialization_changed, truncated, expired) =
            merge_pending_materializations(&mut proposed, &self.queue, Instant::now());
        self.evidence.materializations_truncated |= truncated;
        if materialization_changed {
            let allowances = materialized_effective_allowances(&proposed);
            let ruleset = render_dns_mediated_replacement_ruleset(Mode::Block, &allowances);
            let active_ruleset = render_dns_mediated_ruleset(Mode::Block, &allowances);
            let expected = expected_dns_mediated_owned_state(Mode::Block, &allowances);
            if self.backend.preflight(&ruleset).is_ok()
                && self.backend.replace_owned_state(&ruleset).is_ok()
                && self.backend.verify_owned_state(&expected).is_ok()
            {
                self.active = proposed;
                self.expected_state = expected;
                self.evidence.ruleset_hash = sha256_hex(active_ruleset.as_bytes());
                self.evidence.materialized_https_allowances = report_materializations(&self.active);
                self.evidence.expired_materializations = self
                    .evidence
                    .expired_materializations
                    .saturating_add(expired);
                self.evidence.network_verification_status = "verified";
            } else {
                self.evidence.network_verification_status = "critical_dynamic_update_failed";
                self.record_critical(
                    "dns_candidate_dynamic_update_failed",
                    "approved DNS-derived owned nftables replacement failed after test readiness",
                );
            }
            changed = true;
        }

        if elapsed >= self.next_verification {
            if self
                .backend
                .verify_owned_state(&self.expected_state)
                .is_err()
            {
                self.evidence.network_verification_status = "critical_drift";
                self.record_critical(
                    "dns_candidate_network_drift",
                    "DNS-mediated owned nftables state drifted after test readiness",
                );
            }
            if self.lockdown.verify_sudo_disabled().is_err() {
                self.evidence.sudo_status = "critical_drift";
                self.record_critical(
                    "dns_candidate_sudo_drift",
                    "measured passwordless sudo state drifted after test readiness",
                );
            }
            if self.lockdown.verify_containers_disabled().is_err() {
                self.evidence.container_status = "critical_drift";
                self.record_critical(
                    "dns_candidate_container_drift",
                    "measured container control state drifted after test readiness",
                );
            }
            self.next_verification = elapsed + RESIDENT_VERIFICATION_INTERVAL;
            changed = true;
        }
        if changed {
            self.evidence.findings = self.findings.retained.clone();
            self.evidence.findings_truncated = self.findings.truncated;
            self.evidence.counters.sampled_violations = self.findings.sampled_total;
            self.evidence.counters.total_violations =
                self.backend.total_violation_packets().unwrap_or_else(|_| {
                    self.record_critical(
                        "dns_candidate_counter_read_failed",
                        "DNS-mediated violation counter could not be read after test readiness",
                    );
                    self.evidence.counters.total_violations
                });
            self.runtime
                .replace_report(&self.evidence)
                .map_err(runtime_error)?;
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

pub fn run_dns_mediated_host_block_candidate_test_service(
    unit_name: &str,
    runtime_root: &Path,
    plan: &PlanData,
) -> Result<(), DnsMediationError> {
    validate_test_service_context(unit_name)
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    if plan.selected_mode != Mode::Block
        || plan.assurance_status != AssuranceStatus::PlannedBlockContainment
        || plan.platform_profile.id != "none"
        || !plan.requested_policy.is_empty()
    {
        return Err(DnsMediationError::new(
            "invalid_dns_block_candidate_policy",
            "DNS-mediated block candidate accepts only standard block with no selected profile or user allowances",
        ));
    }
    let runtime =
        TestRuntimeStore::create(runtime_root, &plan.invocation_id).map_err(runtime_error)?;
    let queue = Arc::new(Mutex::new(MaterializationQueue::default()));
    let mediation = DnsMediationSession::establish(
        &runtime.directory,
        DnsEvidenceScope::HostBlockCandidate,
        Some(queue.clone()),
    )?;
    let mut session = DnsMediatedBlockSession::establish(runtime, mediation, queue)?;
    let start = Instant::now();
    loop {
        session.poll_once(start.elapsed(), POLL_INTERVAL)?;
    }
}

fn initial_dns_block_evidence(
    active: &BTreeMap<(String, IpAddr), ActiveMaterialization>,
    materializations_truncated: bool,
    ruleset_hash: String,
) -> DnsMediatedBlockEvidence {
    DnsMediatedBlockEvidence {
        status: DNS_MEDIATED_BLOCK_EVIDENCE_STATUS,
        mode: Mode::Block,
        candidate_profile_id: DNS_MEDIATED_EXACT_STATUS_CANDIDATE_ID,
        candidate_hostnames: DNS_BLOCK_CANDIDATE_HOSTNAMES.to_vec(),
        setup_status: "setting_up",
        network_application_status: "not_applied",
        network_verification_status: "not_verified",
        sudo_status: "not_checked",
        container_status: "not_checked",
        readiness_status: "not_emitted",
        rollback_status: "not_required",
        ruleset_hash,
        dns_upstream_policy: "root_resident_mediator_only_udp_53",
        materialization_status: "bounded_ttl_approved_name_https_only",
        materialized_https_allowances: report_materializations(active),
        materializations_truncated,
        expired_materializations: 0,
        counters: NetworkEvidenceCounters {
            total_violations: 0,
            sampled_violations: 0,
        },
        findings: Vec::new(),
        findings_truncated: false,
        critical_findings: Vec::new(),
        critical_findings_truncated: false,
        protection_available: false,
        limitations: dns_block_limitations(),
    }
}

fn dns_block_limitations() -> Vec<&'static str> {
    vec![
        "dns_mediated_host_block_candidate_test_only_no_public_activation",
        "candidate_hostnames_are_exact_and_not_a_default_platform_profile",
        "approved_status_https_destinations_remain_egress_channels",
        "resolved_status_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
        "dynamic_owned_table_replacement_resets_network_counters",
        "terminal_job_success_required_before_profile_selection",
    ]
}

fn prehydrate_candidate_names() -> Result<(), DnsMediationError> {
    for hostname in DNS_BLOCK_CANDIDATE_HOSTNAMES {
        if (hostname, 443_u16)
            .to_socket_addrs()
            .map_err(|_| {
                DnsMediationError::new(
                    "dns_candidate_prehydration_failed",
                    "failed to resolve a fixed DNS-mediated bootstrap hostname",
                )
            })?
            .next()
            .is_none()
        {
            return Err(DnsMediationError::new(
                "dns_candidate_prehydration_failed",
                "a fixed DNS-mediated bootstrap hostname returned no addresses",
            ));
        }
    }
    Ok(())
}

fn merge_pending_materializations(
    active: &mut BTreeMap<(String, IpAddr), ActiveMaterialization>,
    queue: &Arc<Mutex<MaterializationQueue>>,
    now: Instant,
) -> (bool, bool, u64) {
    let mut changed = false;
    let expired = active
        .extract_if(.., |_, materialization| materialization.expires_at <= now)
        .count() as u64;
    changed |= expired > 0;
    let (pending, truncated) = {
        let mut queue = queue.lock().expect("DNS materialization lock poisoned");
        (std::mem::take(&mut queue.pending), queue.truncated)
    };
    for materialization in pending {
        let key = (materialization.hostname.clone(), materialization.address);
        active.insert(
            key,
            ActiveMaterialization {
                hostname: materialization.hostname,
                address: materialization.address,
                observed_ttl_seconds: materialization.ttl_seconds,
                expires_at: now + Duration::from_secs(u64::from(materialization.ttl_seconds)),
            },
        );
        changed = true;
    }
    (changed, truncated, expired)
}

fn materialized_effective_allowances(
    active: &BTreeMap<(String, IpAddr), ActiveMaterialization>,
) -> Vec<EffectiveAllowance> {
    active
        .values()
        .map(|materialization| EffectiveAllowance {
            destination_type: DestinationType::Ip,
            destination: materialization.address.to_string(),
            protocol: Protocol::Tcp,
            port: 443,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn report_materializations(
    active: &BTreeMap<(String, IpAddr), ActiveMaterialization>,
) -> Vec<DnsMaterializedHttpsAllowance> {
    active
        .values()
        .map(|materialization| DnsMaterializedHttpsAllowance {
            hostname: materialization.hostname.clone(),
            address: materialization.address.to_string(),
            protocol: "tcp",
            port: 443,
            observed_ttl_seconds: materialization.observed_ttl_seconds,
        })
        .collect()
}

fn rollback_dns_block_setup(
    backend: &mut NativeNftBackend<SystemNftExecutor>,
    lockdown: &mut SystemLockdownControl,
    mediation: &mut DnsMediationSession,
) -> &'static str {
    let lockdown_result = lockdown.rollback_pre_ready();
    let network_result = backend.rollback_pre_activation();
    let dns_result = mediation.routing.rollback();
    match (lockdown_result, network_result, dns_result) {
        (Ok(lockdown_changed), Ok(network_changed), Ok(dns_changed))
            if lockdown_changed || network_changed || dns_changed =>
        {
            "rolled_back_pre_ready"
        }
        (Ok(_), Ok(_), Ok(_)) => "nothing_to_rollback",
        _ => "rollback_failed",
    }
}

fn runtime_error(error: RuntimeError) -> DnsMediationError {
    DnsMediationError::new(error.code, error.message)
}

fn backend_error(error: crate::nft_backend::BackendError) -> DnsMediationError {
    DnsMediationError::new(error.code, error.message)
}

fn lockdown_error(error: crate::lockdown::LockdownError) -> DnsMediationError {
    DnsMediationError::new(error.code, error.message)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hash = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hash, "{byte:02x}").expect("writing hexadecimal bytes to String must succeed");
    }
    hash
}

fn start_dns_proxy(
    recorder: ObservationRecorder,
) -> Result<Vec<JoinHandle<()>>, DnsMediationError> {
    let mut threads = Vec::new();
    for address in [HOST_DNS_BIND, DOCKER_DNS_BIND] {
        let udp = UdpSocket::bind(address).map_err(|_| {
            DnsMediationError::new(
                "dns_proxy_bind_failed",
                "failed to bind a fixed local DNS proxy listener",
            )
        })?;
        let tcp = TcpListener::bind(address).map_err(|_| {
            DnsMediationError::new(
                "dns_proxy_bind_failed",
                "failed to bind a fixed local DNS proxy stream listener",
            )
        })?;
        let udp_recorder = recorder.clone();
        threads.push(thread::spawn(move || serve_udp(udp, udp_recorder)));
        let tcp_recorder = recorder.clone();
        threads.push(thread::spawn(move || serve_tcp(tcp, tcp_recorder)));
    }
    Ok(threads)
}

fn serve_udp(socket: UdpSocket, recorder: ObservationRecorder) {
    let mut query = [0_u8; MAX_DNS_PACKET_BYTES];
    loop {
        let Ok((length, peer)) = socket.recv_from(&mut query) else {
            continue;
        };
        let bytes = &query[..length];
        let parsed_question = parse_dns_question(bytes);
        if let Some((hostname, query_type)) = &parsed_question {
            recorder.record_query(hostname, *query_type);
        }
        if !query_is_forwardable(&recorder, parsed_question.as_ref()) {
            if let Some(response) = refused_response(bytes) {
                let _ = socket.send_to(&response, peer);
            }
            continue;
        }
        let Ok(upstream) = UdpSocket::bind("0.0.0.0:0") else {
            continue;
        };
        let _ = upstream.set_read_timeout(Some(DNS_FORWARD_TIMEOUT));
        if upstream.send_to(bytes, UPSTREAM_DNS).is_err() {
            continue;
        }
        let mut response = [0_u8; MAX_DNS_PACKET_BYTES];
        if let Ok((response_length, _)) = upstream.recv_from(&mut response) {
            let response = &response[..response_length];
            if let Some((hostname, query_type)) = &parsed_question {
                recorder.record_response(hostname, *query_type, response);
            }
            let _ = socket.send_to(response, peer);
        }
    }
}

fn serve_tcp(listener: TcpListener, recorder: ObservationRecorder) {
    for mut client in listener.incoming().flatten() {
        let mut length = [0_u8; 2];
        if client.read_exact(&mut length).is_err() {
            continue;
        }
        let query_length = usize::from(u16::from_be_bytes(length));
        if query_length == 0 || query_length > MAX_DNS_PACKET_BYTES {
            continue;
        }
        let mut query = vec![0_u8; query_length];
        if client.read_exact(&mut query).is_err() {
            continue;
        }
        let parsed_question = parse_dns_question(&query);
        if let Some((hostname, query_type)) = &parsed_question {
            recorder.record_query(hostname, *query_type);
        }
        if !query_is_forwardable(&recorder, parsed_question.as_ref()) {
            if let Some(response) = refused_response(&query) {
                let _ = client.write_all(&(response.len() as u16).to_be_bytes());
                let _ = client.write_all(&response);
            }
            continue;
        }
        let Ok(mut upstream) = TcpStream::connect(UPSTREAM_DNS) else {
            continue;
        };
        let _ = upstream.set_read_timeout(Some(DNS_FORWARD_TIMEOUT));
        if upstream.write_all(&length).is_err() || upstream.write_all(&query).is_err() {
            continue;
        }
        let mut response_length = [0_u8; 2];
        if upstream.read_exact(&mut response_length).is_err() {
            continue;
        }
        let size = usize::from(u16::from_be_bytes(response_length));
        if size == 0 || size > MAX_DNS_PACKET_BYTES {
            continue;
        }
        let mut response = vec![0_u8; size];
        if upstream.read_exact(&mut response).is_err() {
            continue;
        }
        if let Some((hostname, query_type)) = &parsed_question {
            recorder.record_response(hostname, *query_type, &response);
        }
        let _ = client.write_all(&response_length);
        let _ = client.write_all(&response);
    }
}

fn query_is_forwardable(
    recorder: &ObservationRecorder,
    parsed_question: Option<&(String, u16)>,
) -> bool {
    match (recorder.scope, parsed_question) {
        (DnsEvidenceScope::Audit, _) => true,
        (DnsEvidenceScope::HostBlockCandidate, Some((hostname, _))) => {
            recorder.scope.forward_query(hostname)
        }
        (DnsEvidenceScope::HostBlockCandidate, None) => false,
    }
}

fn refused_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut response = query.to_vec();
    let flags = u16::from_be_bytes([response[2], response[3]]);
    response[2..4].copy_from_slice(&((flags | 0x8000) & 0xfff0 | 0x0005).to_be_bytes());
    response[6..12].fill(0);
    Some(response)
}

fn parse_dns_question(packet: &[u8]) -> Option<(String, u16)> {
    if packet.len() < 12 || u16::from_be_bytes([packet[4], packet[5]]) == 0 {
        return None;
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    while offset < packet.len() {
        let length = usize::from(packet[offset]);
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset + length > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[offset..offset + length]).ok()?;
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return None;
        }
        labels.push(label.to_ascii_lowercase());
        offset += length;
    }
    if labels.is_empty() || offset + 4 > packet.len() {
        return None;
    }
    Some((
        labels.join("."),
        u16::from_be_bytes([packet[offset], packet[offset + 1]]),
    ))
}

fn parse_dns_address_answers(packet: &[u8]) -> Vec<DnsAddressAnswer> {
    if packet.len() < 12 {
        return Vec::new();
    }
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]);
    let mut offset = 12;
    for _ in 0..question_count {
        let Some(next) = skip_dns_name(packet, offset) else {
            return Vec::new();
        };
        if next + 4 > packet.len() {
            return Vec::new();
        }
        offset = next + 4;
    }
    let mut addresses = Vec::new();
    for _ in 0..answer_count {
        let Some(next) = skip_dns_name(packet, offset) else {
            return Vec::new();
        };
        if next + 10 > packet.len() {
            return Vec::new();
        }
        let answer_type = u16::from_be_bytes([packet[next], packet[next + 1]]);
        let answer_class = u16::from_be_bytes([packet[next + 2], packet[next + 3]]);
        let ttl_seconds = u32::from_be_bytes([
            packet[next + 4],
            packet[next + 5],
            packet[next + 6],
            packet[next + 7],
        ]);
        let data_length = usize::from(u16::from_be_bytes([packet[next + 8], packet[next + 9]]));
        let data_offset = next + 10;
        if data_offset + data_length > packet.len() {
            return Vec::new();
        }
        let address = match (answer_type, answer_class, data_length) {
            (1, 1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                packet[data_offset],
                packet[data_offset + 1],
                packet[data_offset + 2],
                packet[data_offset + 3],
            ))),
            (28, 1, 16) => {
                let mut bytes = [0_u8; 16];
                bytes.copy_from_slice(&packet[data_offset..data_offset + 16]);
                Some(IpAddr::V6(Ipv6Addr::from(bytes)))
            }
            _ => None,
        };
        if let Some(address) = address {
            addresses.push(DnsAddressAnswer {
                address,
                ttl_seconds,
            });
        }
        offset = data_offset + data_length;
    }
    addresses
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *packet.get(offset)?;
        if length == 0 {
            return Some(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            packet.get(offset + 1)?;
            return Some(offset + 2);
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        offset = offset.checked_add(usize::from(length) + 1)?;
        if offset > packet.len() {
            return None;
        }
    }
}

fn retain_address_answers(
    observation: &mut RetainedObservation,
    answers: impl IntoIterator<Item = DnsAddressAnswer>,
) {
    for answer in answers {
        observation.minimum_observed_ttl_seconds = Some(
            observation
                .minimum_observed_ttl_seconds
                .map_or(answer.ttl_seconds, |existing| {
                    existing.min(answer.ttl_seconds)
                }),
        );
        if observation.resolved_addresses.contains(&answer.address) {
            continue;
        }
        if observation.resolved_addresses.len() < MAX_RETAINED_ADDRESSES_PER_OBSERVATION {
            observation.resolved_addresses.insert(answer.address);
        } else {
            observation.addresses_truncated = true;
        }
    }
}

fn normalize_hostname(hostname: &str) -> Option<String> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty()
        || hostname.len() > 253
        || !hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
    {
        None
    } else {
        Some(hostname)
    }
}

fn reportable_github_hostname(hostname: &str) -> bool {
    hostname == "github.com"
        || hostname.ends_with(".github.com")
        || hostname.ends_with(".githubusercontent.com")
        || hostname.ends_with(".githubapp.com")
        || (hostname.starts_with("productionresultssa")
            && hostname.ends_with(".blob.core.windows.net"))
}

fn matches_candidate_pattern(hostname: &str) -> bool {
    (hostname.ends_with(".actions.githubusercontent.com")
        && hostname != "actions.githubusercontent.com")
        || hostname == "codeload.github.com"
        || hostname == "actions-results-receiver-production.githubapp.com"
        || (hostname.starts_with("productionresultssa")
            && hostname.ends_with(".blob.core.windows.net"))
}

fn matches_exact_block_candidate_hostname(hostname: &str) -> bool {
    DNS_BLOCK_CANDIDATE_HOSTNAMES.contains(&hostname)
}

fn candidate_classification(scope: DnsEvidenceScope, hostname: &str) -> &'static str {
    match scope {
        DnsEvidenceScope::Audit if matches_candidate_pattern(hostname) => {
            "matches_candidate_pattern"
        }
        DnsEvidenceScope::HostBlockCandidate
            if matches_exact_block_candidate_hostname(hostname) =>
        {
            "matches_exact_candidate_hostname"
        }
        _ => "github_related_outside_candidate",
    }
}

fn query_type_name(query_type: u16) -> String {
    match query_type {
        1 => "a".to_owned(),
        28 => "aaaa".to_owned(),
        value => format!("type_{value}"),
    }
}

fn evidence_from_state(
    state: &ObservationState,
    routing_status: &'static str,
    scope: DnsEvidenceScope,
) -> DnsMediationEvidence {
    DnsMediationEvidence {
        status: scope.status(),
        candidate_profile_id: scope.candidate_profile_id(),
        candidate_domain_patterns: match scope {
            DnsEvidenceScope::Audit => DNS_CANDIDATE_PATTERNS.to_vec(),
            DnsEvidenceScope::HostBlockCandidate => Vec::new(),
        },
        candidate_hostnames: match scope {
            DnsEvidenceScope::Audit => Vec::new(),
            DnsEvidenceScope::HostBlockCandidate => DNS_BLOCK_CANDIDATE_HOSTNAMES.to_vec(),
        },
        mode: scope.mode(),
        protection_available: false,
        routing_status,
        host_dns_routing: "local_mediator_test_only",
        docker_dns_routing: "local_mediator_test_only",
        answer_attribution_status: "bounded_reportable_hostname_answers_only",
        proxy_policy_status: match scope {
            DnsEvidenceScope::Audit => "audit_forwards_without_name_authorization",
            DnsEvidenceScope::HostBlockCandidate => "block_forwards_only_exact_candidate_hostnames",
        },
        observations: state
            .retained
            .iter()
            .map(
                |((hostname, query_type, classification), observation)| DnsObservation {
                    hostname: hostname.clone(),
                    query_type: query_type_name(*query_type),
                    candidate_classification: classification,
                    occurrences: observation.occurrences,
                    resolved_addresses: observation
                        .resolved_addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    minimum_observed_ttl_seconds: observation.minimum_observed_ttl_seconds,
                    addresses_truncated: observation.addresses_truncated,
                },
            )
            .collect(),
        observations_truncated: state.truncated,
        excluded_non_github_query_count: state.excluded_non_github_query_count,
        blocked_non_candidate_query_count: state.blocked_non_candidate_query_count,
        limitations: match scope {
            DnsEvidenceScope::Audit => vec![
                "dns_mediation_audit_test_only_no_public_activation",
                "candidate_patterns_not_selected_as_platform_profile",
                "audit_observes_queries_without_blocking_names",
                "dns_answers_attribute_addresses_without_authorizing_firewall_rules",
                "dns_ttls_are_evidence_for_future_bounded_refresh_design_only",
                "evidence_collected_before_hosted_job_teardown",
                "terminal_block_success_required_before_default_selection",
            ],
            DnsEvidenceScope::HostBlockCandidate => vec![
                "dns_mediated_host_block_candidate_test_only_no_public_activation",
                "candidate_hostnames_are_exact_and_not_a_default_platform_profile",
                "dns_answers_materialize_only_bounded_candidate_https_addresses",
                "approved_status_https_destinations_remain_egress_channels",
                "resolved_status_ip_addresses_may_serve_additional_destinations",
                "root_resident_dns_upstream_channel_remains_an_egress_limitation",
                "terminal_job_success_required_before_profile_selection",
            ],
        },
    }
}

fn write_report(path: &Path, evidence: &DnsMediationEvidence) -> Result<(), DnsMediationError> {
    let bytes = serde_json::to_vec(evidence).map_err(|_| {
        DnsMediationError::new(
            "dns_evidence_serialize_failed",
            "failed to serialize bounded DNS mediation evidence",
        )
    })?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(DnsMediationError::new(
            "dns_evidence_report_too_large",
            "DNS mediation evidence exceeds the fixed report limit",
        ));
    }
    let pending = path.with_extension("json.next");
    let _ = fs::remove_file(&pending);
    write_new_file(&pending, &bytes, 0o644)?;
    fs::rename(&pending, path).map_err(|_| {
        DnsMediationError::new(
            "dns_evidence_write_failed",
            "failed to atomically publish DNS mediation evidence",
        )
    })
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), DnsMediationError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| {
            DnsMediationError::new(
                "dns_evidence_write_failed",
                "failed to create bounded DNS mediation evidence file",
            )
        })?;
    file.write_all(bytes).map_err(|_| {
        DnsMediationError::new(
            "dns_evidence_write_failed",
            "failed to write bounded DNS mediation evidence file",
        )
    })
}

fn replace_external_file(path: &Path, bytes: &[u8]) -> Result<(), DnsMediationError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| {
            DnsMediationError::new(
                "dns_routing_setup_failed",
                "failed to write fixed DNS routing configuration",
            )
        })?;
    file.write_all(bytes).map_err(|_| {
        DnsMediationError::new(
            "dns_routing_setup_failed",
            "failed to persist fixed DNS routing configuration",
        )
    })
}

fn fixed_command(path: &str, arguments: &[&str]) -> Result<(), DnsMediationError> {
    let status = Command::new(path)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| {
            DnsMediationError::new(
                "dns_routing_command_failed",
                "failed to execute a fixed DNS routing command",
            )
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(DnsMediationError::new(
            "dns_routing_command_failed",
            "a fixed DNS routing command reported failure",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, query_type: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 12];
        bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&query_type.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes
    }

    fn response_with_address(
        name: &str,
        query_type: u16,
        ttl_seconds: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut bytes = query(name, query_type);
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0xc0, 0x0c]);
        bytes.extend_from_slice(&query_type.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&ttl_seconds.to_be_bytes());
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    #[test]
    fn parses_and_normalizes_bounded_dns_questions() {
        assert_eq!(
            parse_dns_question(&query("Pipelines.Actions.GitHubusercontent.Com", 1)),
            Some(("pipelines.actions.githubusercontent.com".to_owned(), 1))
        );
        assert!(parse_dns_question(&[]).is_none());
        let mut compressed = query("example.com", 1);
        compressed[12] = 0xc0;
        assert!(parse_dns_question(&compressed).is_none());
    }

    #[test]
    fn classifies_fixed_candidate_patterns_without_authorizing_extra_hosts() {
        assert!(matches_candidate_pattern(
            "pipelines.actions.githubusercontent.com"
        ));
        assert!(matches_candidate_pattern(
            "actions-results-receiver-production.githubapp.com"
        ));
        assert!(matches_candidate_pattern(
            "productionresultssa17.blob.core.windows.net"
        ));
        assert!(matches_candidate_pattern("codeload.github.com"));
        assert!(!matches_candidate_pattern("api.github.com"));
        assert!(!matches_candidate_pattern("unrelated.example.com"));
        assert!(reportable_github_hostname("api.github.com"));
        assert!(!reportable_github_hostname(
            "unclassified-account.blob.core.windows.net"
        ));
    }

    #[test]
    fn blocking_scope_forwards_only_candidate_names_and_refuses_others() {
        assert!(
            DnsEvidenceScope::HostBlockCandidate
                .forward_query("pipelines.actions.githubusercontent.com")
        );
        assert!(
            DnsEvidenceScope::HostBlockCandidate
                .forward_query("results-receiver.actions.githubusercontent.com")
        );
        assert!(
            !DnsEvidenceScope::HostBlockCandidate
                .forward_query("payload.pipelines.actions.githubusercontent.com")
        );
        assert!(
            matches_candidate_pattern("payload.pipelines.actions.githubusercontent.com"),
            "the audit hypothesis remains broader than block authorization"
        );
        assert!(!DnsEvidenceScope::HostBlockCandidate.forward_query("api.github.com"));
        assert!(DnsEvidenceScope::Audit.forward_query("api.github.com"));
        let response = refused_response(&query("api.github.com", 1)).unwrap();
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 5);
        assert_ne!(u16::from_be_bytes([response[2], response[3]]) & 0x8000, 0);
    }

    #[test]
    fn extracts_bounded_dns_answer_addresses_and_ttls() {
        assert_eq!(
            parse_dns_address_answers(&response_with_address(
                "pipelines.actions.githubusercontent.com",
                1,
                30,
                &[192, 0, 2, 10],
            )),
            vec![DnsAddressAnswer {
                address: "192.0.2.10".parse().expect("IPv4 fixture must parse"),
                ttl_seconds: 30,
            }]
        );
        assert_eq!(
            parse_dns_address_answers(&response_with_address(
                "pipelines.actions.githubusercontent.com",
                28,
                60,
                &"2001:db8::1"
                    .parse::<Ipv6Addr>()
                    .expect("IPv6 fixture must parse")
                    .octets(),
            )),
            vec![DnsAddressAnswer {
                address: "2001:db8::1".parse().expect("IPv6 fixture must parse"),
                ttl_seconds: 60,
            }]
        );
        assert!(parse_dns_address_answers(&[]).is_empty());
    }

    #[test]
    fn bounds_and_deduplicates_retained_address_attribution() {
        let mut observation = RetainedObservation::default();
        retain_address_answers(
            &mut observation,
            [
                DnsAddressAnswer {
                    address: "192.0.2.10".parse().expect("IPv4 fixture must parse"),
                    ttl_seconds: 60,
                },
                DnsAddressAnswer {
                    address: "192.0.2.10".parse().expect("IPv4 fixture must parse"),
                    ttl_seconds: 30,
                },
            ],
        );
        for value in 0..=MAX_RETAINED_ADDRESSES_PER_OBSERVATION {
            retain_address_answers(
                &mut observation,
                [DnsAddressAnswer {
                    address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, value as u8)),
                    ttl_seconds: 45,
                }],
            );
        }
        assert_eq!(
            observation.resolved_addresses.len(),
            MAX_RETAINED_ADDRESSES_PER_OBSERVATION
        );
        assert_eq!(observation.minimum_observed_ttl_seconds, Some(30));
        assert!(observation.addresses_truncated);
    }

    #[test]
    fn materializes_only_bounded_ttl_https_addresses_and_expires_them() {
        let queue = Arc::new(Mutex::new(MaterializationQueue::default()));
        let now = Instant::now();
        queue
            .lock()
            .unwrap()
            .pending
            .insert(PendingMaterialization {
                hostname: "pipelines.actions.githubusercontent.com".to_owned(),
                address: "192.0.2.10".parse().unwrap(),
                ttl_seconds: 30,
            });
        let mut active = BTreeMap::new();
        let (changed, truncated, expired) =
            merge_pending_materializations(&mut active, &queue, now);

        assert!(changed);
        assert!(!truncated);
        assert_eq!(expired, 0);
        assert_eq!(
            materialized_effective_allowances(&active),
            vec![EffectiveAllowance {
                destination_type: DestinationType::Ip,
                destination: "192.0.2.10".to_owned(),
                protocol: Protocol::Tcp,
                port: 443,
            }]
        );
        let (changed, _, expired) =
            merge_pending_materializations(&mut active, &queue, now + Duration::from_secs(31));
        assert!(changed);
        assert_eq!(expired, 1);
        assert!(active.is_empty());
    }

    #[test]
    fn builds_bounded_sanitized_evidence() {
        let mut state = ObservationState::default();
        state.retained.insert(
            (
                "pipelines.actions.githubusercontent.com".to_owned(),
                1,
                "matches_candidate_pattern",
            ),
            RetainedObservation {
                occurrences: 2,
                resolved_addresses: BTreeSet::from([
                    "192.0.2.10".parse().expect("IPv4 fixture must parse"),
                    "2001:db8::1".parse().expect("IPv6 fixture must parse"),
                ]),
                minimum_observed_ttl_seconds: Some(30),
                addresses_truncated: false,
            },
        );
        state.excluded_non_github_query_count = 1;
        let evidence = evidence_from_state(&state, "active_test_only", DnsEvidenceScope::Audit);
        assert_eq!(evidence.observations.len(), 1);
        assert_eq!(evidence.observations[0].query_type, "a");
        assert_eq!(evidence.observations[0].occurrences, 2);
        assert_eq!(
            evidence.observations[0].resolved_addresses,
            vec!["192.0.2.10", "2001:db8::1"]
        );
        assert_eq!(
            evidence.observations[0].minimum_observed_ttl_seconds,
            Some(30)
        );
        assert!(!evidence.observations[0].addresses_truncated);
        assert_eq!(evidence.excluded_non_github_query_count, 1);
        assert!(!evidence.protection_available);
    }
}
