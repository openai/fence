use crate::config::{
    ContainerPolicy, DestinationType, MAX_REPORT_BYTES, Mode, Protocol, parse_and_normalize,
};
use crate::error::ErrorDetail;
use crate::findings::{ConnectionFinding, FindingCollection, bounded_timestamp_now};
use crate::lifecycle::{
    CriticalFinding, NativeResidentNetwork, RESIDENT_VERIFICATION_INTERVAL, ResidentSession,
    require_production_root_process, validate_production_service_context,
    validate_test_service_context,
};
use crate::lockdown::{LockdownControl, LockdownPosture, SystemLockdownControl};
use crate::nflog::NflogReader;
use crate::nft::{
    NetworkEvidenceCounters, OwnedNftState, expected_dns_mediated_owned_state,
    render_dns_mediated_replacement_ruleset, render_dns_mediated_ruleset,
};
use crate::nft_backend::{NativeNftBackend, SystemNftExecutor};
use crate::plan::{AssuranceStatus, EffectiveAllowance, PlanData, build_plan};
use crate::platform_profile::{
    GITHUB_HOSTED_JOB_STATUS_ACTIONS_SUFFIX_PATTERN, GITHUB_HOSTED_JOB_STATUS_BOOTSTRAP_HOSTNAMES,
    GITHUB_HOSTED_JOB_STATUS_EXACT_COMPATIBILITY_HOSTNAMES,
    GITHUB_HOSTED_JOB_STATUS_HTTPS_REFRESH_OVERLAP_SECONDS,
    GITHUB_HOSTED_JOB_STATUS_MAX_DERIVED_CNAME_AUTHORIZATIONS,
    GITHUB_HOSTED_JOB_STATUS_MAX_DERIVED_CNAME_DEPTH,
    GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS,
    GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS,
    GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_TTL_SECONDS, GITHUB_HOSTED_JOB_STATUS_PROFILE_ID,
    GITHUB_HOSTED_JOB_STATUS_REFRESH_INTERVAL_SECONDS, GITHUB_HOSTED_JOB_STATUS_UPSTREAM_DNS,
    github_hosted_job_status_dns_mediation_plan,
};
use crate::resolver::SystemResolver;
use crate::runtime::{
    ProductionRuntimeStore, RuntimeDocumentStore, RuntimeError, TestRuntimeStore,
};
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
pub const DNS_MEDIATED_COMPATIBILITY_CANDIDATE_ID: &str =
    "github_hosted_dns_mediated_bounded_actions_suffix_candidate_v6";
pub const DNS_MEDIATED_BLOCK_EVIDENCE_STATUS: &str = "dns_mediated_host_block_candidate_test_only";
pub const DNS_MEDIATED_BLOCK_READY_STATUS: &str =
    "dns_mediated_host_block_candidate_ready_no_public_activation";
pub const PROTECTED_BLOCK_STATUS: &str = "protected_host_block";
pub const PROTECTED_BLOCK_READY_STATUS: &str = "ready";
pub const PROTECTED_DEGRADED_BLOCK_STATUS: &str = "protected_host_block_degraded";
pub const PROTECTED_DEGRADED_BLOCK_READY_STATUS: &str = "ready_degraded";
pub const DNS_CANDIDATE_PATTERNS: [&str; 4] = [
    "*.actions.githubusercontent.com",
    "codeload.github.com",
    "actions-results-receiver-production.githubapp.com",
    "productionresultssa*.blob.core.windows.net",
];
pub const DNS_BLOCK_COMPATIBILITY_PATTERNS: [&str; 2] = [
    GITHUB_HOSTED_JOB_STATUS_ACTIONS_SUFFIX_PATTERN,
    GITHUB_HOSTED_JOB_STATUS_EXACT_COMPATIBILITY_HOSTNAMES[0],
];
pub const DNS_BLOCK_CANDIDATE_BOOTSTRAP_HOSTNAMES: [&str; 4] =
    GITHUB_HOSTED_JOB_STATUS_BOOTSTRAP_HOSTNAMES;
const MAX_RETAINED_DNS_OBSERVATIONS: usize = 256;
const MAX_RETAINED_ADDRESSES_PER_OBSERVATION: usize = 32;
const MAX_DYNAMIC_MATERIALIZATIONS: usize = 128;
const MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS: usize =
    GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS;
const MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS: usize =
    GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS;
const MAX_DERIVED_CNAME_AUTHORIZATIONS: usize =
    GITHUB_HOSTED_JOB_STATUS_MAX_DERIVED_CNAME_AUTHORIZATIONS;
const MAX_DERIVED_CNAME_DEPTH: u8 = GITHUB_HOSTED_JOB_STATUS_MAX_DERIVED_CNAME_DEPTH;
const MAX_DYNAMIC_TTL_SECONDS: u32 = GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_TTL_SECONDS;
const DNS_CANDIDATE_REFRESH_INTERVAL: Duration =
    Duration::from_secs(GITHUB_HOSTED_JOB_STATUS_REFRESH_INTERVAL_SECONDS);
const DNS_MATERIALIZATION_REFRESH_OVERLAP: Duration =
    Duration::from_secs(GITHUB_HOSTED_JOB_STATUS_HTTPS_REFRESH_OVERLAP_SECONDS);
const MAX_CRITICAL_FINDINGS: usize = 64;
const MAX_DNS_PACKET_BYTES: usize = 4096;
const UPSTREAM_DNS: &str = GITHUB_HOSTED_JOB_STATUS_UPSTREAM_DNS;
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
    ProtectedHostBlock,
    ProtectedHostBlockDegraded,
}

impl DnsEvidenceScope {
    fn mode(self) -> Mode {
        match self {
            Self::Audit => Mode::Audit,
            Self::HostBlockCandidate
            | Self::ProtectedHostBlock
            | Self::ProtectedHostBlockDegraded => Mode::Block,
        }
    }

    fn is_block(self) -> bool {
        matches!(
            self,
            Self::HostBlockCandidate | Self::ProtectedHostBlock | Self::ProtectedHostBlockDegraded
        )
    }

    #[cfg(test)]
    fn forward_query(self, hostname: &str, query_type: u16) -> bool {
        match self {
            Self::Audit => true,
            Self::HostBlockCandidate
            | Self::ProtectedHostBlock
            | Self::ProtectedHostBlockDegraded => {
                matches_supported_block_query_type(query_type)
                    && authorized_block_candidate_hostname(
                        hostname,
                        &mut CnameAuthorizationState::default(),
                        Instant::now(),
                    )
            }
        }
    }

    fn status(self) -> &'static str {
        match self {
            Self::Audit => DNS_MEDIATION_EVIDENCE_STATUS,
            Self::HostBlockCandidate => DNS_MEDIATED_BLOCK_EVIDENCE_STATUS,
            Self::ProtectedHostBlock => PROTECTED_BLOCK_STATUS,
            Self::ProtectedHostBlockDegraded => PROTECTED_DEGRADED_BLOCK_STATUS,
        }
    }

    fn candidate_profile_id(self) -> &'static str {
        match self {
            Self::Audit => DNS_MEDIATED_GITHUB_CANDIDATE_ID,
            Self::HostBlockCandidate
            | Self::ProtectedHostBlock
            | Self::ProtectedHostBlockDegraded => DNS_MEDIATED_COMPATIBILITY_CANDIDATE_ID,
        }
    }

    fn active_routing_status(self) -> &'static str {
        match self {
            Self::Audit | Self::HostBlockCandidate => "active_test_only",
            Self::ProtectedHostBlock | Self::ProtectedHostBlockDegraded => "active",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsBlockRuntimeScope {
    TestEvidence,
    ProductionStandardBlock,
    ProductionUnsafePreserve,
}

impl DnsBlockRuntimeScope {
    fn evidence_status(self) -> &'static str {
        match self {
            Self::TestEvidence => DNS_MEDIATED_BLOCK_EVIDENCE_STATUS,
            Self::ProductionStandardBlock => PROTECTED_BLOCK_STATUS,
            Self::ProductionUnsafePreserve => PROTECTED_DEGRADED_BLOCK_STATUS,
        }
    }

    fn ready_status(self) -> &'static str {
        match self {
            Self::TestEvidence => DNS_MEDIATED_BLOCK_READY_STATUS,
            Self::ProductionStandardBlock => PROTECTED_BLOCK_READY_STATUS,
            Self::ProductionUnsafePreserve => PROTECTED_DEGRADED_BLOCK_READY_STATUS,
        }
    }

    fn resident_status(self) -> &'static str {
        match self {
            Self::TestEvidence => "resident_dns_mediated_host_block_candidate_test_only",
            Self::ProductionStandardBlock => "resident_protected",
            Self::ProductionUnsafePreserve => "resident_degraded",
        }
    }

    fn protection_available(self) -> bool {
        matches!(self, Self::ProductionStandardBlock)
    }

    fn dns_scope(self) -> DnsEvidenceScope {
        match self {
            Self::TestEvidence => DnsEvidenceScope::HostBlockCandidate,
            Self::ProductionStandardBlock => DnsEvidenceScope::ProtectedHostBlock,
            Self::ProductionUnsafePreserve => DnsEvidenceScope::ProtectedHostBlockDegraded,
        }
    }

    fn limitations(self) -> Vec<&'static str> {
        match self {
            Self::TestEvidence => dns_block_test_limitations(),
            Self::ProductionStandardBlock => protected_block_limitations(),
            Self::ProductionUnsafePreserve => protected_degraded_block_limitations(),
        }
    }

    fn lockdown_posture(self) -> LockdownPosture {
        match self {
            Self::TestEvidence | Self::ProductionStandardBlock => LockdownPosture::StandardBlock,
            Self::ProductionUnsafePreserve => LockdownPosture::UnsafePreserve,
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
    pub selected_platform_profile_id: Option<&'static str>,
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
    pub bounded_actions_suffix_authorizations: Vec<String>,
    pub bounded_actions_suffix_authorizations_truncated: bool,
    pub derived_cname_authorizations: Vec<DnsDerivedCnameAuthorization>,
    pub derived_cname_authorizations_truncated: bool,
    pub excluded_non_github_query_count: u64,
    pub blocked_non_candidate_query_count: u64,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsDerivedCnameAuthorization {
    pub hostname: String,
    pub source_hostname: String,
    pub observed_ttl_seconds: u32,
    pub depth: u8,
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
    pub selected_platform_profile_id: &'static str,
    pub policy_hash_schema_version: u32,
    pub policy_hash: String,
    pub base_ruleset_hash: String,
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
    selected_platform_profile_id: &'static str,
    policy_hash_schema_version: u32,
    policy_hash: &'a str,
    base_ruleset_hash: &'a str,
    ruleset_hash: &'a str,
    planned_owned_state: &'a OwnedNftState,
    readiness_status: &'static str,
}

#[derive(Debug, Serialize)]
struct DnsMediatedBlockReady<'a> {
    status: &'static str,
    mode: Mode,
    candidate_profile_id: &'static str,
    selected_platform_profile_id: &'static str,
    policy_hash_schema_version: u32,
    policy_hash: &'a str,
    base_ruleset_hash: &'a str,
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

#[derive(Debug, Clone, Eq, PartialEq)]
struct DnsAddressAnswer {
    hostname: String,
    address: IpAddr,
    ttl_seconds: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DnsCnameAnswer {
    owner: String,
    target: String,
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

#[derive(Debug, Default)]
struct CnameAuthorizationState {
    bounded_actions_suffix: BTreeSet<String>,
    bounded_actions_suffix_truncated: bool,
    active: BTreeMap<String, ActiveCnameAuthorization>,
    truncated: bool,
}

#[derive(Debug)]
struct ActiveCnameAuthorization {
    source_hostname: String,
    observed_ttl_seconds: u32,
    depth: u8,
    expires_at: Instant,
}

#[derive(Clone)]
struct ObservationRecorder {
    state: Arc<Mutex<ObservationState>>,
    cname_authorizations: Arc<Mutex<CnameAuthorizationState>>,
    report_path: PathBuf,
    scope: DnsEvidenceScope,
    materializations: Option<Arc<Mutex<MaterializationQueue>>>,
}

impl ObservationRecorder {
    fn forward_query(&self, hostname: &str, query_type: u16) -> bool {
        match self.scope {
            DnsEvidenceScope::Audit => true,
            DnsEvidenceScope::HostBlockCandidate
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                if !matches_supported_block_query_type(query_type) {
                    return false;
                }
                let mut authorizations = self
                    .cname_authorizations
                    .lock()
                    .expect("DNS CNAME authorization lock poisoned");
                authorized_block_candidate_hostname(hostname, &mut authorizations, Instant::now())
            }
        }
    }

    fn candidate_classification(&self, hostname: &str) -> &'static str {
        let classification = candidate_classification(self.scope, hostname);
        if classification != "github_related_outside_candidate" {
            classification
        } else {
            let mut authorizations = self
                .cname_authorizations
                .lock()
                .expect("DNS CNAME authorization lock poisoned");
            remove_expired_cname_authorizations(&mut authorizations, Instant::now());
            if authorizations.bounded_actions_suffix.contains(hostname) {
                "matches_bounded_actions_suffix_authorization"
            } else if authorizations.active.contains_key(hostname) {
                "matches_ttl_bounded_cname_descendant"
            } else {
                classification
            }
        }
    }

    fn materialization_ttl_seconds(&self, hostname: &str, ttl_seconds: u32) -> Option<u32> {
        if matches_exact_block_candidate_hostname(hostname) {
            return bound_materialization_ttl(ttl_seconds, None);
        }
        let now = Instant::now();
        let mut authorizations = self
            .cname_authorizations
            .lock()
            .expect("DNS CNAME authorization lock poisoned");
        remove_expired_cname_authorizations(&mut authorizations, now);
        if authorizations.bounded_actions_suffix.contains(hostname) {
            return bound_materialization_ttl(ttl_seconds, None);
        }
        let remaining_seconds = authorizations
            .active
            .get(hostname)?
            .expires_at
            .saturating_duration_since(now);
        bound_materialization_ttl(ttl_seconds, Some(remaining_seconds))
    }

    fn evidence_from_state(
        &self,
        state: &ObservationState,
        routing_status: &'static str,
    ) -> DnsMediationEvidence {
        let mut authorizations = self
            .cname_authorizations
            .lock()
            .expect("DNS CNAME authorization lock poisoned");
        remove_expired_cname_authorizations(&mut authorizations, Instant::now());
        evidence_from_state_and_authorizations(state, routing_status, self.scope, &authorizations)
    }

    fn record_query(&self, hostname: &str, query_type: u16, forwarded: bool) {
        let normalized = normalize_hostname(hostname);
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        if let Some(hostname) = normalized
            .as_ref()
            .filter(|name| reportable_github_hostname(name))
            .cloned()
        {
            let classification = self.candidate_classification(&hostname);
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
        if self.scope.is_block() && !forwarded {
            state.blocked_non_candidate_query_count =
                state.blocked_non_candidate_query_count.saturating_add(1);
        }
        let evidence = self.evidence_from_state(&state, self.scope.active_routing_status());
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        let _ = write_result;
    }

    fn record_response(&self, hostname: &str, query_type: u16, packet: &[u8]) {
        let Some(hostname) = normalize_hostname(hostname) else {
            return;
        };
        let forwardable_block_response =
            self.scope.is_block() && self.forward_query(&hostname, query_type);
        if forwardable_block_response {
            let mut authorizations = self
                .cname_authorizations
                .lock()
                .expect("DNS CNAME authorization lock poisoned");
            retain_cname_authorizations(
                &mut authorizations,
                parse_dns_cname_answers(packet),
                Instant::now(),
            );
        }
        let answers = parse_dns_address_answers(packet);
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        if reportable_github_hostname(&hostname) {
            let classification = self.candidate_classification(&hostname);
            let key = (hostname, query_type, classification);
            if let Some(observation) = state.retained.get_mut(&key) {
                retain_address_answers(observation, answers.clone());
            }
        }
        if forwardable_block_response && let Some(queue) = &self.materializations {
            let mut queue = queue.lock().expect("DNS materialization lock poisoned");
            for answer in answers {
                let Some(ttl_seconds) =
                    self.materialization_ttl_seconds(&answer.hostname, answer.ttl_seconds)
                else {
                    continue;
                };
                if queue.pending.len() >= MAX_DYNAMIC_MATERIALIZATIONS {
                    queue.truncated = true;
                    break;
                }
                queue.pending.insert(PendingMaterialization {
                    hostname: answer.hostname,
                    address: answer.address,
                    ttl_seconds,
                });
            }
        }
        let evidence = self.evidence_from_state(&state, self.scope.active_routing_status());
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
        let mut authorizations = self.cname_authorizations.lock().map_err(|_| {
            DnsMediationError::new(
                "dns_cname_authorization_state_failed",
                "DNS CNAME authorization state could not be reset after setup",
            )
        })?;
        *authorizations = CnameAuthorizationState::default();
        let evidence = evidence_from_state_and_authorizations(
            &state,
            "active_test_only",
            self.scope,
            &authorizations,
        );
        drop(authorizations);
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
            cname_authorizations: Arc::new(Mutex::new(CnameAuthorizationState::default())),
            report_path,
            scope,
            materializations,
        };
        write_report(
            &recorder.report_path,
            &evidence_from_state_and_authorizations(
                &recorder
                    .state
                    .lock()
                    .expect("DNS observation lock poisoned"),
                "setting_up",
                scope,
                &recorder
                    .cname_authorizations
                    .lock()
                    .expect("DNS CNAME authorization lock poisoned"),
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

struct DnsMediatedBlockSession<R: RuntimeDocumentStore> {
    _mediation: DnsMediationSession,
    queue: Arc<Mutex<MaterializationQueue>>,
    backend: NativeNftBackend<SystemNftExecutor>,
    lockdown: SystemLockdownControl,
    reader: NflogReader,
    runtime: R,
    base_allowances: Vec<EffectiveAllowance>,
    active: BTreeMap<(String, IpAddr), ActiveMaterialization>,
    expected_state: OwnedNftState,
    evidence: DnsMediatedBlockEvidence,
    findings: FindingCollection,
    scope: DnsBlockRuntimeScope,
    next_dns_refresh: Duration,
    next_verification: Duration,
}

impl<R: RuntimeDocumentStore> DnsMediatedBlockSession<R> {
    fn establish(
        runtime: R,
        mut mediation: DnsMediationSession,
        queue: Arc<Mutex<MaterializationQueue>>,
        plan: &PlanData,
        scope: DnsBlockRuntimeScope,
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
                "dns_block_prehydration_failed",
                "DNS-mediated block lifecycle did not materialize fixed bootstrap names",
            ));
        }
        let allowances =
            effective_allowances_with_materializations(&plan.effective_policy, &active);
        let ruleset = render_dns_mediated_ruleset(Mode::Block, &allowances);
        let ruleset_hash = sha256_hex(ruleset.as_bytes());
        let expected_state = expected_dns_mediated_owned_state(Mode::Block, &allowances);
        let mut evidence = initial_dns_block_evidence(
            plan,
            &active,
            materializations_truncated,
            ruleset_hash.clone(),
            scope,
        );
        if let Err(error) = runtime.write_state_exclusive(&DnsMediatedBlockState {
            status: scope.evidence_status(),
            mode: Mode::Block,
            candidate_profile_id: DNS_MEDIATED_COMPATIBILITY_CANDIDATE_ID,
            selected_platform_profile_id: GITHUB_HOSTED_JOB_STATUS_PROFILE_ID,
            policy_hash_schema_version: plan.policy_hash_schema_version,
            policy_hash: &plan.policy_hash,
            base_ruleset_hash: &plan.ruleset_hash,
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
        let mut lockdown = SystemLockdownControl::new(runtime.directory());
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
            match scope.lockdown_posture() {
                LockdownPosture::StandardBlock => {
                    lockdown.disable_sudo().map_err(lockdown_error)?;
                    lockdown.disable_containers().map_err(lockdown_error)?;
                    lockdown.verify_sudo_disabled().map_err(lockdown_error)?;
                    lockdown
                        .verify_containers_disabled()
                        .map_err(lockdown_error)?;
                    evidence.sudo_status = "disabled_verified";
                    evidence.container_status = "disabled_verified";
                }
                LockdownPosture::UnsafePreserve => {
                    lockdown.disable_sudo().map_err(lockdown_error)?;
                    lockdown.verify_sudo_disabled().map_err(lockdown_error)?;
                    lockdown
                        .verify_containers_available()
                        .map_err(lockdown_error)?;
                    evidence.sudo_status = "disabled_verified";
                    evidence.container_status = "preserved_unsafe";
                }
                LockdownPosture::Audit => unreachable!("block sessions cannot use audit posture"),
            }
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
            status: scope.ready_status(),
            mode: Mode::Block,
            candidate_profile_id: DNS_MEDIATED_COMPATIBILITY_CANDIDATE_ID,
            selected_platform_profile_id: GITHUB_HOSTED_JOB_STATUS_PROFILE_ID,
            policy_hash_schema_version: plan.policy_hash_schema_version,
            policy_hash: &plan.policy_hash,
            base_ruleset_hash: &plan.ruleset_hash,
            ruleset_hash: &ruleset_hash,
            protection_available: scope.protection_available(),
            limitations: scope.limitations(),
        }) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(runtime_error(error));
        }
        evidence.setup_status = scope.resident_status();
        evidence.readiness_status = scope.ready_status();
        runtime.replace_report(&evidence).map_err(runtime_error)?;
        Ok(Self {
            _mediation: mediation,
            queue,
            backend,
            lockdown,
            reader,
            runtime,
            base_allowances: plan.effective_policy.clone(),
            active,
            expected_state,
            evidence,
            findings: FindingCollection::empty(),
            scope,
            next_dns_refresh: DNS_CANDIDATE_REFRESH_INTERVAL,
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
                    "dns_block_nflog_failure",
                    "DNS-mediated block NFLOG collection failed after readiness",
                );
                changed = true;
            }
        }

        if elapsed >= self.next_dns_refresh {
            if prehydrate_candidate_names().is_err() {
                self.record_critical(
                    "dns_block_root_refresh_failed",
                    "DNS-mediated exact-root refresh failed after readiness",
                );
            }
            self.next_dns_refresh = elapsed + DNS_CANDIDATE_REFRESH_INTERVAL;
            changed = true;
        }

        let mut proposed = self.active.clone();
        let (materialization_changed, truncated, expired) =
            merge_pending_materializations(&mut proposed, &self.queue, Instant::now());
        self.evidence.materializations_truncated |= truncated;
        if materialization_changed {
            let allowances =
                effective_allowances_with_materializations(&self.base_allowances, &proposed);
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
                    "dns_block_dynamic_update_failed",
                    "approved DNS-derived owned nftables replacement failed after readiness",
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
                    "dns_block_network_drift",
                    "DNS-mediated owned nftables state drifted after readiness",
                );
            }
            if self.lockdown.verify_sudo_disabled().is_err() {
                self.evidence.sudo_status = "critical_drift";
                self.record_critical(
                    "dns_block_sudo_drift",
                    "measured passwordless sudo state drifted after readiness",
                );
            }
            match self.scope.lockdown_posture() {
                LockdownPosture::StandardBlock => {
                    if self.lockdown.verify_containers_disabled().is_err() {
                        self.evidence.container_status = "critical_drift";
                        self.record_critical(
                            "dns_block_container_drift",
                            "measured container control state drifted after readiness",
                        );
                    }
                }
                LockdownPosture::UnsafePreserve => {
                    if self.lockdown.verify_containers_available().is_err() {
                        self.evidence.container_status = "critical_drift";
                        self.record_critical(
                            "dns_block_container_drift",
                            "preserved container control path drifted after readiness",
                        );
                    }
                }
                LockdownPosture::Audit => unreachable!("block sessions cannot use audit posture"),
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
                        "dns_block_counter_read_failed",
                        "DNS-mediated violation counter could not be read after readiness",
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

pub fn run_protected_block_service(config: &Path) -> Result<(), DnsMediationError> {
    require_production_root_process()
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    let runtime = ProductionRuntimeStore::open(config).map_err(runtime_error)?;
    validate_production_service_context(&runtime.invocation_id)
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    let normalized = parse_and_normalize(&runtime.read_config_bounded().map_err(runtime_error)?)
        .map_err(config_error)?;
    if normalized.invocation_id != runtime.invocation_id {
        return Err(DnsMediationError::new(
            "unsafe_runtime_config",
            "trusted launcher configuration invocation identifier must match its runtime directory",
        ));
    }
    let plan = build_plan(normalized, &SystemResolver).map_err(config_error)?;
    let scope = match (plan.assurance_status, plan.container_policy) {
        (AssuranceStatus::PlannedBlockContainment, Some(ContainerPolicy::Disable)) => {
            DnsBlockRuntimeScope::ProductionStandardBlock
        }
        (
            AssuranceStatus::PlannedBlockDegradedContainerAccess,
            Some(ContainerPolicy::UnsafePreserve),
        ) => DnsBlockRuntimeScope::ProductionUnsafePreserve,
        _ => {
            return Err(DnsMediationError::new(
                "protected_run_policy_not_activated",
                "protected run accepts only standard block or explicit unsafe-preserve block with the reviewed hosted job-status profile",
            ));
        }
    };
    if plan.selected_mode != Mode::Block
        || plan.platform_profile.id != GITHUB_HOSTED_JOB_STATUS_PROFILE_ID
        || plan.platform_profile.dns_mediated_compatibility.as_ref()
            != Some(&github_hosted_job_status_dns_mediation_plan())
    {
        return Err(DnsMediationError::new(
            "protected_run_policy_not_activated",
            "protected run accepts only standard block or explicit unsafe-preserve block with the reviewed hosted job-status profile",
        ));
    }
    let mut fingerprint = SystemLockdownControl::new(runtime.directory());
    fingerprint
        .verify_supported_host()
        .map_err(lockdown_error)?;

    let queue = Arc::new(Mutex::new(MaterializationQueue::default()));
    let mediation = DnsMediationSession::establish(
        runtime.directory(),
        scope.dns_scope(),
        Some(queue.clone()),
    )?;
    let mut session = DnsMediatedBlockSession::establish(runtime, mediation, queue, &plan, scope)?;
    let start = Instant::now();
    loop {
        session.poll_once(start.elapsed(), POLL_INTERVAL)?;
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
        || plan.platform_profile.id != GITHUB_HOSTED_JOB_STATUS_PROFILE_ID
        || plan.platform_profile.dns_mediated_compatibility.as_ref()
            != Some(&github_hosted_job_status_dns_mediation_plan())
        || !plan.requested_policy.is_empty()
    {
        return Err(DnsMediationError::new(
            "invalid_selected_profile_runtime_policy",
            "DNS-mediated block evidence accepts only standard block with the reviewed hosted job-status profile and no user allowances",
        ));
    }
    let runtime =
        TestRuntimeStore::create(runtime_root, &plan.invocation_id).map_err(runtime_error)?;
    let queue = Arc::new(Mutex::new(MaterializationQueue::default()));
    let mediation = DnsMediationSession::establish(
        &runtime.directory,
        DnsBlockRuntimeScope::TestEvidence.dns_scope(),
        Some(queue.clone()),
    )?;
    let mut session = DnsMediatedBlockSession::establish(
        runtime,
        mediation,
        queue,
        plan,
        DnsBlockRuntimeScope::TestEvidence,
    )?;
    let start = Instant::now();
    loop {
        session.poll_once(start.elapsed(), POLL_INTERVAL)?;
    }
}

fn initial_dns_block_evidence(
    plan: &PlanData,
    active: &BTreeMap<(String, IpAddr), ActiveMaterialization>,
    materializations_truncated: bool,
    ruleset_hash: String,
    scope: DnsBlockRuntimeScope,
) -> DnsMediatedBlockEvidence {
    DnsMediatedBlockEvidence {
        status: scope.evidence_status(),
        mode: Mode::Block,
        candidate_profile_id: DNS_MEDIATED_COMPATIBILITY_CANDIDATE_ID,
        selected_platform_profile_id: GITHUB_HOSTED_JOB_STATUS_PROFILE_ID,
        policy_hash_schema_version: plan.policy_hash_schema_version,
        policy_hash: plan.policy_hash.clone(),
        base_ruleset_hash: plan.ruleset_hash.clone(),
        candidate_hostnames: DNS_BLOCK_CANDIDATE_BOOTSTRAP_HOSTNAMES.to_vec(),
        setup_status: "setting_up",
        network_application_status: "not_applied",
        network_verification_status: "not_verified",
        sudo_status: "not_checked",
        container_status: "not_checked",
        readiness_status: "not_emitted",
        rollback_status: "not_required",
        ruleset_hash,
        dns_upstream_policy: "root_resident_mediator_only_udp_53",
        materialization_status: "bounded_ttl_plus_refresh_overlap_constrained_actions_or_cname_descendant_https_only",
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
        protection_available: scope.protection_available(),
        limitations: scope.limitations(),
    }
}

fn dns_block_test_limitations() -> Vec<&'static str> {
    vec![
        "dns_mediated_host_block_candidate_test_only_no_public_activation",
        "test_only_evidence_path_does_not_activate_default_planning_descriptor",
        "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
        "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
        "block_dns_queries_are_canonicalized_before_upstream_forwarding",
        "dns_query_timing_and_count_remain_egress_limitations",
        "post_ready_codeload_traffic_is_not_authorized",
        "post_ready_results_storage_traffic_is_not_authorized",
        "cname_descendants_are_bounded_ttl_derived_authorizations",
        "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
        "candidate_bootstrap_roots_refresh_every_5_seconds",
        "https_materialization_expiry_includes_30_second_refresh_overlap",
        "approved_status_https_destinations_remain_egress_channels",
        "resolved_status_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
        "dynamic_owned_table_replacement_resets_network_counters",
        "planner_selection_does_not_activate_runtime_materialization",
    ]
}

fn protected_block_limitations() -> Vec<&'static str> {
    let mut limitations = protected_block_shared_limitations();
    limitations.push("audit_production_activation_not_implemented");
    limitations
}

fn protected_degraded_block_limitations() -> Vec<&'static str> {
    let mut limitations = protected_block_shared_limitations();
    limitations.extend([
        "container_control_preserved_invalidates_containment",
        "container_control_remains_available_to_later_workflow_code",
        "audit_production_activation_not_implemented",
    ]);
    limitations
}

fn protected_block_shared_limitations() -> Vec<&'static str> {
    vec![
        "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
        "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
        "block_dns_queries_are_canonicalized_before_upstream_forwarding",
        "dns_query_timing_and_count_remain_egress_limitations",
        "post_ready_codeload_traffic_is_not_authorized",
        "post_ready_results_storage_traffic_is_not_authorized",
        "cname_descendants_are_bounded_ttl_derived_authorizations",
        "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
        "bootstrap_roots_refresh_every_5_seconds",
        "https_materialization_expiry_includes_30_second_refresh_overlap",
        "approved_status_https_destinations_remain_egress_channels",
        "resolved_status_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
        "dynamic_owned_table_replacement_resets_network_counters",
    ]
}

fn prehydrate_candidate_names() -> Result<(), DnsMediationError> {
    for hostname in DNS_BLOCK_CANDIDATE_BOOTSTRAP_HOSTNAMES {
        if (hostname, 443_u16)
            .to_socket_addrs()
            .map_err(|_| {
                DnsMediationError::new(
                    "dns_block_prehydration_failed",
                    "failed to resolve a fixed DNS-mediated bootstrap hostname",
                )
            })?
            .next()
            .is_none()
        {
            return Err(DnsMediationError::new(
                "dns_block_prehydration_failed",
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
                expires_at: now
                    + Duration::from_secs(u64::from(materialization.ttl_seconds))
                    + DNS_MATERIALIZATION_REFRESH_OVERLAP,
            },
        );
        changed = true;
    }
    (changed, truncated, expired)
}

fn effective_allowances_with_materializations(
    base_allowances: &[EffectiveAllowance],
    active: &BTreeMap<(String, IpAddr), ActiveMaterialization>,
) -> Vec<EffectiveAllowance> {
    base_allowances
        .iter()
        .cloned()
        .chain(active.values().map(|materialization| EffectiveAllowance {
            destination_type: DestinationType::Ip,
            destination: materialization.address.to_string(),
            protocol: Protocol::Tcp,
            port: 443,
        }))
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

fn config_error(error: ErrorDetail) -> DnsMediationError {
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
        let Some(upstream_query) = query_for_upstream(&recorder, bytes, parsed_question.as_ref())
        else {
            if let Some((hostname, query_type)) = &parsed_question {
                recorder.record_query(hostname, *query_type, false);
            }
            if let Some(response) = refused_response(bytes) {
                let _ = socket.send_to(&response, peer);
            }
            continue;
        };
        if let Some((hostname, query_type)) = &parsed_question {
            recorder.record_query(hostname, *query_type, true);
        }
        let Ok(upstream) = UdpSocket::bind("0.0.0.0:0") else {
            continue;
        };
        let _ = upstream.set_read_timeout(Some(DNS_FORWARD_TIMEOUT));
        if upstream.send_to(&upstream_query, UPSTREAM_DNS).is_err() {
            continue;
        }
        let mut response = [0_u8; MAX_DNS_PACKET_BYTES];
        if let Ok((response_length, _)) = upstream.recv_from(&mut response) {
            let response = &mut response[..response_length];
            restore_client_query_id(response, bytes);
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
        let Some(upstream_query) = query_for_upstream(&recorder, &query, parsed_question.as_ref())
        else {
            if let Some((hostname, query_type)) = &parsed_question {
                recorder.record_query(hostname, *query_type, false);
            }
            if let Some(response) = refused_response(&query) {
                let _ = client.write_all(&(response.len() as u16).to_be_bytes());
                let _ = client.write_all(&response);
            }
            continue;
        };
        if let Some((hostname, query_type)) = &parsed_question {
            recorder.record_query(hostname, *query_type, true);
        }
        let Ok(mut upstream) = TcpStream::connect(UPSTREAM_DNS) else {
            continue;
        };
        let _ = upstream.set_read_timeout(Some(DNS_FORWARD_TIMEOUT));
        if upstream
            .write_all(&(upstream_query.len() as u16).to_be_bytes())
            .is_err()
            || upstream.write_all(&upstream_query).is_err()
        {
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
        restore_client_query_id(&mut response, &query);
        if let Some((hostname, query_type)) = &parsed_question {
            recorder.record_response(hostname, *query_type, &response);
        }
        let _ = client.write_all(&response_length);
        let _ = client.write_all(&response);
    }
}

fn query_for_upstream(
    recorder: &ObservationRecorder,
    query: &[u8],
    parsed_question: Option<&(String, u16)>,
) -> Option<Vec<u8>> {
    match (recorder.scope, parsed_question) {
        (DnsEvidenceScope::Audit, _) => Some(query.to_vec()),
        (
            DnsEvidenceScope::HostBlockCandidate
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded,
            Some((hostname, query_type)),
        ) => {
            let canonical = canonical_block_query(hostname, *query_type, query)?;
            recorder
                .forward_query(hostname, *query_type)
                .then_some(canonical)
        }
        (
            DnsEvidenceScope::HostBlockCandidate
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded,
            None,
        ) => None,
    }
}

fn canonical_block_query(hostname: &str, query_type: u16, query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12
        || u16::from_be_bytes([query[4], query[5]]) != 1
        || !matches_supported_block_query_type(query_type)
    {
        return None;
    }
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & 0xf800 != 0 {
        return None;
    }
    let mut offset = 12;
    loop {
        let length = usize::from(*query.get(offset)?);
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset.checked_add(length)? > query.len() {
            return None;
        }
        offset += length;
    }
    if offset + 4 > query.len()
        || u16::from_be_bytes([query[offset], query[offset + 1]]) != query_type
        || u16::from_be_bytes([query[offset + 2], query[offset + 3]]) != 1
    {
        return None;
    }
    let mut canonical = Vec::with_capacity(hostname.len() + 18);
    canonical.extend_from_slice(&0_u16.to_be_bytes());
    canonical.extend_from_slice(&(flags & 0x0110).to_be_bytes());
    canonical.extend_from_slice(&1_u16.to_be_bytes());
    canonical.extend_from_slice(&0_u16.to_be_bytes());
    canonical.extend_from_slice(&0_u16.to_be_bytes());
    canonical.extend_from_slice(&0_u16.to_be_bytes());
    for label in hostname.split('.') {
        canonical.push(u8::try_from(label.len()).ok()?);
        canonical.extend_from_slice(label.as_bytes());
    }
    canonical.push(0);
    canonical.extend_from_slice(&query_type.to_be_bytes());
    canonical.extend_from_slice(&1_u16.to_be_bytes());
    Some(canonical)
}

fn restore_client_query_id(response: &mut [u8], query: &[u8]) {
    if response.len() >= 2 && query.len() >= 2 {
        response[..2].copy_from_slice(&query[..2]);
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
        let Some(hostname) = parse_dns_name(packet, offset) else {
            return Vec::new();
        };
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
                hostname,
                address,
                ttl_seconds,
            });
        }
        offset = data_offset + data_length;
    }
    addresses
}

fn parse_dns_cname_answers(packet: &[u8]) -> Vec<DnsCnameAnswer> {
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
    let mut aliases = Vec::new();
    for _ in 0..answer_count {
        let Some(owner) = parse_dns_name(packet, offset) else {
            return Vec::new();
        };
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
        if answer_type == 5
            && answer_class == 1
            && skip_dns_name(packet, data_offset) == Some(data_offset + data_length)
            && let Some(target) = parse_dns_name(packet, data_offset)
        {
            aliases.push(DnsCnameAnswer {
                owner,
                target,
                ttl_seconds,
            });
        }
        offset = data_offset + data_length;
    }
    aliases
}

fn parse_dns_name(packet: &[u8], offset: usize) -> Option<String> {
    let mut current = offset;
    let mut labels = Vec::new();
    let mut pointers_followed = 0;
    loop {
        let length = *packet.get(current)?;
        if length == 0 {
            break;
        }
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(current + 1)?;
            current = usize::from(length & 0x3f) << 8 | usize::from(next);
            pointers_followed += 1;
            if pointers_followed > MAX_DERIVED_CNAME_DEPTH as usize {
                return None;
            }
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        current += 1;
        let end = current.checked_add(usize::from(length))?;
        let label = std::str::from_utf8(packet.get(current..end)?).ok()?;
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
        labels.push(label.to_ascii_lowercase());
        current = end;
    }
    normalize_hostname(&labels.join("."))
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

fn remove_expired_cname_authorizations(state: &mut CnameAuthorizationState, now: Instant) {
    state
        .active
        .retain(|_, authorization| authorization.expires_at > now);
}

fn bound_materialization_ttl(
    ttl_seconds: u32,
    authorization_remaining: Option<Duration>,
) -> Option<u32> {
    let mut bounded_ttl = ttl_seconds.min(MAX_DYNAMIC_TTL_SECONDS);
    if let Some(remaining) = authorization_remaining {
        let remaining_seconds = u32::try_from(remaining.as_secs()).unwrap_or(u32::MAX);
        bounded_ttl = bounded_ttl.min(remaining_seconds);
    }
    (bounded_ttl > 0).then_some(bounded_ttl)
}

fn authorized_block_candidate_hostname(
    hostname: &str,
    state: &mut CnameAuthorizationState,
    now: Instant,
) -> bool {
    remove_expired_cname_authorizations(state, now);
    if matches_exact_block_candidate_hostname(hostname) || state.active.contains_key(hostname) {
        return true;
    }
    if !matches_constrained_dynamic_actions_suffix_hostname(hostname) {
        return false;
    }
    if state.bounded_actions_suffix.contains(hostname) {
        return true;
    }
    if state.bounded_actions_suffix.len() >= MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS {
        state.bounded_actions_suffix_truncated = true;
        return false;
    }
    state.bounded_actions_suffix.insert(hostname.to_owned());
    true
}

fn retain_cname_authorizations(
    state: &mut CnameAuthorizationState,
    aliases: impl IntoIterator<Item = DnsCnameAnswer>,
    now: Instant,
) {
    remove_expired_cname_authorizations(state, now);
    let mut pending: Vec<DnsCnameAnswer> = aliases.into_iter().collect();
    for _ in 0..MAX_DERIVED_CNAME_DEPTH {
        let mut progressed = false;
        pending.retain(|alias| {
            let source_depth = if matches_exact_block_candidate_hostname(&alias.owner)
                || state.bounded_actions_suffix.contains(&alias.owner)
            {
                Some(0)
            } else {
                state
                    .active
                    .get(&alias.owner)
                    .map(|authorization| authorization.depth)
            };
            let Some(source_depth) = source_depth else {
                return true;
            };
            let depth = source_depth.saturating_add(1);
            if alias.ttl_seconds == 0 || depth > MAX_DERIVED_CNAME_DEPTH {
                return false;
            }
            if !state.active.contains_key(&alias.target)
                && state.active.len() >= MAX_DERIVED_CNAME_AUTHORIZATIONS
            {
                state.truncated = true;
                return false;
            }
            state.active.insert(
                alias.target.clone(),
                ActiveCnameAuthorization {
                    source_hostname: alias.owner.clone(),
                    observed_ttl_seconds: alias.ttl_seconds.min(MAX_DYNAMIC_TTL_SECONDS),
                    depth,
                    expires_at: now
                        + Duration::from_secs(u64::from(
                            alias.ttl_seconds.min(MAX_DYNAMIC_TTL_SECONDS),
                        )),
                },
            );
            progressed = true;
            false
        });
        if !progressed {
            break;
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
    matches_actions_suffix_hostname(hostname)
        || hostname == "codeload.github.com"
        || hostname == "actions-results-receiver-production.githubapp.com"
        || (hostname.starts_with("productionresultssa")
            && hostname.ends_with(".blob.core.windows.net"))
}

fn matches_exact_block_candidate_hostname(hostname: &str) -> bool {
    DNS_BLOCK_CANDIDATE_BOOTSTRAP_HOSTNAMES.contains(&hostname)
        || hostname == "actions-results-receiver-production.githubapp.com"
}

fn matches_actions_suffix_hostname(hostname: &str) -> bool {
    hostname.ends_with(".actions.githubusercontent.com")
        && hostname != "actions.githubusercontent.com"
}

fn matches_constrained_dynamic_actions_suffix_hostname(hostname: &str) -> bool {
    let Some(prefix) = hostname.strip_suffix(".actions.githubusercontent.com") else {
        return false;
    };
    let labels: Vec<&str> = prefix.split('.').collect();
    !matches_exact_block_candidate_hostname(hostname)
        && !labels.is_empty()
        && labels.len() <= MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn matches_supported_block_query_type(query_type: u16) -> bool {
    matches!(query_type, 1 | 28)
}

fn candidate_classification(scope: DnsEvidenceScope, hostname: &str) -> &'static str {
    match scope {
        DnsEvidenceScope::Audit if matches_candidate_pattern(hostname) => {
            "matches_candidate_pattern"
        }
        DnsEvidenceScope::HostBlockCandidate
        | DnsEvidenceScope::ProtectedHostBlock
        | DnsEvidenceScope::ProtectedHostBlockDegraded
            if matches_exact_block_candidate_hostname(hostname) =>
        {
            "matches_candidate_pattern"
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

#[cfg(test)]
fn evidence_from_state(
    state: &ObservationState,
    routing_status: &'static str,
    scope: DnsEvidenceScope,
) -> DnsMediationEvidence {
    evidence_from_state_and_authorizations(
        state,
        routing_status,
        scope,
        &CnameAuthorizationState::default(),
    )
}

fn evidence_from_state_and_authorizations(
    state: &ObservationState,
    routing_status: &'static str,
    scope: DnsEvidenceScope,
    cname_authorizations: &CnameAuthorizationState,
) -> DnsMediationEvidence {
    DnsMediationEvidence {
        status: scope.status(),
        candidate_profile_id: scope.candidate_profile_id(),
        selected_platform_profile_id: match scope {
            DnsEvidenceScope::Audit => None,
            DnsEvidenceScope::HostBlockCandidate
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                Some(GITHUB_HOSTED_JOB_STATUS_PROFILE_ID)
            }
        },
        candidate_domain_patterns: match scope {
            DnsEvidenceScope::Audit => DNS_CANDIDATE_PATTERNS.to_vec(),
            DnsEvidenceScope::HostBlockCandidate
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                DNS_BLOCK_COMPATIBILITY_PATTERNS.to_vec()
            }
        },
        candidate_hostnames: match scope {
            DnsEvidenceScope::Audit => Vec::new(),
            DnsEvidenceScope::HostBlockCandidate
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                DNS_BLOCK_CANDIDATE_BOOTSTRAP_HOSTNAMES.to_vec()
            }
        },
        mode: scope.mode(),
        protection_available: scope == DnsEvidenceScope::ProtectedHostBlock,
        routing_status,
        host_dns_routing: match scope {
            DnsEvidenceScope::ProtectedHostBlock | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                "local_root_resident_mediator"
            }
            _ => "local_mediator_test_only",
        },
        docker_dns_routing: match scope {
            DnsEvidenceScope::ProtectedHostBlock | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                "local_root_resident_mediator"
            }
            _ => "local_mediator_test_only",
        },
        answer_attribution_status: "bounded_reportable_hostname_answers_only",
        proxy_policy_status: match scope {
            DnsEvidenceScope::Audit => "audit_forwards_without_name_authorization",
            DnsEvidenceScope::HostBlockCandidate
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                "block_forwards_exact_roots_bounded_actions_suffix_names_and_bounded_cname_descendants"
            }
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
        bounded_actions_suffix_authorizations: cname_authorizations
            .bounded_actions_suffix
            .iter()
            .cloned()
            .collect(),
        bounded_actions_suffix_authorizations_truncated: cname_authorizations
            .bounded_actions_suffix_truncated,
        derived_cname_authorizations: cname_authorizations
            .active
            .iter()
            .map(|(hostname, authorization)| DnsDerivedCnameAuthorization {
                hostname: hostname.clone(),
                source_hostname: authorization.source_hostname.clone(),
                observed_ttl_seconds: authorization.observed_ttl_seconds,
                depth: authorization.depth,
            })
            .collect(),
        derived_cname_authorizations_truncated: cname_authorizations.truncated,
        excluded_non_github_query_count: state.excluded_non_github_query_count,
        blocked_non_candidate_query_count: state.blocked_non_candidate_query_count,
        limitations: match scope {
            DnsEvidenceScope::Audit => vec![
                "dns_mediation_audit_test_only_no_public_activation",
                "audit_measurement_patterns_do_not_define_default_descriptor",
                "audit_observes_queries_without_blocking_names",
                "dns_answers_attribute_addresses_without_authorizing_firewall_rules",
                "dns_ttls_are_evidence_for_future_bounded_refresh_design_only",
                "evidence_collected_before_hosted_job_teardown",
                "audit_measurement_does_not_activate_runtime_materialization",
            ],
            DnsEvidenceScope::HostBlockCandidate => vec![
                "dns_mediated_host_block_candidate_test_only_no_public_activation",
                "test_only_evidence_path_does_not_activate_default_planning_descriptor",
                "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
                "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
                "block_dns_queries_are_canonicalized_before_upstream_forwarding",
                "dns_query_timing_and_count_remain_egress_limitations",
                "post_ready_codeload_traffic_is_not_authorized",
                "post_ready_results_storage_traffic_is_not_authorized",
                "cname_descendants_are_bounded_ttl_derived_authorizations",
                "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
                "candidate_bootstrap_roots_refresh_every_5_seconds",
                "https_materialization_expiry_includes_30_second_refresh_overlap",
                "dns_answers_materialize_only_bounded_candidate_or_cname_descendant_https_addresses",
                "approved_status_https_destinations_remain_egress_channels",
                "resolved_status_ip_addresses_may_serve_additional_destinations",
                "root_resident_dns_upstream_channel_remains_an_egress_limitation",
                "planner_selection_does_not_activate_runtime_materialization",
            ],
            DnsEvidenceScope::ProtectedHostBlock => protected_dns_scope_limitations(false),
            DnsEvidenceScope::ProtectedHostBlockDegraded => protected_dns_scope_limitations(true),
        },
    }
}

fn protected_dns_scope_limitations(degraded: bool) -> Vec<&'static str> {
    let mut limitations = vec![
        "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
        "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
        "block_dns_queries_are_canonicalized_before_upstream_forwarding",
        "dns_query_timing_and_count_remain_egress_limitations",
        "post_ready_codeload_traffic_is_not_authorized",
        "post_ready_results_storage_traffic_is_not_authorized",
        "cname_descendants_are_bounded_ttl_derived_authorizations",
        "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
        "bootstrap_roots_refresh_every_5_seconds",
        "https_materialization_expiry_includes_30_second_refresh_overlap",
        "dns_answers_materialize_only_bounded_status_or_cname_descendant_https_addresses",
        "approved_status_https_destinations_remain_egress_channels",
        "resolved_status_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
    ];
    if degraded {
        limitations.push("container_control_preserved_invalidates_containment");
    }
    limitations
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

    fn response_with_cname(name: &str, target: &str, ttl_seconds: u32) -> Vec<u8> {
        let mut bytes = query(name, 1);
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0xc0, 0x0c]);
        bytes.extend_from_slice(&5_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&ttl_seconds.to_be_bytes());
        let mut target_bytes = Vec::new();
        for label in target.split('.') {
            target_bytes.push(label.len() as u8);
            target_bytes.extend_from_slice(label.as_bytes());
        }
        target_bytes.push(0);
        bytes.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&target_bytes);
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
    fn canonicalizes_block_queries_before_upstream_forwarding() {
        let mut mixed_case = query("MiXeD.Actions.GitHubusercontent.Com", 1);
        mixed_case[..2].copy_from_slice(&0x1234_u16.to_be_bytes());
        mixed_case[2..4].copy_from_slice(&0x0110_u16.to_be_bytes());
        mixed_case.extend_from_slice(b"caller-controlled-additional-bytes");
        let canonical =
            canonical_block_query("mixed.actions.githubusercontent.com", 1, &mixed_case)
                .expect("valid block query must canonicalize");
        assert_eq!(&canonical[..2], &[0, 0]);
        assert_eq!(
            parse_dns_question(&canonical),
            Some(("mixed.actions.githubusercontent.com".to_owned(), 1))
        );
        assert!(
            !canonical
                .windows(b"caller-controlled-additional-bytes".len())
                .any(|window| window == b"caller-controlled-additional-bytes")
        );
        let mut response = canonical.clone();
        restore_client_query_id(&mut response, &mixed_case);
        assert_eq!(&response[..2], &0x1234_u16.to_be_bytes());

        let mut multiple_questions = query("mixed.actions.githubusercontent.com", 1);
        multiple_questions[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert!(
            canonical_block_query(
                "mixed.actions.githubusercontent.com",
                1,
                &multiple_questions,
            )
            .is_none()
        );
        assert!(
            canonical_block_query(
                "mixed.actions.githubusercontent.com",
                16,
                &query("mixed.actions.githubusercontent.com", 16),
            )
            .is_none()
        );
    }

    #[test]
    fn malformed_block_queries_do_not_consume_dynamic_authorizations() {
        let recorder = ObservationRecorder {
            state: Arc::new(Mutex::new(ObservationState::default())),
            cname_authorizations: Arc::new(Mutex::new(CnameAuthorizationState::default())),
            report_path: PathBuf::from("unused-test-report.json"),
            scope: DnsEvidenceScope::HostBlockCandidate,
            materializations: None,
        };
        let mut malformed = query("malformed.actions.githubusercontent.com", 1);
        malformed[4..6].copy_from_slice(&2_u16.to_be_bytes());
        let parsed = parse_dns_question(&malformed);
        assert!(query_for_upstream(&recorder, &malformed, parsed.as_ref()).is_none());
        assert!(
            recorder
                .cname_authorizations
                .lock()
                .unwrap()
                .bounded_actions_suffix
                .is_empty()
        );

        let valid = query("validated.actions.githubusercontent.com", 1);
        let parsed = parse_dns_question(&valid);
        assert!(query_for_upstream(&recorder, &valid, parsed.as_ref()).is_some());
        assert!(
            recorder
                .cname_authorizations
                .lock()
                .unwrap()
                .bounded_actions_suffix
                .contains("validated.actions.githubusercontent.com")
        );
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
                .forward_query("vstoken.actions.githubusercontent.com", 1)
        );
        assert!(
            DnsEvidenceScope::HostBlockCandidate
                .forward_query("pipelines.actions.githubusercontent.com", 1)
        );
        assert!(
            DnsEvidenceScope::HostBlockCandidate
                .forward_query("results-receiver.actions.githubusercontent.com", 1)
        );
        assert!(
            DnsEvidenceScope::HostBlockCandidate
                .forward_query("payload.pipelines.actions.githubusercontent.com", 1)
        );
        assert!(
            DnsEvidenceScope::HostBlockCandidate
                .forward_query("actions-results-receiver-production.githubapp.com", 1)
        );
        assert!(
            DnsEvidenceScope::HostBlockCandidate
                .forward_query("bounded-dynamic.pipelines.actions.githubusercontent.com", 1,),
            "the candidate permits only bounded dynamic names in the documented suffix class"
        );
        assert!(
            !DnsEvidenceScope::HostBlockCandidate.forward_query(
                "lookalike.payload.pipelines.actions.githubusercontent.com",
                1,
            ),
            "dynamic suffix names may have at most two prefix labels"
        );
        assert!(!DnsEvidenceScope::HostBlockCandidate.forward_query("codeload.github.com", 1));
        assert!(
            !DnsEvidenceScope::HostBlockCandidate
                .forward_query("productionresultssa17.blob.core.windows.net", 1)
        );
        assert!(!DnsEvidenceScope::HostBlockCandidate.forward_query("api.github.com", 1));
        assert!(
            !DnsEvidenceScope::HostBlockCandidate
                .forward_query("bounded-dynamic.actions.githubusercontent.com", 16,)
        );
        assert!(
            DnsEvidenceScope::Audit.forward_query("productionresultssa17.blob.core.windows.net", 1)
        );
        assert!(DnsEvidenceScope::Audit.forward_query("api.github.com", 16));
        let response = refused_response(&query("api.github.com", 1)).unwrap();
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 5);
        assert_ne!(u16::from_be_bytes([response[2], response[3]]) & 0x8000, 0);
    }

    #[test]
    fn bounds_dynamic_actions_suffix_names_for_the_candidate_lifetime() {
        let now = Instant::now();
        let mut authorizations = CnameAuthorizationState::default();
        for index in 0..MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS {
            assert!(authorized_block_candidate_hostname(
                &format!("dynamic-{index}.actions.githubusercontent.com"),
                &mut authorizations,
                now,
            ));
        }
        assert_eq!(
            authorizations.bounded_actions_suffix.len(),
            MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS
        );
        assert!(authorized_block_candidate_hostname(
            "dynamic-0.actions.githubusercontent.com",
            &mut authorizations,
            now + Duration::from_secs(600),
        ));
        assert!(!authorized_block_candidate_hostname(
            "dynamic-overflow.actions.githubusercontent.com",
            &mut authorizations,
            now,
        ));
        assert!(authorizations.bounded_actions_suffix_truncated);
        assert!(!authorized_block_candidate_hostname(
            "three.labels.deep.actions.githubusercontent.com",
            &mut CnameAuthorizationState::default(),
            now,
        ));
        assert!(!authorized_block_candidate_hostname(
            "-invalid.actions.githubusercontent.com",
            &mut CnameAuthorizationState::default(),
            now,
        ));
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
                hostname: "pipelines.actions.githubusercontent.com".to_owned(),
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
                hostname: "pipelines.actions.githubusercontent.com".to_owned(),
                address: "2001:db8::1".parse().expect("IPv6 fixture must parse"),
                ttl_seconds: 60,
            }]
        );
        assert!(parse_dns_address_answers(&[]).is_empty());
    }

    #[test]
    fn authorizes_only_bounded_ttl_cname_descendants_of_exact_roots() {
        let now = Instant::now();
        let mut authorizations = CnameAuthorizationState::default();
        assert_eq!(bound_materialization_ttl(600, None), Some(300));
        assert_eq!(
            bound_materialization_ttl(300, Some(Duration::from_secs(20))),
            Some(20)
        );
        assert_eq!(
            bound_materialization_ttl(300, Some(Duration::from_millis(999))),
            None
        );
        assert!(!authorized_block_candidate_hostname(
            "glb-example.github.com",
            &mut authorizations,
            now,
        ));
        retain_cname_authorizations(
            &mut authorizations,
            parse_dns_cname_answers(&response_with_cname(
                "payload.pipelines.actions.githubusercontent.com",
                "glb-example.github.com",
                60,
            )),
            now,
        );
        assert!(authorized_block_candidate_hostname(
            "glb-example.github.com",
            &mut authorizations,
            now,
        ));
        assert!(!authorized_block_candidate_hostname(
            "glb-example.github.com",
            &mut authorizations,
            now + Duration::from_secs(61),
        ));
        retain_cname_authorizations(
            &mut authorizations,
            [DnsCnameAnswer {
                owner: "payload.pipelines.actions.githubusercontent.com".to_owned(),
                target: "edge.example.net".to_owned(),
                ttl_seconds: 60,
            }],
            now,
        );
        assert!(authorized_block_candidate_hostname(
            "edge.example.net",
            &mut authorizations,
            now,
        ));
        retain_cname_authorizations(
            &mut authorizations,
            [DnsCnameAnswer {
                owner: "unrelated.example.net".to_owned(),
                target: "not-derived.example.net".to_owned(),
                ttl_seconds: 60,
            }],
            now,
        );
        assert!(!authorized_block_candidate_hostname(
            "not-derived.example.net",
            &mut authorizations,
            now,
        ));
        let mut truncated = response_with_cname(
            "payload.pipelines.actions.githubusercontent.com",
            "glb-example.github.com",
            60,
        );
        truncated.pop();
        assert!(parse_dns_cname_answers(&truncated).is_empty());
    }

    #[test]
    fn bounds_and_deduplicates_retained_address_attribution() {
        let mut observation = RetainedObservation::default();
        retain_address_answers(
            &mut observation,
            [
                DnsAddressAnswer {
                    hostname: "pipelines.actions.githubusercontent.com".to_owned(),
                    address: "192.0.2.10".parse().expect("IPv4 fixture must parse"),
                    ttl_seconds: 60,
                },
                DnsAddressAnswer {
                    hostname: "pipelines.actions.githubusercontent.com".to_owned(),
                    address: "192.0.2.10".parse().expect("IPv4 fixture must parse"),
                    ttl_seconds: 30,
                },
            ],
        );
        for value in 0..=MAX_RETAINED_ADDRESSES_PER_OBSERVATION {
            retain_address_answers(
                &mut observation,
                [DnsAddressAnswer {
                    hostname: "pipelines.actions.githubusercontent.com".to_owned(),
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
            effective_allowances_with_materializations(&[], &active),
            vec![EffectiveAllowance {
                destination_type: DestinationType::Ip,
                destination: "192.0.2.10".to_owned(),
                protocol: Protocol::Tcp,
                port: 443,
            }]
        );
        let (changed, _, expired) =
            merge_pending_materializations(&mut active, &queue, now + Duration::from_secs(31));
        assert!(!changed);
        assert_eq!(expired, 0);
        assert_eq!(active.len(), 1);
        let (changed, _, expired) =
            merge_pending_materializations(&mut active, &queue, now + Duration::from_secs(61));
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

    #[test]
    fn degraded_production_scope_preserves_container_limitation_without_protection_claim() {
        let scope = DnsBlockRuntimeScope::ProductionUnsafePreserve;
        let evidence =
            evidence_from_state(&ObservationState::default(), "active", scope.dns_scope());

        assert_eq!(scope.evidence_status(), PROTECTED_DEGRADED_BLOCK_STATUS);
        assert_eq!(scope.ready_status(), PROTECTED_DEGRADED_BLOCK_READY_STATUS);
        assert_eq!(scope.resident_status(), "resident_degraded");
        assert_eq!(scope.lockdown_posture(), LockdownPosture::UnsafePreserve);
        assert!(!scope.protection_available());
        assert_eq!(evidence.status, PROTECTED_DEGRADED_BLOCK_STATUS);
        assert!(!evidence.protection_available);
        assert!(
            evidence
                .limitations
                .contains(&"container_control_preserved_invalidates_containment")
        );
        assert!(
            scope
                .limitations()
                .contains(&"container_control_remains_available_to_later_workflow_code")
        );
    }
}
