use crate::config::{
    ContainerPolicy, DestinationType, MAX_REPORT_BYTES, Mode, Protocol, parse_and_normalize,
};
use crate::error::ErrorDetail;
use crate::findings::{ConnectionFinding, FindingCollection, bounded_timestamp_now};
use crate::lifecycle::{
    CriticalFinding, RESIDENT_VERIFICATION_INTERVAL, require_production_root_process,
    validate_production_service_context, validate_test_service_context,
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
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_ACTIONS_SUFFIX_PATTERN,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HOSTNAMES,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HTTPS_REFRESH_OVERLAP_SECONDS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_AUTHORIZATIONS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_DEPTH,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_TTL_SECONDS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_REFRESH_INTERVAL_SECONDS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_UPSTREAM_DNS,
    github_hosted_workflow_bootstrap_dns_mediation_plan,
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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const DNS_MEDIATED_PROFILE_REALIZATION_ID: &str =
    "github_hosted_workflow_bootstrap_dns_mediation_v1";
pub const RUNTIME_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const SELECTED_PROFILE_RUNTIME_EVIDENCE_STATUS: &str = "selected_profile_runtime_test_only";
pub const SELECTED_PROFILE_RUNTIME_READY_STATUS: &str =
    "selected_profile_runtime_ready_no_public_activation";
pub const PROTECTED_BLOCK_STATUS: &str = "protected_host_block";
pub const PROTECTED_BLOCK_READY_STATUS: &str = "ready";
pub const PROTECTED_DEGRADED_BLOCK_STATUS: &str = "protected_host_block_degraded";
pub const PROTECTED_DEGRADED_BLOCK_READY_STATUS: &str = "ready_degraded";
pub const PROTECTED_AUDIT_STATUS: &str = "protected_host_audit_observation";
pub const PROTECTED_AUDIT_READY_STATUS: &str = "ready_observation_only";
pub const DNS_MEDIATED_COMPATIBILITY_PATTERNS: [&str; 2] = [
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_ACTIONS_SUFFIX_PATTERN,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES[0],
];
pub const SELECTED_PROFILE_RUNTIME_BOOTSTRAP_HOSTNAMES: [&str; 7] =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HOSTNAMES;
const MAX_RETAINED_DNS_OBSERVATIONS: usize = 256;
const MAX_RETAINED_ADDRESSES_PER_OBSERVATION: usize = 32;
const MAX_DYNAMIC_MATERIALIZATIONS: usize = 128;
const MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS: usize =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS;
const MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS: usize =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS;
const MAX_DERIVED_CNAME_AUTHORIZATIONS: usize =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_AUTHORIZATIONS;
const MAX_DERIVED_CNAME_DEPTH: u8 = GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_DEPTH;
const MAX_DYNAMIC_TTL_SECONDS: u32 = GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_TTL_SECONDS;
const DNS_PROFILE_REFRESH_INTERVAL: Duration =
    Duration::from_secs(GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_REFRESH_INTERVAL_SECONDS);
const DNS_MATERIALIZATION_REFRESH_OVERLAP: Duration =
    Duration::from_secs(GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HTTPS_REFRESH_OVERLAP_SECONDS);
const MAX_CRITICAL_FINDINGS: usize = 64;
const MAX_DNS_PACKET_BYTES: usize = 4096;
const UPSTREAM_DNS: &str = GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_UPSTREAM_DNS;
const HOST_DNS_BIND: &str = "127.0.0.1:53";
const DOCKER_DNS_BIND: &str = "172.17.0.1:53";
const RESOLVED_DROP_IN_DIR: &str = "/etc/systemd/resolved.conf.d";
const RESOLVED_DROP_IN_PATH: &str = "/etc/systemd/resolved.conf.d/90-fence-evidence.conf";
const DOCKER_DAEMON_PATH: &str = "/etc/docker/daemon.json";
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_ROUTING_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DOCKER_DAEMON_CONFIG_BYTES: u64 = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsEvidenceScope {
    ProtectedHostAudit,
    SelectedProfileRuntimeTest,
    ProtectedHostBlock,
    ProtectedHostBlockDegraded,
}

impl DnsEvidenceScope {
    fn mode(self) -> Mode {
        match self {
            Self::ProtectedHostAudit => Mode::Audit,
            Self::SelectedProfileRuntimeTest
            | Self::ProtectedHostBlock
            | Self::ProtectedHostBlockDegraded => Mode::Block,
        }
    }

    fn is_block(self) -> bool {
        matches!(
            self,
            Self::SelectedProfileRuntimeTest
                | Self::ProtectedHostBlock
                | Self::ProtectedHostBlockDegraded
        )
    }

    #[cfg(test)]
    fn forward_query(self, hostname: &str, query_type: u16) -> bool {
        match self {
            Self::ProtectedHostAudit => true,
            Self::SelectedProfileRuntimeTest
            | Self::ProtectedHostBlock
            | Self::ProtectedHostBlockDegraded => {
                matches_supported_block_query_type(query_type)
                    && authorized_selected_profile_hostname(
                        hostname,
                        &mut CnameAuthorizationState::default(),
                        Instant::now(),
                    )
            }
        }
    }

    fn status(self) -> &'static str {
        match self {
            Self::ProtectedHostAudit => PROTECTED_AUDIT_STATUS,
            Self::SelectedProfileRuntimeTest => SELECTED_PROFILE_RUNTIME_EVIDENCE_STATUS,
            Self::ProtectedHostBlock => PROTECTED_BLOCK_STATUS,
            Self::ProtectedHostBlockDegraded => PROTECTED_DEGRADED_BLOCK_STATUS,
        }
    }

    fn profile_realization_id(self) -> &'static str {
        let _ = self;
        DNS_MEDIATED_PROFILE_REALIZATION_ID
    }

    fn active_routing_status(self) -> &'static str {
        match self {
            Self::SelectedProfileRuntimeTest => "active_test_only",
            Self::ProtectedHostAudit
            | Self::ProtectedHostBlock
            | Self::ProtectedHostBlockDegraded => "active",
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
            Self::TestEvidence => SELECTED_PROFILE_RUNTIME_EVIDENCE_STATUS,
            Self::ProductionStandardBlock => PROTECTED_BLOCK_STATUS,
            Self::ProductionUnsafePreserve => PROTECTED_DEGRADED_BLOCK_STATUS,
        }
    }

    fn ready_status(self) -> &'static str {
        match self {
            Self::TestEvidence => SELECTED_PROFILE_RUNTIME_READY_STATUS,
            Self::ProductionStandardBlock => PROTECTED_BLOCK_READY_STATUS,
            Self::ProductionUnsafePreserve => PROTECTED_DEGRADED_BLOCK_READY_STATUS,
        }
    }

    fn resident_status(self) -> &'static str {
        match self {
            Self::TestEvidence => "resident_selected_profile_runtime_test_only",
            Self::ProductionStandardBlock => "resident_protected",
            Self::ProductionUnsafePreserve => "resident_degraded",
        }
    }

    fn protection_available(self) -> bool {
        matches!(self, Self::ProductionStandardBlock)
    }

    fn dns_scope(self) -> DnsEvidenceScope {
        match self {
            Self::TestEvidence => DnsEvidenceScope::SelectedProfileRuntimeTest,
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
    pub profile_classification: &'static str,
    pub occurrences: u64,
    pub resolved_addresses: Vec<String>,
    pub minimum_observed_ttl_seconds: Option<u32>,
    pub addresses_truncated: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsMediationEvidence {
    pub runtime_evidence_schema_version: u32,
    pub status: &'static str,
    pub profile_realization_id: &'static str,
    pub platform_profile_id: &'static str,
    pub authorized_domain_patterns: Vec<&'static str>,
    pub bootstrap_hostnames: Vec<&'static str>,
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
    pub blocked_non_profile_query_count: u64,
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
    pub runtime_evidence_schema_version: u32,
    pub status: &'static str,
    pub mode: Mode,
    pub profile_realization_id: &'static str,
    pub platform_profile_id: &'static str,
    pub policy_hash_schema_version: u32,
    pub policy_hash: String,
    pub base_ruleset_hash: String,
    pub bootstrap_hostnames: Vec<&'static str>,
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
    runtime_evidence_schema_version: u32,
    status: &'static str,
    mode: Mode,
    profile_realization_id: &'static str,
    platform_profile_id: &'static str,
    policy_hash_schema_version: u32,
    policy_hash: &'a str,
    base_ruleset_hash: &'a str,
    ruleset_hash: &'a str,
    planned_owned_state: &'a OwnedNftState,
    readiness_status: &'static str,
}

#[derive(Debug, Serialize)]
struct DnsMediatedBlockReady<'a> {
    runtime_evidence_schema_version: u32,
    status: &'static str,
    mode: Mode,
    profile_realization_id: &'static str,
    platform_profile_id: &'static str,
    policy_hash_schema_version: u32,
    policy_hash: &'a str,
    base_ruleset_hash: &'a str,
    ruleset_hash: &'a str,
    protection_available: bool,
    limitations: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsMediatedAuditEvidence {
    pub runtime_evidence_schema_version: u32,
    pub status: &'static str,
    pub mode: Mode,
    pub profile_realization_id: &'static str,
    pub platform_profile_id: &'static str,
    pub policy_hash_schema_version: u32,
    pub policy_hash: String,
    pub base_ruleset_hash: String,
    pub ruleset_hash: String,
    pub setup_status: &'static str,
    pub network_application_status: &'static str,
    pub network_verification_status: &'static str,
    pub sudo_status: &'static str,
    pub container_status: &'static str,
    pub readiness_status: &'static str,
    pub rollback_status: &'static str,
    pub counters: NetworkEvidenceCounters,
    pub findings: Vec<ConnectionFinding>,
    pub findings_truncated: bool,
    pub critical_findings: Vec<CriticalFinding>,
    pub critical_findings_truncated: bool,
    pub protection_available: bool,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct DnsMediatedAuditState<'a> {
    runtime_evidence_schema_version: u32,
    status: &'static str,
    mode: Mode,
    profile_realization_id: &'static str,
    platform_profile_id: &'static str,
    policy_hash_schema_version: u32,
    policy_hash: &'a str,
    base_ruleset_hash: &'a str,
    ruleset_hash: &'a str,
    planned_owned_state: &'a OwnedNftState,
    readiness_status: &'static str,
}

#[derive(Debug, Serialize)]
struct DnsMediatedAuditReady<'a> {
    runtime_evidence_schema_version: u32,
    status: &'static str,
    mode: Mode,
    profile_realization_id: &'static str,
    platform_profile_id: &'static str,
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
    blocked_non_profile_query_count: u64,
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
    source_hostname: String,
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
    source_hostname: String,
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
    report_write_failed: Arc<AtomicBool>,
    report_path: PathBuf,
    scope: DnsEvidenceScope,
    materializations: Option<Arc<Mutex<MaterializationQueue>>>,
}

impl ObservationRecorder {
    fn forward_query(&self, hostname: &str, query_type: u16) -> bool {
        match self.scope {
            DnsEvidenceScope::ProtectedHostAudit => true,
            DnsEvidenceScope::SelectedProfileRuntimeTest
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                if !matches_supported_block_query_type(query_type) {
                    return false;
                }
                let mut authorizations = self
                    .cname_authorizations
                    .lock()
                    .expect("DNS CNAME authorization lock poisoned");
                authorized_selected_profile_hostname(hostname, &mut authorizations, Instant::now())
            }
        }
    }

    fn profile_classification(&self, hostname: &str) -> &'static str {
        let classification = profile_classification(self.scope, hostname);
        if classification != "github_related_outside_profile" {
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
        if matches_exact_selected_profile_hostname(hostname) {
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
            let classification = self.profile_classification(&hostname);
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
            state.blocked_non_profile_query_count =
                state.blocked_non_profile_query_count.saturating_add(1);
        }
        let evidence = self.evidence_from_state(&state, self.scope.active_routing_status());
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        if write_result.is_err() {
            self.report_write_failed.store(true, Ordering::Relaxed);
        }
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
            let classification = self.profile_classification(&hostname);
            let key = (hostname.clone(), query_type, classification);
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
                    source_hostname: hostname.clone(),
                    hostname: answer.hostname,
                    address: answer.address,
                    ttl_seconds,
                });
            }
        }
        let evidence = self.evidence_from_state(&state, self.scope.active_routing_status());
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        if write_result.is_err() {
            self.report_write_failed.store(true, Ordering::Relaxed);
        }
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
            self.scope.active_routing_status(),
            self.scope,
            &authorizations,
        );
        drop(authorizations);
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        write_result
    }

    fn take_report_write_failure(&self) -> bool {
        self.report_write_failed.swap(false, Ordering::Relaxed)
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
        self.docker_original = read_optional_external_file(docker_path)?;
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
    recorder: ObservationRecorder,
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
            report_write_failed: Arc::new(AtomicBool::new(false)),
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
            recorder,
            _threads: threads,
        })
    }
}

struct DnsMediatedAuditSession<R: RuntimeDocumentStore> {
    _mediation: DnsMediationSession,
    backend: NativeNftBackend<SystemNftExecutor>,
    lockdown: SystemLockdownControl,
    reader: NflogReader,
    runtime: R,
    expected_state: OwnedNftState,
    evidence: DnsMediatedAuditEvidence,
    findings: FindingCollection,
    next_verification: Duration,
}

impl<R: RuntimeDocumentStore> DnsMediatedAuditSession<R> {
    fn establish(
        runtime: R,
        mut mediation: DnsMediationSession,
        plan: &PlanData,
    ) -> Result<Self, DnsMediationError> {
        let ruleset = render_dns_mediated_ruleset(Mode::Audit, &plan.effective_policy);
        let ruleset_hash = sha256_hex(ruleset.as_bytes());
        let expected_state = expected_dns_mediated_owned_state(Mode::Audit, &plan.effective_policy);
        let mut evidence = initial_dns_audit_evidence(plan, ruleset_hash.clone());
        if let Err(error) = runtime.write_state_exclusive(&DnsMediatedAuditState {
            runtime_evidence_schema_version: RUNTIME_EVIDENCE_SCHEMA_VERSION,
            status: PROTECTED_AUDIT_STATUS,
            mode: Mode::Audit,
            profile_realization_id: DNS_MEDIATED_PROFILE_REALIZATION_ID,
            platform_profile_id: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
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
        let reader = match NflogReader::bind(Mode::Audit) {
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
            lockdown.verify_sudo_available().map_err(lockdown_error)?;
            lockdown
                .verify_containers_available()
                .map_err(lockdown_error)?;
            evidence.sudo_status = "preserved_verified";
            evidence.container_status = "preserved_verified";
            evidence.counters.total_violations =
                backend.total_violation_packets().map_err(backend_error)?;
            Ok(())
        })();
        if let Err(error) = setup_result {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(error);
        }

        evidence.setup_status = "verified_before_observation_ready";
        if let Err(error) = runtime.replace_report(&evidence) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(runtime_error(error));
        }
        if let Err(error) = runtime.write_ready_exclusive(&DnsMediatedAuditReady {
            runtime_evidence_schema_version: RUNTIME_EVIDENCE_SCHEMA_VERSION,
            status: PROTECTED_AUDIT_READY_STATUS,
            mode: Mode::Audit,
            profile_realization_id: DNS_MEDIATED_PROFILE_REALIZATION_ID,
            platform_profile_id: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
            policy_hash_schema_version: plan.policy_hash_schema_version,
            policy_hash: &plan.policy_hash,
            base_ruleset_hash: &plan.ruleset_hash,
            ruleset_hash: &ruleset_hash,
            protection_available: false,
            limitations: protected_audit_limitations(),
        }) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(runtime_error(error));
        }
        evidence.setup_status = "resident_observation_only";
        evidence.readiness_status = PROTECTED_AUDIT_READY_STATUS;
        runtime.replace_report(&evidence).map_err(runtime_error)?;
        Ok(Self {
            _mediation: mediation,
            backend,
            lockdown,
            reader,
            runtime,
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
        if self._mediation.recorder.take_report_write_failure() {
            self.record_critical(
                "dns_audit_evidence_write_failed",
                "DNS-mediated audit evidence could not be persisted after readiness",
            );
            changed = true;
        }
        let mut finding_received = false;
        match self.reader.next_finding(finding_timeout) {
            Ok(Some(finding)) => {
                self.findings.record_finding(finding);
                finding_received = true;
                changed = true;
            }
            Ok(None) => {}
            Err(_) => {
                self.record_critical(
                    "dns_audit_nflog_failure",
                    "DNS-mediated audit NFLOG collection failed after observation readiness",
                );
                changed = true;
            }
        }
        let verification_due = elapsed >= self.next_verification;
        if verification_due {
            if self
                .backend
                .verify_owned_state(&self.expected_state)
                .is_err()
            {
                self.evidence.network_verification_status = "critical_drift";
                self.record_critical(
                    "dns_audit_network_drift",
                    "DNS-mediated audit owned nftables state drifted after observation readiness",
                );
            }
            if self.lockdown.verify_sudo_available().is_err() {
                self.evidence.sudo_status = "critical_drift";
                self.record_critical(
                    "dns_audit_sudo_drift",
                    "measured passwordless sudo availability drifted after observation readiness",
                );
            }
            if self.lockdown.verify_containers_available().is_err() {
                self.evidence.container_status = "critical_drift";
                self.record_critical(
                    "dns_audit_container_drift",
                    "measured container availability drifted after observation readiness",
                );
            }
            self.next_verification = elapsed + RESIDENT_VERIFICATION_INTERVAL;
            changed = true;
        }
        if changed {
            self.evidence.findings = self.findings.retained.clone();
            self.evidence.findings_truncated = self.findings.truncated;
            self.evidence.counters.sampled_violations = self.findings.sampled_total;
            if verification_due || finding_received {
                self.evidence.counters.total_violations =
                    self.backend.total_violation_packets().unwrap_or_else(|_| {
                        self.record_critical(
                            "dns_audit_counter_read_failed",
                            "DNS-mediated audit violation counter could not be read after readiness",
                        );
                        self.evidence.counters.total_violations
                    });
            }
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

struct DnsMediatedBlockSession<R: RuntimeDocumentStore> {
    _mediation: DnsMediationSession,
    queue: Arc<Mutex<MaterializationQueue>>,
    backend: NativeNftBackend<SystemNftExecutor>,
    lockdown: SystemLockdownControl,
    reader: NflogReader,
    runtime: R,
    base_allowances: Vec<EffectiveAllowance>,
    active: BTreeMap<(String, String, IpAddr), ActiveMaterialization>,
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
        let prehydrated = match prehydrate_selected_profile_names() {
            Ok(materializations) => materializations,
            Err(error) => {
                let _ = mediation.routing.rollback();
                return Err(error.into_dns_error());
            }
        };
        enqueue_pending_materializations(&queue, prehydrated);
        let mut active = BTreeMap::new();
        let (changed, materializations_truncated, _) =
            merge_pending_materializations(&mut active, &queue, Instant::now());
        if !changed || !active_covers_selected_profile_bootstrap_roots(&active) {
            let _ = mediation.routing.rollback();
            return Err(DnsMediationError::new(
                "dns_block_prehydration_failed",
                "DNS-mediated block lifecycle did not materialize every fixed bootstrap name",
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
            runtime_evidence_schema_version: RUNTIME_EVIDENCE_SCHEMA_VERSION,
            status: scope.evidence_status(),
            mode: Mode::Block,
            profile_realization_id: DNS_MEDIATED_PROFILE_REALIZATION_ID,
            platform_profile_id: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
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
            runtime_evidence_schema_version: RUNTIME_EVIDENCE_SCHEMA_VERSION,
            status: scope.ready_status(),
            mode: Mode::Block,
            profile_realization_id: DNS_MEDIATED_PROFILE_REALIZATION_ID,
            platform_profile_id: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
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
            next_dns_refresh: DNS_PROFILE_REFRESH_INTERVAL,
            next_verification: RESIDENT_VERIFICATION_INTERVAL,
        })
    }

    fn poll_once(
        &mut self,
        elapsed: Duration,
        finding_timeout: Duration,
    ) -> Result<(), DnsMediationError> {
        let mut changed = false;
        if self._mediation.recorder.take_report_write_failure() {
            self.record_critical(
                "dns_block_evidence_write_failed",
                "DNS-mediated block evidence could not be persisted after readiness",
            );
            changed = true;
        }
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

        let mut root_refresh_error = None;
        if elapsed >= self.next_dns_refresh {
            match prehydrate_selected_profile_names() {
                Ok(materializations) => {
                    enqueue_pending_materializations(&self.queue, materializations)
                }
                Err(error) => root_refresh_error = Some(error),
            };
            self.next_dns_refresh = elapsed + DNS_PROFILE_REFRESH_INTERVAL;
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
        if let Some((code, message)) =
            root_refresh_critical_finding(root_refresh_error.as_ref(), &self.active)
        {
            self.evidence.network_verification_status = "critical_dynamic_update_failed";
            self.record_critical(code, message);
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

pub fn run_protected_service(config: &Path) -> Result<(), DnsMediationError> {
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
    if plan.platform_profile.id != GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID
        || plan.platform_profile.dns_mediated_compatibility.as_ref()
            != Some(&github_hosted_workflow_bootstrap_dns_mediation_plan())
    {
        return Err(DnsMediationError::new(
            "protected_run_policy_not_activated",
            "protected run accepts only reviewed block or audit modes with the hosted workflow-bootstrap profile",
        ));
    }
    let mut fingerprint = SystemLockdownControl::new(runtime.directory());
    fingerprint
        .verify_supported_host()
        .map_err(lockdown_error)?;

    match (plan.assurance_status, plan.container_policy) {
        (AssuranceStatus::AuditObservationOnly, None) => {
            let mediation = DnsMediationSession::establish(
                runtime.directory(),
                DnsEvidenceScope::ProtectedHostAudit,
                None,
            )?;
            let mut session = DnsMediatedAuditSession::establish(runtime, mediation, &plan)?;
            let start = Instant::now();
            loop {
                session.poll_once(start.elapsed(), POLL_INTERVAL)?;
            }
        }
        (AssuranceStatus::PlannedBlockContainment, Some(ContainerPolicy::Disable))
        | (
            AssuranceStatus::PlannedBlockDegradedContainerAccess,
            Some(ContainerPolicy::UnsafePreserve),
        ) => {
            let scope = match plan.assurance_status {
                AssuranceStatus::PlannedBlockContainment => {
                    DnsBlockRuntimeScope::ProductionStandardBlock
                }
                AssuranceStatus::PlannedBlockDegradedContainerAccess => {
                    DnsBlockRuntimeScope::ProductionUnsafePreserve
                }
                AssuranceStatus::AuditObservationOnly => unreachable!("block match excludes audit"),
            };
            let queue = Arc::new(Mutex::new(MaterializationQueue::default()));
            let mediation = DnsMediationSession::establish(
                runtime.directory(),
                scope.dns_scope(),
                Some(queue.clone()),
            )?;
            let mut session =
                DnsMediatedBlockSession::establish(runtime, mediation, queue, &plan, scope)?;
            let start = Instant::now();
            loop {
                session.poll_once(start.elapsed(), POLL_INTERVAL)?;
            }
        }
        _ => Err(DnsMediationError::new(
            "protected_run_policy_not_activated",
            "protected run accepts only reviewed block or audit modes with the hosted workflow-bootstrap profile",
        )),
    }
}

pub fn run_selected_profile_runtime_test_service(
    unit_name: &str,
    runtime_root: &Path,
    plan: &PlanData,
) -> Result<(), DnsMediationError> {
    validate_test_service_context(unit_name)
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    if plan.selected_mode != Mode::Block
        || plan.assurance_status != AssuranceStatus::PlannedBlockContainment
        || plan.platform_profile.id != GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID
        || plan.platform_profile.dns_mediated_compatibility.as_ref()
            != Some(&github_hosted_workflow_bootstrap_dns_mediation_plan())
        || !plan.requested_policy.is_empty()
    {
        return Err(DnsMediationError::new(
            "invalid_selected_profile_runtime_policy",
            "DNS-mediated block evidence accepts only standard block with the reviewed hosted workflow-bootstrap profile and no user allowlist entries",
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
    active: &BTreeMap<(String, String, IpAddr), ActiveMaterialization>,
    materializations_truncated: bool,
    ruleset_hash: String,
    scope: DnsBlockRuntimeScope,
) -> DnsMediatedBlockEvidence {
    DnsMediatedBlockEvidence {
        runtime_evidence_schema_version: RUNTIME_EVIDENCE_SCHEMA_VERSION,
        status: scope.evidence_status(),
        mode: Mode::Block,
        profile_realization_id: DNS_MEDIATED_PROFILE_REALIZATION_ID,
        platform_profile_id: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
        policy_hash_schema_version: plan.policy_hash_schema_version,
        policy_hash: plan.policy_hash.clone(),
        base_ruleset_hash: plan.ruleset_hash.clone(),
        bootstrap_hostnames: SELECTED_PROFILE_RUNTIME_BOOTSTRAP_HOSTNAMES.to_vec(),
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

fn initial_dns_audit_evidence(plan: &PlanData, ruleset_hash: String) -> DnsMediatedAuditEvidence {
    DnsMediatedAuditEvidence {
        runtime_evidence_schema_version: RUNTIME_EVIDENCE_SCHEMA_VERSION,
        status: PROTECTED_AUDIT_STATUS,
        mode: Mode::Audit,
        profile_realization_id: DNS_MEDIATED_PROFILE_REALIZATION_ID,
        platform_profile_id: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
        policy_hash_schema_version: plan.policy_hash_schema_version,
        policy_hash: plan.policy_hash.clone(),
        base_ruleset_hash: plan.ruleset_hash.clone(),
        ruleset_hash,
        setup_status: "setting_up",
        network_application_status: "not_applied",
        network_verification_status: "not_verified",
        sudo_status: "not_checked",
        container_status: "not_checked",
        readiness_status: "not_emitted",
        rollback_status: "not_required",
        counters: NetworkEvidenceCounters {
            total_violations: 0,
            sampled_violations: 0,
        },
        findings: Vec::new(),
        findings_truncated: false,
        critical_findings: Vec::new(),
        critical_findings_truncated: false,
        protection_available: false,
        limitations: protected_audit_limitations(),
    }
}

fn dns_block_test_limitations() -> Vec<&'static str> {
    vec![
        "selected_profile_runtime_test_only_no_public_activation",
        "test_only_evidence_path_does_not_activate_default_planning_descriptor",
        "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
        "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
        "block_dns_queries_are_canonicalized_before_upstream_forwarding",
        "dns_query_timing_and_count_remain_egress_limitations",
        "post_ready_codeload_traffic_is_not_authorized",
        "post_ready_results_storage_traffic_is_not_authorized",
        "cname_descendants_are_bounded_ttl_derived_authorizations",
        "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
        "bootstrap_roots_prehydrated_before_ready_with_fixed_max_ttl",
        "bootstrap_roots_refresh_every_5_seconds",
        "https_materialization_expiry_includes_30_second_refresh_overlap",
        "approved_workflow_bootstrap_https_destinations_remain_egress_channels",
        "resolved_workflow_bootstrap_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
        "dynamic_owned_table_replacement_resets_network_counters",
    ]
}

fn protected_audit_limitations() -> Vec<&'static str> {
    vec![
        "audit_observation_only_no_containment_claim",
        "audit_installs_owned_non_blocking_nftables_observation_rules",
        "audit_routes_host_and_docker_dns_through_local_root_resident_mediator",
        "audit_forwards_dns_without_name_authorization",
        "audit_preserves_passwordless_sudo_and_container_control",
        "later_workflow_code_retains_arbitrary_egress_in_audit_mode",
        "packet_prefixes_transiently_inspected_in_memory_not_serialized",
        "remote_reporting_not_implemented",
    ]
}

fn protected_block_limitations() -> Vec<&'static str> {
    protected_block_shared_limitations()
}

fn protected_degraded_block_limitations() -> Vec<&'static str> {
    let mut limitations = protected_block_shared_limitations();
    limitations.extend([
        "container_control_preserved_invalidates_containment",
        "container_control_remains_available_to_later_workflow_code",
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
        "approved_workflow_bootstrap_https_destinations_remain_egress_channels",
        "resolved_workflow_bootstrap_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
        "dynamic_owned_table_replacement_resets_network_counters",
    ]
}

#[derive(Debug)]
enum PrehydrationQueryError {
    Transient,
    Fatal(DnsMediationError),
}

#[derive(Debug)]
enum PrehydrationError {
    Transient(DnsMediationError),
    Fatal(DnsMediationError),
}

impl PrehydrationError {
    fn into_dns_error(self) -> DnsMediationError {
        match self {
            Self::Transient(error) | Self::Fatal(error) => error,
        }
    }
}

fn prehydrate_selected_profile_names() -> Result<Vec<PendingMaterialization>, PrehydrationError> {
    let mut materializations = Vec::new();
    let now = Instant::now();
    for hostname in SELECTED_PROFILE_RUNTIME_BOOTSTRAP_HOSTNAMES {
        let hostname_materializations = materializations_from_bootstrap_query_results(
            hostname,
            now,
            [1_u16, 28_u16].map(|query_type| {
                (
                    query_type,
                    query_fixed_upstream_for_prehydration(hostname, query_type),
                )
            }),
        )?;
        materializations.extend(hostname_materializations);
        if materializations.len() > MAX_DYNAMIC_MATERIALIZATIONS {
            return Err(PrehydrationError::Fatal(DnsMediationError::new(
                "dns_block_prehydration_failed",
                "fixed DNS-mediated bootstrap hostnames exceeded the materialization bound",
            )));
        }
    }
    Ok(materializations)
}

fn materializations_from_bootstrap_query_results(
    hostname: &str,
    now: Instant,
    results: impl IntoIterator<Item = (u16, Result<Vec<u8>, PrehydrationQueryError>)>,
) -> Result<Vec<PendingMaterialization>, PrehydrationError> {
    let mut materializations = Vec::new();
    let mut transient_failures = 0_u8;
    for (query_type, result) in results {
        match result {
            Ok(response) => materializations.extend(
                pending_materializations_from_bootstrap_response(
                    hostname, query_type, &response, now,
                )
                .map_err(PrehydrationError::Fatal)?,
            ),
            Err(PrehydrationQueryError::Transient) => {
                transient_failures = transient_failures.saturating_add(1);
            }
            Err(PrehydrationQueryError::Fatal(error)) => {
                return Err(PrehydrationError::Fatal(error));
            }
        }
    }
    materializations.sort();
    materializations.dedup();
    if materializations.is_empty() {
        let message = if transient_failures > 0 {
            "a fixed DNS-mediated bootstrap hostname could not be materialized before its query attempts completed"
        } else {
            "a fixed DNS-mediated bootstrap hostname returned no upstream addresses"
        };
        let error = DnsMediationError::new("dns_block_prehydration_failed", message);
        return if transient_failures > 0 {
            Err(PrehydrationError::Transient(error))
        } else {
            Err(PrehydrationError::Fatal(error))
        };
    }
    Ok(materializations)
}

fn root_refresh_critical_finding(
    error: Option<&PrehydrationError>,
    active: &BTreeMap<(String, String, IpAddr), ActiveMaterialization>,
) -> Option<(&'static str, &'static str)> {
    match error {
        Some(PrehydrationError::Fatal(_)) => Some((
            "dns_block_root_refresh_integrity_failed",
            "DNS-mediated exact-root refresh received invalid bootstrap DNS evidence after readiness",
        )),
        Some(PrehydrationError::Transient(_))
            if !active_covers_selected_profile_bootstrap_roots(active) =>
        {
            Some((
                "dns_block_root_refresh_failed",
                "DNS-mediated exact-root refresh lost required bootstrap coverage after readiness",
            ))
        }
        _ => None,
    }
}

fn query_fixed_upstream_for_prehydration(
    hostname: &str,
    query_type: u16,
) -> Result<Vec<u8>, PrehydrationQueryError> {
    let query = canonical_dns_query(hostname, query_type, 0x0100).ok_or_else(|| {
        PrehydrationQueryError::Fatal(DnsMediationError::new(
            "dns_block_prehydration_failed",
            "failed to build a fixed DNS-mediated bootstrap query",
        ))
    })?;
    let upstream = UdpSocket::bind("0.0.0.0:0").map_err(|_| PrehydrationQueryError::Transient)?;
    upstream
        .set_read_timeout(Some(DNS_FORWARD_TIMEOUT))
        .map_err(|_| PrehydrationQueryError::Transient)?;
    upstream
        .set_write_timeout(Some(DNS_FORWARD_TIMEOUT))
        .map_err(|_| PrehydrationQueryError::Transient)?;
    upstream
        .connect(UPSTREAM_DNS)
        .map_err(|_| PrehydrationQueryError::Transient)?;
    upstream
        .send(&query)
        .map_err(|_| PrehydrationQueryError::Transient)?;
    let mut response = [0_u8; MAX_DNS_PACKET_BYTES];
    let response_length = upstream
        .recv(&mut response)
        .map_err(|_| PrehydrationQueryError::Transient)?;
    let response = response[..response_length].to_vec();
    if !response_matches_upstream_query(&response, &query)
        || parse_dns_question(&response) != Some((hostname.to_owned(), query_type))
    {
        return Err(PrehydrationQueryError::Fatal(DnsMediationError::new(
            "dns_block_prehydration_failed",
            "fixed upstream DNS response did not match the bootstrap query",
        )));
    }
    Ok(response)
}

fn pending_materializations_from_bootstrap_response(
    queried_hostname: &str,
    query_type: u16,
    packet: &[u8],
    now: Instant,
) -> Result<Vec<PendingMaterialization>, DnsMediationError> {
    if parse_dns_question(packet) != Some((queried_hostname.to_owned(), query_type)) {
        return Err(DnsMediationError::new(
            "dns_block_prehydration_failed",
            "fixed upstream DNS response did not match the bootstrap query",
        ));
    }
    let mut authorizations = CnameAuthorizationState::default();
    retain_cname_authorizations(&mut authorizations, parse_dns_cname_answers(packet), now);

    let mut materializations = Vec::new();
    for answer in parse_dns_address_answers(packet) {
        let Some(ttl_seconds) = prehydration_materialization_ttl_seconds(
            &authorizations,
            &answer.hostname,
            answer.ttl_seconds,
            now,
        ) else {
            continue;
        };
        materializations.push(PendingMaterialization {
            source_hostname: queried_hostname.to_owned(),
            hostname: answer.hostname,
            address: answer.address,
            ttl_seconds,
        });
    }
    materializations.sort();
    materializations.dedup();
    if materializations.len() > MAX_RETAINED_ADDRESSES_PER_OBSERVATION {
        return Err(DnsMediationError::new(
            "dns_block_prehydration_failed",
            "a fixed DNS-mediated bootstrap hostname exceeded the address bound",
        ));
    }
    Ok(materializations)
}

fn prehydration_materialization_ttl_seconds(
    authorizations: &CnameAuthorizationState,
    hostname: &str,
    ttl_seconds: u32,
    now: Instant,
) -> Option<u32> {
    if matches_exact_selected_profile_hostname(hostname) {
        return bound_materialization_ttl(ttl_seconds, None);
    }
    let remaining_seconds = authorizations
        .active
        .get(hostname)?
        .expires_at
        .saturating_duration_since(now);
    bound_materialization_ttl(ttl_seconds, Some(remaining_seconds))
}

fn enqueue_pending_materializations(
    queue: &Arc<Mutex<MaterializationQueue>>,
    materializations: impl IntoIterator<Item = PendingMaterialization>,
) {
    let mut queue = queue.lock().expect("DNS materialization lock poisoned");
    for materialization in materializations {
        if queue.pending.len() >= MAX_DYNAMIC_MATERIALIZATIONS
            && !queue.pending.contains(&materialization)
        {
            queue.truncated = true;
            break;
        }
        queue.pending.insert(materialization);
    }
}

fn merge_pending_materializations(
    active: &mut BTreeMap<(String, String, IpAddr), ActiveMaterialization>,
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
        let key = (
            materialization.source_hostname.clone(),
            materialization.hostname.clone(),
            materialization.address,
        );
        active.insert(
            key,
            ActiveMaterialization {
                source_hostname: materialization.source_hostname,
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
    active: &BTreeMap<(String, String, IpAddr), ActiveMaterialization>,
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
    active: &BTreeMap<(String, String, IpAddr), ActiveMaterialization>,
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

fn active_covers_selected_profile_bootstrap_roots(
    active: &BTreeMap<(String, String, IpAddr), ActiveMaterialization>,
) -> bool {
    let covered = active
        .values()
        .filter(|materialization| {
            matches_exact_selected_profile_hostname(&materialization.source_hostname)
        })
        .map(|materialization| materialization.source_hostname.as_str())
        .collect::<BTreeSet<_>>();
    SELECTED_PROFILE_RUNTIME_BOOTSTRAP_HOSTNAMES
        .iter()
        .all(|hostname| covered.contains(hostname))
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

fn rollback_dns_audit_setup(
    backend: &mut NativeNftBackend<SystemNftExecutor>,
    mediation: &mut DnsMediationSession,
) -> &'static str {
    let network_result = backend.rollback_pre_activation();
    let dns_result = mediation.routing.rollback();
    match (network_result, dns_result) {
        (Ok(network_changed), Ok(dns_changed)) if network_changed || dns_changed => {
            "rolled_back_pre_ready"
        }
        (Ok(_), Ok(_)) => "nothing_to_rollback",
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
        let _ = upstream.set_write_timeout(Some(DNS_FORWARD_TIMEOUT));
        if upstream.connect(UPSTREAM_DNS).is_err() || upstream.send(&upstream_query).is_err() {
            continue;
        }
        let mut response = [0_u8; MAX_DNS_PACKET_BYTES];
        if let Ok(response_length) = upstream.recv(&mut response) {
            let response = &mut response[..response_length];
            if !response_matches_upstream_query(response, &upstream_query) {
                continue;
            }
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
        if set_dns_tcp_deadlines(&client).is_err() {
            continue;
        }
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
        let Ok(mut upstream) = connect_upstream_tcp() else {
            continue;
        };
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
        if !response_matches_upstream_query(&response, &upstream_query) {
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

fn connect_upstream_tcp() -> std::io::Result<TcpStream> {
    let address = UPSTREAM_DNS.parse().map_err(|error| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid fixed upstream DNS address: {error}"),
        )
    })?;
    let stream = TcpStream::connect_timeout(&address, DNS_FORWARD_TIMEOUT)?;
    set_dns_tcp_deadlines(&stream)?;
    Ok(stream)
}

fn set_dns_tcp_deadlines(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(DNS_FORWARD_TIMEOUT))?;
    stream.set_write_timeout(Some(DNS_FORWARD_TIMEOUT))
}

fn response_matches_upstream_query(response: &[u8], upstream_query: &[u8]) -> bool {
    response.len() >= 2 && upstream_query.len() >= 2 && response[..2] == upstream_query[..2]
}

fn query_for_upstream(
    recorder: &ObservationRecorder,
    query: &[u8],
    parsed_question: Option<&(String, u16)>,
) -> Option<Vec<u8>> {
    match (recorder.scope, parsed_question) {
        (DnsEvidenceScope::ProtectedHostAudit, _) => Some(query.to_vec()),
        (
            DnsEvidenceScope::SelectedProfileRuntimeTest
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
            DnsEvidenceScope::SelectedProfileRuntimeTest
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
    canonical_dns_query(hostname, query_type, flags & 0x0110)
}

fn canonical_dns_query(hostname: &str, query_type: u16, flags: u16) -> Option<Vec<u8>> {
    if !matches_supported_block_query_type(query_type) {
        return None;
    }
    let hostname = normalize_hostname(hostname)?;
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

fn authorized_selected_profile_hostname(
    hostname: &str,
    state: &mut CnameAuthorizationState,
    now: Instant,
) -> bool {
    remove_expired_cname_authorizations(state, now);
    if matches_exact_selected_profile_hostname(hostname) || state.active.contains_key(hostname) {
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
            let source_depth = if matches_exact_selected_profile_hostname(&alias.owner)
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
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.ends_with('.') {
        return None;
    }
    let hostname = hostname.to_ascii_lowercase();
    if hostname.is_empty() || hostname.len() > 253 {
        return None;
    }
    hostname
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        .then_some(hostname)
}

fn reportable_github_hostname(hostname: &str) -> bool {
    hostname == "github.com"
        || hostname.ends_with(".github.com")
        || hostname.ends_with(".githubusercontent.com")
        || hostname.ends_with(".githubapp.com")
        || (hostname.starts_with("productionresultssa")
            && hostname.ends_with(".blob.core.windows.net"))
}

fn matches_selected_profile_pattern(hostname: &str) -> bool {
    matches_actions_suffix_hostname(hostname)
        || hostname == "actions-results-receiver-production.githubapp.com"
}

fn matches_exact_selected_profile_hostname(hostname: &str) -> bool {
    SELECTED_PROFILE_RUNTIME_BOOTSTRAP_HOSTNAMES.contains(&hostname)
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
    !matches_exact_selected_profile_hostname(hostname)
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

fn profile_classification(scope: DnsEvidenceScope, hostname: &str) -> &'static str {
    match scope {
        DnsEvidenceScope::ProtectedHostAudit
            if matches_selected_profile_pattern(hostname)
                || matches_exact_selected_profile_hostname(hostname) =>
        {
            "matches_selected_profile_pattern"
        }
        DnsEvidenceScope::SelectedProfileRuntimeTest
        | DnsEvidenceScope::ProtectedHostBlock
        | DnsEvidenceScope::ProtectedHostBlockDegraded
            if matches_exact_selected_profile_hostname(hostname) =>
        {
            "matches_selected_profile_pattern"
        }
        _ => "github_related_outside_profile",
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
        runtime_evidence_schema_version: RUNTIME_EVIDENCE_SCHEMA_VERSION,
        status: scope.status(),
        profile_realization_id: scope.profile_realization_id(),
        platform_profile_id: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
        authorized_domain_patterns: DNS_MEDIATED_COMPATIBILITY_PATTERNS.to_vec(),
        bootstrap_hostnames: SELECTED_PROFILE_RUNTIME_BOOTSTRAP_HOSTNAMES.to_vec(),
        mode: scope.mode(),
        protection_available: scope == DnsEvidenceScope::ProtectedHostBlock,
        routing_status,
        host_dns_routing: match scope {
            DnsEvidenceScope::ProtectedHostAudit
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => "local_root_resident_mediator",
            _ => "local_mediator_test_only",
        },
        docker_dns_routing: match scope {
            DnsEvidenceScope::ProtectedHostAudit
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => "local_root_resident_mediator",
            _ => "local_mediator_test_only",
        },
        answer_attribution_status: "bounded_reportable_hostname_answers_only",
        proxy_policy_status: match scope {
            DnsEvidenceScope::ProtectedHostAudit => "audit_forwards_without_name_authorization",
            DnsEvidenceScope::SelectedProfileRuntimeTest
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
                    profile_classification: classification,
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
        blocked_non_profile_query_count: state.blocked_non_profile_query_count,
        limitations: match scope {
            DnsEvidenceScope::ProtectedHostAudit => protected_dns_audit_limitations(),
            DnsEvidenceScope::SelectedProfileRuntimeTest => vec![
                "selected_profile_runtime_test_only_no_public_activation",
                "test_only_evidence_path_does_not_activate_default_planning_descriptor",
                "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
                "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
                "block_dns_queries_are_canonicalized_before_upstream_forwarding",
                "dns_query_timing_and_count_remain_egress_limitations",
                "post_ready_codeload_traffic_is_not_authorized",
                "post_ready_results_storage_traffic_is_not_authorized",
                "cname_descendants_are_bounded_ttl_derived_authorizations",
                "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
                "bootstrap_roots_prehydrated_before_ready_with_fixed_max_ttl",
                "bootstrap_roots_refresh_every_5_seconds",
                "https_materialization_expiry_includes_30_second_refresh_overlap",
                "dns_answers_materialize_only_bounded_profile_or_cname_descendant_https_addresses",
                "approved_workflow_bootstrap_https_destinations_remain_egress_channels",
                "resolved_workflow_bootstrap_ip_addresses_may_serve_additional_destinations",
                "root_resident_dns_upstream_channel_remains_an_egress_limitation",
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
        "bootstrap_roots_prehydrated_before_ready_with_fixed_max_ttl",
        "bootstrap_roots_refresh_every_5_seconds",
        "https_materialization_expiry_includes_30_second_refresh_overlap",
        "dns_answers_materialize_only_bounded_workflow_bootstrap_or_cname_descendant_https_addresses",
        "approved_workflow_bootstrap_https_destinations_remain_egress_channels",
        "resolved_workflow_bootstrap_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
    ];
    if degraded {
        limitations.push("container_control_preserved_invalidates_containment");
    }
    limitations
}

fn protected_dns_audit_limitations() -> Vec<&'static str> {
    vec![
        "audit_observation_only_no_containment_claim",
        "audit_routes_host_and_docker_dns_through_local_root_resident_mediator",
        "audit_forwards_dns_without_name_authorization",
        "dns_query_timing_and_count_remain_egress_limitations",
        "dns_answers_attribute_addresses_without_authorizing_firewall_rules",
        "audit_preserves_passwordless_sudo_and_container_control",
        "later_workflow_code_retains_arbitrary_egress_in_audit_mode",
    ]
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
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            return Err(DnsMediationError::new(
                "dns_routing_setup_failed",
                "fixed DNS routing configuration is not a regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => {
            return Err(DnsMediationError::new(
                "dns_routing_setup_failed",
                "failed to inspect fixed DNS routing configuration",
            ));
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| {
            DnsMediationError::new(
                "dns_routing_setup_failed",
                "failed to write fixed DNS routing configuration",
            )
        })?;
    let metadata = file.metadata().map_err(|_| {
        DnsMediationError::new(
            "dns_routing_setup_failed",
            "failed to inspect fixed DNS routing configuration output",
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(DnsMediationError::new(
            "dns_routing_setup_failed",
            "fixed DNS routing configuration output is not a regular file",
        ));
    }
    file.write_all(bytes).map_err(|_| {
        DnsMediationError::new(
            "dns_routing_setup_failed",
            "failed to persist fixed DNS routing configuration",
        )
    })
}

fn read_optional_external_file(path: &Path) -> Result<Option<Vec<u8>>, DnsMediationError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(DnsMediationError::new(
                "dns_routing_setup_failed",
                "failed to read bounded Docker DNS configuration input",
            ));
        }
    };
    let metadata = file.metadata().map_err(|_| {
        DnsMediationError::new(
            "dns_routing_setup_failed",
            "failed to inspect Docker DNS configuration input",
        )
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_DOCKER_DAEMON_CONFIG_BYTES {
        return Err(DnsMediationError::new(
            "dns_routing_setup_failed",
            "Docker DNS configuration input is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_DOCKER_DAEMON_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            DnsMediationError::new(
                "dns_routing_setup_failed",
                "failed to read bounded Docker DNS configuration input",
            )
        })?;
    if bytes.len() as u64 > MAX_DOCKER_DAEMON_CONFIG_BYTES {
        return Err(DnsMediationError::new(
            "dns_routing_setup_failed",
            "Docker DNS configuration input exceeds its fixed size limit",
        ));
    }
    Ok(Some(bytes))
}

fn fixed_command(path: &str, arguments: &[&str]) -> Result<(), DnsMediationError> {
    let mut child = Command::new(path)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            DnsMediationError::new(
                "dns_routing_command_failed",
                "failed to execute a fixed DNS routing command",
            )
        })?;
    let deadline = Instant::now() + DNS_ROUTING_COMMAND_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| {
            DnsMediationError::new(
                "dns_routing_command_failed",
                "failed to wait for a fixed DNS routing command",
            )
        })? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DnsMediationError::new(
                "dns_routing_command_timeout",
                "a fixed DNS routing command exceeded its deadline",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    };
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
        append_dns_name(&mut bytes, name);
        bytes.extend_from_slice(&query_type.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes
    }

    fn append_dns_name(bytes: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
    }

    fn active_with_all_bootstrap_roots(
        now: Instant,
    ) -> BTreeMap<(String, String, IpAddr), ActiveMaterialization> {
        SELECTED_PROFILE_RUNTIME_BOOTSTRAP_HOSTNAMES
            .iter()
            .map(|hostname| {
                let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
                (
                    ((*hostname).to_owned(), (*hostname).to_owned(), address),
                    ActiveMaterialization {
                        source_hostname: (*hostname).to_owned(),
                        hostname: (*hostname).to_owned(),
                        address,
                        observed_ttl_seconds: 60,
                        expires_at: now + Duration::from_secs(60),
                    },
                )
            })
            .collect()
    }

    fn prehydration_error_code(error: &PrehydrationError) -> &'static str {
        match error {
            PrehydrationError::Transient(error) | PrehydrationError::Fatal(error) => error.code,
        }
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
        append_dns_name(&mut target_bytes, target);
        bytes.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&target_bytes);
        bytes
    }

    fn response_with_cname_and_address(
        name: &str,
        target: &str,
        cname_ttl_seconds: u32,
        address_ttl_seconds: u32,
        address: &[u8],
    ) -> Vec<u8> {
        let mut bytes = query(name, 1);
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0xc0, 0x0c]);
        bytes.extend_from_slice(&5_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&cname_ttl_seconds.to_be_bytes());
        let mut target_bytes = Vec::new();
        append_dns_name(&mut target_bytes, target);
        bytes.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&target_bytes);
        append_dns_name(&mut bytes, target);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&address_ttl_seconds.to_be_bytes());
        bytes.extend_from_slice(&(address.len() as u16).to_be_bytes());
        bytes.extend_from_slice(address);
        bytes
    }

    fn response_with_unrelated_address(question: &str, answer: &str, address: &[u8]) -> Vec<u8> {
        let mut bytes = query(question, 1);
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
        append_dns_name(&mut bytes, answer);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&60_u32.to_be_bytes());
        bytes.extend_from_slice(&(address.len() as u16).to_be_bytes());
        bytes.extend_from_slice(address);
        bytes
    }

    #[test]
    fn parses_and_normalizes_bounded_dns_questions() {
        assert_eq!(
            parse_dns_question(&query("Pipelines.Actions.GitHubusercontent.Com", 1)),
            Some(("pipelines.actions.githubusercontent.com".to_owned(), 1))
        );
        assert_eq!(
            normalize_hostname("Pipelines.Actions.GitHubusercontent.Com."),
            Some("pipelines.actions.githubusercontent.com".to_owned())
        );
        assert!(normalize_hostname("pipelines..actions.githubusercontent.com").is_none());
        assert!(normalize_hostname("-pipelines.actions.githubusercontent.com").is_none());
        assert!(normalize_hostname("pipelines-.actions.githubusercontent.com").is_none());
        assert!(normalize_hostname("pipelines.actions.githubusercontent.com..").is_none());
        assert!(normalize_hostname(&format!("{}.example.com", "a".repeat(64))).is_none());
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
        assert!(response_matches_upstream_query(&canonical, &canonical));
        let mut mismatched_response = canonical.clone();
        mismatched_response[..2].copy_from_slice(&1_u16.to_be_bytes());
        assert!(!response_matches_upstream_query(
            &mismatched_response,
            &canonical
        ));

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
            report_write_failed: Arc::new(AtomicBool::new(false)),
            report_path: PathBuf::from("unused-test-report.json"),
            scope: DnsEvidenceScope::SelectedProfileRuntimeTest,
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
    fn classifies_selected_profile_patterns_without_authorizing_extra_hosts() {
        assert!(matches_selected_profile_pattern(
            "pipelines.actions.githubusercontent.com"
        ));
        assert!(matches_selected_profile_pattern(
            "actions-results-receiver-production.githubapp.com"
        ));
        assert!(!matches_selected_profile_pattern(
            "productionresultssa17.blob.core.windows.net"
        ));
        assert!(!matches_selected_profile_pattern("codeload.github.com"));
        assert!(!matches_selected_profile_pattern("api.github.com"));
        assert!(matches_exact_selected_profile_hostname("github.com"));
        assert!(matches_exact_selected_profile_hostname("api.github.com"));
        assert!(matches_exact_selected_profile_hostname(
            "release-assets.githubusercontent.com"
        ));
        assert!(!matches_exact_selected_profile_hostname(
            "uploads.github.com"
        ));
        assert!(!matches_selected_profile_pattern("unrelated.example.com"));
        assert!(reportable_github_hostname("api.github.com"));
        assert!(!reportable_github_hostname(
            "unclassified-account.blob.core.windows.net"
        ));
        assert_eq!(
            profile_classification(DnsEvidenceScope::ProtectedHostAudit, "api.github.com"),
            "matches_selected_profile_pattern"
        );
        assert_eq!(
            profile_classification(DnsEvidenceScope::ProtectedHostAudit, "uploads.github.com"),
            "github_related_outside_profile"
        );
    }

    #[test]
    fn blocking_scope_forwards_only_selected_profile_names_and_refuses_others() {
        assert!(
            DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("vstoken.actions.githubusercontent.com", 1)
        );
        assert!(
            DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("pipelines.actions.githubusercontent.com", 1)
        );
        assert!(
            DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("results-receiver.actions.githubusercontent.com", 1)
        );
        assert!(
            DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("payload.pipelines.actions.githubusercontent.com", 1)
        );
        assert!(
            DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("actions-results-receiver-production.githubapp.com", 1)
        );
        assert!(DnsEvidenceScope::SelectedProfileRuntimeTest.forward_query("github.com", 1));
        assert!(DnsEvidenceScope::SelectedProfileRuntimeTest.forward_query("api.github.com", 1));
        assert!(
            DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("release-assets.githubusercontent.com", 1)
        );
        assert!(
            DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("bounded-dynamic.pipelines.actions.githubusercontent.com", 1,),
            "the selected profile permits only bounded dynamic names in the documented suffix class"
        );
        assert!(
            !DnsEvidenceScope::SelectedProfileRuntimeTest.forward_query(
                "lookalike.payload.pipelines.actions.githubusercontent.com",
                1,
            ),
            "dynamic suffix names may have at most two prefix labels"
        );
        assert!(
            !DnsEvidenceScope::SelectedProfileRuntimeTest.forward_query("codeload.github.com", 1)
        );
        assert!(
            !DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("productionresultssa17.blob.core.windows.net", 1)
        );
        assert!(
            !DnsEvidenceScope::SelectedProfileRuntimeTest.forward_query("uploads.github.com", 1)
        );
        assert!(
            !DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("bounded-dynamic.actions.githubusercontent.com", 16,)
        );
        assert!(
            DnsEvidenceScope::ProtectedHostAudit
                .forward_query("productionresultssa17.blob.core.windows.net", 1)
        );
        assert!(DnsEvidenceScope::ProtectedHostAudit.forward_query("api.github.com", 16));
        let response = refused_response(&query("api.github.com", 1)).unwrap();
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 5);
        assert_ne!(u16::from_be_bytes([response[2], response[3]]) & 0x8000, 0);
    }

    #[test]
    fn bounds_dynamic_actions_suffix_names_for_the_profile_lifetime() {
        let now = Instant::now();
        let mut authorizations = CnameAuthorizationState::default();
        for index in 0..MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS {
            assert!(authorized_selected_profile_hostname(
                &format!("dynamic-{index}.actions.githubusercontent.com"),
                &mut authorizations,
                now,
            ));
        }
        assert_eq!(
            authorizations.bounded_actions_suffix.len(),
            MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS
        );
        assert!(authorized_selected_profile_hostname(
            "dynamic-0.actions.githubusercontent.com",
            &mut authorizations,
            now + Duration::from_secs(600),
        ));
        assert!(!authorized_selected_profile_hostname(
            "dynamic-overflow.actions.githubusercontent.com",
            &mut authorizations,
            now,
        ));
        assert!(authorizations.bounded_actions_suffix_truncated);
        assert!(!authorized_selected_profile_hostname(
            "three.labels.deep.actions.githubusercontent.com",
            &mut CnameAuthorizationState::default(),
            now,
        ));
        assert!(!authorized_selected_profile_hostname(
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
        assert!(!authorized_selected_profile_hostname(
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
        assert!(authorized_selected_profile_hostname(
            "glb-example.github.com",
            &mut authorizations,
            now,
        ));
        assert!(!authorized_selected_profile_hostname(
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
        assert!(authorized_selected_profile_hostname(
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
        assert!(!authorized_selected_profile_hostname(
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
                source_hostname: "pipelines.actions.githubusercontent.com".to_owned(),
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
    fn prehydrated_bootstrap_materializations_are_deterministic_and_bounded() {
        let now = Instant::now();
        let root_materializations = pending_materializations_from_bootstrap_response(
            "github.com",
            1,
            &response_with_address("github.com", 1, 600, &[192, 0, 2, 10]),
            now,
        )
        .unwrap();
        let cname_materializations = pending_materializations_from_bootstrap_response(
            "github.com",
            1,
            &response_with_cname_and_address(
                "github.com",
                "edge.example.net",
                40,
                120,
                &[192, 0, 2, 20],
            ),
            now,
        )
        .unwrap();
        let unrelated_materializations = pending_materializations_from_bootstrap_response(
            "github.com",
            1,
            &response_with_unrelated_address(
                "github.com",
                "unrelated.example.net",
                &[192, 0, 2, 30],
            ),
            now,
        )
        .unwrap();
        let mut materializations = root_materializations;
        materializations.extend(cname_materializations);
        materializations.extend(unrelated_materializations);
        materializations.sort();
        materializations.dedup();

        assert_eq!(
            materializations
                .iter()
                .map(|materialization| (
                    materialization.hostname.as_str(),
                    materialization.address.to_string(),
                    materialization.ttl_seconds
                ))
                .collect::<Vec<_>>(),
            vec![
                ("edge.example.net", "192.0.2.20".to_owned(), 40),
                (
                    "github.com",
                    "192.0.2.10".to_owned(),
                    MAX_DYNAMIC_TTL_SECONDS
                ),
            ]
        );

        let queue = Arc::new(Mutex::new(MaterializationQueue::default()));
        enqueue_pending_materializations(&queue, materializations.clone());
        enqueue_pending_materializations(&queue, materializations);
        let mut active = BTreeMap::new();
        let (changed, truncated, expired) =
            merge_pending_materializations(&mut active, &queue, Instant::now());
        assert!(changed);
        assert!(!truncated);
        assert_eq!(expired, 0);
        assert_eq!(active.len(), 2);
        assert!(active_covers_selected_profile_bootstrap_roots(
            &SELECTED_PROFILE_RUNTIME_BOOTSTRAP_HOSTNAMES
                .iter()
                .map(|hostname| {
                    (
                        (
                            (*hostname).to_owned(),
                            (*hostname).to_owned(),
                            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                        ),
                        ActiveMaterialization {
                            source_hostname: (*hostname).to_owned(),
                            hostname: (*hostname).to_owned(),
                            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                            observed_ttl_seconds: 60,
                            expires_at: now + Duration::from_secs(60),
                        },
                    )
                })
                .collect()
        ));
        assert!(!active_covers_selected_profile_bootstrap_roots(&active));

        assert_eq!(
            pending_materializations_from_bootstrap_response(
                "api.github.com",
                1,
                &response_with_address("github.com", 1, 60, &[192, 0, 2, 10]),
                now,
            )
            .unwrap_err()
            .code,
            "dns_block_prehydration_failed"
        );
        let mut oversized = query("github.com", 1);
        oversized[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        oversized[6..8]
            .copy_from_slice(&((MAX_RETAINED_ADDRESSES_PER_OBSERVATION + 1) as u16).to_be_bytes());
        for value in 0..=MAX_RETAINED_ADDRESSES_PER_OBSERVATION {
            oversized.extend_from_slice(&[0xc0, 0x0c]);
            oversized.extend_from_slice(&1_u16.to_be_bytes());
            oversized.extend_from_slice(&1_u16.to_be_bytes());
            oversized.extend_from_slice(&60_u32.to_be_bytes());
            oversized.extend_from_slice(&4_u16.to_be_bytes());
            oversized.extend_from_slice(&[198, 51, 100, value as u8]);
        }
        assert_eq!(
            pending_materializations_from_bootstrap_response("github.com", 1, &oversized, now)
                .unwrap_err()
                .code,
            "dns_block_prehydration_failed"
        );
    }

    #[test]
    fn bootstrap_prehydration_tolerates_one_transient_query_family_failure() {
        let now = Instant::now();
        let materializations = materializations_from_bootstrap_query_results(
            "github.com",
            now,
            [
                (1, Err(PrehydrationQueryError::Transient)),
                (
                    28,
                    Ok(response_with_address(
                        "github.com",
                        28,
                        60,
                        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    )),
                ),
            ],
        )
        .unwrap();

        assert_eq!(materializations.len(), 1);
        assert_eq!(materializations[0].source_hostname, "github.com");
        assert_eq!(materializations[0].hostname, "github.com");
        assert_eq!(
            materializations[0].address,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );

        let error = materializations_from_bootstrap_query_results(
            "github.com",
            now,
            [
                (1, Err(PrehydrationQueryError::Transient)),
                (28, Err(PrehydrationQueryError::Transient)),
            ],
        )
        .unwrap_err();
        assert!(matches!(error, PrehydrationError::Transient(_)));
        assert_eq!(
            prehydration_error_code(&error),
            "dns_block_prehydration_failed"
        );
    }

    #[test]
    fn post_ready_root_refresh_preserves_fatal_error_classification() {
        let now = Instant::now();
        let active = active_with_all_bootstrap_roots(now);
        assert_eq!(
            root_refresh_critical_finding(
                Some(&PrehydrationError::Transient(DnsMediationError::new(
                    "dns_block_prehydration_failed",
                    "transient refresh miss"
                ))),
                &active,
            ),
            None
        );
        assert_eq!(
            root_refresh_critical_finding(
                Some(&PrehydrationError::Fatal(DnsMediationError::new(
                    "dns_block_prehydration_failed",
                    "invalid refresh response"
                ))),
                &active,
            )
            .map(|(code, _)| code),
            Some("dns_block_root_refresh_integrity_failed")
        );
        assert_eq!(
            root_refresh_critical_finding(
                Some(&PrehydrationError::Transient(DnsMediationError::new(
                    "dns_block_prehydration_failed",
                    "transient refresh miss"
                ))),
                &BTreeMap::new(),
            )
            .map(|(code, _)| code),
            Some("dns_block_root_refresh_failed")
        );
    }

    #[test]
    fn builds_bounded_sanitized_evidence() {
        let mut state = ObservationState::default();
        state.retained.insert(
            (
                "pipelines.actions.githubusercontent.com".to_owned(),
                1,
                "matches_selected_profile_pattern",
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
        let evidence = evidence_from_state(&state, "active", DnsEvidenceScope::ProtectedHostAudit);
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

    #[test]
    fn protected_audit_scope_is_observation_only_with_preserved_privilege_paths() {
        let evidence = evidence_from_state(
            &ObservationState::default(),
            "active",
            DnsEvidenceScope::ProtectedHostAudit,
        );

        assert_eq!(evidence.status, PROTECTED_AUDIT_STATUS);
        assert_eq!(evidence.mode, Mode::Audit);
        assert_eq!(
            evidence.platform_profile_id,
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID
        );
        assert_eq!(evidence.routing_status, "active");
        assert_eq!(evidence.host_dns_routing, "local_root_resident_mediator");
        assert_eq!(evidence.docker_dns_routing, "local_root_resident_mediator");
        assert!(!evidence.protection_available);
        assert!(
            evidence
                .limitations
                .contains(&"audit_observation_only_no_containment_claim")
        );
        assert!(
            protected_audit_limitations()
                .contains(&"audit_preserves_passwordless_sudo_and_container_control")
        );
    }

    #[test]
    fn bounds_tcp_dns_socket_io_and_external_docker_configuration_inputs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        set_dns_tcp_deadlines(&server).unwrap();
        assert_eq!(server.read_timeout().unwrap(), Some(DNS_FORWARD_TIMEOUT));
        assert_eq!(server.write_timeout().unwrap(), Some(DNS_FORWARD_TIMEOUT));
        drop(client);

        let root = Path::new("target/tmp/dns-mediator-safe-file-tests");
        let _ = fs::remove_dir_all(root);
        fs::create_dir_all(root).unwrap();
        let config = root.join("daemon.json");
        fs::write(&config, b"{}").unwrap();
        assert_eq!(
            read_optional_external_file(&config).unwrap(),
            Some(b"{}".to_vec())
        );

        let oversized = root.join("oversized.json");
        fs::write(
            &oversized,
            vec![b'x'; MAX_DOCKER_DAEMON_CONFIG_BYTES as usize + 1],
        )
        .unwrap();
        assert_eq!(
            read_optional_external_file(&oversized).unwrap_err().code,
            "dns_routing_setup_failed"
        );

        let linked = root.join("linked.json");
        std::os::unix::fs::symlink(&config, &linked).unwrap();
        assert_eq!(
            read_optional_external_file(&linked).unwrap_err().code,
            "dns_routing_setup_failed"
        );
        assert_eq!(
            replace_external_file(&linked, b"{}").unwrap_err().code,
            "dns_routing_setup_failed"
        );

        let directory = root.join("directory");
        fs::create_dir(&directory).unwrap();
        assert_eq!(
            read_optional_external_file(&directory).unwrap_err().code,
            "dns_routing_setup_failed"
        );
        assert_eq!(
            replace_external_file(&directory, b"{}").unwrap_err().code,
            "dns_routing_setup_failed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retains_dns_observation_report_write_failures_for_resident_checks() {
        let root = Path::new("target/tmp/dns-mediator-report-write-failure");
        let _ = fs::remove_dir_all(root);
        let recorder = ObservationRecorder {
            state: Arc::new(Mutex::new(ObservationState::default())),
            cname_authorizations: Arc::new(Mutex::new(CnameAuthorizationState::default())),
            report_write_failed: Arc::new(AtomicBool::new(false)),
            report_path: root.join("missing/report.json"),
            scope: DnsEvidenceScope::ProtectedHostAudit,
            materializations: None,
        };
        recorder.record_query("pipelines.actions.githubusercontent.com", 1, true);
        assert!(recorder.take_report_write_failure());
        assert!(!recorder.take_report_write_failure());
    }
}
