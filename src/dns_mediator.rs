use crate::attribution::{
    ATTRIBUTION_WORKER_NAME, AttributionCoordinator, AttributionSubmission, DnsCallerProvenance,
    DnsClientSocket, SocketProtocol, TrustedRunnerWorker, attribution_channel,
};
use crate::config::{
    ContainerPolicy, DestinationType, MAX_EXPANDED_RULES, MAX_REPORT_BYTES,
    MAX_USER_WILDCARD_AUTHORIZATIONS, Mode, Protocol, parse_and_normalize,
};
use crate::error::ErrorDetail;
use crate::findings::{
    ConnectionEvent, ConnectionFinding, FindingCollection, bounded_timestamp_now,
};
use crate::hosted_runner::{AcceptedResolverV2, hosted_runner_fingerprint_requirement};
use crate::hostname_policy::{
    ExactHostnamePolicy, HostnamePolicyOrigin, HostnameTransport, RuntimeHostnamePolicy,
};
use crate::lifecycle::{
    CriticalFinding, RESIDENT_VERIFICATION_INTERVAL, require_production_root_process,
    validate_production_service_context, validate_test_service_context,
};
use crate::local_control::{
    CurrentFenceOwner, LocalControlObservation, LocalControlSnapshot, NoCurrentFenceOwner,
    OBSERVATION_TIMEOUT, PinnedCurrentFenceOwner, SOCKET_PROBE_TIMEOUT, SystemUnixSocketAccess,
    accepted_local_control_snapshot, observe_local_control_inventory,
    verify_local_control_observation, verify_no_additive_local_control_observation,
};
use crate::lockdown::{
    LockdownControl, LockdownPosture, SystemLockdownControl, runner_path_writable,
};
use crate::nflog::NflogReader;
use crate::nft::{
    NetworkEvidenceCounters, OwnedNftState, expected_dns_mediated_owned_state,
    render_dns_mediated_replacement_ruleset, render_dns_mediated_ruleset,
};
use crate::nft_backend::{NativeNftBackend, SystemNftExecutor};
use crate::plan::{AssuranceStatus, EffectiveAllowance, PlanData, build_activation_plan};
use crate::platform_profile::{
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_ACTIONS_SUFFIX_PATTERN,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_GITHUBAPP_SUFFIX_PATTERN,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HTTPS_REFRESH_OVERLAP_SECONDS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_AUTHORIZATIONS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_DEPTH,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_GITHUBAPP_SUFFIX_AUTHORIZATIONS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_GITHUBAPP_SUFFIX_PREFIX_LABELS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_TTL_SECONDS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_RESULTS_STORAGE_AUTHORIZATIONS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_REFRESH_INTERVAL_SECONDS,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_RESULTS_STORAGE_PATTERN,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_TRUSTED_RESULTS_STORAGE_HOSTNAME,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_UPSTREAM_DNS,
    is_optional_github_hosted_workflow_bootstrap_hostname,
    reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan,
};
use crate::runtime::{
    ProductionRuntimeStore, RuntimeDocumentStore, RuntimeError, TestRuntimeStore,
};
use crate::trusted_executable::{TrustedExecutable, TrustedExecutableSet};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const DNS_MEDIATED_PROFILE_REALIZATION_ID: &str =
    "github_hosted_workflow_bootstrap_dns_provenance_v5";
pub const RUNTIME_EVIDENCE_SCHEMA_VERSION: u32 = 5;
pub const SELECTED_PROFILE_RUNTIME_EVIDENCE_STATUS: &str = "selected_profile_runtime_test_only";
pub const SELECTED_PROFILE_RUNTIME_READY_STATUS: &str =
    "selected_profile_runtime_ready_no_public_activation";
pub const PROTECTED_BLOCK_STATUS: &str = "protected_host_block";
pub const PROTECTED_BLOCK_READY_STATUS: &str = "ready";
pub const PROTECTED_DEGRADED_BLOCK_STATUS: &str = "protected_host_block_degraded";
pub const PROTECTED_DEGRADED_BLOCK_READY_STATUS: &str = "ready_degraded";
pub const PROTECTED_AUDIT_STATUS: &str = "protected_host_audit_observation";
pub const PROTECTED_AUDIT_READY_STATUS: &str = "ready_observation_only";
pub const DNS_MEDIATED_COMPATIBILITY_PATTERNS: [&str; 4] = [
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_ACTIONS_SUFFIX_PATTERN,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_GITHUBAPP_SUFFIX_PATTERN,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES[0],
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_RESULTS_STORAGE_PATTERN,
];

fn authorized_domain_patterns(hostname_policy: &RuntimeHostnamePolicy) -> Vec<&'static str> {
    if hostname_policy.allow_dynamic_githubapp_suffix {
        DNS_MEDIATED_COMPATIBILITY_PATTERNS.to_vec()
    } else {
        vec![
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_ACTIONS_SUFFIX_PATTERN,
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES[0],
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_RESULTS_STORAGE_PATTERN,
        ]
    }
}
const MAX_RETAINED_DNS_OBSERVATIONS: usize = 256;
const MAX_RETAINED_ADDRESSES_PER_OBSERVATION: usize = 32;
const MAX_MATERIALIZATIONS_PER_UPDATE: usize = 128;
const MAX_ACTIVE_MATERIALIZATIONS: usize = MAX_EXPANDED_RULES;
const MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS: usize =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS;
const MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS: usize =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS;
const MAX_DYNAMIC_GITHUBAPP_SUFFIX_AUTHORIZATIONS: usize =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_GITHUBAPP_SUFFIX_AUTHORIZATIONS;
const MAX_DYNAMIC_GITHUBAPP_SUFFIX_PREFIX_LABELS: usize =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_GITHUBAPP_SUFFIX_PREFIX_LABELS;
const MAX_RESULTS_STORAGE_AUTHORIZATIONS: usize =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_RESULTS_STORAGE_AUTHORIZATIONS;
const MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS: usize = MAX_USER_WILDCARD_AUTHORIZATIONS;
const MAX_DERIVED_CNAME_AUTHORIZATIONS: usize =
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_AUTHORIZATIONS;
const MAX_DERIVED_CNAME_DEPTH: u8 = GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_DEPTH;
const MAX_DYNAMIC_TTL_SECONDS: u32 = GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_TTL_SECONDS;
const DNS_PROFILE_REFRESH_INTERVAL: Duration =
    Duration::from_secs(GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_REFRESH_INTERVAL_SECONDS);
const MAX_USER_HOSTNAME_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const DNS_MATERIALIZATION_REFRESH_OVERLAP: Duration =
    Duration::from_secs(GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HTTPS_REFRESH_OVERLAP_SECONDS);
const MATERIALIZATION_REQUEST_QUEUE_CAPACITY: usize = 32;
const RESIDENT_EVENT_CHANNEL_CAPACITY: usize = 32;
const RESIDENT_WORKER_START_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CRITICAL_FINDINGS: usize = 64;
const MAX_DNS_PACKET_BYTES: usize = 4096;
const UPSTREAM_DNS: &str = GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_UPSTREAM_DNS;
const HOST_DNS_BIND: &str = "127.0.0.1:53";
const DOCKER_DNS_BIND: &str = "172.17.0.1:53";
const RESOLVER_SOURCE_FILE_NAME: &str = "resolv.conf";
const RESOLVER_SOURCE_CONTENTS: &[u8] = b"nameserver 127.0.0.1\noptions attempts:1 timeout:2\n";
const DOCKER_DAEMON_PATH: &str = "/etc/docker/daemon.json";
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
const STARTUP_PREHYDRATION_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_PREHYDRATION_MAX_ATTEMPTS: usize = 3;
const DNS_ROUTING_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DOCKER_DAEMON_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1024;
const RESIDENT_IDLE_INTERVAL: Duration = Duration::from_millis(100);
const REQUIRED_RESIDENT_WORKERS: [&str; 5] = [
    "docker_tcp_dns",
    "docker_udp_dns",
    "host_tcp_dns",
    "host_udp_dns",
    ATTRIBUTION_WORKER_NAME,
];

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ResidentWorkerHealth {
    pub name: &'static str,
    pub status: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ResidentHealth {
    pub status: &'static str,
    pub resident_pid: u32,
    pub verification_sequence: u64,
    pub last_successful_verification_unix_milliseconds: u64,
    pub verification_interval_seconds: u64,
    pub workers: Vec<ResidentWorkerHealth>,
}

#[derive(Debug)]
enum ResidentWorkerEvent {
    Started(&'static str),
    Fatal {
        worker: &'static str,
        code: &'static str,
        message: &'static str,
    },
}

#[derive(Debug)]
struct ResidentWorkerFailure {
    worker: &'static str,
    code: &'static str,
    message: &'static str,
}

struct ResidentWorkerSupervisor {
    events: Receiver<ResidentWorkerEvent>,
    statuses: BTreeMap<&'static str, &'static str>,
    disconnected_reported: bool,
}

fn initial_resident_health() -> ResidentHealth {
    ResidentHealth {
        status: "starting",
        resident_pid: std::process::id(),
        verification_sequence: 0,
        last_successful_verification_unix_milliseconds: 0,
        verification_interval_seconds: RESIDENT_VERIFICATION_INTERVAL.as_secs(),
        workers: REQUIRED_RESIDENT_WORKERS
            .into_iter()
            .map(|name| ResidentWorkerHealth {
                name,
                status: "starting",
            })
            .collect(),
    }
}

fn unix_time_milliseconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn advance_resident_health(
    health: &mut ResidentHealth,
    workers: Vec<ResidentWorkerHealth>,
    now_milliseconds: u64,
) {
    health.status = "healthy";
    health.workers = workers;
    health.verification_sequence = health.verification_sequence.saturating_add(1);
    health.last_successful_verification_unix_milliseconds = now_milliseconds;
}

impl ResidentWorkerSupervisor {
    fn new(events: Receiver<ResidentWorkerEvent>) -> Self {
        Self {
            events,
            statuses: REQUIRED_RESIDENT_WORKERS
                .into_iter()
                .map(|worker| (worker, "starting"))
                .collect(),
            disconnected_reported: false,
        }
    }

    fn wait_for_startup(&mut self) -> Result<(), DnsMediationError> {
        let deadline = Instant::now() + RESIDENT_WORKER_START_TIMEOUT;
        while self.statuses.values().any(|status| *status == "starting") {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(DnsMediationError::new(
                    "resident_worker_start_timeout",
                    "required resident workers did not all report startup",
                ));
            }
            match self.events.recv_timeout(remaining) {
                Ok(event) => {
                    if let Some(failure) = self.apply_event(event) {
                        return Err(DnsMediationError::new(failure.code, failure.message));
                    }
                }
                Err(_) => {
                    return Err(DnsMediationError::new(
                        "resident_worker_start_failed",
                        "resident worker supervision disconnected before readiness",
                    ));
                }
            }
        }
        Ok(())
    }

    fn drain_failures(&mut self) -> Vec<ResidentWorkerFailure> {
        let mut failures = Vec::new();
        loop {
            match self.events.try_recv() {
                Ok(event) => {
                    if let Some(failure) = self.apply_event(event) {
                        failures.push(failure);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if !self.disconnected_reported {
                        self.disconnected_reported = true;
                        failures.push(ResidentWorkerFailure {
                            worker: "resident_event_channel",
                            code: "resident_worker_channel_disconnected",
                            message: "resident worker supervision channel disconnected",
                        });
                    }
                    break;
                }
            }
        }
        failures
    }

    fn apply_event(&mut self, event: ResidentWorkerEvent) -> Option<ResidentWorkerFailure> {
        match event {
            ResidentWorkerEvent::Started(worker) => {
                if let Some(status) = self.statuses.get_mut(worker) {
                    *status = "running";
                }
                None
            }
            ResidentWorkerEvent::Fatal {
                worker,
                code,
                message,
            } => {
                if let Some(status) = self.statuses.get_mut(worker) {
                    *status = "failed";
                }
                Some(ResidentWorkerFailure {
                    worker,
                    code,
                    message,
                })
            }
        }
    }

    fn all_healthy(&self) -> bool {
        self.statuses.values().all(|status| *status == "running")
    }

    fn worker_health(&self) -> Vec<ResidentWorkerHealth> {
        self.statuses
            .iter()
            .map(|(name, status)| ResidentWorkerHealth { name, status })
            .collect()
    }
}

#[cfg(test)]
fn test_hostname_policy(disable_broad_github_domains: bool) -> RuntimeHostnamePolicy {
    let config = format!(
        r#"{{"schema_version":1,"mode":"block","invocation_id":"test-policy","disable_broad_github_domains":{disable_broad_github_domains},"allowlist":[]}}"#
    );
    let normalized = parse_and_normalize(config.as_bytes()).expect("test policy must parse");
    crate::hostname_policy::build_runtime_hostname_policy(&normalized)
}

#[cfg(test)]
fn test_user_wildcard_hostname_policy() -> RuntimeHostnamePolicy {
    let normalized = parse_and_normalize(
        br#"{"schema_version":1,"mode":"block","invocation_id":"test-wildcard-policy","allowlist":[{"destination_type":"hostname","destination":"*.docker.io","protocol":"tcp","port":443},{"destination_type":"hostname","destination":"*.docker.io","protocol":"tcp","port":8443},{"destination_type":"hostname","destination":"*.*.docker.io","protocol":"udp","port":53}]}"#,
    )
    .expect("test wildcard policy must parse");
    crate::hostname_policy::build_runtime_hostname_policy(&normalized)
}

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
                    && authorized_hostname(
                        hostname,
                        &mut CnameAuthorizationState::default(),
                        Instant::now(),
                        &test_hostname_policy(false),
                        DnsQueryProvenance::Untrusted,
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

    fn limitations(
        self,
        allow_dynamic_githubapp_suffix: bool,
        has_user_wildcards: bool,
    ) -> Vec<&'static str> {
        let mut limitations = match self {
            Self::TestEvidence => dns_block_test_limitations(allow_dynamic_githubapp_suffix),
            Self::ProductionStandardBlock => {
                protected_block_limitations(allow_dynamic_githubapp_suffix)
            }
            Self::ProductionUnsafePreserve => {
                protected_degraded_block_limitations(allow_dynamic_githubapp_suffix)
            }
        };
        limitations.extend(user_wildcard_limitations(has_user_wildcards));
        limitations
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
    pub policy_classification: &'static str,
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
    pub bootstrap_hostnames: Vec<String>,
    pub hostname_policy: RuntimeHostnamePolicy,
    pub mode: Mode,
    pub protection_available: bool,
    pub resident_health: ResidentHealth,
    pub routing_status: &'static str,
    pub host_dns_routing: &'static str,
    pub docker_dns_routing: &'static str,
    pub answer_attribution_status: &'static str,
    pub proxy_policy_status: &'static str,
    pub observations: Vec<DnsObservation>,
    pub observations_truncated: bool,
    pub bounded_actions_suffix_authorizations: Vec<String>,
    pub bounded_actions_suffix_authorizations_truncated: bool,
    pub bounded_githubapp_suffix_authorizations: Vec<String>,
    pub bounded_githubapp_suffix_authorizations_truncated: bool,
    pub bounded_user_wildcard_authorizations: Vec<String>,
    pub bounded_user_wildcard_authorizations_truncated: bool,
    pub user_wildcard_request_rejections: u64,
    pub runner_authorized_results_storage: Vec<DnsResultsStorageAuthorization>,
    pub runner_authorized_results_storage_truncated: bool,
    pub results_storage_authorization_count: u64,
    pub results_storage_attribution_failures: u64,
    pub results_storage_request_rejections: u64,
    pub derived_cname_authorizations: Vec<DnsDerivedCnameAuthorization>,
    pub derived_cname_authorizations_truncated: bool,
    pub excluded_unretained_query_count: u64,
    pub blocked_non_profile_query_count: u64,
    pub materialization_batch_count: u64,
    pub materialization_request_rejections: u64,
    pub materialization_update_max_milliseconds: u64,
    pub hostname_refresh_warnings: u64,
    pub upstream_request_failures: u64,
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
pub struct DnsResultsStorageAuthorization {
    pub hostname: String,
    pub authorization_origin: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsMaterializedAllowance {
    pub source_hostname: String,
    pub hostname: String,
    pub address: String,
    pub protocol: Protocol,
    pub port: u16,
    pub origins: Vec<HostnamePolicyOrigin>,
    pub observed_ttl_seconds: u32,
    pub expires_in_seconds: u64,
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
    pub bootstrap_hostnames: Vec<String>,
    pub hostname_policy: RuntimeHostnamePolicy,
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
    pub materialized_allowances: Vec<DnsMaterializedAllowance>,
    pub materializations_truncated: bool,
    pub expired_materializations: u64,
    pub hostname_refresh_warnings: u64,
    pub counters: NetworkEvidenceCounters,
    pub findings: Vec<ConnectionFinding>,
    pub findings_truncated: bool,
    pub critical_findings: Vec<CriticalFinding>,
    pub critical_findings_truncated: bool,
    pub resident_health: ResidentHealth,
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
    resident_health: &'a ResidentHealth,
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
    resident_health: &'a ResidentHealth,
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
    pub resident_health: ResidentHealth,
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
    resident_health: &'a ResidentHealth,
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
    resident_health: &'a ResidentHealth,
    protection_available: bool,
    limitations: Vec<&'static str>,
}

#[derive(Debug, Default)]
struct ObservationState {
    retained: BTreeMap<(String, u16, &'static str), RetainedObservation>,
    truncated: bool,
    excluded_unretained_query_count: u64,
    blocked_non_profile_query_count: u64,
    materialization_batch_count: u64,
    materialization_request_rejections: u64,
    materialization_update_max_milliseconds: u64,
    hostname_refresh_warnings: u64,
    upstream_request_failures: u64,
    results_storage_authorization_count: u64,
    results_storage_attribution_failures: u64,
    results_storage_request_rejections: u64,
    user_wildcard_request_rejections: u64,
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

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct DnsAnswerRecords {
    addresses: Vec<DnsAddressAnswer>,
    aliases: Vec<DnsCnameAnswer>,
}

type AuthorizedHostnamePolicy = (Vec<HostnamePolicyOrigin>, Vec<HostnameTransport>);

#[derive(Debug, Clone)]
struct ValidatedDnsResponse {
    authorizations: Vec<(String, ActiveCnameAuthorization)>,
    materializations: Vec<PendingMaterialization>,
    policy: AuthorizedHostnamePolicy,
    requires_runner_provenance: bool,
    root_authorization: Option<ActiveCnameAuthorization>,
    valid_until: Option<Instant>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsResponseValidationError {
    Invalid,
    Capacity,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct PendingMaterialization {
    source_hostname: String,
    hostname: String,
    address: IpAddr,
    protocol: Protocol,
    port: u16,
    origins: Vec<HostnamePolicyOrigin>,
    ttl_seconds: u32,
    expires_at: Instant,
}

type PendingMaterializationIdentity = (
    String,
    String,
    IpAddr,
    Protocol,
    u16,
    Vec<HostnamePolicyOrigin>,
);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MaterializationCompletion {
    AppliedVerifiedAndCommitted,
    Failed,
}

#[derive(Debug)]
struct MaterializationRequest {
    queried_hostname: String,
    response: ValidatedDnsResponse,
    completion: SyncSender<MaterializationCompletion>,
}

#[derive(Debug, Clone)]
struct MaterializationSubmitter {
    requests: SyncSender<MaterializationRequest>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsResponseDisposition {
    ForwardOriginal,
    RetryableFailure,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsQueryAuthorization {
    Forward(Option<&'static str>),
    Refused(Option<&'static str>),
    RetryableFailure(Option<&'static str>),
}

#[derive(Debug, Eq, PartialEq)]
enum DnsQueryDispatch {
    Forward(Vec<u8>, Option<&'static str>),
    Refused(Option<&'static str>),
    RetryableFailure(Option<&'static str>),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsListenerKind {
    Host,
    Docker,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DnsQueryClient {
    listener_kind: DnsListenerKind,
    socket: DnsClientSocket,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsQueryProvenance {
    TrustedRunnerWorker,
    Untrusted,
    AttributionFailed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct MaterializationMerge {
    rules_changed: bool,
    metadata_changed: bool,
    expired: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ActiveMaterialization {
    source_hostname: String,
    hostname: String,
    address: IpAddr,
    protocol: Protocol,
    port: u16,
    origins: Vec<HostnamePolicyOrigin>,
    observed_ttl_seconds: u32,
    expires_at: Instant,
}

type ActiveMaterializationKey = (String, String, IpAddr, Protocol, u16);

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct CnameAuthorizationState {
    bounded_actions_suffix: BTreeSet<String>,
    bounded_actions_suffix_truncated: bool,
    bounded_githubapp_suffix: BTreeSet<String>,
    bounded_githubapp_suffix_truncated: bool,
    bounded_user_wildcard: BTreeSet<String>,
    bounded_user_wildcard_truncated: bool,
    runner_authorized_results_storage: BTreeSet<String>,
    runner_authorized_results_storage_truncated: bool,
    active: BTreeMap<String, ActiveCnameAuthorization>,
    truncated: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ActiveCnameAuthorization {
    source_hostname: String,
    origins: Vec<HostnamePolicyOrigin>,
    transports: Vec<HostnameTransport>,
    requires_runner_provenance: bool,
    observed_ttl_seconds: u32,
    depth: u8,
    expires_at: Instant,
}

#[derive(Clone)]
struct ObservationRecorder {
    state: Arc<Mutex<ObservationState>>,
    cname_authorizations: Arc<Mutex<CnameAuthorizationState>>,
    report_write_failed: Arc<AtomicBool>,
    resident_health: Arc<Mutex<ResidentHealth>>,
    shutdown: Arc<AtomicBool>,
    report_path: PathBuf,
    scope: DnsEvidenceScope,
    hostname_policy: RuntimeHostnamePolicy,
    materializations: Option<MaterializationSubmitter>,
    trusted_runner_worker: Option<Arc<TrustedRunnerWorker>>,
}

impl ObservationRecorder {
    fn forward_query(
        &self,
        hostname: &str,
        query_type: u16,
        client: Option<DnsQueryClient>,
    ) -> Result<DnsQueryAuthorization, DnsMediationError> {
        match self.scope {
            DnsEvidenceScope::ProtectedHostAudit => {
                if !matches_supported_block_query_type(query_type) {
                    return Ok(DnsQueryAuthorization::Forward(Some("outside_policy")));
                }
                let requires_runner_provenance = {
                    let mut authorizations = self
                        .cname_authorizations
                        .lock()
                        .expect("DNS CNAME authorization lock poisoned");
                    remove_expired_cname_authorizations(&mut authorizations, Instant::now());
                    requires_runner_results_storage_provenance(
                        hostname,
                        &authorizations,
                        &self.hostname_policy,
                    )
                };
                let provenance = if requires_runner_provenance {
                    self.results_storage_provenance(client)?
                } else {
                    DnsQueryProvenance::Untrusted
                };
                let mut authorizations = self
                    .cname_authorizations
                    .lock()
                    .expect("DNS CNAME authorization lock poisoned");
                let wildcard_capacity_rejected = user_wildcard_capacity_rejected(
                    hostname,
                    &authorizations,
                    &self.hostname_policy,
                );
                let previous_results_storage_count =
                    authorizations.runner_authorized_results_storage.len();
                let authorized = authorized_hostname(
                    hostname,
                    &mut authorizations,
                    Instant::now(),
                    &self.hostname_policy,
                    provenance,
                );
                let authorization_added = authorizations.runner_authorized_results_storage.len()
                    > previous_results_storage_count;
                drop(authorizations);
                if requires_runner_provenance {
                    self.record_results_storage_observation(authorization_added, provenance);
                }
                if wildcard_capacity_rejected {
                    self.record_user_wildcard_rejection();
                }
                Ok(DnsQueryAuthorization::Forward(
                    (!authorized).then_some("outside_policy"),
                ))
            }
            DnsEvidenceScope::SelectedProfileRuntimeTest
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                if !matches_supported_block_query_type(query_type) {
                    return Ok(DnsQueryAuthorization::Refused(None));
                }
                let requires_runner_provenance = {
                    let mut authorizations = self
                        .cname_authorizations
                        .lock()
                        .expect("DNS CNAME authorization lock poisoned");
                    remove_expired_cname_authorizations(&mut authorizations, Instant::now());
                    requires_runner_results_storage_provenance(
                        hostname,
                        &authorizations,
                        &self.hostname_policy,
                    )
                };
                let provenance = if requires_runner_provenance {
                    self.results_storage_provenance(client)?
                } else {
                    DnsQueryProvenance::Untrusted
                };
                let mut authorizations = self
                    .cname_authorizations
                    .lock()
                    .expect("DNS CNAME authorization lock poisoned");
                let wildcard_capacity_rejected = user_wildcard_capacity_rejected(
                    hostname,
                    &authorizations,
                    &self.hostname_policy,
                );
                let previous_results_storage_count =
                    authorizations.runner_authorized_results_storage.len();
                let authorized = authorized_hostname(
                    hostname,
                    &mut authorizations,
                    Instant::now(),
                    &self.hostname_policy,
                    provenance,
                );
                let authorization_added = authorizations.runner_authorized_results_storage.len()
                    > previous_results_storage_count;
                drop(authorizations);
                if requires_runner_provenance {
                    self.record_results_storage_decision(
                        authorized,
                        authorization_added,
                        provenance,
                    );
                }
                if wildcard_capacity_rejected {
                    self.record_user_wildcard_rejection();
                }
                Ok(query_authorization(
                    authorized,
                    requires_runner_provenance,
                    provenance,
                ))
            }
        }
    }

    fn results_storage_provenance(
        &self,
        client: Option<DnsQueryClient>,
    ) -> Result<DnsQueryProvenance, DnsMediationError> {
        let Some(client) = client else {
            return Ok(DnsQueryProvenance::AttributionFailed);
        };
        if client.listener_kind != DnsListenerKind::Host {
            return Ok(DnsQueryProvenance::Untrusted);
        }
        let Some(worker) = &self.trusted_runner_worker else {
            return Ok(DnsQueryProvenance::AttributionFailed);
        };
        match worker.classify_dns_client(client.socket) {
            Ok(provenance) => Ok(match provenance {
                DnsCallerProvenance::TrustedRunnerWorker => DnsQueryProvenance::TrustedRunnerWorker,
                DnsCallerProvenance::Untrusted => DnsQueryProvenance::Untrusted,
                DnsCallerProvenance::AttributionFailed => DnsQueryProvenance::AttributionFailed,
            }),
            Err(error) => {
                self.record_results_storage_identity_failure();
                Err(DnsMediationError::new(error.code, error.message))
            }
        }
    }

    fn record_results_storage_observation(
        &self,
        authorization_added: bool,
        provenance: DnsQueryProvenance,
    ) {
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        if authorization_added {
            state.results_storage_authorization_count =
                state.results_storage_authorization_count.saturating_add(1);
        }
        if provenance == DnsQueryProvenance::AttributionFailed {
            state.results_storage_attribution_failures =
                state.results_storage_attribution_failures.saturating_add(1);
        }
    }

    fn record_results_storage_identity_failure(&self) {
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        state.results_storage_attribution_failures =
            state.results_storage_attribution_failures.saturating_add(1);
        if self.scope.is_block() {
            state.results_storage_request_rejections =
                state.results_storage_request_rejections.saturating_add(1);
        }
    }

    fn record_user_wildcard_rejection(&self) {
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        state.user_wildcard_request_rejections =
            state.user_wildcard_request_rejections.saturating_add(1);
    }

    fn record_results_storage_decision(
        &self,
        authorized: bool,
        authorization_added: bool,
        provenance: DnsQueryProvenance,
    ) {
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        if authorization_added {
            state.results_storage_authorization_count =
                state.results_storage_authorization_count.saturating_add(1);
        }
        if provenance == DnsQueryProvenance::AttributionFailed {
            state.results_storage_attribution_failures =
                state.results_storage_attribution_failures.saturating_add(1);
        }
        if !authorized {
            state.results_storage_request_rejections =
                state.results_storage_request_rejections.saturating_add(1);
        }
    }

    fn policy_classification(&self, hostname: &str) -> &'static str {
        let mut authorizations = self
            .cname_authorizations
            .lock()
            .expect("DNS CNAME authorization lock poisoned");
        remove_expired_cname_authorizations(&mut authorizations, Instant::now());
        policy_classification(hostname, &authorizations, &self.hostname_policy)
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
        evidence_from_state_and_authorizations(
            state,
            routing_status,
            self.scope,
            &authorizations,
            &self.hostname_policy,
            &self
                .resident_health
                .lock()
                .expect("resident health lock poisoned"),
        )
    }

    fn record_query(
        &self,
        hostname: &str,
        query_type: u16,
        forwarded: bool,
        classification_override: Option<&'static str>,
    ) {
        let normalized = normalize_hostname(hostname);
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        if let Some(hostname) = normalized {
            let classification =
                classification_override.unwrap_or_else(|| self.policy_classification(&hostname));
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
            state.excluded_unretained_query_count =
                state.excluded_unretained_query_count.saturating_add(1);
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

    fn record_response(
        &self,
        hostname: &str,
        query_type: u16,
        packet: &[u8],
        classification_override: Option<&'static str>,
    ) -> DnsResponseDisposition {
        let Some(hostname) = normalize_hostname(hostname) else {
            return if self.scope.is_block() {
                DnsResponseDisposition::RetryableFailure
            } else {
                DnsResponseDisposition::ForwardOriginal
            };
        };
        let forwardable_block_response = self.scope.is_block();
        let records = parse_complete_dns_response(packet, &hostname, query_type);
        let mut observed_answers = if forwardable_block_response {
            Vec::new()
        } else {
            records
                .as_ref()
                .map(|records| records.addresses.clone())
                .unwrap_or_default()
        };
        let mut block_validation = None;
        if let Some(records) = records.as_ref() {
            let now = Instant::now();
            let mut authorizations = self
                .cname_authorizations
                .lock()
                .expect("DNS CNAME authorization lock poisoned");
            remove_expired_cname_authorizations(&mut authorizations, now);
            match validate_dns_response_lineage(
                &hostname,
                records,
                &authorizations,
                now,
                &self.hostname_policy,
            ) {
                Ok(response) => {
                    if forwardable_block_response {
                        observed_answers = records.addresses.clone();
                        block_validation = Some(response);
                    } else {
                        let _ = commit_dns_response_authorizations(&mut authorizations, response);
                    }
                }
                Err(DnsResponseValidationError::Capacity) => {
                    authorizations.truncated = true;
                }
                Err(DnsResponseValidationError::Invalid) => {}
            }
        }
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        let classification =
            classification_override.unwrap_or_else(|| self.policy_classification(&hostname));
        let key = (hostname.clone(), query_type, classification);
        if let Some(observation) = state.retained.get_mut(&key) {
            retain_address_answers(observation, observed_answers);
        }
        drop(state);

        let disposition = if !forwardable_block_response {
            DnsResponseDisposition::ForwardOriginal
        } else if block_validation.is_none() {
            self.record_materialization_rejection();
            DnsResponseDisposition::RetryableFailure
        } else if block_validation
            .as_ref()
            .is_some_and(|response| response.materializations.is_empty())
        {
            DnsResponseDisposition::ForwardOriginal
        } else if let Some(submitter) = &self.materializations {
            let response = block_validation.expect("block validation checked above");
            match submit_materialization_request(
                submitter,
                hostname.clone(),
                response,
                &self.shutdown,
            ) {
                Ok(MaterializationCompletion::AppliedVerifiedAndCommitted) => {
                    DnsResponseDisposition::ForwardOriginal
                }
                Ok(MaterializationCompletion::Failed) => DnsResponseDisposition::RetryableFailure,
                Err(()) => {
                    self.record_materialization_rejection();
                    DnsResponseDisposition::RetryableFailure
                }
            }
        } else {
            self.record_materialization_rejection();
            DnsResponseDisposition::RetryableFailure
        };

        let state = self.state.lock().expect("DNS observation lock poisoned");
        let evidence = self.evidence_from_state(&state, self.scope.active_routing_status());
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        if write_result.is_err() {
            self.report_write_failed.store(true, Ordering::Relaxed);
        }
        disposition
    }

    fn record_materialization_rejection(&self) {
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        state.materialization_request_rejections =
            state.materialization_request_rejections.saturating_add(1);
    }

    fn record_materialization_batch(&self, elapsed: Duration) {
        let elapsed_milliseconds = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        state.materialization_batch_count = state.materialization_batch_count.saturating_add(1);
        state.materialization_update_max_milliseconds = state
            .materialization_update_max_milliseconds
            .max(elapsed_milliseconds);
        let evidence = self.evidence_from_state(&state, self.scope.active_routing_status());
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        if write_result.is_err() {
            self.report_write_failed.store(true, Ordering::Relaxed);
        }
    }

    fn record_hostname_refresh_warning(&self) {
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        state.hostname_refresh_warnings = state.hostname_refresh_warnings.saturating_add(1);
        let evidence = self.evidence_from_state(&state, self.scope.active_routing_status());
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        if write_result.is_err() {
            self.report_write_failed.store(true, Ordering::Relaxed);
        }
    }

    fn record_upstream_request_failure(&self) {
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        state.upstream_request_failures = state.upstream_request_failures.saturating_add(1);
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
            &self.hostname_policy,
            &self
                .resident_health
                .lock()
                .expect("resident health lock poisoned"),
        );
        drop(authorizations);
        let write_result = write_report(&self.report_path, &evidence);
        drop(state);
        write_result
    }

    fn take_report_write_failure(&self) -> bool {
        self.report_write_failed.swap(false, Ordering::Relaxed)
    }

    fn refresh_report(&self) -> Result<(), DnsMediationError> {
        let state = self.state.lock().map_err(|_| {
            DnsMediationError::new(
                "dns_observation_state_failed",
                "DNS observation state could not be read during resident verification",
            )
        })?;
        write_report(
            &self.report_path,
            &self.evidence_from_state(&state, self.scope.active_routing_status()),
        )
    }
}

fn query_authorization(
    authorized: bool,
    requires_runner_provenance: bool,
    provenance: DnsQueryProvenance,
) -> DnsQueryAuthorization {
    if authorized {
        DnsQueryAuthorization::Forward(None)
    } else if requires_runner_provenance && provenance != DnsQueryProvenance::Untrusted {
        DnsQueryAuthorization::RetryableFailure(Some("outside_policy"))
    } else if requires_runner_provenance {
        DnsQueryAuthorization::Refused(Some("outside_policy"))
    } else {
        DnsQueryAuthorization::Refused(None)
    }
}

struct DnsRouting {
    executables: Arc<TrustedExecutableSet>,
    docker_original: Option<Vec<u8>>,
    resolver_source: PathBuf,
    resolver_target: PathBuf,
    resolver_source_created: bool,
    resolver_mounted: bool,
    docker_changed: bool,
}

impl DnsRouting {
    fn activate(
        runtime_directory: &Path,
        executables: Arc<TrustedExecutableSet>,
    ) -> Result<Self, DnsMediationError> {
        let accepted = hosted_runner_fingerprint_requirement().accepted.resolver;
        let mut routing = Self {
            executables,
            docker_original: None,
            resolver_source: runtime_directory.join(RESOLVER_SOURCE_FILE_NAME),
            resolver_target: PathBuf::from(accepted.canonical_target),
            resolver_source_created: false,
            resolver_mounted: false,
            docker_changed: false,
        };
        let result = routing.activate_inner();
        if result.is_err() {
            let _ = routing.rollback();
        }
        result.map(|()| routing)
    }

    fn activate_inner(&mut self) -> Result<(), DnsMediationError> {
        self.verify_supported_resolver_layout()?;
        if self.resolver_source.exists() {
            return Err(DnsMediationError::new(
                "dns_routing_conflict",
                "DNS routing refuses a preexisting owned resolver file",
            ));
        }
        write_new_file(&self.resolver_source, RESOLVER_SOURCE_CONTENTS, 0o644).map_err(|_| {
            DnsMediationError::new(
                "dns_routing_setup_failed",
                "failed to create the owned resolver routing file",
            )
        })?;
        self.resolver_source_created = true;
        let source = self.resolver_source.to_str().ok_or_else(|| {
            DnsMediationError::new(
                "dns_routing_setup_failed",
                "owned resolver source path is not valid UTF-8",
            )
        })?;
        let target = self.resolver_target.to_str().ok_or_else(|| {
            DnsMediationError::new(
                "dns_routing_setup_failed",
                "accepted resolver target path is not valid UTF-8",
            )
        })?;
        if let Err(error) = fixed_command(
            &self.executables,
            TrustedExecutable::Mount,
            &["--bind", source, target],
        ) {
            self.resolver_mounted = paths_have_same_identity(
                self.resolver_source.as_path(),
                self.resolver_target.as_path(),
            );
            return Err(error);
        }
        self.resolver_mounted = true;
        fixed_command(
            &self.executables,
            TrustedExecutable::Mount,
            &["-o", "remount,bind,ro,nodev,nosuid", source, target],
        )?;
        self.verify_active_resolver_mount()?;

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
        fixed_command(
            &self.executables,
            TrustedExecutable::Systemctl,
            &["restart", "docker.service"],
        )?;
        self.verify_active()
    }

    fn rollback(&mut self) -> Result<bool, DnsMediationError> {
        let changed = self.resolver_source_created || self.resolver_mounted || self.docker_changed;
        if self.docker_changed {
            match self.docker_original.as_deref() {
                Some(bytes) => replace_external_file(Path::new(DOCKER_DAEMON_PATH), bytes)?,
                None => {
                    let _ = fs::remove_file(DOCKER_DAEMON_PATH);
                }
            }
            fixed_command(
                &self.executables,
                TrustedExecutable::Systemctl,
                &["restart", "docker.service"],
            )?;
            self.docker_changed = false;
        }
        if self.resolver_mounted {
            let target = self.resolver_target.to_str().ok_or_else(|| {
                DnsMediationError::new(
                    "dns_routing_rollback_failed",
                    "accepted resolver target path is not valid UTF-8",
                )
            })?;
            fixed_command(&self.executables, TrustedExecutable::Umount, &[target])?;
            self.resolver_mounted = false;
        }
        if self.resolver_source_created {
            fs::remove_file(&self.resolver_source).map_err(|_| {
                DnsMediationError::new(
                    "dns_routing_rollback_failed",
                    "failed to remove provisional resolver routing",
                )
            })?;
            self.resolver_source_created = false;
        }
        Ok(changed)
    }

    fn verify_active(&self) -> Result<(), DnsMediationError> {
        self.verify_active_resolver_mount()?;
        verify_docker_dns_route()
    }

    fn verify_supported_resolver_layout(&self) -> Result<(), DnsMediationError> {
        let accepted = hosted_runner_fingerprint_requirement().accepted.resolver;
        let resolv_conf = Path::new(accepted.resolv_conf_path);
        let metadata = fs::symlink_metadata(resolv_conf).map_err(|_| {
            DnsMediationError::new(
                "unsupported_resolver_layout",
                "host resolver layout does not match the reviewed runner fingerprint",
            )
        })?;
        let canonical = fs::canonicalize(resolv_conf).map_err(|_| {
            DnsMediationError::new(
                "unsupported_resolver_layout",
                "host resolver target could not be resolved safely",
            )
        })?;
        let target_metadata = fs::symlink_metadata(&canonical).map_err(|_| {
            DnsMediationError::new(
                "unsupported_resolver_layout",
                "host resolver target could not be inspected safely",
            )
        })?;
        if !resolver_layout_is_supported(
            metadata.file_type().is_symlink(),
            &canonical,
            &accepted,
            target_metadata.file_type().is_file(),
            target_metadata.file_type().is_symlink(),
            target_metadata.uid(),
            target_metadata.permissions().mode() & 0o777,
        ) {
            return Err(DnsMediationError::new(
                "unsupported_resolver_layout",
                "host resolver layout does not match the reviewed runner fingerprint",
            ));
        }
        Ok(())
    }

    fn verify_active_resolver_mount(&self) -> Result<(), DnsMediationError> {
        let source_metadata = fs::symlink_metadata(&self.resolver_source).map_err(|_| {
            DnsMediationError::new(
                "dns_routing_verification_failed",
                "owned resolver source is unavailable",
            )
        })?;
        let target_metadata = fs::symlink_metadata(&self.resolver_target).map_err(|_| {
            DnsMediationError::new(
                "dns_routing_verification_failed",
                "active resolver mount target is unavailable",
            )
        })?;
        let source_contents = fs::read(&self.resolver_source).map_err(|_| {
            DnsMediationError::new(
                "dns_routing_verification_failed",
                "owned resolver source could not be verified",
            )
        })?;
        let target_contents = fs::read(&self.resolver_target).map_err(|_| {
            DnsMediationError::new(
                "dns_routing_verification_failed",
                "active resolver contents could not be verified",
            )
        })?;
        if !source_metadata.file_type().is_file()
            || source_metadata.file_type().is_symlink()
            || source_metadata.uid() != 0
            || source_metadata.permissions().mode() & 0o777 != 0o644
            || source_metadata.dev() != target_metadata.dev()
            || source_metadata.ino() != target_metadata.ino()
            || source_contents != RESOLVER_SOURCE_CONTENTS
            || target_contents != RESOLVER_SOURCE_CONTENTS
            || !mount_has_required_options(&self.resolver_target)
        {
            return Err(DnsMediationError::new(
                "dns_routing_verification_failed",
                "active resolver mount does not match the reviewed direct-query routing",
            ));
        }
        Ok(())
    }
}

fn resolver_layout_is_supported(
    resolv_conf_is_symlink: bool,
    canonical_target: &Path,
    accepted: &AcceptedResolverV2,
    target_is_file: bool,
    target_is_symlink: bool,
    target_uid: u32,
    target_mode: u32,
) -> bool {
    resolv_conf_is_symlink
        && canonical_target == Path::new(accepted.canonical_target)
        && target_is_file
        && !target_is_symlink
        && target_uid == accepted.target_uid
        && target_mode == 0o644
}

fn paths_have_same_identity(left: &Path, right: &Path) -> bool {
    let Ok(left) = fs::symlink_metadata(left) else {
        return false;
    };
    let Ok(right) = fs::symlink_metadata(right) else {
        return false;
    };
    left.dev() == right.dev() && left.ino() == right.ino()
}

pub struct DnsMediationSession {
    routing: DnsRouting,
    fence_owner: PinnedCurrentFenceOwner,
    recorder: ObservationRecorder,
    resident_health: Arc<Mutex<ResidentHealth>>,
    supervisor: ResidentWorkerSupervisor,
    attribution: AttributionCoordinator,
    stop_workers: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

struct DnsProxyRuntime {
    threads: Vec<JoinHandle<()>>,
    supervisor: ResidentWorkerSupervisor,
    attribution: AttributionCoordinator,
}

impl DnsMediationSession {
    fn establish(
        runtime_directory: &Path,
        executables: Arc<TrustedExecutableSet>,
        scope: DnsEvidenceScope,
        hostname_policy: RuntimeHostnamePolicy,
        materializations: Option<MaterializationSubmitter>,
    ) -> Result<Self, DnsMediationError> {
        let fence_owner =
            PinnedCurrentFenceOwner::capture(Path::new("/proc")).map_err(local_control_error)?;
        let trusted_runner_worker = Arc::new(
            TrustedRunnerWorker::discover_system()
                .map_err(|error| DnsMediationError::new(error.code, error.message))?,
        );
        let report_path = runtime_directory.join("dns-report.json");
        let resident_health = Arc::new(Mutex::new(initial_resident_health()));
        let stop_workers = Arc::new(AtomicBool::new(false));
        let recorder = ObservationRecorder {
            state: Arc::new(Mutex::new(ObservationState::default())),
            cname_authorizations: Arc::new(Mutex::new(CnameAuthorizationState::default())),
            report_write_failed: Arc::new(AtomicBool::new(false)),
            resident_health: Arc::clone(&resident_health),
            shutdown: Arc::clone(&stop_workers),
            report_path,
            scope,
            hostname_policy,
            materializations,
            trusted_runner_worker: Some(trusted_runner_worker),
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
                &recorder.hostname_policy,
                &resident_health
                    .lock()
                    .expect("resident health lock poisoned"),
            ),
        )?;
        let DnsProxyRuntime {
            mut threads,
            mut supervisor,
            attribution,
        } = start_dns_proxy(recorder.clone(), Arc::clone(&stop_workers))?;
        if let Err(error) = supervisor.wait_for_startup() {
            shutdown_dns_workers(&stop_workers, &mut threads);
            return Err(error);
        }
        {
            let mut health = resident_health
                .lock()
                .expect("resident health lock poisoned");
            health.workers = supervisor.worker_health();
        }
        let routing = match DnsRouting::activate(runtime_directory, executables) {
            Ok(routing) => routing,
            Err(error) => {
                shutdown_dns_workers(&stop_workers, &mut threads);
                return Err(error);
            }
        };
        if let Err(error) = recorder.reset_after_activation() {
            let mut routing = routing;
            let _ = routing.rollback();
            shutdown_dns_workers(&stop_workers, &mut threads);
            return Err(error);
        }
        Ok(Self {
            routing,
            fence_owner,
            recorder,
            resident_health,
            supervisor,
            attribution,
            stop_workers,
            threads,
        })
    }

    fn drain_worker_failures(&mut self) -> Vec<ResidentWorkerFailure> {
        let failures = self.supervisor.drain_failures();
        if !failures.is_empty() {
            self.mark_resident_critical();
        }
        self.sync_worker_health();
        failures
    }

    fn submit_attribution(
        &self,
        finding_index: usize,
        tuple: crate::attribution::SocketTuple,
    ) -> AttributionSubmission {
        self.attribution.submit(finding_index, tuple)
    }

    fn drain_attribution_results(&self) -> Vec<crate::attribution::AttributionResult> {
        self.attribution.drain()
    }

    fn mark_verification_successful(&mut self) {
        let workers = self.supervisor.worker_health();
        let mut health = self
            .resident_health
            .lock()
            .expect("resident health lock poisoned");
        if health.status == "critical" {
            return;
        }
        advance_resident_health(&mut health, workers, unix_time_milliseconds());
    }

    fn mark_resident_critical(&mut self) {
        self.resident_health
            .lock()
            .expect("resident health lock poisoned")
            .status = "critical";
    }

    fn resident_health(&self) -> ResidentHealth {
        self.resident_health
            .lock()
            .expect("resident health lock poisoned")
            .clone()
    }

    fn workers_healthy(&self) -> bool {
        self.supervisor.all_healthy()
    }

    fn sync_worker_health(&mut self) {
        self.resident_health
            .lock()
            .expect("resident health lock poisoned")
            .workers = self.supervisor.worker_health();
    }

    fn inject_test_worker_failure(&mut self) -> ResidentWorkerFailure {
        let failure = self
            .supervisor
            .apply_event(ResidentWorkerEvent::Fatal {
                worker: "host_udp_dns",
                code: "resident_worker_test_failure",
                message: "required resident DNS worker failed during hosted evidence",
            })
            .expect("test worker failure event must be fatal");
        self.mark_resident_critical();
        self.sync_worker_health();
        failure
    }
}

impl Drop for DnsMediationSession {
    fn drop(&mut self) {
        shutdown_dns_workers(&self.stop_workers, &mut self.threads);
    }
}

fn record_connection_event(
    mediation: &DnsMediationSession,
    findings: &mut FindingCollection,
    event: ConnectionEvent,
) {
    let tuple = event.tuple;
    let Some(index) = findings.record_finding(event.finding) else {
        return;
    };
    if let Some(tuple) = tuple
        && let AttributionSubmission::Rejected(attribution) =
            mediation.submit_attribution(index, tuple)
    {
        findings.record_attribution(index, attribution);
    }
}

fn apply_attribution_results(
    mediation: &DnsMediationSession,
    findings: &mut FindingCollection,
) -> bool {
    let results = mediation.drain_attribution_results();
    let changed = !results.is_empty();
    for result in results {
        findings.record_attribution(result.finding_index, result.attribution);
    }
    changed
}

fn local_control_error(
    error: crate::local_control::LocalControlVerificationError,
) -> DnsMediationError {
    DnsMediationError::new(error.code, error.message)
}

fn accepted_local_control_inventory() -> Result<LocalControlSnapshot, DnsMediationError> {
    accepted_local_control_snapshot(
        &hosted_runner_fingerprint_requirement()
            .accepted
            .local_control_inventory,
    )
    .map_err(local_control_error)
}

fn observe_local_control(
    executables: &TrustedExecutableSet,
    current_fence: &dyn CurrentFenceOwner,
) -> LocalControlObservation {
    let deadline = Instant::now() + OBSERVATION_TIMEOUT;
    let socket_access = SystemUnixSocketAccess::new(|path: &std::ffi::OsStr| {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let timeout = remaining.min(SOCKET_PROBE_TIMEOUT);
        if timeout.is_zero() {
            None
        } else {
            runner_path_writable(executables, path, timeout).ok()
        }
    });
    observe_local_control_inventory(Path::new("/proc"), &socket_access, current_fence)
}

fn verify_pre_activation_local_control(
    executables: &TrustedExecutableSet,
) -> Result<(), DnsMediationError> {
    let accepted = accepted_local_control_inventory()?;
    let observed = observe_local_control(executables, &NoCurrentFenceOwner);
    verify_local_control_observation(&accepted, &observed).map_err(local_control_error)
}

fn establish_local_control_baseline(
    mediation: &DnsMediationSession,
    posture: LockdownPosture,
) -> Result<LocalControlSnapshot, DnsMediationError> {
    let accepted_inventory = hosted_runner_fingerprint_requirement()
        .accepted
        .local_control_inventory;
    let observed = observe_local_control(&mediation.routing.executables, &mediation.fence_owner);
    match posture {
        LockdownPosture::StandardBlock => {
            verify_no_additive_local_control_observation(&accepted_inventory, &observed)
        }
        LockdownPosture::UnsafePreserve | LockdownPosture::Audit => {
            let accepted = accepted_local_control_snapshot(&accepted_inventory)
                .map_err(local_control_error)?;
            verify_local_control_observation(&accepted, &observed)
        }
    }
    .map_err(local_control_error)?;
    Ok(observed.snapshot)
}

fn verify_resident_local_control(
    mediation: &DnsMediationSession,
    baseline: &LocalControlSnapshot,
) -> Result<(), crate::local_control::LocalControlVerificationError> {
    let observed = observe_local_control(&mediation.routing.executables, &mediation.fence_owner);
    verify_local_control_observation(baseline, &observed)
}

struct DnsMediatedAuditSession<R: RuntimeDocumentStore> {
    _mediation: DnsMediationSession,
    backend: NativeNftBackend<SystemNftExecutor>,
    lockdown: SystemLockdownControl,
    reader: NflogReader,
    runtime: R,
    expected_state: OwnedNftState,
    local_control_baseline: LocalControlSnapshot,
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
        let initial_health = mediation.resident_health();
        let mut evidence =
            initial_dns_audit_evidence(plan, ruleset_hash.clone(), initial_health.clone());
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
            resident_health: &initial_health,
        }) {
            let _ = mediation.routing.rollback();
            return Err(runtime_error(error));
        }
        if let Err(error) = runtime.replace_report(&evidence) {
            let _ = mediation.routing.rollback();
            return Err(runtime_error(error));
        }

        let executables = Arc::clone(&mediation.routing.executables);
        let mut backend = NativeNftBackend::new(SystemNftExecutor::host(Arc::clone(&executables)));
        let mut lockdown = SystemLockdownControl::new(executables);
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
            establish_local_control_baseline(&mediation, LockdownPosture::Audit)
        })();
        let local_control_baseline = match setup_result {
            Ok(baseline) => baseline,
            Err(error) => {
                evidence.setup_status = "failed_pre_ready";
                evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
                let _ = runtime.replace_report(&evidence);
                return Err(error);
            }
        };

        if let Some(failure) = mediation.drain_worker_failures().into_iter().next() {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(DnsMediationError::new(failure.code, failure.message));
        }
        if !mediation.workers_healthy() {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(DnsMediationError::new(
                "resident_worker_unhealthy",
                "required resident DNS workers were not healthy before readiness",
            ));
        }
        if let Err(error) = runtime.verify_evidence_persistence(false) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(runtime_error(error));
        }
        mediation.mark_verification_successful();
        evidence.resident_health = mediation.resident_health();
        if let Err(error) = mediation.recorder.refresh_report() {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(error);
        }
        if let Err(error) = verify_resident_local_control(&mediation, &local_control_baseline) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(local_control_error(error));
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
            resident_health: &evidence.resident_health,
            protection_available: false,
            limitations: protected_audit_limitations(
                plan.runtime_hostname_policy.has_user_wildcards(),
            ),
        }) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status = rollback_dns_audit_setup(&mut backend, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(runtime_error(error));
        }
        lockdown.commit_no_restore();
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
            local_control_baseline,
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
        for failure in self._mediation.drain_worker_failures() {
            let _worker = failure.worker;
            self.record_critical(failure.code, failure.message);
            changed = true;
        }
        if self._mediation.recorder.take_report_write_failure() {
            self.record_critical(
                "dns_audit_evidence_write_failed",
                "DNS-mediated audit evidence could not be persisted after readiness",
            );
            changed = true;
        }
        if apply_attribution_results(&self._mediation, &mut self.findings) {
            changed = true;
        }
        let mut finding_received = false;
        match self.reader.next_event(finding_timeout) {
            Ok(Some(event)) => {
                record_connection_event(&self._mediation, &mut self.findings, event);
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
            let mut verification_succeeded = true;
            if self._mediation.routing.verify_active().is_err() {
                verification_succeeded = false;
                self.record_critical(
                    "dns_audit_routing_drift",
                    "DNS-mediated audit routing drifted after observation readiness",
                );
            }
            if self
                .backend
                .verify_owned_state(&self.expected_state)
                .is_err()
            {
                verification_succeeded = false;
                self.evidence.network_verification_status = "critical_drift";
                self.record_critical(
                    "dns_audit_network_drift",
                    "DNS-mediated audit owned nftables state drifted after observation readiness",
                );
            }
            if self.lockdown.verify_sudo_available().is_err() {
                verification_succeeded = false;
                self.evidence.sudo_status = "critical_drift";
                self.record_critical(
                    "dns_audit_sudo_drift",
                    "measured passwordless sudo availability drifted after observation readiness",
                );
            }
            if self.lockdown.verify_containers_available().is_err() {
                verification_succeeded = false;
                self.evidence.container_status = "critical_drift";
                self.record_critical(
                    "dns_audit_container_drift",
                    "measured container availability drifted after observation readiness",
                );
            }
            if let Err(error) =
                verify_resident_local_control(&self._mediation, &self.local_control_baseline)
            {
                verification_succeeded = false;
                self.record_critical(error.code, error.message);
            }
            if !self._mediation.workers_healthy() {
                verification_succeeded = false;
                self.record_critical(
                    "dns_audit_worker_unhealthy",
                    "required resident DNS worker health could not be verified after observation readiness",
                );
            }
            if self.runtime.verify_evidence_persistence(true).is_err() {
                verification_succeeded = false;
                self.record_critical(
                    "dns_audit_evidence_persistence_failed",
                    "resident audit evidence files could not be verified after observation readiness",
                );
            }
            if self._mediation.recorder.refresh_report().is_err() {
                verification_succeeded = false;
                self.record_critical(
                    "dns_audit_evidence_write_failed",
                    "DNS-mediated audit evidence could not be refreshed during resident verification",
                );
            }
            if verification_succeeded && self.evidence.critical_findings.is_empty() {
                self._mediation.mark_verification_successful();
                self.evidence.resident_health = self._mediation.resident_health();
                if self._mediation.recorder.refresh_report().is_err() {
                    self.record_critical(
                        "dns_audit_evidence_write_failed",
                        "DNS-mediated audit evidence could not persist the resident verification heartbeat",
                    );
                }
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
            if self.runtime.replace_report(&self.evidence).is_err() {
                self.record_critical(
                    "dns_audit_report_write_failed",
                    "resident audit report could not be persisted after readiness",
                );
                let _ = self.runtime.replace_report(&self.evidence);
            }
        }
        Ok(())
    }

    fn record_critical(&mut self, code: &'static str, message: &'static str) {
        self._mediation.mark_resident_critical();
        self.evidence.resident_health = self._mediation.resident_health();
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
    materialization_requests: Receiver<MaterializationRequest>,
    pending_materialization_request: Option<MaterializationRequest>,
    backend: NativeNftBackend<SystemNftExecutor>,
    lockdown: SystemLockdownControl,
    reader: NflogReader,
    runtime: R,
    base_allowances: Vec<EffectiveAllowance>,
    active: BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
    expected_state: OwnedNftState,
    local_control_baseline: LocalControlSnapshot,
    evidence: DnsMediatedBlockEvidence,
    findings: FindingCollection,
    scope: DnsBlockRuntimeScope,
    next_hostname_refresh: BTreeMap<String, Duration>,
    next_verification: Duration,
}

impl<R: RuntimeDocumentStore> DnsMediatedBlockSession<R> {
    fn establish(
        runtime: R,
        mut mediation: DnsMediationSession,
        materialization_requests: Receiver<MaterializationRequest>,
        plan: &PlanData,
        scope: DnsBlockRuntimeScope,
    ) -> Result<Self, DnsMediationError> {
        let hostname_policy = mediation.recorder.hostname_policy.clone();
        let prehydrated = match prehydrate_exact_hostnames(&hostname_policy) {
            Ok(materializations) => materializations,
            Err(error) => {
                let _ = mediation.routing.rollback();
                return Err(error.into_dns_error());
            }
        };
        let mut active = BTreeMap::new();
        let merge = merge_materializations(&mut active, prehydrated, Instant::now());
        if !merge.rules_changed || !active_covers_exact_hostname_policy(&active, &hostname_policy) {
            let _ = mediation.routing.rollback();
            return Err(DnsMediationError::new(
                "dns_block_prehydration_failed",
                "DNS-mediated block lifecycle did not materialize every required exact hostname",
            ));
        }
        let allowances =
            effective_allowances_with_materializations(&plan.runtime_static_policy, &active);
        if allowances.len() > MAX_EXPANDED_RULES {
            let _ = mediation.routing.rollback();
            return Err(DnsMediationError::new(
                "dns_block_prehydration_failed",
                "DNS-mediated policy exceeded the fixed effective-rule bound before activation",
            ));
        }
        let ruleset = render_dns_mediated_ruleset(Mode::Block, &allowances);
        let ruleset_hash = sha256_hex(ruleset.as_bytes());
        let expected_state = expected_dns_mediated_owned_state(Mode::Block, &allowances);
        let initial_health = mediation.resident_health();
        let mut evidence = initial_dns_block_evidence(
            plan,
            &active,
            false,
            ruleset_hash.clone(),
            scope,
            initial_health.clone(),
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
            resident_health: &initial_health,
        }) {
            let _ = mediation.routing.rollback();
            return Err(runtime_error(error));
        }
        if let Err(error) = runtime.replace_report(&evidence) {
            let _ = mediation.routing.rollback();
            return Err(runtime_error(error));
        }

        let executables = Arc::clone(&mediation.routing.executables);
        let mut backend = NativeNftBackend::new(SystemNftExecutor::host(Arc::clone(&executables)));
        let mut lockdown = SystemLockdownControl::new(executables);
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
            establish_local_control_baseline(&mediation, scope.lockdown_posture())
        })();
        let local_control_baseline = match setup_result {
            Ok(baseline) => baseline,
            Err(error) => {
                evidence.setup_status = "failed_pre_ready";
                evidence.rollback_status =
                    rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
                let _ = runtime.replace_report(&evidence);
                return Err(error);
            }
        };
        if let Some(failure) = mediation.drain_worker_failures().into_iter().next() {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(DnsMediationError::new(failure.code, failure.message));
        }
        if !mediation.workers_healthy() {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(DnsMediationError::new(
                "resident_worker_unhealthy",
                "required resident DNS workers were not healthy before readiness",
            ));
        }
        if let Err(error) = runtime.verify_evidence_persistence(false) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(runtime_error(error));
        }
        mediation.mark_verification_successful();
        evidence.resident_health = mediation.resident_health();
        if let Err(error) = mediation.recorder.refresh_report() {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(error);
        }
        if let Err(error) = verify_resident_local_control(&mediation, &local_control_baseline) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(local_control_error(error));
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
            resident_health: &evidence.resident_health,
            protection_available: scope.protection_available(),
            limitations: scope.limitations(
                plan.runtime_hostname_policy.allow_dynamic_githubapp_suffix,
                plan.runtime_hostname_policy.has_user_wildcards(),
            ),
        }) {
            evidence.setup_status = "failed_pre_ready";
            evidence.rollback_status =
                rollback_dns_block_setup(&mut backend, &mut lockdown, &mut mediation);
            let _ = runtime.replace_report(&evidence);
            return Err(runtime_error(error));
        }
        lockdown.commit_no_restore();
        evidence.setup_status = scope.resident_status();
        evidence.readiness_status = scope.ready_status();
        runtime.replace_report(&evidence).map_err(runtime_error)?;
        let next_hostname_refresh =
            hostname_refresh_schedule(&hostname_policy, &active, Duration::ZERO);
        Ok(Self {
            _mediation: mediation,
            materialization_requests,
            pending_materialization_request: None,
            backend,
            lockdown,
            reader,
            runtime,
            base_allowances: plan.runtime_static_policy.clone(),
            active,
            expected_state,
            local_control_baseline,
            evidence,
            findings: FindingCollection::empty(),
            scope,
            next_hostname_refresh,
            next_verification: RESIDENT_VERIFICATION_INTERVAL,
        })
    }

    fn poll_once(
        &mut self,
        elapsed: Duration,
        finding_timeout: Duration,
    ) -> Result<(), DnsMediationError> {
        let mut changed = false;
        for failure in self._mediation.drain_worker_failures() {
            let _worker = failure.worker;
            self.record_critical(failure.code, failure.message);
            changed = true;
        }
        if self._mediation.recorder.take_report_write_failure() {
            self.record_critical(
                "dns_block_evidence_write_failed",
                "DNS-mediated block evidence could not be persisted after readiness",
            );
            changed = true;
        }
        if apply_attribution_results(&self._mediation, &mut self.findings) {
            changed = true;
        }
        match self.reader.next_event(finding_timeout) {
            Ok(Some(event)) => {
                record_connection_event(&self._mediation, &mut self.findings, event);
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
        let mut refresh_materializations = BTreeSet::new();
        let due_hostname = self
            .next_hostname_refresh
            .iter()
            .find_map(|(hostname, due)| (*due <= elapsed).then(|| hostname.clone()));
        if let Some(hostname) = due_hostname {
            let entry = self
                ._mediation
                .recorder
                .hostname_policy
                .exact_entry(&hostname)
                .expect("refresh schedule contains only exact policy hostnames")
                .clone();
            match prehydrate_exact_hostname(&entry, &self._mediation.recorder.hostname_policy) {
                Ok(materializations) => {
                    let refresh_interval = hostname_refresh_interval(&entry, &materializations);
                    refresh_materializations.extend(materializations);
                    self.next_hostname_refresh
                        .insert(hostname, elapsed + refresh_interval);
                }
                Err(error) => {
                    if matches!(error, PrehydrationError::Transient(_)) {
                        self.evidence.hostname_refresh_warnings =
                            self.evidence.hostname_refresh_warnings.saturating_add(1);
                        self._mediation.recorder.record_hostname_refresh_warning();
                    }
                    self.next_hostname_refresh
                        .insert(hostname, elapsed + DNS_PROFILE_REFRESH_INTERVAL);
                    root_refresh_error = Some(error);
                }
            };
            changed = true;
        }

        let refresh_attempted = !refresh_materializations.is_empty();
        let requests = self.collect_materialization_requests();
        let batch_started = Instant::now();
        let mut authorizations = self
            ._mediation
            .recorder
            .cname_authorizations
            .lock()
            .expect("DNS CNAME authorization lock poisoned");
        let transaction_now = Instant::now();
        let (
            proposed_authorizations,
            materializations,
            accepted_requests,
            rejected_requests,
            materialization_capacity_rejected,
        ) = stage_materialization_transactions(
            &authorizations,
            &self._mediation.recorder.hostname_policy,
            refresh_materializations,
            requests,
            transaction_now,
        );
        let accepted_request_count = accepted_requests.len();
        let rejected_request_count = rejected_requests.len();
        let batch_has_work = !materializations.is_empty();
        let mut proposed = self.active.clone();
        let merge = merge_materializations(&mut proposed, materializations, transaction_now);
        let proposed_allowances =
            effective_allowances_with_materializations(&self.base_allowances, &proposed);
        let materialization_bound_exceeded =
            materialization_candidate_exceeds_bounds(&proposed, &proposed_allowances);
        let ruleset = render_dns_mediated_replacement_ruleset(Mode::Block, &proposed_allowances);
        let active_ruleset = render_dns_mediated_ruleset(Mode::Block, &proposed_allowances);
        let expected = expected_dns_mediated_owned_state(Mode::Block, &proposed_allowances);
        let transaction_requires_verification =
            materialization_candidate_requires_verification(accepted_request_count, &merge);
        let verification_succeeded = if materialization_bound_exceeded {
            false
        } else if merge.rules_changed {
            self.backend.preflight(&ruleset).is_ok()
                && self.backend.replace_owned_state(&ruleset).is_ok()
                && self.backend.verify_owned_state(&expected).is_ok()
        } else if transaction_requires_verification {
            self.backend.verify_owned_state(&expected).is_ok()
        } else {
            true
        };
        let update_succeeded = publish_verified_materialization_transaction(
            verification_succeeded,
            &mut authorizations,
            &mut self.active,
            proposed_authorizations,
            proposed,
        );
        if update_succeeded && transaction_requires_verification {
            self.expected_state = expected;
            self.evidence.ruleset_hash = sha256_hex(active_ruleset.as_bytes());
            self.evidence.network_verification_status = "verified";
        }
        drop(authorizations);

        if rejected_request_count > 0 {
            for _ in 0..rejected_request_count {
                self._mediation.recorder.record_materialization_rejection();
            }
            changed = true;
        }
        if materialization_capacity_rejected || materialization_bound_exceeded {
            self.evidence.materializations_truncated = true;
        }
        if !update_succeeded {
            for _ in 0..accepted_request_count {
                self._mediation.recorder.record_materialization_rejection();
            }
            if refresh_attempted {
                self.evidence.hostname_refresh_warnings =
                    self.evidence.hostname_refresh_warnings.saturating_add(1);
                self._mediation.recorder.record_hostname_refresh_warning();
            }
            if !materialization_bound_exceeded {
                self.evidence.network_verification_status = "critical_dynamic_update_failed";
                self.record_critical(
                    "dns_block_dynamic_update_failed",
                    "approved DNS-derived owned nftables replacement failed after readiness",
                );
            }
        }
        if batch_has_work {
            self._mediation
                .recorder
                .record_materialization_batch(batch_started.elapsed());
        }
        if update_succeeded {
            if merge.metadata_changed || merge.rules_changed {
                self.evidence.materialized_allowances = report_materializations(&self.active);
                self.evidence.expired_materializations = self
                    .evidence
                    .expired_materializations
                    .saturating_add(merge.expired);
            }
            complete_materialization_requests(
                accepted_requests,
                MaterializationCompletion::AppliedVerifiedAndCommitted,
            );
        } else {
            complete_materialization_requests(accepted_requests, MaterializationCompletion::Failed);
        }
        complete_materialization_requests(rejected_requests, MaterializationCompletion::Failed);
        if batch_has_work || merge.rules_changed || merge.metadata_changed {
            changed = true;
        }
        if let Some((code, message)) = root_refresh_critical_finding(
            root_refresh_error.as_ref(),
            &self.active,
            &self._mediation.recorder.hostname_policy,
        ) {
            self.evidence.network_verification_status = "critical_dynamic_update_failed";
            self.record_critical(code, message);
            changed = true;
        }

        if elapsed >= self.next_verification {
            let mut verification_succeeded = true;
            if self._mediation.routing.verify_active().is_err() {
                verification_succeeded = false;
                self.record_critical(
                    "dns_block_routing_drift",
                    "DNS-mediated direct-query routing drifted after readiness",
                );
            }
            if self
                .backend
                .verify_owned_state(&self.expected_state)
                .is_err()
            {
                verification_succeeded = false;
                self.evidence.network_verification_status = "critical_drift";
                self.record_critical(
                    "dns_block_network_drift",
                    "DNS-mediated owned nftables state drifted after readiness",
                );
            }
            if self.lockdown.verify_sudo_disabled().is_err() {
                verification_succeeded = false;
                self.evidence.sudo_status = "critical_drift";
                self.record_critical(
                    "dns_block_sudo_drift",
                    "measured passwordless sudo state drifted after readiness",
                );
            }
            match self.scope.lockdown_posture() {
                LockdownPosture::StandardBlock => {
                    if self.lockdown.verify_containers_disabled().is_err() {
                        verification_succeeded = false;
                        self.evidence.container_status = "critical_drift";
                        self.record_critical(
                            "dns_block_container_drift",
                            "measured container control state drifted after readiness",
                        );
                    }
                }
                LockdownPosture::UnsafePreserve => {
                    if self.lockdown.verify_containers_available().is_err() {
                        verification_succeeded = false;
                        self.evidence.container_status = "critical_drift";
                        self.record_critical(
                            "dns_block_container_drift",
                            "preserved container control path drifted after readiness",
                        );
                    }
                }
                LockdownPosture::Audit => unreachable!("block sessions cannot use audit posture"),
            }
            if let Err(error) =
                verify_resident_local_control(&self._mediation, &self.local_control_baseline)
            {
                verification_succeeded = false;
                self.record_critical(error.code, error.message);
            }
            if !self._mediation.workers_healthy() {
                verification_succeeded = false;
                self.record_critical(
                    "dns_block_worker_unhealthy",
                    "required resident DNS worker health could not be verified after readiness",
                );
            }
            if self.runtime.verify_evidence_persistence(true).is_err() {
                verification_succeeded = false;
                self.record_critical(
                    "dns_block_evidence_persistence_failed",
                    "resident block evidence files could not be verified after readiness",
                );
            }
            if self._mediation.recorder.refresh_report().is_err() {
                verification_succeeded = false;
                self.record_critical(
                    "dns_block_evidence_write_failed",
                    "DNS-mediated block evidence could not be refreshed during resident verification",
                );
            }
            if verification_succeeded && self.evidence.critical_findings.is_empty() {
                self._mediation.mark_verification_successful();
                self.evidence.resident_health = self._mediation.resident_health();
                if self._mediation.recorder.refresh_report().is_err() {
                    self.record_critical(
                        "dns_block_evidence_write_failed",
                        "DNS-mediated block evidence could not persist the resident verification heartbeat",
                    );
                }
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
            if self.runtime.replace_report(&self.evidence).is_err() {
                self.record_critical(
                    "dns_block_report_write_failed",
                    "resident block report could not be persisted after readiness",
                );
                let _ = self.runtime.replace_report(&self.evidence);
            }
        }
        Ok(())
    }

    fn collect_materialization_requests(&mut self) -> Vec<MaterializationRequest> {
        let mut requests = Vec::new();
        if let Some(request) = self.pending_materialization_request.take() {
            requests.push(request);
        }
        while requests.len() < MATERIALIZATION_REQUEST_QUEUE_CAPACITY {
            match self.materialization_requests.try_recv() {
                Ok(request) => requests.push(request),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }

        requests
    }

    fn wait_for_materialization_or_housekeeping(&mut self, timeout: Duration) {
        if self.pending_materialization_request.is_some() {
            return;
        }
        if let Ok(request) = self.materialization_requests.recv_timeout(timeout) {
            self.pending_materialization_request = Some(request);
        }
    }

    fn record_critical(&mut self, code: &'static str, message: &'static str) {
        self._mediation.mark_resident_critical();
        self.evidence.resident_health = self._mediation.resident_health();
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
    let executables = Arc::new(
        TrustedExecutableSet::capture_reviewed_hosted()
            .map_err(|error| DnsMediationError::new(error.code, error.message))?,
    );
    let runtime = ProductionRuntimeStore::open(config).map_err(runtime_error)?;
    validate_production_service_context(&runtime.invocation_id, &executables)
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    let normalized = parse_and_normalize(&runtime.read_config_bounded().map_err(runtime_error)?)
        .map_err(config_error)?;
    if normalized.invocation_id != runtime.invocation_id {
        return Err(DnsMediationError::new(
            "unsafe_runtime_config",
            "trusted launcher configuration invocation identifier must match its runtime directory",
        ));
    }
    let plan = build_activation_plan(normalized).map_err(config_error)?;
    if plan.platform_profile.id != GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID
        || plan
            .platform_profile
            .dns_mediated_compatibility
            .as_ref()
            .is_none_or(|profile| {
                !reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan(profile)
            })
    {
        return Err(DnsMediationError::new(
            "protected_run_policy_not_activated",
            "protected run accepts only reviewed block or audit modes with the hosted workflow-bootstrap profile",
        ));
    }
    let hostname_policy = plan.runtime_hostname_policy.clone();
    let mut fingerprint = SystemLockdownControl::new(Arc::clone(&executables));
    fingerprint
        .verify_supported_host()
        .map_err(lockdown_error)?;
    verify_pre_activation_local_control(&executables)?;

    match (plan.assurance_status, plan.container_policy) {
        (AssuranceStatus::AuditObservationOnly, None) => {
            let mediation = DnsMediationSession::establish(
                runtime.directory(),
                Arc::clone(&executables),
                DnsEvidenceScope::ProtectedHostAudit,
                hostname_policy.clone(),
                None,
            )?;
            let mut session = DnsMediatedAuditSession::establish(runtime, mediation, &plan)?;
            let start = Instant::now();
            loop {
                session.poll_once(start.elapsed(), RESIDENT_IDLE_INTERVAL)?;
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
            let (materialization_submitter, materialization_requests) =
                materialization_request_channel();
            let mediation = DnsMediationSession::establish(
                runtime.directory(),
                Arc::clone(&executables),
                scope.dns_scope(),
                hostname_policy.clone(),
                Some(materialization_submitter),
            )?;
            let mut session = DnsMediatedBlockSession::establish(
                runtime,
                mediation,
                materialization_requests,
                &plan,
                scope,
            )?;
            let start = Instant::now();
            loop {
                session.poll_once(start.elapsed(), Duration::ZERO)?;
                session.wait_for_materialization_or_housekeeping(RESIDENT_IDLE_INTERVAL);
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
    inject_worker_failure: bool,
) -> Result<(), DnsMediationError> {
    let executables = Arc::new(
        TrustedExecutableSet::capture_reviewed_hosted()
            .map_err(|error| DnsMediationError::new(error.code, error.message))?,
    );
    validate_test_service_context(unit_name, &executables)
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    if plan.selected_mode != Mode::Block
        || plan.assurance_status != AssuranceStatus::PlannedBlockContainment
        || plan.platform_profile.id != GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID
        || plan
            .platform_profile
            .dns_mediated_compatibility
            .as_ref()
            .is_none_or(|profile| {
                !reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan(profile)
            })
        || !plan.requested_policy.is_empty()
    {
        return Err(DnsMediationError::new(
            "invalid_selected_profile_runtime_policy",
            "DNS-mediated block evidence accepts only standard block with the reviewed hosted workflow-bootstrap profile and no user allowlist entries",
        ));
    }
    let mut fingerprint = SystemLockdownControl::new(Arc::clone(&executables));
    fingerprint
        .verify_supported_host()
        .map_err(lockdown_error)?;
    verify_pre_activation_local_control(&executables)?;
    let runtime =
        TestRuntimeStore::create(runtime_root, &plan.invocation_id).map_err(runtime_error)?;
    let (materialization_submitter, materialization_requests) = materialization_request_channel();
    let mediation = DnsMediationSession::establish(
        &runtime.directory,
        executables,
        DnsBlockRuntimeScope::TestEvidence.dns_scope(),
        plan.runtime_hostname_policy.clone(),
        Some(materialization_submitter),
    )?;
    let mut session = DnsMediatedBlockSession::establish(
        runtime,
        mediation,
        materialization_requests,
        plan,
        DnsBlockRuntimeScope::TestEvidence,
    )?;
    if inject_worker_failure {
        let failure = session._mediation.inject_test_worker_failure();
        session.record_critical(failure.code, failure.message);
        let _ = session.runtime.replace_report(&session.evidence);
    }
    let start = Instant::now();
    loop {
        session.poll_once(start.elapsed(), Duration::ZERO)?;
        session.wait_for_materialization_or_housekeeping(RESIDENT_IDLE_INTERVAL);
    }
}

fn initial_dns_block_evidence(
    plan: &PlanData,
    active: &BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
    materializations_truncated: bool,
    ruleset_hash: String,
    scope: DnsBlockRuntimeScope,
    resident_health: ResidentHealth,
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
        bootstrap_hostnames: plan.runtime_hostname_policy.platform_hostnames(),
        hostname_policy: plan.runtime_hostname_policy.clone(),
        setup_status: "setting_up",
        network_application_status: "not_applied",
        network_verification_status: "not_verified",
        sudo_status: "not_checked",
        container_status: "not_checked",
        readiness_status: "not_emitted",
        rollback_status: "not_required",
        ruleset_hash,
        dns_upstream_policy: "root_resident_mediator_only_udp_53",
        materialization_status: "bounded_ttl_exact_host_user_wildcard_and_cname_transport_policy",
        materialized_allowances: report_materializations(active),
        materializations_truncated,
        expired_materializations: 0,
        hostname_refresh_warnings: 0,
        counters: NetworkEvidenceCounters {
            total_violations: 0,
            sampled_violations: 0,
        },
        findings: Vec::new(),
        findings_truncated: false,
        critical_findings: Vec::new(),
        critical_findings_truncated: false,
        resident_health,
        protection_available: scope.protection_available(),
        limitations: scope.limitations(
            plan.runtime_hostname_policy.allow_dynamic_githubapp_suffix,
            plan.runtime_hostname_policy.has_user_wildcards(),
        ),
    }
}

fn initial_dns_audit_evidence(
    plan: &PlanData,
    ruleset_hash: String,
    resident_health: ResidentHealth,
) -> DnsMediatedAuditEvidence {
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
        resident_health,
        protection_available: false,
        limitations: protected_audit_limitations(plan.runtime_hostname_policy.has_user_wildcards()),
    }
}

fn githubapp_profile_limitations(allow_dynamic_githubapp_suffix: bool) -> Vec<&'static str> {
    if allow_dynamic_githubapp_suffix {
        vec![
            "bounded_githubapp_suffix_dns_authorization_remains_an_egress_limitation",
            "githubapp_suffix_authorizations_are_limited_to_8_unique_single_label_names",
        ]
    } else {
        vec!["dynamic_githubapp_suffix_authorization_disabled"]
    }
}

fn user_wildcard_limitations(has_user_wildcards: bool) -> Vec<&'static str> {
    if has_user_wildcards {
        vec![
            "bounded_user_wildcard_dns_authorization_remains_an_egress_limitation",
            "configured_user_wildcard_dns_names_and_transports_remain_egress_and_data_channels",
            "user_wildcard_authorizations_are_limited_to_8_unique_names_and_two_exact_prefix_label_shapes",
        ]
    } else {
        Vec::new()
    }
}

fn dns_block_test_limitations(allow_dynamic_githubapp_suffix: bool) -> Vec<&'static str> {
    let mut limitations = vec![
        "selected_profile_runtime_test_only_no_public_activation",
        "test_only_evidence_path_does_not_activate_default_planning_descriptor",
        "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
        "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
        "block_dns_queries_are_canonicalized_before_upstream_forwarding",
        "dns_query_timing_and_count_remain_egress_limitations",
        "post_ready_codeload_traffic_is_not_authorized",
        "runner_authorized_results_storage_accounts_remain_egress_channels",
        "static_results_storage_compatibility_account_remains_an_egress_channel",
        "results_storage_authorization_is_limited_to_four_runner_requested_accounts",
        "later_workflow_code_can_reach_authorized_results_storage_addresses",
        "cname_descendants_are_bounded_ttl_derived_authorizations",
        "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
        "required_bootstrap_roots_prehydrated_before_ready_with_fixed_max_ttl",
        "bootstrap_roots_refresh_every_5_seconds",
        "https_materialization_expiry_includes_30_second_refresh_overlap",
        "approved_workflow_bootstrap_https_destinations_remain_egress_channels",
        "resolved_workflow_bootstrap_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
        "dynamic_owned_table_replacement_resets_network_counters",
        "local_process_attribution_is_bounded_best_effort_and_not_telemetry",
        "process_arguments_full_paths_and_environment_are_not_retained",
        "socket_ownership_races_may_produce_ambiguous_or_missing_attribution",
    ];
    limitations.extend(githubapp_profile_limitations(
        allow_dynamic_githubapp_suffix,
    ));
    limitations
}

fn protected_audit_limitations(has_user_wildcards: bool) -> Vec<&'static str> {
    let mut limitations = vec![
        "audit_observation_only_no_containment_claim",
        "audit_installs_owned_non_blocking_nftables_observation_rules",
        "audit_routes_host_dns_directly_and_docker_dns_separately_through_local_root_resident_mediator",
        "audit_forwards_dns_while_simulating_name_authorization",
        "audit_preserves_passwordless_sudo_and_container_control",
        "later_workflow_code_retains_arbitrary_egress_in_audit_mode",
        "packet_prefixes_transiently_inspected_in_memory_not_serialized",
        "local_process_attribution_is_bounded_best_effort_and_not_telemetry",
        "process_arguments_full_paths_and_environment_are_not_retained",
        "socket_ownership_races_may_produce_ambiguous_or_missing_attribution",
        "remote_reporting_not_implemented",
    ];
    limitations.extend(user_wildcard_limitations(has_user_wildcards));
    limitations
}

fn protected_block_limitations(allow_dynamic_githubapp_suffix: bool) -> Vec<&'static str> {
    protected_block_shared_limitations(allow_dynamic_githubapp_suffix)
}

fn protected_degraded_block_limitations(allow_dynamic_githubapp_suffix: bool) -> Vec<&'static str> {
    let mut limitations = protected_block_shared_limitations(allow_dynamic_githubapp_suffix);
    limitations.extend([
        "container_control_preserved_invalidates_containment",
        "container_control_remains_available_to_later_workflow_code",
    ]);
    limitations
}

fn protected_block_shared_limitations(allow_dynamic_githubapp_suffix: bool) -> Vec<&'static str> {
    let mut limitations = vec![
        "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
        "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
        "block_dns_queries_are_canonicalized_before_upstream_forwarding",
        "dns_query_timing_and_count_remain_egress_limitations",
        "post_ready_codeload_traffic_is_not_authorized",
        "runner_authorized_results_storage_accounts_remain_egress_channels",
        "static_results_storage_compatibility_account_remains_an_egress_channel",
        "results_storage_authorization_is_limited_to_four_runner_requested_accounts",
        "later_workflow_code_can_reach_authorized_results_storage_addresses",
        "cname_descendants_are_bounded_ttl_derived_authorizations",
        "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
        "bootstrap_roots_refresh_every_5_seconds",
        "https_materialization_expiry_includes_30_second_refresh_overlap",
        "approved_workflow_bootstrap_https_destinations_remain_egress_channels",
        "resolved_workflow_bootstrap_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
        "dynamic_owned_table_replacement_resets_network_counters",
        "local_process_attribution_is_bounded_best_effort_and_not_telemetry",
        "process_arguments_full_paths_and_environment_are_not_retained",
        "socket_ownership_races_may_produce_ambiguous_or_missing_attribution",
    ];
    limitations.extend(githubapp_profile_limitations(
        allow_dynamic_githubapp_suffix,
    ));
    limitations
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

fn prehydrate_exact_hostnames(
    hostname_policy: &RuntimeHostnamePolicy,
) -> Result<Vec<PendingMaterialization>, PrehydrationError> {
    let deadline = Instant::now() + STARTUP_PREHYDRATION_TIMEOUT;
    let mut materializations = Vec::new();
    for entry in startup_prehydration_entries(hostname_policy) {
        let result = if is_optional_platform_hostname_entry(entry) {
            prehydrate_exact_hostname(entry, hostname_policy)
        } else {
            prehydrate_exact_hostname_for_startup(entry, hostname_policy, deadline)
        };
        match result {
            Ok(hostname_materializations) => materializations.extend(hostname_materializations),
            Err(PrehydrationError::Transient(_)) if is_optional_platform_hostname_entry(entry) => {}
            Err(error) => return Err(error),
        }
        if materializations.len() > MAX_ACTIVE_MATERIALIZATIONS {
            return Err(PrehydrationError::Fatal(DnsMediationError::new(
                "dns_block_prehydration_failed",
                "exact DNS-mediated hostnames exceeded the active materialization bound",
            )));
        }
    }
    Ok(materializations)
}

fn is_optional_platform_hostname_entry(entry: &ExactHostnamePolicy) -> bool {
    is_optional_github_hosted_workflow_bootstrap_hostname(&entry.hostname)
        && entry.origins.as_slice() == [HostnamePolicyOrigin::Platform]
}

fn startup_prehydration_entries(
    hostname_policy: &RuntimeHostnamePolicy,
) -> impl Iterator<Item = &ExactHostnamePolicy> {
    let required = hostname_policy
        .exact
        .iter()
        .filter(|entry| !is_optional_platform_hostname_entry(entry));
    let optional = hostname_policy
        .exact
        .iter()
        .filter(|entry| is_optional_platform_hostname_entry(entry));
    required.chain(optional)
}

fn prehydrate_exact_hostname_for_startup(
    entry: &ExactHostnamePolicy,
    hostname_policy: &RuntimeHostnamePolicy,
    deadline: Instant,
) -> Result<Vec<PendingMaterialization>, PrehydrationError> {
    prehydrate_exact_hostname_for_startup_with_query(
        entry,
        hostname_policy,
        deadline,
        query_fixed_upstream_for_prehydration_with_timeout,
    )
}

fn prehydrate_exact_hostname_for_startup_with_query<F>(
    entry: &ExactHostnamePolicy,
    hostname_policy: &RuntimeHostnamePolicy,
    deadline: Instant,
    mut query: F,
) -> Result<Vec<PendingMaterialization>, PrehydrationError>
where
    F: FnMut(&str, u16, Duration) -> Result<Vec<u8>, PrehydrationQueryError>,
{
    let mut last_transient = None;
    for _ in 0..STARTUP_PREHYDRATION_MAX_ATTEMPTS {
        if Instant::now() >= deadline {
            break;
        }
        let result =
            prehydrate_exact_hostname_with_query(entry, hostname_policy, |hostname, query_type| {
                let timeout = deadline
                    .saturating_duration_since(Instant::now())
                    .min(DNS_FORWARD_TIMEOUT);
                if timeout.is_zero() {
                    Err(PrehydrationQueryError::Transient)
                } else {
                    query(hostname, query_type, timeout)
                }
            });
        match result {
            Ok(materializations) => return Ok(materializations),
            Err(PrehydrationError::Fatal(error)) => {
                return Err(PrehydrationError::Fatal(error));
            }
            Err(PrehydrationError::Transient(error)) => last_transient = Some(error),
        }
    }
    Err(PrehydrationError::Transient(last_transient.unwrap_or_else(
        || {
            DnsMediationError::new(
                "dns_block_prehydration_failed",
                "fixed DNS-mediated bootstrap prehydration exceeded its startup deadline",
            )
        },
    )))
}

fn prehydrate_exact_hostname(
    entry: &ExactHostnamePolicy,
    hostname_policy: &RuntimeHostnamePolicy,
) -> Result<Vec<PendingMaterialization>, PrehydrationError> {
    prehydrate_exact_hostname_with_query(
        entry,
        hostname_policy,
        query_fixed_upstream_for_prehydration,
    )
}

fn prehydrate_exact_hostname_with_query<F>(
    entry: &ExactHostnamePolicy,
    hostname_policy: &RuntimeHostnamePolicy,
    mut query: F,
) -> Result<Vec<PendingMaterialization>, PrehydrationError>
where
    F: FnMut(&str, u16) -> Result<Vec<u8>, PrehydrationQueryError>,
{
    let hostname = &entry.hostname;
    let materializations = materializations_from_bootstrap_query_results(
        hostname,
        Instant::now(),
        hostname_policy,
        [1_u16, 28_u16]
            .into_iter()
            .map(|query_type| (query_type, query(hostname, query_type))),
    )?;
    if materializations.len() > MAX_MATERIALIZATIONS_PER_UPDATE {
        return Err(PrehydrationError::Fatal(DnsMediationError::new(
            "dns_block_prehydration_failed",
            "one exact hostname exceeded the fixed per-update materialization bound",
        )));
    }
    Ok(materializations)
}

fn hostname_refresh_schedule(
    hostname_policy: &RuntimeHostnamePolicy,
    active: &BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
    elapsed: Duration,
) -> BTreeMap<String, Duration> {
    hostname_policy
        .exact
        .iter()
        .map(|entry| {
            (
                entry.hostname.clone(),
                elapsed + hostname_refresh_interval_from_active(entry, active),
            )
        })
        .collect()
}

fn hostname_refresh_interval(
    entry: &ExactHostnamePolicy,
    materializations: &[PendingMaterialization],
) -> Duration {
    if entry.origins.contains(&HostnamePolicyOrigin::Platform) {
        return DNS_PROFILE_REFRESH_INTERVAL;
    }
    let minimum_ttl = materializations
        .iter()
        .map(|materialization| materialization.ttl_seconds)
        .min()
        .unwrap_or(1);
    user_hostname_refresh_interval(minimum_ttl)
}

fn hostname_refresh_interval_from_active(
    entry: &ExactHostnamePolicy,
    active: &BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
) -> Duration {
    if entry.origins.contains(&HostnamePolicyOrigin::Platform) {
        return DNS_PROFILE_REFRESH_INTERVAL;
    }
    let minimum_ttl = active
        .values()
        .filter(|materialization| materialization.source_hostname == entry.hostname)
        .map(|materialization| materialization.observed_ttl_seconds)
        .min()
        .unwrap_or(1);
    user_hostname_refresh_interval(minimum_ttl)
}

fn user_hostname_refresh_interval(ttl_seconds: u32) -> Duration {
    let half_ttl = u64::from(ttl_seconds).div_ceil(2).max(1);
    Duration::from_secs(half_ttl).min(MAX_USER_HOSTNAME_REFRESH_INTERVAL)
}

fn materializations_from_bootstrap_query_results(
    hostname: &str,
    now: Instant,
    hostname_policy: &RuntimeHostnamePolicy,
    results: impl IntoIterator<Item = (u16, Result<Vec<u8>, PrehydrationQueryError>)>,
) -> Result<Vec<PendingMaterialization>, PrehydrationError> {
    let mut materializations = Vec::new();
    let mut transient_failures = 0_u8;
    for (query_type, result) in results {
        match result {
            Ok(response) => materializations.extend(
                pending_materializations_from_bootstrap_response(
                    hostname,
                    query_type,
                    &response,
                    now,
                    hostname_policy,
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
        return Err(PrehydrationError::Transient(error));
    }
    Ok(materializations)
}

fn root_refresh_critical_finding(
    error: Option<&PrehydrationError>,
    active: &BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
    hostname_policy: &RuntimeHostnamePolicy,
) -> Option<(&'static str, &'static str)> {
    match error {
        Some(PrehydrationError::Fatal(_)) => Some((
            "dns_block_root_refresh_integrity_failed",
            "DNS-mediated exact-root refresh received invalid bootstrap DNS evidence after readiness",
        )),
        Some(PrehydrationError::Transient(_))
            if !active_covers_exact_hostname_policy(active, hostname_policy) =>
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
    query_fixed_upstream_for_prehydration_with_timeout(hostname, query_type, DNS_FORWARD_TIMEOUT)
}

fn query_fixed_upstream_for_prehydration_with_timeout(
    hostname: &str,
    query_type: u16,
    timeout: Duration,
) -> Result<Vec<u8>, PrehydrationQueryError> {
    let timeout = timeout.min(DNS_FORWARD_TIMEOUT);
    if timeout.is_zero() {
        return Err(PrehydrationQueryError::Transient);
    }
    let query = canonical_dns_query(hostname, query_type, 0x0100).ok_or_else(|| {
        PrehydrationQueryError::Fatal(DnsMediationError::new(
            "dns_block_prehydration_failed",
            "failed to build a fixed DNS-mediated bootstrap query",
        ))
    })?;
    let upstream = UdpSocket::bind("0.0.0.0:0").map_err(|_| PrehydrationQueryError::Transient)?;
    upstream
        .set_read_timeout(Some(timeout))
        .map_err(|_| PrehydrationQueryError::Transient)?;
    upstream
        .set_write_timeout(Some(timeout))
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
    if !response_matches_upstream_query(&response, &query) {
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
    hostname_policy: &RuntimeHostnamePolicy,
) -> Result<Vec<PendingMaterialization>, DnsMediationError> {
    let records =
        parse_complete_dns_response(packet, queried_hostname, query_type).ok_or_else(|| {
            DnsMediationError::new(
                "dns_block_prehydration_failed",
                "fixed upstream DNS response did not match the bootstrap query",
            )
        })?;
    let authorizations = CnameAuthorizationState::default();
    let response = validate_dns_response_lineage(
        queried_hostname,
        &records,
        &authorizations,
        now,
        hostname_policy,
    )
    .map_err(|_| {
        DnsMediationError::new(
            "dns_block_prehydration_failed",
            "a fixed DNS-mediated bootstrap response had invalid response-local lineage",
        )
    })?;
    let mut materializations = response.materializations;
    materializations.sort();
    materializations.dedup();
    if materializations
        .iter()
        .map(|materialization| materialization.address)
        .collect::<BTreeSet<_>>()
        .len()
        > MAX_RETAINED_ADDRESSES_PER_OBSERVATION
    {
        return Err(DnsMediationError::new(
            "dns_block_prehydration_failed",
            "a fixed DNS-mediated bootstrap hostname exceeded the address bound",
        ));
    }
    Ok(materializations)
}

fn materialization_request_channel() -> (MaterializationSubmitter, Receiver<MaterializationRequest>)
{
    let (requests, receiver) = mpsc::sync_channel(MATERIALIZATION_REQUEST_QUEUE_CAPACITY);
    (MaterializationSubmitter { requests }, receiver)
}

fn submit_materialization_request(
    submitter: &MaterializationSubmitter,
    queried_hostname: String,
    mut response: ValidatedDnsResponse,
    shutdown: &AtomicBool,
) -> Result<MaterializationCompletion, ()> {
    response.materializations = coalesce_pending_materializations(response.materializations)
        .into_iter()
        .collect();
    let materialization_count = response.materializations.len();
    if materialization_count == 0 || materialization_count > MAX_MATERIALIZATIONS_PER_UPDATE {
        return Err(());
    }
    let (completion, result) = mpsc::sync_channel(1);
    let request = MaterializationRequest {
        queried_hostname,
        response,
        completion,
    };
    match submitter.requests.try_send(request) {
        Ok(()) => loop {
            match result.recv_timeout(Duration::from_millis(250)) {
                Ok(completion) => break Ok(completion),
                Err(mpsc::RecvTimeoutError::Timeout) if !shutdown.load(Ordering::Relaxed) => {}
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(());
                }
            }
        },
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => Err(()),
    }
}

fn stage_materialization_transactions(
    current_authorizations: &CnameAuthorizationState,
    hostname_policy: &RuntimeHostnamePolicy,
    initial: BTreeSet<PendingMaterialization>,
    requests: Vec<MaterializationRequest>,
    now: Instant,
) -> (
    CnameAuthorizationState,
    BTreeSet<PendingMaterialization>,
    Vec<MaterializationRequest>,
    Vec<MaterializationRequest>,
    bool,
) {
    let mut authorizations = current_authorizations.clone();
    let mut materializations = coalesce_pending_materializations(initial);
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut materialization_capacity_rejected = false;
    for request in requests {
        let mut proposed_authorizations = authorizations.clone();
        if !commit_staged_dns_response(
            &mut proposed_authorizations,
            &request.queried_hostname,
            request.response.clone(),
            now,
            hostname_policy,
        ) {
            authorizations.truncated |= proposed_authorizations.truncated;
            rejected.push(request);
            continue;
        }
        let combined = coalesce_pending_materializations(
            materializations
                .iter()
                .cloned()
                .chain(request.response.materializations.iter().cloned()),
        );
        if combined.len() > MAX_MATERIALIZATIONS_PER_UPDATE {
            materialization_capacity_rejected = true;
            rejected.push(request);
        } else {
            authorizations = proposed_authorizations;
            materializations = combined;
            accepted.push(request);
        }
    }
    (
        authorizations,
        materializations,
        accepted,
        rejected,
        materialization_capacity_rejected,
    )
}

fn materialization_candidate_exceeds_bounds(
    active: &BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
    effective_allowances: &[EffectiveAllowance],
) -> bool {
    active.len() > MAX_ACTIVE_MATERIALIZATIONS || effective_allowances.len() > MAX_EXPANDED_RULES
}

fn materialization_candidate_requires_verification(
    accepted_request_count: usize,
    merge: &MaterializationMerge,
) -> bool {
    accepted_request_count > 0 || merge.rules_changed || merge.metadata_changed
}

fn publish_verified_materialization_transaction(
    verification_succeeded: bool,
    authorizations: &mut CnameAuthorizationState,
    active: &mut BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
    proposed_authorizations: CnameAuthorizationState,
    proposed_active: BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
) -> bool {
    if !verification_succeeded {
        return false;
    }
    *active = proposed_active;
    *authorizations = proposed_authorizations;
    true
}

fn coalesce_pending_materializations(
    materializations: impl IntoIterator<Item = PendingMaterialization>,
) -> BTreeSet<PendingMaterialization> {
    let mut coalesced = BTreeMap::<PendingMaterializationIdentity, PendingMaterialization>::new();
    for materialization in materializations {
        let identity = (
            materialization.source_hostname.clone(),
            materialization.hostname.clone(),
            materialization.address,
            materialization.protocol,
            materialization.port,
            materialization.origins.clone(),
        );
        match coalesced.entry(identity) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(materialization);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let minimum_ttl = entry.get().ttl_seconds.min(materialization.ttl_seconds);
                let minimum_expiry = entry.get().expires_at.min(materialization.expires_at);
                entry.get_mut().ttl_seconds = minimum_ttl;
                entry.get_mut().expires_at = minimum_expiry;
            }
        }
    }
    coalesced.into_values().collect()
}

fn merge_materializations(
    active: &mut BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
    materializations: impl IntoIterator<Item = PendingMaterialization>,
    now: Instant,
) -> MaterializationMerge {
    let rules_before = active
        .values()
        .map(|materialization| {
            (
                materialization.address,
                materialization.protocol,
                materialization.port,
            )
        })
        .collect::<BTreeSet<_>>();
    let expired = active
        .extract_if(.., |_, materialization| materialization.expires_at <= now)
        .count() as u64;
    let mut metadata_changed = expired > 0;
    for materialization in coalesce_pending_materializations(materializations) {
        let expires_at = materialization.expires_at + DNS_MATERIALIZATION_REFRESH_OVERLAP;
        if expires_at <= now {
            continue;
        }
        let key = (
            materialization.source_hostname.clone(),
            materialization.hostname.clone(),
            materialization.address,
            materialization.protocol,
            materialization.port,
        );
        let replacement = ActiveMaterialization {
            source_hostname: materialization.source_hostname,
            hostname: materialization.hostname,
            address: materialization.address,
            protocol: materialization.protocol,
            port: materialization.port,
            origins: materialization.origins,
            observed_ttl_seconds: materialization.ttl_seconds,
            expires_at,
        };
        metadata_changed |= active.get(&key).is_none_or(|current| {
            current.observed_ttl_seconds != replacement.observed_ttl_seconds
                || current.expires_at != replacement.expires_at
        });
        active.insert(key, replacement);
    }
    let rules_after = active
        .values()
        .map(|materialization| {
            (
                materialization.address,
                materialization.protocol,
                materialization.port,
            )
        })
        .collect::<BTreeSet<_>>();
    MaterializationMerge {
        rules_changed: rules_before != rules_after,
        metadata_changed,
        expired,
    }
}

fn complete_materialization_requests(
    requests: impl IntoIterator<Item = MaterializationRequest>,
    completion: MaterializationCompletion,
) {
    for request in requests {
        let _ = request.completion.try_send(completion);
    }
}

fn effective_allowances_with_materializations(
    base_allowances: &[EffectiveAllowance],
    active: &BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
) -> Vec<EffectiveAllowance> {
    base_allowances
        .iter()
        .cloned()
        .chain(active.values().map(|materialization| EffectiveAllowance {
            destination_type: DestinationType::Ip,
            destination: materialization.address.to_string(),
            protocol: materialization.protocol,
            port: materialization.port,
        }))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn report_materializations(
    active: &BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
) -> Vec<DnsMaterializedAllowance> {
    let now = Instant::now();
    active
        .values()
        .map(|materialization| DnsMaterializedAllowance {
            source_hostname: materialization.source_hostname.clone(),
            hostname: materialization.hostname.clone(),
            address: materialization.address.to_string(),
            protocol: materialization.protocol,
            port: materialization.port,
            origins: materialization.origins.clone(),
            observed_ttl_seconds: materialization.observed_ttl_seconds,
            expires_in_seconds: materialization
                .expires_at
                .saturating_duration_since(now)
                .as_secs(),
        })
        .collect()
}

fn active_covers_exact_hostname_policy(
    active: &BTreeMap<ActiveMaterializationKey, ActiveMaterialization>,
    hostname_policy: &RuntimeHostnamePolicy,
) -> bool {
    let covered = active
        .values()
        .map(|materialization| {
            (
                materialization.source_hostname.as_str(),
                HostnameTransport {
                    protocol: materialization.protocol,
                    port: materialization.port,
                },
            )
        })
        .collect::<BTreeSet<_>>();
    hostname_policy.exact.iter().all(|entry| {
        if is_optional_platform_hostname_entry(entry) {
            return true;
        }
        entry
            .transports
            .iter()
            .all(|transport| covered.contains(&(entry.hostname.as_str(), *transport)))
    })
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
    stop: Arc<AtomicBool>,
) -> Result<DnsProxyRuntime, DnsMediationError> {
    let mut listeners = Vec::new();
    for (address, listener_kind, udp_worker, tcp_worker) in [
        (
            HOST_DNS_BIND,
            DnsListenerKind::Host,
            "host_udp_dns",
            "host_tcp_dns",
        ),
        (
            DOCKER_DNS_BIND,
            DnsListenerKind::Docker,
            "docker_udp_dns",
            "docker_tcp_dns",
        ),
    ] {
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
        udp.set_read_timeout(Some(Duration::from_millis(250)))
            .map_err(|_| {
                DnsMediationError::new(
                    "dns_proxy_bind_failed",
                    "failed to configure a fixed local DNS proxy listener",
                )
            })?;
        tcp.set_nonblocking(true).map_err(|_| {
            DnsMediationError::new(
                "dns_proxy_bind_failed",
                "failed to configure a fixed local DNS proxy stream listener",
            )
        })?;
        listeners.push((listener_kind, udp_worker, udp, tcp_worker, tcp));
    }

    let (events, receiver) = mpsc::sync_channel(RESIDENT_EVENT_CHANNEL_CAPACITY);
    let (attribution, attribution_worker) =
        attribution_channel().map_err(|error| DnsMediationError::new(error.code, error.message))?;
    let mut threads = Vec::new();
    for (listener_kind, udp_worker, udp, tcp_worker, tcp) in listeners {
        let udp_recorder = recorder.clone();
        let udp_thread =
            spawn_supervised_worker(udp_worker, Arc::clone(&stop), events.clone(), move |stop| {
                serve_udp(udp, listener_kind, udp_recorder, stop)
            });
        match udp_thread {
            Ok(thread) => threads.push(thread),
            Err(error) => {
                shutdown_dns_workers(&stop, &mut threads);
                return Err(error);
            }
        }
        let tcp_recorder = recorder.clone();
        let tcp_thread =
            spawn_supervised_worker(tcp_worker, Arc::clone(&stop), events.clone(), move |stop| {
                serve_tcp(tcp, listener_kind, tcp_recorder, stop)
            });
        match tcp_thread {
            Ok(thread) => threads.push(thread),
            Err(error) => {
                shutdown_dns_workers(&stop, &mut threads);
                return Err(error);
            }
        }
    }
    match spawn_supervised_worker(
        ATTRIBUTION_WORKER_NAME,
        Arc::clone(&stop),
        events.clone(),
        move |stop| {
            attribution_worker
                .run(stop)
                .map_err(|error| DnsMediationError::new(error.code, error.message))
        },
    ) {
        Ok(thread) => threads.push(thread),
        Err(error) => {
            shutdown_dns_workers(&stop, &mut threads);
            return Err(error);
        }
    }
    drop(events);
    Ok(DnsProxyRuntime {
        threads,
        supervisor: ResidentWorkerSupervisor::new(receiver),
        attribution,
    })
}

fn spawn_supervised_worker<F>(
    name: &'static str,
    stop: Arc<AtomicBool>,
    events: SyncSender<ResidentWorkerEvent>,
    worker: F,
) -> Result<JoinHandle<()>, DnsMediationError>
where
    F: FnOnce(&AtomicBool) -> Result<(), DnsMediationError> + Send + 'static,
{
    thread::Builder::new()
        .name(format!("fence-{name}"))
        .spawn(move || {
            if events.send(ResidentWorkerEvent::Started(name)).is_err() {
                return;
            }
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker(&stop)));
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let event = match outcome {
                Ok(Ok(())) => ResidentWorkerEvent::Fatal {
                    worker: name,
                    code: "resident_worker_exited",
                    message: "required resident worker exited unexpectedly",
                },
                Ok(Err(error)) => ResidentWorkerEvent::Fatal {
                    worker: name,
                    code: error.code,
                    message: "required resident worker encountered a fatal failure",
                },
                Err(_) => ResidentWorkerEvent::Fatal {
                    worker: name,
                    code: "resident_worker_panicked",
                    message: "required resident worker panicked",
                },
            };
            let _ = events.send(event);
        })
        .map_err(|_| {
            DnsMediationError::new(
                "resident_worker_spawn_failed",
                "failed to start a required resident worker",
            )
        })
}

fn shutdown_dns_workers(stop: &AtomicBool, threads: &mut Vec<JoinHandle<()>>) {
    stop.store(true, Ordering::Relaxed);
    for thread in threads.drain(..) {
        let _ = thread.join();
    }
}

fn serve_udp(
    socket: UdpSocket,
    listener_kind: DnsListenerKind,
    recorder: ObservationRecorder,
    stop: &AtomicBool,
) -> Result<(), DnsMediationError> {
    let listener = socket.local_addr().map_err(|_| {
        DnsMediationError::new(
            "dns_udp_listener_failed",
            "resident UDP DNS listener address could not be verified",
        )
    })?;
    let mut query = [0_u8; MAX_DNS_PACKET_BYTES];
    while !stop.load(Ordering::Relaxed) {
        let (length, peer) = match socket.recv_from(&mut query) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => {
                return Err(DnsMediationError::new(
                    "dns_udp_listener_failed",
                    "resident UDP DNS listener failed",
                ));
            }
        };
        let bytes = &query[..length];
        let parsed_question = parse_dns_question(bytes);
        let client = DnsQueryClient {
            listener_kind,
            socket: DnsClientSocket {
                protocol: SocketProtocol::Udp,
                peer,
                listener,
            },
        };
        let (upstream_query, response_classification) =
            match query_for_upstream(&recorder, bytes, parsed_question.as_ref(), Some(client))? {
                DnsQueryDispatch::Forward(query, classification_override) => {
                    if let Some((hostname, query_type)) = &parsed_question {
                        recorder.record_query(hostname, *query_type, true, classification_override);
                    }
                    (query, classification_override)
                }
                DnsQueryDispatch::Refused(classification_override) => {
                    record_rejected_query(
                        &recorder,
                        parsed_question.as_ref(),
                        classification_override,
                    );
                    if let Some(response) = refused_response(bytes) {
                        let _ = socket.send_to(&response, peer);
                    }
                    continue;
                }
                DnsQueryDispatch::RetryableFailure(classification_override) => {
                    record_rejected_query(
                        &recorder,
                        parsed_question.as_ref(),
                        classification_override,
                    );
                    send_udp_retryable_failure(&socket, bytes, peer);
                    continue;
                }
            };
        let Ok(upstream) = UdpSocket::bind("0.0.0.0:0") else {
            recorder.record_upstream_request_failure();
            send_udp_retryable_failure(&socket, bytes, peer);
            continue;
        };
        let _ = upstream.set_read_timeout(Some(DNS_FORWARD_TIMEOUT));
        let _ = upstream.set_write_timeout(Some(DNS_FORWARD_TIMEOUT));
        if upstream.connect(UPSTREAM_DNS).is_err() || upstream.send(&upstream_query).is_err() {
            recorder.record_upstream_request_failure();
            send_udp_retryable_failure(&socket, bytes, peer);
            continue;
        }
        let mut response = [0_u8; MAX_DNS_PACKET_BYTES];
        let Ok(response_length) = upstream.recv(&mut response) else {
            recorder.record_upstream_request_failure();
            send_udp_retryable_failure(&socket, bytes, peer);
            continue;
        };
        let response = &mut response[..response_length];
        if !response_matches_upstream_query(response, &upstream_query) {
            recorder.record_upstream_request_failure();
            send_udp_retryable_failure(&socket, bytes, peer);
            continue;
        }
        restore_client_query_id(response, bytes);
        let disposition = parsed_question
            .as_ref()
            .map(|(hostname, query_type)| {
                recorder.record_response(hostname, *query_type, response, response_classification)
            })
            .unwrap_or(DnsResponseDisposition::ForwardOriginal);
        let Some(output) = dns_response_for_disposition(bytes, response, disposition) else {
            continue;
        };
        let _ = socket.send_to(&output, peer);
    }
    Ok(())
}

fn send_udp_retryable_failure(socket: &UdpSocket, query: &[u8], peer: std::net::SocketAddr) {
    if let Some(response) = server_failure_response(query) {
        let _ = socket.send_to(&response, peer);
    }
}

fn serve_tcp(
    listener: TcpListener,
    listener_kind: DnsListenerKind,
    recorder: ObservationRecorder,
    stop: &AtomicBool,
) -> Result<(), DnsMediationError> {
    while !stop.load(Ordering::Relaxed) {
        let (mut client, peer) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(DnsMediationError::new(
                    "dns_tcp_listener_failed",
                    "resident TCP DNS listener failed",
                ));
            }
        };
        if set_dns_tcp_deadlines(&client).is_err() {
            continue;
        }
        let Ok(local) = client.local_addr() else {
            continue;
        };
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
        let query_client = DnsQueryClient {
            listener_kind,
            socket: DnsClientSocket {
                protocol: SocketProtocol::Tcp,
                peer,
                listener: local,
            },
        };
        let (upstream_query, response_classification) = match query_for_upstream(
            &recorder,
            &query,
            parsed_question.as_ref(),
            Some(query_client),
        )? {
            DnsQueryDispatch::Forward(query, classification_override) => {
                if let Some((hostname, query_type)) = &parsed_question {
                    recorder.record_query(hostname, *query_type, true, classification_override);
                }
                (query, classification_override)
            }
            DnsQueryDispatch::Refused(classification_override) => {
                record_rejected_query(&recorder, parsed_question.as_ref(), classification_override);
                if let Some(response) = refused_response(&query) {
                    let _ = client.write_all(&(response.len() as u16).to_be_bytes());
                    let _ = client.write_all(&response);
                }
                continue;
            }
            DnsQueryDispatch::RetryableFailure(classification_override) => {
                record_rejected_query(&recorder, parsed_question.as_ref(), classification_override);
                write_tcp_retryable_failure(&mut client, &query);
                continue;
            }
        };
        let Ok(mut upstream) = connect_upstream_tcp() else {
            recorder.record_upstream_request_failure();
            write_tcp_retryable_failure(&mut client, &query);
            continue;
        };
        if upstream
            .write_all(&(upstream_query.len() as u16).to_be_bytes())
            .is_err()
            || upstream.write_all(&upstream_query).is_err()
        {
            recorder.record_upstream_request_failure();
            write_tcp_retryable_failure(&mut client, &query);
            continue;
        }
        let mut response_length = [0_u8; 2];
        if upstream.read_exact(&mut response_length).is_err() {
            recorder.record_upstream_request_failure();
            write_tcp_retryable_failure(&mut client, &query);
            continue;
        }
        let size = usize::from(u16::from_be_bytes(response_length));
        if size == 0 || size > MAX_DNS_PACKET_BYTES {
            recorder.record_upstream_request_failure();
            write_tcp_retryable_failure(&mut client, &query);
            continue;
        }
        let mut response = vec![0_u8; size];
        if upstream.read_exact(&mut response).is_err() {
            recorder.record_upstream_request_failure();
            write_tcp_retryable_failure(&mut client, &query);
            continue;
        }
        if !response_matches_upstream_query(&response, &upstream_query) {
            recorder.record_upstream_request_failure();
            write_tcp_retryable_failure(&mut client, &query);
            continue;
        }
        restore_client_query_id(&mut response, &query);
        let disposition = parsed_question
            .as_ref()
            .map(|(hostname, query_type)| {
                recorder.record_response(hostname, *query_type, &response, response_classification)
            })
            .unwrap_or(DnsResponseDisposition::ForwardOriginal);
        let Some(output) = dns_response_for_disposition(&query, &response, disposition) else {
            continue;
        };
        let Ok(output_length) = u16::try_from(output.len()) else {
            continue;
        };
        let _ = client.write_all(&output_length.to_be_bytes());
        let _ = client.write_all(&output);
    }
    Ok(())
}

fn write_tcp_retryable_failure(client: &mut TcpStream, query: &[u8]) {
    let Some(response) = server_failure_response(query) else {
        return;
    };
    let Ok(length) = u16::try_from(response.len()) else {
        return;
    };
    let _ = client.write_all(&length.to_be_bytes());
    let _ = client.write_all(&response);
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

fn parse_complete_dns_response(
    packet: &[u8],
    queried_hostname: &str,
    query_type: u16,
) -> Option<DnsAnswerRecords> {
    if packet.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    if flags & 0x8000 == 0
        || flags & 0x0200 != 0
        || question_count != 1
        || parse_dns_question(packet) != Some((queried_hostname.to_owned(), query_type))
    {
        return None;
    }

    let question_name_end = skip_dns_name(packet, 12)?;
    if question_name_end + 4 > packet.len()
        || u16::from_be_bytes([packet[question_name_end], packet[question_name_end + 1]])
            != query_type
        || u16::from_be_bytes([packet[question_name_end + 2], packet[question_name_end + 3]]) != 1
    {
        return None;
    }

    let answer_count = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
    let record_count = answer_count
        .checked_add(usize::from(u16::from_be_bytes([packet[8], packet[9]])))
        .and_then(|count| {
            count.checked_add(usize::from(u16::from_be_bytes([packet[10], packet[11]])))
        });
    let record_count = record_count?;
    let mut records = DnsAnswerRecords::default();
    let mut offset = question_name_end + 4;
    for record_index in 0..record_count {
        let owner_offset = offset;
        let owner_end = skip_dns_name(packet, owner_offset)?;
        if owner_end + 10 > packet.len() {
            return None;
        }
        let record_type = u16::from_be_bytes([packet[owner_end], packet[owner_end + 1]]);
        let record_class = u16::from_be_bytes([packet[owner_end + 2], packet[owner_end + 3]]);
        let ttl_seconds = u32::from_be_bytes([
            packet[owner_end + 4],
            packet[owner_end + 5],
            packet[owner_end + 6],
            packet[owner_end + 7],
        ]);
        let data_length = usize::from(u16::from_be_bytes([
            packet[owner_end + 8],
            packet[owner_end + 9],
        ]));
        let data_offset = owner_end + 10;
        let data_end = data_offset.checked_add(data_length)?;
        if data_end > packet.len() {
            return None;
        }

        let owner_is_root = packet.get(owner_offset) == Some(&0);
        let owner = if owner_is_root {
            None
        } else {
            Some(parse_dns_name(packet, owner_offset)?)
        };
        if record_class == 1 {
            match record_type {
                1 | 28 if record_type != query_type => {
                    return None;
                }
                1 if data_length != 4 || owner_is_root || record_index >= answer_count => {
                    return None;
                }
                28 if data_length != 16 || owner_is_root || record_index >= answer_count => {
                    return None;
                }
                5 if owner_is_root
                    || record_index >= answer_count
                    || skip_dns_name(packet, data_offset) != Some(data_end)
                    || parse_dns_name(packet, data_offset).is_none() =>
                {
                    return None;
                }
                1 => records.addresses.push(DnsAddressAnswer {
                    hostname: owner.expect("A owner checked above"),
                    address: IpAddr::V4(Ipv4Addr::new(
                        packet[data_offset],
                        packet[data_offset + 1],
                        packet[data_offset + 2],
                        packet[data_offset + 3],
                    )),
                    ttl_seconds,
                }),
                28 => {
                    let mut bytes = [0_u8; 16];
                    bytes.copy_from_slice(&packet[data_offset..data_end]);
                    records.addresses.push(DnsAddressAnswer {
                        hostname: owner.expect("AAAA owner checked above"),
                        address: IpAddr::V6(Ipv6Addr::from(bytes)),
                        ttl_seconds,
                    });
                }
                5 => records.aliases.push(DnsCnameAnswer {
                    owner: owner.expect("CNAME owner checked above"),
                    target: parse_dns_name(packet, data_offset)
                        .expect("CNAME target checked above"),
                    ttl_seconds,
                }),
                _ => {}
            }
        }
        offset = data_end;
    }
    (offset == packet.len()).then_some(records)
}

fn query_for_upstream(
    recorder: &ObservationRecorder,
    query: &[u8],
    parsed_question: Option<&(String, u16)>,
    client: Option<DnsQueryClient>,
) -> Result<DnsQueryDispatch, DnsMediationError> {
    match (recorder.scope, parsed_question) {
        (DnsEvidenceScope::ProtectedHostAudit, Some((hostname, query_type))) => recorder
            .forward_query(hostname, *query_type, client)
            .map(|authorization| match authorization {
                DnsQueryAuthorization::Forward(classification) => {
                    DnsQueryDispatch::Forward(query.to_vec(), classification)
                }
                DnsQueryAuthorization::Refused(classification)
                | DnsQueryAuthorization::RetryableFailure(classification) => {
                    DnsQueryDispatch::Forward(query.to_vec(), classification)
                }
            }),
        (DnsEvidenceScope::ProtectedHostAudit, None) => {
            Ok(DnsQueryDispatch::Forward(query.to_vec(), None))
        }
        (
            DnsEvidenceScope::SelectedProfileRuntimeTest
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded,
            Some((hostname, query_type)),
        ) => {
            let Some(canonical) = canonical_block_query(hostname, *query_type, query) else {
                return Ok(DnsQueryDispatch::Refused(None));
            };
            recorder
                .forward_query(hostname, *query_type, client)
                .map(|authorization| match authorization {
                    DnsQueryAuthorization::Forward(classification) => {
                        DnsQueryDispatch::Forward(canonical, classification)
                    }
                    DnsQueryAuthorization::Refused(classification) => {
                        DnsQueryDispatch::Refused(classification)
                    }
                    DnsQueryAuthorization::RetryableFailure(classification) => {
                        DnsQueryDispatch::RetryableFailure(classification)
                    }
                })
        }
        (
            DnsEvidenceScope::SelectedProfileRuntimeTest
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded,
            None,
        ) => Ok(DnsQueryDispatch::Refused(None)),
    }
}

fn record_rejected_query(
    recorder: &ObservationRecorder,
    parsed_question: Option<&(String, u16)>,
    classification_override: Option<&'static str>,
) {
    if let Some((hostname, query_type)) = parsed_question {
        recorder.record_query(hostname, *query_type, false, classification_override);
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

fn dns_response_for_disposition(
    query: &[u8],
    response: &[u8],
    disposition: DnsResponseDisposition,
) -> Option<Vec<u8>> {
    match disposition {
        DnsResponseDisposition::ForwardOriginal => Some(response.to_vec()),
        DnsResponseDisposition::RetryableFailure => server_failure_response(query),
    }
}

fn server_failure_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
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
    let question_end = offset.checked_add(4)?;
    if question_end > query.len() {
        return None;
    }
    let mut response = query[..question_end].to_vec();
    let flags = u16::from_be_bytes([response[2], response[3]]);
    response[2..4].copy_from_slice(&(0x8000 | (flags & 0x7900) | 0x0002).to_be_bytes());
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
    let mut bounded_ttl = ttl_seconds.clamp(1, MAX_DYNAMIC_TTL_SECONDS);
    if let Some(remaining) = authorization_remaining {
        let remaining_seconds = u32::try_from(remaining.as_secs()).unwrap_or(u32::MAX);
        if remaining_seconds == 0 {
            return None;
        }
        bounded_ttl = bounded_ttl.min(remaining_seconds);
    }
    Some(bounded_ttl)
}

fn platform_transport_policy() -> (Vec<HostnamePolicyOrigin>, Vec<HostnameTransport>) {
    (
        vec![HostnamePolicyOrigin::Platform],
        vec![HostnameTransport {
            protocol: Protocol::Tcp,
            port: 443,
        }],
    )
}

fn direct_hostname_policy(
    hostname: &str,
    state: &CnameAuthorizationState,
    hostname_policy: &RuntimeHostnamePolicy,
) -> Option<(Vec<HostnamePolicyOrigin>, Vec<HostnameTransport>)> {
    let mut origins = BTreeSet::new();
    let mut transports = BTreeSet::new();
    if let Some(entry) = hostname_policy.exact_entry(hostname) {
        origins.extend(entry.origins.iter().copied());
        transports.extend(entry.transports.iter().copied());
    }
    if state.bounded_actions_suffix.contains(hostname)
        || state.bounded_githubapp_suffix.contains(hostname)
        || state.runner_authorized_results_storage.contains(hostname)
    {
        let (platform_origins, platform_transports) = platform_transport_policy();
        origins.extend(platform_origins);
        transports.extend(platform_transports);
    }
    if state.bounded_user_wildcard.contains(hostname) {
        let wildcard_transports = hostname_policy.user_wildcard_transports(hostname);
        if !wildcard_transports.is_empty() {
            origins.insert(HostnamePolicyOrigin::User);
            transports.extend(wildcard_transports);
        }
    }
    (!origins.is_empty() && !transports.is_empty()).then(|| {
        (
            origins.into_iter().collect(),
            transports.into_iter().collect(),
        )
    })
}

fn hostname_policy_for_authorized_name(
    hostname: &str,
    state: &CnameAuthorizationState,
    hostname_policy: &RuntimeHostnamePolicy,
) -> Option<(Vec<HostnamePolicyOrigin>, Vec<HostnameTransport>)> {
    if let Some(policy) = direct_hostname_policy(hostname, state, hostname_policy) {
        return Some(policy);
    }
    cname_policy_for_authorized_name(hostname, state, hostname_policy)
}

fn cname_policy_for_authorized_name(
    hostname: &str,
    state: &CnameAuthorizationState,
    _hostname_policy: &RuntimeHostnamePolicy,
) -> Option<(Vec<HostnamePolicyOrigin>, Vec<HostnameTransport>)> {
    state.active.get(hostname).map(|authorization| {
        (
            authorization.origins.clone(),
            authorization.transports.clone(),
        )
    })
}

fn user_wildcard_capacity_rejected(
    hostname: &str,
    state: &CnameAuthorizationState,
    hostname_policy: &RuntimeHostnamePolicy,
) -> bool {
    cname_policy_for_authorized_name(hostname, state, hostname_policy).is_none()
        && !state.bounded_user_wildcard.contains(hostname)
        && !hostname_policy
            .user_wildcard_transports(hostname)
            .is_empty()
        && state.bounded_user_wildcard.len() >= MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS
}

fn admit_user_wildcard_hostname(
    hostname: &str,
    state: &mut CnameAuthorizationState,
    hostname_policy: &RuntimeHostnamePolicy,
) {
    if cname_policy_for_authorized_name(hostname, state, hostname_policy).is_some()
        || state.bounded_user_wildcard.contains(hostname)
        || hostname_policy
            .user_wildcard_transports(hostname)
            .is_empty()
    {
        return;
    }
    if state.bounded_user_wildcard.len() >= MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS {
        state.bounded_user_wildcard_truncated = true;
        return;
    }
    state.bounded_user_wildcard.insert(hostname.to_owned());
}

fn authorized_hostname(
    hostname: &str,
    state: &mut CnameAuthorizationState,
    now: Instant,
    hostname_policy: &RuntimeHostnamePolicy,
    provenance: DnsQueryProvenance,
) -> bool {
    remove_expired_cname_authorizations(state, now);
    if requires_runner_results_storage_provenance(hostname, state, hostname_policy)
        && provenance != DnsQueryProvenance::TrustedRunnerWorker
    {
        return false;
    }
    if cname_policy_for_authorized_name(hostname, state, hostname_policy).is_some() {
        return true;
    }
    admit_user_wildcard_hostname(hostname, state, hostname_policy);
    if matches_results_storage_hostname(hostname) && hostname_policy.exact_entry(hostname).is_none()
    {
        if !state.runner_authorized_results_storage.contains(hostname)
            && state.runner_authorized_results_storage.len() >= MAX_RESULTS_STORAGE_AUTHORIZATIONS
        {
            state.runner_authorized_results_storage_truncated = true;
        } else {
            state
                .runner_authorized_results_storage
                .insert(hostname.to_owned());
        }
        return hostname_policy_for_authorized_name(hostname, state, hostname_policy).is_some();
    }
    if matches_constrained_dynamic_githubapp_suffix_hostname(hostname, hostname_policy) {
        if !state.bounded_githubapp_suffix.contains(hostname)
            && state.bounded_githubapp_suffix.len() >= MAX_DYNAMIC_GITHUBAPP_SUFFIX_AUTHORIZATIONS
        {
            state.bounded_githubapp_suffix_truncated = true;
        } else {
            state.bounded_githubapp_suffix.insert(hostname.to_owned());
        }
        return hostname_policy_for_authorized_name(hostname, state, hostname_policy).is_some();
    }
    if matches_constrained_dynamic_actions_suffix_hostname(hostname, hostname_policy) {
        if !state.bounded_actions_suffix.contains(hostname)
            && state.bounded_actions_suffix.len() >= MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS
        {
            state.bounded_actions_suffix_truncated = true;
        } else {
            state.bounded_actions_suffix.insert(hostname.to_owned());
        }
    }
    hostname_policy_for_authorized_name(hostname, state, hostname_policy).is_some()
}

fn validate_dns_response_lineage(
    queried_hostname: &str,
    records: &DnsAnswerRecords,
    state: &CnameAuthorizationState,
    now: Instant,
    hostname_policy: &RuntimeHostnamePolicy,
) -> Result<ValidatedDnsResponse, DnsResponseValidationError> {
    let policy = hostname_policy_for_authorized_name(queried_hostname, state, hostname_policy)
        .ok_or(DnsResponseValidationError::Invalid)?;
    let requires_runner_provenance =
        requires_runner_results_storage_provenance(queried_hostname, state, hostname_policy);
    let mut forbidden = BTreeSet::from([queried_hostname.to_owned()]);
    let mut depth = 0_u8;
    let mut lineage_expiry: Option<Instant> = None;
    let mut root_authorization = None;
    if direct_hostname_policy(queried_hostname, state, hostname_policy).is_none() {
        let authorization = state
            .active
            .get(queried_hostname)
            .ok_or(DnsResponseValidationError::Invalid)?;
        depth = authorization.depth;
        lineage_expiry = Some(authorization.expires_at);
        if authorization
            .expires_at
            .saturating_duration_since(now)
            .is_zero()
        {
            return Err(DnsResponseValidationError::Invalid);
        }
        root_authorization = Some(authorization.clone());
    }

    let mut edges = BTreeMap::<String, DnsCnameAnswer>::new();
    let retains_lineage = !records.addresses.is_empty();
    for alias in &records.aliases {
        if alias.owner == alias.target {
            return Err(DnsResponseValidationError::Invalid);
        }
        match edges.entry(alias.owner.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(alias.clone());
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if entry.get().target != alias.target {
                    return Err(DnsResponseValidationError::Invalid);
                }
                let ttl_seconds = entry.get().ttl_seconds.min(alias.ttl_seconds);
                entry.get_mut().ttl_seconds = ttl_seconds;
            }
        }
    }

    let mut current = queried_hostname.to_owned();
    let mut new_authorization_names = BTreeSet::new();
    let mut authorizations = Vec::new();
    while let Some(alias) = edges.remove(&current) {
        depth = depth
            .checked_add(1)
            .filter(|value| *value <= MAX_DERIVED_CNAME_DEPTH)
            .ok_or(DnsResponseValidationError::Invalid)?;
        if !forbidden.insert(alias.target.clone()) {
            return Err(DnsResponseValidationError::Invalid);
        }
        let edge_expiry = now
            + Duration::from_secs(u64::from(
                alias.ttl_seconds.clamp(1, MAX_DYNAMIC_TTL_SECONDS),
            ));
        lineage_expiry =
            Some(lineage_expiry.map_or(edge_expiry, |existing| existing.min(edge_expiry)));
        let expiry = lineage_expiry.ok_or(DnsResponseValidationError::Invalid)?;
        let observed_ttl_seconds = u32::try_from(expiry.saturating_duration_since(now).as_secs())
            .ok()
            .filter(|ttl| *ttl > 0)
            .ok_or(DnsResponseValidationError::Invalid)?;
        if retains_lineage
            && !state.active.contains_key(&alias.target)
            && new_authorization_names.insert(alias.target.clone())
            && state
                .active
                .len()
                .saturating_add(new_authorization_names.len())
                > MAX_DERIVED_CNAME_AUTHORIZATIONS
        {
            return Err(DnsResponseValidationError::Capacity);
        }
        if retains_lineage {
            authorizations.push((
                alias.target.clone(),
                ActiveCnameAuthorization {
                    source_hostname: current,
                    origins: policy.0.clone(),
                    transports: policy.1.clone(),
                    requires_runner_provenance,
                    observed_ttl_seconds,
                    depth,
                    expires_at: expiry,
                },
            ));
        }
        current = alias.target;
    }
    if !edges.is_empty() {
        return Err(DnsResponseValidationError::Invalid);
    }

    // A resolver can return a fully rooted CNAME chain without an address for
    // the requested family. Validate the complete chain and treat it as NODATA,
    // retain none of it because no terminal address proved a materializable
    // response-local lineage.
    if records.addresses.is_empty() {
        return Ok(ValidatedDnsResponse {
            authorizations: Vec::new(),
            materializations: Vec::new(),
            policy,
            requires_runner_provenance,
            root_authorization,
            valid_until: None,
        });
    }

    let mut materializations = Vec::new();
    let mut response_expiry = lineage_expiry;
    for answer in &records.addresses {
        if answer.hostname != current {
            return Err(DnsResponseValidationError::Invalid);
        }
        let remaining = lineage_expiry.map(|expiry| expiry.saturating_duration_since(now));
        let ttl_seconds = bound_materialization_ttl(answer.ttl_seconds, remaining)
            .ok_or(DnsResponseValidationError::Invalid)?;
        let address_expiry = now + Duration::from_secs(u64::from(ttl_seconds));
        response_expiry =
            Some(response_expiry.map_or(address_expiry, |existing| existing.min(address_expiry)));
        materializations.extend(policy.1.iter().map(|transport| PendingMaterialization {
            source_hostname: queried_hostname.to_owned(),
            hostname: answer.hostname.clone(),
            address: answer.address,
            protocol: transport.protocol,
            port: transport.port,
            origins: policy.0.clone(),
            ttl_seconds,
            expires_at: address_expiry,
        }));
    }
    if let Some(expiry) = response_expiry {
        let observed_ttl_seconds = u32::try_from(expiry.saturating_duration_since(now).as_secs())
            .ok()
            .filter(|ttl| *ttl > 0)
            .ok_or(DnsResponseValidationError::Invalid)?;
        for (_, authorization) in &mut authorizations {
            authorization.expires_at = authorization.expires_at.min(expiry);
            authorization.observed_ttl_seconds =
                authorization.observed_ttl_seconds.min(observed_ttl_seconds);
        }
    }
    let materializations = coalesce_pending_materializations(materializations)
        .into_iter()
        .collect::<Vec<_>>();
    if materializations.len() > MAX_MATERIALIZATIONS_PER_UPDATE {
        return Err(DnsResponseValidationError::Capacity);
    }
    Ok(ValidatedDnsResponse {
        authorizations,
        materializations,
        policy,
        requires_runner_provenance,
        root_authorization,
        valid_until: response_expiry,
    })
}

fn commit_staged_dns_response(
    state: &mut CnameAuthorizationState,
    queried_hostname: &str,
    response: ValidatedDnsResponse,
    now: Instant,
    hostname_policy: &RuntimeHostnamePolicy,
) -> bool {
    remove_expired_cname_authorizations(state, now);
    let root_is_unchanged = match response.root_authorization.as_ref() {
        Some(expected) => {
            direct_hostname_policy(queried_hostname, state, hostname_policy).is_none()
                && state.active.get(queried_hostname) == Some(expected)
        }
        None => direct_hostname_policy(queried_hostname, state, hostname_policy).is_some(),
    };
    if !root_is_unchanged
        || response
            .valid_until
            .is_some_and(|valid_until| valid_until <= now)
        || hostname_policy_for_authorized_name(queried_hostname, state, hostname_policy)
            != Some(response.policy.clone())
        || requires_runner_results_storage_provenance(queried_hostname, state, hostname_policy)
            != response.requires_runner_provenance
    {
        return false;
    }
    let new_authorizations = response
        .authorizations
        .iter()
        .map(|(hostname, _)| hostname)
        .filter(|hostname| !state.active.contains_key(*hostname))
        .collect::<BTreeSet<_>>()
        .len();
    if state.active.len().saturating_add(new_authorizations) > MAX_DERIVED_CNAME_AUTHORIZATIONS {
        state.truncated = true;
        return false;
    }
    commit_dns_response_authorizations(state, response)
}

fn commit_dns_response_authorizations(
    state: &mut CnameAuthorizationState,
    response: ValidatedDnsResponse,
) -> bool {
    if response
        .authorizations
        .iter()
        .any(|(hostname, authorization)| {
            state.active.get(hostname).is_some_and(|existing| {
                existing.origins != authorization.origins
                    || existing.transports != authorization.transports
                    || existing.requires_runner_provenance
                        != authorization.requires_runner_provenance
            })
        })
    {
        return false;
    }
    for (hostname, authorization) in response.authorizations {
        // A different validated parent can converge on an already authorized
        // name with the same effective policy. Keep the existing lineage and
        // expiry so the new response cannot refresh or reparent that grant.
        if state.active.get(&hostname).is_some_and(|existing| {
            existing.source_hostname != authorization.source_hostname
                || existing.depth != authorization.depth
        }) {
            continue;
        }
        state.active.insert(hostname, authorization);
    }
    true
}

fn requires_runner_results_storage_provenance(
    hostname: &str,
    state: &CnameAuthorizationState,
    hostname_policy: &RuntimeHostnamePolicy,
) -> bool {
    if hostname == GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_TRUSTED_RESULTS_STORAGE_HOSTNAME
        && matches_exact_platform_hostname(hostname, hostname_policy)
    {
        return false;
    }
    if matches_results_storage_hostname(hostname)
        || state.runner_authorized_results_storage.contains(hostname)
    {
        return true;
    }
    state
        .active
        .get(hostname)
        .is_some_and(|authorization| authorization.requires_runner_provenance)
}

fn matches_results_storage_hostname(hostname: &str) -> bool {
    let Some(account) = hostname
        .strip_prefix("productionresultssa")
        .and_then(|value| value.strip_suffix(".blob.core.windows.net"))
    else {
        return false;
    };
    !account.is_empty() && account.len() <= 5 && account.bytes().all(|byte| byte.is_ascii_digit())
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

#[cfg(test)]
fn matches_selected_profile_pattern(
    hostname: &str,
    hostname_policy: &RuntimeHostnamePolicy,
) -> bool {
    matches_actions_suffix_hostname(hostname)
        || matches_constrained_dynamic_githubapp_suffix_hostname(hostname, hostname_policy)
        || hostname_policy
            .exact_entry(hostname)
            .is_some_and(|entry| entry.origins.contains(&HostnamePolicyOrigin::Platform))
        || hostname == "actions-results-receiver-production.githubapp.com"
}

fn matches_exact_platform_hostname(
    hostname: &str,
    hostname_policy: &RuntimeHostnamePolicy,
) -> bool {
    hostname_policy
        .exact_entry(hostname)
        .is_some_and(|entry| entry.origins.contains(&HostnamePolicyOrigin::Platform))
}

#[cfg(test)]
fn matches_actions_suffix_hostname(hostname: &str) -> bool {
    hostname.ends_with(".actions.githubusercontent.com")
        && hostname != "actions.githubusercontent.com"
}

fn matches_constrained_dynamic_actions_suffix_hostname(
    hostname: &str,
    hostname_policy: &RuntimeHostnamePolicy,
) -> bool {
    let Some(prefix) = hostname.strip_suffix(".actions.githubusercontent.com") else {
        return false;
    };
    let labels: Vec<&str> = prefix.split('.').collect();
    !matches_exact_platform_hostname(hostname, hostname_policy)
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

fn matches_constrained_dynamic_githubapp_suffix_hostname(
    hostname: &str,
    hostname_policy: &RuntimeHostnamePolicy,
) -> bool {
    if !hostname_policy.allow_dynamic_githubapp_suffix {
        return false;
    }
    let Some(prefix) = hostname.strip_suffix(".githubapp.com") else {
        return false;
    };
    let labels: Vec<&str> = prefix.split('.').collect();
    !matches_exact_platform_hostname(hostname, hostname_policy)
        && !labels.is_empty()
        && labels.len() <= MAX_DYNAMIC_GITHUBAPP_SUFFIX_PREFIX_LABELS
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

fn policy_classification(
    hostname: &str,
    authorizations: &CnameAuthorizationState,
    hostname_policy: &RuntimeHostnamePolicy,
) -> &'static str {
    if let Some((origins, _)) = direct_hostname_policy(hostname, authorizations, hostname_policy) {
        let wildcard = authorizations.bounded_user_wildcard.contains(hostname);
        return match (
            origins.contains(&HostnamePolicyOrigin::Platform),
            origins.contains(&HostnamePolicyOrigin::User),
        ) {
            (true, true) => "platform_and_user_allowlist",
            (true, false) => {
                if authorizations.bounded_actions_suffix.contains(hostname)
                    || authorizations.bounded_githubapp_suffix.contains(hostname)
                {
                    "dynamic_platform"
                } else if authorizations
                    .runner_authorized_results_storage
                    .contains(hostname)
                {
                    "runner_authorized_results_storage"
                } else {
                    "platform_profile"
                }
            }
            (false, true) => {
                if wildcard {
                    "user_wildcard_allowlist"
                } else {
                    "user_allowlist"
                }
            }
            (false, false) => "outside_policy",
        };
    }
    if let Some(authorization) = authorizations.active.get(hostname) {
        if authorization.requires_runner_provenance {
            return "runner_authorized_results_storage_cname_derived";
        }
        return if authorization.origins.contains(&HostnamePolicyOrigin::User) {
            "user_cname_derived"
        } else {
            "platform_cname_derived"
        };
    }
    "outside_policy"
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
    let config = parse_and_normalize(
        br#"{"schema_version":1,"mode":"block","invocation_id":"evidence","allowlist":[]}"#,
    )
    .expect("test hostname policy must parse");
    let hostname_policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
    evidence_from_state_and_authorizations(
        state,
        routing_status,
        scope,
        &CnameAuthorizationState::default(),
        &hostname_policy,
        &initial_resident_health(),
    )
}

fn evidence_from_state_and_authorizations(
    state: &ObservationState,
    routing_status: &'static str,
    scope: DnsEvidenceScope,
    cname_authorizations: &CnameAuthorizationState,
    hostname_policy: &RuntimeHostnamePolicy,
    resident_health: &ResidentHealth,
) -> DnsMediationEvidence {
    DnsMediationEvidence {
        runtime_evidence_schema_version: RUNTIME_EVIDENCE_SCHEMA_VERSION,
        status: scope.status(),
        profile_realization_id: scope.profile_realization_id(),
        platform_profile_id: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
        authorized_domain_patterns: authorized_domain_patterns(hostname_policy),
        bootstrap_hostnames: hostname_policy.platform_hostnames(),
        hostname_policy: hostname_policy.clone(),
        mode: scope.mode(),
        protection_available: scope == DnsEvidenceScope::ProtectedHostBlock,
        resident_health: resident_health.clone(),
        routing_status,
        host_dns_routing: match scope {
            DnsEvidenceScope::ProtectedHostAudit
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                "direct_client_to_root_resident_mediator"
            }
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
            DnsEvidenceScope::ProtectedHostAudit => {
                "audit_forwards_while_simulating_name_authorization"
            }
            DnsEvidenceScope::SelectedProfileRuntimeTest
            | DnsEvidenceScope::ProtectedHostBlock
            | DnsEvidenceScope::ProtectedHostBlockDegraded => {
                "block_forwards_exact_roots_bounded_user_wildcard_names_actions_suffix_names_githubapp_suffix_names_results_storage_and_bounded_cname_descendants"
            }
        },
        observations: state
            .retained
            .iter()
            .map(
                |((hostname, query_type, classification), observation)| DnsObservation {
                    hostname: hostname.clone(),
                    query_type: query_type_name(*query_type),
                    policy_classification: classification,
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
        bounded_githubapp_suffix_authorizations: cname_authorizations
            .bounded_githubapp_suffix
            .iter()
            .cloned()
            .collect(),
        bounded_githubapp_suffix_authorizations_truncated: cname_authorizations
            .bounded_githubapp_suffix_truncated,
        bounded_user_wildcard_authorizations: cname_authorizations
            .bounded_user_wildcard
            .iter()
            .cloned()
            .collect(),
        bounded_user_wildcard_authorizations_truncated: cname_authorizations
            .bounded_user_wildcard_truncated,
        user_wildcard_request_rejections: state.user_wildcard_request_rejections,
        runner_authorized_results_storage: cname_authorizations
            .runner_authorized_results_storage
            .iter()
            .map(|hostname| DnsResultsStorageAuthorization {
                hostname: hostname.clone(),
                authorization_origin: "pinned_runner_worker_dns",
            })
            .collect(),
        runner_authorized_results_storage_truncated: cname_authorizations
            .runner_authorized_results_storage_truncated,
        results_storage_authorization_count: state.results_storage_authorization_count,
        results_storage_attribution_failures: state.results_storage_attribution_failures,
        results_storage_request_rejections: state.results_storage_request_rejections,
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
        excluded_unretained_query_count: state.excluded_unretained_query_count,
        blocked_non_profile_query_count: state.blocked_non_profile_query_count,
        materialization_batch_count: state.materialization_batch_count,
        materialization_request_rejections: state.materialization_request_rejections,
        materialization_update_max_milliseconds: state.materialization_update_max_milliseconds,
        hostname_refresh_warnings: state.hostname_refresh_warnings,
        upstream_request_failures: state.upstream_request_failures,
        limitations: match scope {
            DnsEvidenceScope::ProtectedHostAudit => {
                protected_dns_audit_limitations(hostname_policy.has_user_wildcards())
            }
            DnsEvidenceScope::SelectedProfileRuntimeTest => vec![
                "selected_profile_runtime_test_only_no_public_activation",
                "test_only_evidence_path_does_not_activate_default_planning_descriptor",
                "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
                "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
                "bounded_githubapp_suffix_dns_authorization_remains_an_egress_limitation",
                "githubapp_suffix_authorizations_are_limited_to_8_unique_single_label_names",
                "block_dns_queries_are_canonicalized_before_upstream_forwarding",
                "dns_query_timing_and_count_remain_egress_limitations",
                "post_ready_codeload_traffic_is_not_authorized",
                "runner_authorized_results_storage_accounts_remain_egress_channels",
                "static_results_storage_compatibility_account_remains_an_egress_channel",
                "results_storage_authorization_is_limited_to_four_runner_requested_accounts",
                "cname_descendants_are_bounded_ttl_derived_authorizations",
                "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
                "required_bootstrap_roots_prehydrated_before_ready_with_fixed_max_ttl",
                "bootstrap_roots_refresh_every_5_seconds",
                "https_materialization_expiry_includes_30_second_refresh_overlap",
                "dns_answers_materialize_only_bounded_profile_or_cname_descendant_https_addresses",
                "approved_workflow_bootstrap_https_destinations_remain_egress_channels",
                "resolved_workflow_bootstrap_ip_addresses_may_serve_additional_destinations",
                "root_resident_dns_upstream_channel_remains_an_egress_limitation",
            ],
            DnsEvidenceScope::ProtectedHostBlock => protected_dns_scope_limitations(
                false,
                hostname_policy.allow_dynamic_githubapp_suffix,
                hostname_policy.has_user_wildcards(),
            ),
            DnsEvidenceScope::ProtectedHostBlockDegraded => protected_dns_scope_limitations(
                true,
                hostname_policy.allow_dynamic_githubapp_suffix,
                hostname_policy.has_user_wildcards(),
            ),
        },
    }
}

fn protected_dns_scope_limitations(
    degraded: bool,
    allow_dynamic_githubapp_suffix: bool,
    has_user_wildcards: bool,
) -> Vec<&'static str> {
    let mut limitations = vec![
        "bounded_actions_suffix_dns_authorization_remains_an_egress_limitation",
        "actions_suffix_authorizations_are_limited_to_8_unique_names_and_two_prefix_labels",
        "block_dns_queries_are_canonicalized_before_upstream_forwarding",
        "dns_query_timing_and_count_remain_egress_limitations",
        "post_ready_codeload_traffic_is_not_authorized",
        "runner_authorized_results_storage_accounts_remain_egress_channels",
        "static_results_storage_compatibility_account_remains_an_egress_channel",
        "results_storage_authorization_is_limited_to_four_runner_requested_accounts",
        "later_workflow_code_can_reach_authorized_results_storage_addresses",
        "cname_descendants_are_bounded_ttl_derived_authorizations",
        "dns_cname_descendants_may_delegate_to_external_dns_operator_names",
        "required_bootstrap_roots_prehydrated_before_ready_with_fixed_max_ttl",
        "bootstrap_roots_refresh_every_5_seconds",
        "https_materialization_expiry_includes_30_second_refresh_overlap",
        "dns_answers_materialize_only_bounded_workflow_bootstrap_or_cname_descendant_https_addresses",
        "approved_workflow_bootstrap_https_destinations_remain_egress_channels",
        "resolved_workflow_bootstrap_ip_addresses_may_serve_additional_destinations",
        "root_resident_dns_upstream_channel_remains_an_egress_limitation",
    ];
    limitations.extend(githubapp_profile_limitations(
        allow_dynamic_githubapp_suffix,
    ));
    limitations.extend(user_wildcard_limitations(has_user_wildcards));
    if degraded {
        limitations.push("container_control_preserved_invalidates_containment");
    }
    limitations
}

fn protected_dns_audit_limitations(has_user_wildcards: bool) -> Vec<&'static str> {
    let mut limitations = vec![
        "audit_observation_only_no_containment_claim",
        "audit_routes_host_dns_directly_and_docker_dns_separately_through_local_root_resident_mediator",
        "audit_forwards_dns_while_simulating_name_authorization",
        "dns_query_timing_and_count_remain_egress_limitations",
        "dns_answers_attribute_addresses_without_authorizing_firewall_rules",
        "audit_preserves_passwordless_sudo_and_container_control",
        "later_workflow_code_retains_arbitrary_egress_in_audit_mode",
    ];
    limitations.extend(user_wildcard_limitations(has_user_wildcards));
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

fn verify_docker_dns_route() -> Result<(), DnsMediationError> {
    let Some(bytes) = read_optional_external_file(Path::new(DOCKER_DAEMON_PATH))? else {
        return Err(DnsMediationError::new(
            "dns_routing_verification_failed",
            "Docker DNS routing configuration is unavailable",
        ));
    };
    let document = serde_json::from_slice::<Value>(&bytes).map_err(|_| {
        DnsMediationError::new(
            "dns_routing_verification_failed",
            "Docker DNS routing configuration is not structured JSON",
        )
    })?;
    if document.get("dns") != Some(&Value::Array(vec![Value::String("172.17.0.1".to_owned())])) {
        return Err(DnsMediationError::new(
            "dns_routing_verification_failed",
            "Docker DNS routing configuration drifted from the local mediator",
        ));
    }
    Ok(())
}

fn mount_has_required_options(target: &Path) -> bool {
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/proc/self/mountinfo")
    else {
        return false;
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_MOUNTINFO_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MOUNTINFO_BYTES
    {
        return false;
    }
    let Ok(contents) = std::str::from_utf8(&bytes) else {
        return false;
    };
    let Some(target) = target.to_str() else {
        return false;
    };
    mountinfo_has_required_options(contents, target)
}

fn mountinfo_has_required_options(contents: &str, target: &str) -> bool {
    contents.lines().any(|line| {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 || fields[4] != target {
            return false;
        }
        let options = fields[5].split(',').collect::<BTreeSet<_>>();
        ["ro", "nodev", "nosuid"]
            .into_iter()
            .all(|required| options.contains(required))
    })
}

fn fixed_command(
    executables: &TrustedExecutableSet,
    executable: TrustedExecutable,
    arguments: &[&str],
) -> Result<(), DnsMediationError> {
    executables
        .verify_all()
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    let mut command = executables
        .command(executable)
        .map_err(|error| DnsMediationError::new(error.code, error.message))?;
    let mut child = command
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
        thread::sleep(RESIDENT_IDLE_INTERVAL);
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
    use std::sync::atomic::AtomicU64;

    static TEST_REPORT_ID: AtomicU64 = AtomicU64::new(0);

    fn test_recorder(
        scope: DnsEvidenceScope,
        materializations: Option<MaterializationSubmitter>,
    ) -> (ObservationRecorder, PathBuf) {
        test_recorder_with_policy(scope, materializations, test_hostname_policy(false))
    }

    fn test_recorder_with_policy(
        scope: DnsEvidenceScope,
        materializations: Option<MaterializationSubmitter>,
        hostname_policy: RuntimeHostnamePolicy,
    ) -> (ObservationRecorder, PathBuf) {
        let report_path = std::env::temp_dir().join(format!(
            "fence-dns-response-{}-{}.json",
            std::process::id(),
            TEST_REPORT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let recorder = ObservationRecorder {
            state: Arc::new(Mutex::new(ObservationState::default())),
            cname_authorizations: Arc::new(Mutex::new(CnameAuthorizationState::default())),
            report_write_failed: Arc::new(AtomicBool::new(false)),
            resident_health: Arc::new(Mutex::new(initial_resident_health())),
            shutdown: Arc::new(AtomicBool::new(false)),
            report_path: report_path.clone(),
            scope,
            hostname_policy,
            materializations,
            trusted_runner_worker: None,
        };
        (recorder, report_path)
    }

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
    ) -> BTreeMap<ActiveMaterializationKey, ActiveMaterialization> {
        test_hostname_policy(false)
            .exact
            .into_iter()
            .flat_map(|entry| {
                let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
                entry.transports.into_iter().map(move |transport| {
                    (
                        (
                            entry.hostname.clone(),
                            entry.hostname.clone(),
                            address,
                            transport.protocol,
                            transport.port,
                        ),
                        ActiveMaterialization {
                            source_hostname: entry.hostname.clone(),
                            hostname: entry.hostname.clone(),
                            address,
                            protocol: transport.protocol,
                            port: transport.port,
                            origins: entry.origins.clone(),
                            observed_ttl_seconds: 60,
                            expires_at: now + Duration::from_secs(60),
                        },
                    )
                })
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
        response_with_typed_address(name, query_type, query_type, ttl_seconds, data)
    }

    fn response_with_typed_address(
        name: &str,
        query_type: u16,
        answer_type: u16,
        ttl_seconds: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut bytes = query(name, query_type);
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0xc0, 0x0c]);
        bytes.extend_from_slice(&answer_type.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&ttl_seconds.to_be_bytes());
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    fn response_with_cname(name: &str, target: &str, ttl_seconds: u32) -> Vec<u8> {
        response_with_cname_for_type(name, 1, target, ttl_seconds)
    }

    fn response_with_cname_for_type(
        name: &str,
        query_type: u16,
        target: &str,
        ttl_seconds: u32,
    ) -> Vec<u8> {
        let mut bytes = query(name, query_type);
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

    fn response_with_unrelated_cname(
        question: &str,
        owner: &str,
        target: &str,
        ttl_seconds: u32,
    ) -> Vec<u8> {
        let mut bytes = query(question, 1);
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
        append_dns_name(&mut bytes, owner);
        bytes.extend_from_slice(&5_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&ttl_seconds.to_be_bytes());
        let mut target_bytes = Vec::new();
        append_dns_name(&mut target_bytes, target);
        bytes.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&target_bytes);
        bytes
    }

    fn append_test_cname_answer(bytes: &mut Vec<u8>, owner: &str, target: &str, ttl_seconds: u32) {
        append_dns_name(bytes, owner);
        bytes.extend_from_slice(&5_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&ttl_seconds.to_be_bytes());
        let mut target_bytes = Vec::new();
        append_dns_name(&mut target_bytes, target);
        bytes.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&target_bytes);
    }

    fn append_test_ipv4_answer(
        bytes: &mut Vec<u8>,
        owner: &str,
        ttl_seconds: u32,
        address: [u8; 4],
    ) {
        append_dns_name(bytes, owner);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&ttl_seconds.to_be_bytes());
        bytes.extend_from_slice(&4_u16.to_be_bytes());
        bytes.extend_from_slice(&address);
    }

    fn response_with_cname_and_address(
        name: &str,
        target: &str,
        cname_ttl_seconds: u32,
        address_ttl_seconds: u32,
        address: &[u8],
    ) -> Vec<u8> {
        response_with_cname_and_typed_address(
            name,
            1,
            target,
            1,
            cname_ttl_seconds,
            address_ttl_seconds,
            address,
        )
    }

    fn response_with_cname_and_typed_address(
        name: &str,
        query_type: u16,
        target: &str,
        answer_type: u16,
        cname_ttl_seconds: u32,
        address_ttl_seconds: u32,
        address: &[u8],
    ) -> Vec<u8> {
        let mut bytes = query(name, query_type);
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
        bytes.extend_from_slice(&answer_type.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&address_ttl_seconds.to_be_bytes());
        bytes.extend_from_slice(&(address.len() as u16).to_be_bytes());
        bytes.extend_from_slice(address);
        bytes
    }

    fn response_with_unrelated_address(
        question: &str,
        query_type: u16,
        answer: &str,
        address: &[u8],
    ) -> Vec<u8> {
        let mut bytes = query(question, query_type);
        bytes[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&1_u16.to_be_bytes());
        append_dns_name(&mut bytes, answer);
        bytes.extend_from_slice(&query_type.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&60_u32.to_be_bytes());
        bytes.extend_from_slice(&(address.len() as u16).to_be_bytes());
        bytes.extend_from_slice(address);
        bytes
    }

    fn commit_test_cname_lineage(
        authorizations: &mut CnameAuthorizationState,
        root: &str,
        target: &str,
        ttl_seconds: u32,
        now: Instant,
        policy: &RuntimeHostnamePolicy,
    ) {
        let records = DnsAnswerRecords {
            aliases: vec![DnsCnameAnswer {
                owner: root.to_owned(),
                target: target.to_owned(),
                ttl_seconds,
            }],
            addresses: vec![DnsAddressAnswer {
                hostname: target.to_owned(),
                address: "192.0.2.10".parse().unwrap(),
                ttl_seconds,
            }],
        };
        let response =
            validate_dns_response_lineage(root, &records, authorizations, now, policy).unwrap();
        assert!(commit_dns_response_authorizations(authorizations, response));
    }

    fn direct_test_validated_response(
        hostname: &str,
        address: IpAddr,
        ttl_seconds: u32,
        now: Instant,
        policy: &RuntimeHostnamePolicy,
    ) -> ValidatedDnsResponse {
        validate_dns_response_lineage(
            hostname,
            &DnsAnswerRecords {
                aliases: Vec::new(),
                addresses: vec![DnsAddressAnswer {
                    hostname: hostname.to_owned(),
                    address,
                    ttl_seconds,
                }],
            },
            &CnameAuthorizationState::default(),
            now,
            policy,
        )
        .unwrap()
    }

    fn cname_test_validated_response(
        root: &str,
        target: &str,
        address: IpAddr,
        ttl_seconds: u32,
        now: Instant,
        policy: &RuntimeHostnamePolicy,
        authorizations: &CnameAuthorizationState,
    ) -> ValidatedDnsResponse {
        validate_dns_response_lineage(
            root,
            &DnsAnswerRecords {
                aliases: vec![DnsCnameAnswer {
                    owner: root.to_owned(),
                    target: target.to_owned(),
                    ttl_seconds,
                }],
                addresses: vec![DnsAddressAnswer {
                    hostname: target.to_owned(),
                    address,
                    ttl_seconds,
                }],
            },
            authorizations,
            now,
            policy,
        )
        .unwrap()
    }

    fn stage_and_complete_test_request(
        recorder: &ObservationRecorder,
        request: MaterializationRequest,
    ) {
        let (failed_completion, failed_result) = mpsc::sync_channel(1);
        let failed_request = MaterializationRequest {
            queried_hostname: request.queried_hostname.clone(),
            response: request.response.clone(),
            completion: failed_completion,
        };
        let mut authorizations = recorder.cname_authorizations.lock().unwrap();
        let mut active = BTreeMap::new();
        let (staged, materializations, accepted, rejected, materialization_capacity_rejected) =
            stage_materialization_transactions(
                &authorizations,
                &recorder.hostname_policy,
                BTreeSet::new(),
                vec![failed_request],
                Instant::now(),
            );
        assert!(rejected.is_empty());
        assert!(!materialization_capacity_rejected);
        assert_eq!(accepted.len(), 1);
        let mut proposed_active = active.clone();
        merge_materializations(
            &mut proposed_active,
            materializations.clone(),
            Instant::now(),
        );
        assert!(!publish_verified_materialization_transaction(
            false,
            &mut authorizations,
            &mut active,
            staged,
            proposed_active,
        ));
        assert!(authorizations.active.is_empty());
        assert!(active.is_empty());
        complete_materialization_requests(accepted, MaterializationCompletion::Failed);
        assert_eq!(
            failed_result.try_recv().unwrap(),
            MaterializationCompletion::Failed
        );

        let (staged, materializations, accepted, rejected, materialization_capacity_rejected) =
            stage_materialization_transactions(
                &authorizations,
                &recorder.hostname_policy,
                BTreeSet::new(),
                vec![request],
                Instant::now(),
            );
        assert!(rejected.is_empty());
        assert!(!materialization_capacity_rejected);
        assert_eq!(accepted.len(), 1);
        let mut proposed_active = active.clone();
        merge_materializations(&mut proposed_active, materializations, Instant::now());
        assert!(publish_verified_materialization_transaction(
            true,
            &mut authorizations,
            &mut active,
            staged,
            proposed_active,
        ));
        assert!(!authorizations.active.is_empty());
        assert!(!active.is_empty());
        drop(authorizations);
        complete_materialization_requests(
            accepted,
            MaterializationCompletion::AppliedVerifiedAndCommitted,
        );
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
    fn gates_approved_dns_answers_on_verified_materialization() {
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) =
            test_recorder(DnsEvidenceScope::ProtectedHostBlock, Some(submitter));
        let caller = thread::spawn(move || {
            recorder.record_response(
                "github.com",
                1,
                &response_with_address("github.com", 1, 60, &[192, 0, 2, 10]),
                None,
            )
        });
        let request = requests.recv().unwrap();
        thread::sleep(Duration::from_millis(150));
        assert!(!caller.is_finished());
        request
            .completion
            .send(MaterializationCompletion::AppliedVerifiedAndCommitted)
            .unwrap();
        assert_eq!(
            caller.join().unwrap(),
            DnsResponseDisposition::ForwardOriginal
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn gates_zero_ttl_answers_with_a_bounded_minimum_materialization() {
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) =
            test_recorder(DnsEvidenceScope::ProtectedHostBlock, Some(submitter));
        let caller = thread::spawn(move || {
            recorder.record_response(
                "api.github.com",
                1,
                &response_with_address("api.github.com", 1, 0, &[192, 0, 2, 10]),
                None,
            )
        });
        let request = requests.recv().unwrap();
        assert_eq!(request.response.materializations.len(), 1);
        assert_eq!(
            request
                .response
                .materializations
                .first()
                .unwrap()
                .ttl_seconds,
            1
        );
        assert!(!caller.is_finished());
        request
            .completion
            .send(MaterializationCompletion::AppliedVerifiedAndCommitted)
            .unwrap();
        assert_eq!(
            caller.join().unwrap(),
            DnsResponseDisposition::ForwardOriginal
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn gates_direct_results_storage_answers_on_verified_materialization() {
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) =
            test_recorder(DnsEvidenceScope::ProtectedHostBlock, Some(submitter));
        let hostname = "productionresultssa17.blob.core.windows.net";
        {
            let mut authorizations = recorder.cname_authorizations.lock().unwrap();
            assert!(authorized_hostname(
                hostname,
                &mut authorizations,
                Instant::now(),
                &recorder.hostname_policy,
                DnsQueryProvenance::TrustedRunnerWorker,
            ));
        }
        let caller = thread::spawn(move || {
            recorder.record_response(
                hostname,
                1,
                &response_with_address(hostname, 1, 60, &[192, 0, 2, 17]),
                None,
            )
        });
        let request = requests.recv().unwrap();
        let materialization = request.response.materializations.first().unwrap();
        assert_eq!(request.response.materializations.len(), 1);
        assert_eq!(materialization.hostname, hostname);
        assert_eq!(materialization.protocol, Protocol::Tcp);
        assert_eq!(materialization.port, 443);
        assert!(!caller.is_finished());
        request
            .completion
            .send(MaterializationCompletion::AppliedVerifiedAndCommitted)
            .unwrap();
        assert_eq!(
            caller.join().unwrap(),
            DnsResponseDisposition::ForwardOriginal
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn gates_wildcard_answers_on_every_matching_transport_materialization() {
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) = test_recorder_with_policy(
            DnsEvidenceScope::ProtectedHostBlock,
            Some(submitter),
            test_user_wildcard_hostname_policy(),
        );
        let hostname = "auth.docker.io";
        {
            let mut authorizations = recorder.cname_authorizations.lock().unwrap();
            assert!(authorized_hostname(
                hostname,
                &mut authorizations,
                Instant::now(),
                &recorder.hostname_policy,
                DnsQueryProvenance::Untrusted,
            ));
        }
        let mut response = response_with_address(hostname, 1, 60, &[192, 0, 2, 44]);
        response[6..8].copy_from_slice(&2_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[192, 0, 2, 45]);
        let caller = thread::spawn(move || recorder.record_response(hostname, 1, &response, None));
        let request = requests.recv().unwrap();
        assert_eq!(request.response.materializations.len(), 4);
        assert_eq!(
            request
                .response
                .materializations
                .iter()
                .map(|materialization| (materialization.protocol, materialization.port))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([(Protocol::Tcp, 443), (Protocol::Tcp, 8443)])
        );
        assert!(!caller.is_finished());
        request
            .completion
            .send(MaterializationCompletion::AppliedVerifiedAndCommitted)
            .unwrap();
        assert_eq!(
            caller.join().unwrap(),
            DnsResponseDisposition::ForwardOriginal
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn gates_wildcard_aaaa_answers_on_verified_materialization() {
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) = test_recorder_with_policy(
            DnsEvidenceScope::ProtectedHostBlock,
            Some(submitter),
            test_user_wildcard_hostname_policy(),
        );
        let hostname = "auth.docker.io";
        assert!(
            recorder
                .forward_query(hostname, 28, None)
                .is_ok_and(|authorization| authorization == DnsQueryAuthorization::Forward(None))
        );
        let caller = thread::spawn(move || {
            recorder.record_response(
                hostname,
                28,
                &response_with_address(
                    hostname,
                    28,
                    60,
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 44],
                ),
                None,
            )
        });
        let request = requests.recv().unwrap();
        assert_eq!(request.response.materializations.len(), 2);
        assert!(
            request
                .response
                .materializations
                .iter()
                .all(|materialization| {
                    matches!(materialization.address, IpAddr::V6(_))
                        && materialization.protocol == Protocol::Tcp
                        && matches!(materialization.port, 443 | 8443)
                })
        );
        request
            .completion
            .send(MaterializationCompletion::AppliedVerifiedAndCommitted)
            .unwrap();
        assert_eq!(
            caller.join().unwrap(),
            DnsResponseDisposition::ForwardOriginal
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn malformed_or_truncated_block_responses_fail_closed() {
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) = test_recorder_with_policy(
            DnsEvidenceScope::ProtectedHostBlock,
            Some(submitter),
            test_user_wildcard_hostname_policy(),
        );
        let hostname = "auth.docker.io";
        assert_eq!(
            recorder.forward_query(hostname, 1, None).unwrap(),
            DnsQueryAuthorization::Forward(None)
        );
        let mut malformed = response_with_address(hostname, 1, 60, &[192, 0, 2, 44]);
        malformed.pop();
        assert_eq!(
            recorder.record_response(hostname, 1, &malformed, None),
            DnsResponseDisposition::RetryableFailure
        );
        assert!(matches!(requests.try_recv(), Err(TryRecvError::Empty)));

        let mut truncated = response_with_address(hostname, 1, 60, &[192, 0, 2, 44]);
        truncated[2..4].copy_from_slice(&0x8380_u16.to_be_bytes());
        assert_eq!(
            recorder.record_response(hostname, 1, &truncated, None),
            DnsResponseDisposition::RetryableFailure
        );
        assert!(matches!(requests.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(
            recorder
                .state
                .lock()
                .unwrap()
                .materialization_request_rejections,
            2
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn rejects_an_address_response_unless_every_address_is_materializable() {
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) =
            test_recorder(DnsEvidenceScope::ProtectedHostBlock, Some(submitter));
        let mut response = response_with_address("github.com", 1, 60, &[192, 0, 2, 10]);
        response[6..8].copy_from_slice(&2_u16.to_be_bytes());
        append_dns_name(&mut response, "unrelated.example.net");
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&[192, 0, 2, 11]);

        assert_eq!(
            recorder.record_response("github.com", 1, &response, None),
            DnsResponseDisposition::RetryableFailure
        );
        assert!(matches!(requests.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(
            recorder
                .state
                .lock()
                .unwrap()
                .materialization_request_rejections,
            1
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn user_hostname_answers_materialize_every_transport_and_cname_descendant() {
        let config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"user-host","allowlist":[{"destination_type":"hostname","destination":"example.com","protocol":"tcp","port":8443},{"destination_type":"hostname","destination":"example.com","protocol":"udp","port":53}]}"#,
        )
        .unwrap();
        let policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) = test_recorder_with_policy(
            DnsEvidenceScope::ProtectedHostBlock,
            Some(submitter),
            policy,
        );
        let caller_recorder = recorder.clone();
        let caller = thread::spawn(move || {
            caller_recorder.record_response(
                "example.com",
                1,
                &response_with_cname_and_address(
                    "example.com",
                    "edge.example.net",
                    60,
                    60,
                    &[192, 0, 2, 10],
                ),
                None,
            )
        });
        let request = requests.recv().unwrap();
        assert_eq!(
            request
                .response
                .materializations
                .iter()
                .map(|materialization| (
                    materialization.hostname.as_str(),
                    materialization.protocol,
                    materialization.port,
                ))
                .collect::<Vec<_>>(),
            [
                ("edge.example.net", Protocol::Tcp, 8443),
                ("edge.example.net", Protocol::Udp, 53),
            ]
        );
        assert!(
            request
                .response
                .materializations
                .iter()
                .all(|materialization| { materialization.origins == [HostnamePolicyOrigin::User] })
        );
        stage_and_complete_test_request(&recorder, request);
        assert_eq!(
            caller.join().unwrap(),
            DnsResponseDisposition::ForwardOriginal
        );
        assert!(
            recorder
                .cname_authorizations
                .lock()
                .unwrap()
                .active
                .contains_key("edge.example.net")
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn unrelated_platform_cname_in_user_response_is_rejected_without_state() {
        let config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"unrelated-cname","allowlist":[{"destination_type":"hostname","destination":"user.example","protocol":"tcp","port":8443}]}"#,
        )
        .unwrap();
        let policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) = test_recorder_with_policy(
            DnsEvidenceScope::ProtectedHostBlock,
            Some(submitter),
            policy,
        );
        let target = "attacker.example";
        let unrelated = response_with_unrelated_cname("user.example", "github.com", target, 60);
        assert!(parse_complete_dns_response(&unrelated, "user.example", 1).is_some());
        assert_eq!(
            recorder.record_response("user.example", 1, &unrelated, None),
            DnsResponseDisposition::RetryableFailure,
        );
        assert!(matches!(requests.try_recv(), Err(TryRecvError::Empty)));
        assert!(
            recorder
                .cname_authorizations
                .lock()
                .unwrap()
                .active
                .is_empty()
        );
        assert_eq!(
            recorder.forward_query(target, 1, None).unwrap(),
            DnsQueryAuthorization::Refused(None),
        );
        assert_eq!(recorder.policy_classification(target), "outside_policy");
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn rooted_cname_nodata_never_seeds_authorization_state() {
        let policy = test_hostname_policy(false);
        let target = "nodata-edge.example";
        let response = response_with_cname("github.com", target, 60);

        let (submitter, requests) = materialization_request_channel();
        let (block, block_report) = test_recorder_with_policy(
            DnsEvidenceScope::ProtectedHostBlock,
            Some(submitter),
            policy.clone(),
        );
        assert_eq!(
            block.record_response("github.com", 1, &response, None),
            DnsResponseDisposition::ForwardOriginal,
        );
        assert!(matches!(requests.try_recv(), Err(TryRecvError::Empty)));
        assert!(block.cname_authorizations.lock().unwrap().active.is_empty());
        assert_eq!(
            block.forward_query(target, 1, None).unwrap(),
            DnsQueryAuthorization::Refused(None),
        );

        let (audit, audit_report) =
            test_recorder_with_policy(DnsEvidenceScope::ProtectedHostAudit, None, policy);
        assert_eq!(
            audit.record_response("github.com", 1, &response, None),
            DnsResponseDisposition::ForwardOriginal,
        );
        assert!(audit.cname_authorizations.lock().unwrap().active.is_empty());

        let _ = fs::remove_file(block_report);
        let _ = fs::remove_file(audit_report);
    }

    #[test]
    fn wrong_family_addresses_fail_closed_without_authorization_state() {
        let policy = test_hostname_policy(false);
        for (query_type, answer_type, address) in [
            (28, 1, vec![192, 0, 2, 44]),
            (
                1,
                28,
                vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 44],
            ),
        ] {
            let response = response_with_cname_and_typed_address(
                "github.com",
                query_type,
                "wrong-family.example",
                answer_type,
                60,
                60,
                &address,
            );
            assert!(parse_complete_dns_response(&response, "github.com", query_type).is_none());

            let (submitter, requests) = materialization_request_channel();
            let (block, block_report) = test_recorder_with_policy(
                DnsEvidenceScope::ProtectedHostBlock,
                Some(submitter),
                policy.clone(),
            );
            assert_eq!(
                block.record_response("github.com", query_type, &response, None),
                DnsResponseDisposition::RetryableFailure,
            );
            assert!(matches!(requests.try_recv(), Err(TryRecvError::Empty)));
            assert!(block.cname_authorizations.lock().unwrap().active.is_empty());

            let (audit, audit_report) = test_recorder_with_policy(
                DnsEvidenceScope::ProtectedHostAudit,
                None,
                policy.clone(),
            );
            assert_eq!(
                audit.record_response("github.com", query_type, &response, None),
                DnsResponseDisposition::ForwardOriginal,
            );
            assert!(audit.cname_authorizations.lock().unwrap().active.is_empty());

            let _ = fs::remove_file(block_report);
            let _ = fs::remove_file(audit_report);
        }
    }

    #[test]
    fn materialization_capacity_overflow_rejects_block_and_retains_no_audit_state() {
        let policy = test_hostname_policy(false);
        let target = "x.example";
        let mut response = response_with_cname("github.com", target, 60);
        for index in 0..=MAX_MATERIALIZATIONS_PER_UPDATE {
            append_test_ipv4_answer(
                &mut response,
                target,
                60,
                [198, 51, (index / 256) as u8, (index % 256) as u8],
            );
        }
        response[6..8].copy_from_slice(
            &u16::try_from(MAX_MATERIALIZATIONS_PER_UPDATE + 2)
                .unwrap()
                .to_be_bytes(),
        );
        assert!(parse_complete_dns_response(&response, "github.com", 1).is_some());

        let (submitter, requests) = materialization_request_channel();
        let (block, block_report) = test_recorder_with_policy(
            DnsEvidenceScope::ProtectedHostBlock,
            Some(submitter),
            policy.clone(),
        );
        assert_eq!(
            block.record_response("github.com", 1, &response, None),
            DnsResponseDisposition::RetryableFailure,
        );
        assert!(matches!(requests.try_recv(), Err(TryRecvError::Empty)));
        let block_authorizations = block.cname_authorizations.lock().unwrap();
        assert!(block_authorizations.active.is_empty());
        assert!(block_authorizations.truncated);
        drop(block_authorizations);

        let (audit, audit_report) =
            test_recorder_with_policy(DnsEvidenceScope::ProtectedHostAudit, None, policy);
        assert_eq!(
            audit.record_response("github.com", 1, &response, None),
            DnsResponseDisposition::ForwardOriginal,
        );
        let audit_authorizations = audit.cname_authorizations.lock().unwrap();
        assert!(audit_authorizations.active.is_empty());
        assert!(audit_authorizations.truncated);
        drop(audit_authorizations);

        let _ = fs::remove_file(block_report);
        let _ = fs::remove_file(audit_report);
    }

    #[test]
    fn audit_forwards_but_does_not_retain_invalid_response_lineage() {
        let config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"audit","invocation_id":"audit-unrelated-cname","allowlist":[{"destination_type":"hostname","destination":"user.example","protocol":"tcp","port":8443}]}"#,
        )
        .unwrap();
        let policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
        let (recorder, report_path) =
            test_recorder_with_policy(DnsEvidenceScope::ProtectedHostAudit, None, policy);
        let target = "outside.example";
        let unrelated = response_with_unrelated_cname("user.example", "github.com", target, 60);

        assert_eq!(
            recorder.record_response("user.example", 1, &unrelated, None),
            DnsResponseDisposition::ForwardOriginal,
        );
        assert!(
            recorder
                .cname_authorizations
                .lock()
                .unwrap()
                .active
                .is_empty()
        );
        assert_eq!(
            recorder.forward_query(target, 1, None).unwrap(),
            DnsQueryAuthorization::Forward(Some("outside_policy")),
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn audit_retains_and_classifies_arbitrary_hostnames() {
        let config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"audit","invocation_id":"audit-host","allowlist":[{"destination_type":"hostname","destination":"allowed.example","protocol":"tcp","port":443}]}"#,
        )
        .unwrap();
        let policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
        let (recorder, report_path) =
            test_recorder_with_policy(DnsEvidenceScope::ProtectedHostAudit, None, policy);

        recorder.record_query("allowed.example", 1, true, None);
        recorder.record_query("outside.example", 28, true, None);
        let state = recorder.state.lock().unwrap();
        assert!(
            state
                .retained
                .contains_key(&("allowed.example".to_owned(), 1, "user_allowlist",))
        );
        assert!(
            state
                .retained
                .contains_key(&("outside.example".to_owned(), 28, "outside_policy",))
        );
        assert_eq!(state.excluded_unretained_query_count, 0);
        drop(state);
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn failed_disconnected_and_saturated_materialization_requests_fail_closed() {
        let (submitter, requests) = materialization_request_channel();
        let (recorder, report_path) =
            test_recorder(DnsEvidenceScope::ProtectedHostBlock, Some(submitter));
        let caller_recorder = recorder.clone();
        let caller = thread::spawn(move || {
            caller_recorder.record_response(
                "api.github.com",
                1,
                &response_with_address("api.github.com", 1, 60, &[192, 0, 2, 11]),
                None,
            )
        });
        requests
            .recv()
            .unwrap()
            .completion
            .send(MaterializationCompletion::Failed)
            .unwrap();
        assert_eq!(
            caller.join().unwrap(),
            DnsResponseDisposition::RetryableFailure
        );
        assert_eq!(
            recorder
                .state
                .lock()
                .unwrap()
                .materialization_request_rejections,
            0
        );

        let (abandoned, abandoned_requests) = materialization_request_channel();
        let (abandoned_recorder, abandoned_report) =
            test_recorder(DnsEvidenceScope::ProtectedHostBlock, Some(abandoned));
        let abandoned_caller = thread::spawn(move || {
            abandoned_recorder.record_response(
                "api.github.com",
                1,
                &response_with_address("api.github.com", 1, 60, &[192, 0, 2, 11]),
                None,
            )
        });
        drop(abandoned_requests.recv().unwrap());
        assert_eq!(
            abandoned_caller.join().unwrap(),
            DnsResponseDisposition::RetryableFailure
        );

        let (disconnected, receiver) = materialization_request_channel();
        drop(receiver);
        let (disconnected_recorder, disconnected_report) =
            test_recorder(DnsEvidenceScope::ProtectedHostBlock, Some(disconnected));
        assert_eq!(
            disconnected_recorder.record_response(
                "api.github.com",
                1,
                &response_with_address("api.github.com", 1, 60, &[192, 0, 2, 11]),
                None,
            ),
            DnsResponseDisposition::RetryableFailure
        );

        let (saturated, _receiver) = materialization_request_channel();
        let saturation_now = Instant::now();
        let saturation_policy = test_hostname_policy(false);
        for index in 0..MATERIALIZATION_REQUEST_QUEUE_CAPACITY {
            let (completion, _result) = mpsc::sync_channel(1);
            saturated
                .requests
                .try_send(MaterializationRequest {
                    queried_hostname: "api.github.com".to_owned(),
                    response: direct_test_validated_response(
                        "api.github.com",
                        IpAddr::V6(Ipv6Addr::from(index as u128 + 1)),
                        30,
                        saturation_now,
                        &saturation_policy,
                    ),
                    completion,
                })
                .unwrap();
        }
        let (saturated_recorder, saturated_report) =
            test_recorder(DnsEvidenceScope::ProtectedHostBlock, Some(saturated));
        assert_eq!(
            saturated_recorder.record_response(
                "api.github.com",
                1,
                &response_with_address("api.github.com", 1, 60, &[192, 0, 2, 11]),
                None,
            ),
            DnsResponseDisposition::RetryableFailure
        );
        assert_eq!(
            saturated_recorder
                .state
                .lock()
                .unwrap()
                .materialization_request_rejections,
            1
        );
        let _ = fs::remove_file(report_path);
        let _ = fs::remove_file(abandoned_report);
        let _ = fs::remove_file(disconnected_report);
        let _ = fs::remove_file(saturated_report);
    }

    #[test]
    fn materialization_evidence_counters_saturate_and_remain_bounded() {
        let (recorder, report_path) = test_recorder(DnsEvidenceScope::ProtectedHostBlock, None);
        {
            let mut state = recorder.state.lock().unwrap();
            state.materialization_batch_count = u64::MAX;
            state.materialization_request_rejections = u64::MAX;
            state.materialization_update_max_milliseconds = u64::MAX - 1;
            state.hostname_refresh_warnings = u64::MAX;
            state.upstream_request_failures = u64::MAX;
        }
        recorder.record_materialization_rejection();
        recorder.record_materialization_batch(Duration::from_millis(u64::MAX));
        recorder.record_hostname_refresh_warning();
        recorder.record_upstream_request_failure();
        let state = recorder.state.lock().unwrap();
        assert_eq!(state.materialization_batch_count, u64::MAX);
        assert_eq!(state.materialization_request_rejections, u64::MAX);
        assert_eq!(state.materialization_update_max_milliseconds, u64::MAX);
        assert_eq!(state.hostname_refresh_warnings, u64::MAX);
        assert_eq!(state.upstream_request_failures, u64::MAX);
        drop(state);
        let evidence: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
        assert_eq!(evidence["materialization_batch_count"], u64::MAX);
        assert_eq!(evidence["upstream_request_failures"], u64::MAX);
        assert_eq!(
            evidence["materialization_update_max_milliseconds"],
            u64::MAX
        );
        assert!(
            !fs::read(&report_path)
                .unwrap()
                .windows(b"raw-dns-payload".len())
                .any(|window| window == b"raw-dns-payload")
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn exact_hostname_refresh_intervals_are_origin_and_ttl_aware() {
        let platform = ExactHostnamePolicy {
            hostname: "github.com".to_owned(),
            origins: vec![HostnamePolicyOrigin::Platform],
            transports: vec![HostnameTransport {
                protocol: Protocol::Tcp,
                port: 443,
            }],
        };
        let user = ExactHostnamePolicy {
            hostname: "example.com".to_owned(),
            origins: vec![HostnamePolicyOrigin::User],
            transports: vec![HostnameTransport {
                protocol: Protocol::Tcp,
                port: 8443,
            }],
        };
        let materialization = |ttl_seconds| PendingMaterialization {
            source_hostname: "example.com".to_owned(),
            hostname: "example.com".to_owned(),
            address: "192.0.2.10".parse().unwrap(),
            protocol: Protocol::Tcp,
            port: 8443,
            origins: vec![HostnamePolicyOrigin::User],
            ttl_seconds,
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl_seconds)),
        };

        assert_eq!(
            hostname_refresh_interval(&platform, &[materialization(300)]),
            Duration::from_secs(5)
        );
        assert_eq!(
            hostname_refresh_interval(&user, &[materialization(300)]),
            Duration::from_secs(60)
        );
        assert_eq!(
            hostname_refresh_interval(&user, &[materialization(9)]),
            Duration::from_secs(5)
        );
        assert_eq!(user_hostname_refresh_interval(1), Duration::from_secs(1));
    }

    #[test]
    fn block_missing_materialization_owner_fails_closed_but_empty_and_audit_answers_forward() {
        let (block, block_report) = test_recorder(DnsEvidenceScope::ProtectedHostBlock, None);
        assert_eq!(
            block.record_response(
                "github.com",
                1,
                &response_with_address("github.com", 1, 60, &[192, 0, 2, 10]),
                None,
            ),
            DnsResponseDisposition::RetryableFailure
        );
        let mut negative_response = query("github.com", 1);
        negative_response[2..4].copy_from_slice(&0x8183_u16.to_be_bytes());
        assert_eq!(
            block.record_response("github.com", 1, &negative_response, None),
            DnsResponseDisposition::ForwardOriginal
        );
        let (audit, audit_report) = test_recorder(DnsEvidenceScope::ProtectedHostAudit, None);
        assert_eq!(
            audit.record_response(
                "example.com",
                1,
                &response_with_address("example.com", 1, 60, &[192, 0, 2, 12]),
                None,
            ),
            DnsResponseDisposition::ForwardOriginal
        );
        let _ = fs::remove_file(block_report);
        let _ = fs::remove_file(audit_report);
    }

    #[test]
    fn server_failure_preserves_only_the_dns_question() {
        let mut request = query("api.github.com", 1);
        request[..2].copy_from_slice(&0x1234_u16.to_be_bytes());
        request[2..4].copy_from_slice(&0x0110_u16.to_be_bytes());
        let question_length = request.len();
        request.extend_from_slice(b"caller-controlled-additional-bytes");
        let original = response_with_address("api.github.com", 1, 60, &[192, 0, 2, 10]);
        assert_eq!(
            dns_response_for_disposition(
                &request,
                &original,
                DnsResponseDisposition::ForwardOriginal,
            ),
            Some(original)
        );
        let response =
            dns_response_for_disposition(&request, &[], DnsResponseDisposition::RetryableFailure)
                .unwrap();
        assert_eq!(response.len(), question_length);
        assert_eq!(&response[..2], &0x1234_u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([response[2], response[3]]), 0x8102);
        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 2);
        assert_eq!(&response[4..6], &1_u16.to_be_bytes());
        assert_eq!(&response[6..12], &[0; 6]);
        assert_eq!(
            parse_dns_question(&response),
            Some(("api.github.com".to_owned(), 1))
        );
        let records = parse_complete_dns_response(&response, "api.github.com", 1).unwrap();
        assert!(records.addresses.is_empty());
        assert!(records.aliases.is_empty());
        assert!(server_failure_response(&[]).is_none());
    }

    #[test]
    fn malformed_block_queries_do_not_consume_dynamic_authorizations() {
        let recorder = ObservationRecorder {
            state: Arc::new(Mutex::new(ObservationState::default())),
            cname_authorizations: Arc::new(Mutex::new(CnameAuthorizationState::default())),
            report_write_failed: Arc::new(AtomicBool::new(false)),
            resident_health: Arc::new(Mutex::new(initial_resident_health())),
            shutdown: Arc::new(AtomicBool::new(false)),
            report_path: PathBuf::from("unused-test-report.json"),
            scope: DnsEvidenceScope::SelectedProfileRuntimeTest,
            hostname_policy: test_hostname_policy(false),
            materializations: None,
            trusted_runner_worker: None,
        };
        let mut malformed = query("malformed.actions.githubusercontent.com", 1);
        malformed[4..6].copy_from_slice(&2_u16.to_be_bytes());
        let parsed = parse_dns_question(&malformed);
        assert_eq!(
            query_for_upstream(&recorder, &malformed, parsed.as_ref(), None).unwrap(),
            DnsQueryDispatch::Refused(None)
        );
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
        assert!(matches!(
            query_for_upstream(&recorder, &valid, parsed.as_ref(), None).unwrap(),
            DnsQueryDispatch::Forward(_, None)
        ));
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
        let policy = test_hostname_policy(false);
        let opt_out = test_hostname_policy(true);
        let authorizations = CnameAuthorizationState::default();
        assert!(matches_selected_profile_pattern(
            "pipelines.actions.githubusercontent.com",
            &policy
        ));
        assert!(matches_selected_profile_pattern(
            "actions-results-receiver-production.githubapp.com",
            &policy
        ));
        assert!(matches_selected_profile_pattern(
            "hosted-compute-request-orchestrator-prod-eus-02.githubapp.com",
            &policy
        ));
        assert!(!matches_selected_profile_pattern(
            "hosted-compute-request-orchestrator-prod-eus-02.githubapp.com",
            &opt_out
        ));
        assert!(matches_selected_profile_pattern(
            "productionresultssa19.blob.core.windows.net",
            &policy
        ));
        assert!(!matches_selected_profile_pattern(
            "productionresultssa17.blob.core.windows.net",
            &policy
        ));
        assert!(!matches_selected_profile_pattern(
            "codeload.github.com",
            &policy
        ));
        assert!(matches_selected_profile_pattern("api.github.com", &policy));
        assert!(matches_exact_platform_hostname("github.com", &policy));
        assert!(matches_exact_platform_hostname("api.github.com", &policy));
        assert!(matches_exact_platform_hostname(
            "release-assets.githubusercontent.com",
            &policy
        ));
        assert!(matches_exact_platform_hostname(
            "hosted-compute-watchdog-prod-eus-01.githubapp.com",
            &policy
        ));
        assert!(!matches_exact_platform_hostname(
            "uploads.github.com",
            &policy
        ));
        assert!(!matches_selected_profile_pattern(
            "unrelated.example.com",
            &policy
        ));
        assert_eq!(
            policy_classification("api.github.com", &authorizations, &policy),
            "platform_profile"
        );
        assert_eq!(
            policy_classification("uploads.github.com", &authorizations, &policy),
            "outside_policy"
        );
        assert!(!matches_exact_platform_hostname("github.com", &opt_out));
        assert!(!matches_exact_platform_hostname("api.github.com", &opt_out));
        assert!(!matches_exact_platform_hostname(
            "release-assets.githubusercontent.com",
            &opt_out
        ));
        assert!(!matches_exact_platform_hostname(
            "hosted-compute-watchdog-prod-eus-01.githubapp.com",
            &opt_out
        ));
        assert!(matches_exact_platform_hostname(
            "pipelines.actions.githubusercontent.com",
            &opt_out
        ));
        assert_eq!(
            policy_classification("api.github.com", &authorizations, &opt_out),
            "outside_policy"
        );
    }

    #[test]
    fn results_storage_grammar_and_runner_authorization_are_strict_and_bounded() {
        for hostname in [
            "productionresultssa0.blob.core.windows.net",
            "productionresultssa17.blob.core.windows.net",
            "productionresultssa99999.blob.core.windows.net",
        ] {
            assert!(matches_results_storage_hostname(hostname));
        }
        for hostname in [
            "productionresultssa.blob.core.windows.net",
            "productionresultssa100000.blob.core.windows.net",
            "productionresults-17.blob.core.windows.net",
            "productionresultssa17.example.com",
            "prefix.productionresultssa17.blob.core.windows.net",
        ] {
            assert!(!matches_results_storage_hostname(hostname));
        }

        let policy = test_hostname_policy(false);
        let now = Instant::now();
        let mut authorizations = CnameAuthorizationState::default();
        assert!(authorized_hostname(
            "productionresultssa19.blob.core.windows.net",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(authorizations.runner_authorized_results_storage.is_empty());
        assert!(!authorized_hostname(
            "productionresultssa1.blob.core.windows.net",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(authorizations.runner_authorized_results_storage.is_empty());
        for account in 1..=MAX_RESULTS_STORAGE_AUTHORIZATIONS {
            assert!(authorized_hostname(
                &format!("productionresultssa{account}.blob.core.windows.net"),
                &mut authorizations,
                now,
                &policy,
                DnsQueryProvenance::TrustedRunnerWorker,
            ));
        }
        assert!(!authorized_hostname(
            "productionresultssa5.blob.core.windows.net",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::TrustedRunnerWorker,
        ));
        assert!(authorizations.runner_authorized_results_storage_truncated);

        let state = ObservationState {
            results_storage_authorization_count: 4,
            results_storage_request_rejections: 1,
            ..ObservationState::default()
        };
        let evidence = evidence_from_state_and_authorizations(
            &state,
            "active",
            DnsEvidenceScope::ProtectedHostBlock,
            &authorizations,
            &policy,
            &initial_resident_health(),
        );
        assert_eq!(evidence.runner_authorized_results_storage.len(), 4);
        assert!(
            evidence
                .runner_authorized_results_storage
                .iter()
                .all(|item| item.authorization_origin == "pinned_runner_worker_dns")
        );
        assert!(evidence.runner_authorized_results_storage_truncated);
        assert_eq!(evidence.results_storage_authorization_count, 4);
        assert_eq!(evidence.results_storage_request_rejections, 1);

        let mut opt_out_authorizations = CnameAuthorizationState::default();
        assert!(authorized_hostname(
            "productionresultssa17.blob.core.windows.net",
            &mut opt_out_authorizations,
            now,
            &test_hostname_policy(true),
            DnsQueryProvenance::TrustedRunnerWorker,
        ));
    }

    #[test]
    fn results_storage_cname_descendants_preserve_runner_provenance() {
        let policy = test_hostname_policy(false);
        let now = Instant::now();
        let mut authorizations = CnameAuthorizationState::default();
        let root = "productionresultssa17.blob.core.windows.net";
        assert!(authorized_hostname(
            root,
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::TrustedRunnerWorker,
        ));
        commit_test_cname_lineage(
            &mut authorizations,
            root,
            "blob.region.store.core.windows.net",
            60,
            now,
            &policy,
        );
        assert!(!authorized_hostname(
            "blob.region.store.core.windows.net",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(authorized_hostname(
            "blob.region.store.core.windows.net",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::TrustedRunnerWorker,
        ));
        assert_eq!(
            policy_classification(
                "blob.region.store.core.windows.net",
                &authorizations,
                &policy,
            ),
            "runner_authorized_results_storage_cname_derived"
        );
    }

    #[test]
    fn untrusted_and_unattributed_results_storage_queries_fail_closed() {
        let (recorder, report_path) = test_recorder(DnsEvidenceScope::ProtectedHostBlock, None);
        let request = query("productionresultssa17.blob.core.windows.net", 1);
        let parsed = parse_dns_question(&request);
        let docker = DnsQueryClient {
            listener_kind: DnsListenerKind::Docker,
            socket: DnsClientSocket {
                protocol: SocketProtocol::Udp,
                peer: "172.17.0.2:40000".parse().unwrap(),
                listener: "172.17.0.1:53".parse().unwrap(),
            },
        };
        assert_eq!(
            query_for_upstream(&recorder, &request, parsed.as_ref(), Some(docker)).unwrap(),
            DnsQueryDispatch::Refused(Some("outside_policy"))
        );
        assert_eq!(
            query_for_upstream(&recorder, &request, parsed.as_ref(), None).unwrap(),
            DnsQueryDispatch::RetryableFailure(Some("outside_policy"))
        );
        let trusted_static = query("productionresultssa19.blob.core.windows.net", 28);
        let parsed_static = parse_dns_question(&trusted_static);
        assert_eq!(
            query_for_upstream(&recorder, &trusted_static, parsed_static.as_ref(), None).unwrap(),
            DnsQueryDispatch::Forward(trusted_static, None)
        );
        let state = recorder.state.lock().unwrap();
        assert_eq!(state.results_storage_authorization_count, 0);
        assert_eq!(state.results_storage_attribution_failures, 1);
        assert_eq!(state.results_storage_request_rejections, 2);
        drop(state);
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn trusted_results_storage_capacity_rejection_is_retryable() {
        assert_eq!(
            query_authorization(false, true, DnsQueryProvenance::TrustedRunnerWorker,),
            DnsQueryAuthorization::RetryableFailure(Some("outside_policy"))
        );
        assert_eq!(
            query_authorization(false, true, DnsQueryProvenance::AttributionFailed),
            DnsQueryAuthorization::RetryableFailure(Some("outside_policy"))
        );
        assert_eq!(
            query_authorization(false, true, DnsQueryProvenance::Untrusted),
            DnsQueryAuthorization::Refused(Some("outside_policy"))
        );
    }

    #[test]
    fn audit_forwards_unattributed_results_storage_without_calling_it_allowed() {
        let (recorder, report_path) = test_recorder(DnsEvidenceScope::ProtectedHostAudit, None);
        let request = query("productionresultssa17.blob.core.windows.net", 1);
        let parsed = parse_dns_question(&request);
        let dispatch = query_for_upstream(&recorder, &request, parsed.as_ref(), None).unwrap();
        assert_eq!(
            dispatch,
            DnsQueryDispatch::Forward(request, Some("outside_policy"))
        );
        recorder.record_query(
            "productionresultssa17.blob.core.windows.net",
            1,
            true,
            Some("outside_policy"),
        );
        assert_eq!(
            recorder.record_response(
                "productionresultssa17.blob.core.windows.net",
                1,
                &response_with_address(
                    "productionresultssa17.blob.core.windows.net",
                    1,
                    60,
                    &[192, 0, 2, 17],
                ),
                Some("outside_policy"),
            ),
            DnsResponseDisposition::ForwardOriginal
        );
        let state = recorder.state.lock().unwrap();
        assert_eq!(state.results_storage_attribution_failures, 1);
        assert_eq!(state.results_storage_request_rejections, 0);
        assert!(
            state
                .retained
                .keys()
                .any(|(_, _, classification)| { *classification == "outside_policy" })
        );
        assert!(
            state
                .retained
                .get(&(
                    "productionresultssa17.blob.core.windows.net".to_owned(),
                    1,
                    "outside_policy",
                ))
                .is_some_and(|observation| {
                    observation
                        .resolved_addresses
                        .contains(&"192.0.2.17".parse().unwrap())
                })
        );
        drop(state);
        let _ = fs::remove_file(report_path);
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
                .forward_query("hosted-compute-watchdog-prod-eus-01.githubapp.com", 1)
        );
        assert!(DnsEvidenceScope::SelectedProfileRuntimeTest.forward_query(
            "hosted-compute-request-orchestrator-prod-eus-02.githubapp.com",
            1,
        ));
        assert!(
            DnsEvidenceScope::SelectedProfileRuntimeTest
                .forward_query("productionresultssa19.blob.core.windows.net", 1)
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
    fn block_refuses_and_audit_marks_wildcard_budget_overflow() {
        for scope in [
            DnsEvidenceScope::ProtectedHostBlock,
            DnsEvidenceScope::ProtectedHostAudit,
        ] {
            let (recorder, report_path) =
                test_recorder_with_policy(scope, None, test_user_wildcard_hostname_policy());
            for index in 0..MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS {
                assert_eq!(
                    recorder
                        .forward_query(&format!("host-{index}.docker.io"), 1, None)
                        .unwrap(),
                    DnsQueryAuthorization::Forward(None)
                );
            }
            assert_eq!(
                recorder
                    .forward_query("host-0.docker.io", 28, None)
                    .unwrap(),
                DnsQueryAuthorization::Forward(None)
            );
            let overflow = recorder
                .forward_query("overflow.docker.io", 1, None)
                .unwrap();
            if scope.is_block() {
                assert_eq!(overflow, DnsQueryAuthorization::Refused(None));
            } else {
                assert_eq!(
                    overflow,
                    DnsQueryAuthorization::Forward(Some("outside_policy"))
                );
            }
            assert_eq!(
                recorder
                    .state
                    .lock()
                    .unwrap()
                    .user_wildcard_request_rejections,
                1
            );
            assert_eq!(
                recorder
                    .cname_authorizations
                    .lock()
                    .unwrap()
                    .bounded_user_wildcard
                    .len(),
                MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS
            );
            let _ = fs::remove_file(report_path);
        }
    }

    #[test]
    fn audit_forwards_unsupported_wildcard_queries_as_outside_policy() {
        let (recorder, report_path) = test_recorder_with_policy(
            DnsEvidenceScope::ProtectedHostAudit,
            None,
            test_user_wildcard_hostname_policy(),
        );
        assert_eq!(
            recorder.forward_query("auth.docker.io", 16, None).unwrap(),
            DnsQueryAuthorization::Forward(Some("outside_policy"))
        );
        assert!(
            recorder
                .cname_authorizations
                .lock()
                .unwrap()
                .bounded_user_wildcard
                .is_empty()
        );
        let _ = fs::remove_file(report_path);
    }

    #[test]
    fn bounds_dynamic_actions_suffix_names_for_the_profile_lifetime() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let mut authorizations = CnameAuthorizationState::default();
        for index in 0..MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS {
            assert!(authorized_hostname(
                &format!("dynamic-{index}.actions.githubusercontent.com"),
                &mut authorizations,
                now,
                &policy,
                DnsQueryProvenance::Untrusted,
            ));
        }
        assert_eq!(
            authorizations.bounded_actions_suffix.len(),
            MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS
        );
        assert!(authorized_hostname(
            "dynamic-0.actions.githubusercontent.com",
            &mut authorizations,
            now + Duration::from_secs(600),
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(!authorized_hostname(
            "dynamic-overflow.actions.githubusercontent.com",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(authorizations.bounded_actions_suffix_truncated);
        assert!(!authorized_hostname(
            "three.labels.deep.actions.githubusercontent.com",
            &mut CnameAuthorizationState::default(),
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(!authorized_hostname(
            "-invalid.actions.githubusercontent.com",
            &mut CnameAuthorizationState::default(),
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
    }

    #[test]
    fn bounds_dynamic_githubapp_names_and_honors_broad_domain_opt_out() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let mut authorizations = CnameAuthorizationState::default();
        for index in 0..MAX_DYNAMIC_GITHUBAPP_SUFFIX_AUTHORIZATIONS {
            assert!(authorized_hostname(
                &format!("hosted-compute-{index}.githubapp.com"),
                &mut authorizations,
                now,
                &policy,
                DnsQueryProvenance::Untrusted,
            ));
        }
        assert_eq!(
            authorizations.bounded_githubapp_suffix.len(),
            MAX_DYNAMIC_GITHUBAPP_SUFFIX_AUTHORIZATIONS
        );
        assert!(!authorized_hostname(
            "hosted-compute-overflow.githubapp.com",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(authorizations.bounded_githubapp_suffix_truncated);
        let evidence = evidence_from_state_and_authorizations(
            &ObservationState::default(),
            "active",
            DnsEvidenceScope::ProtectedHostBlock,
            &authorizations,
            &policy,
            &initial_resident_health(),
        );
        assert_eq!(
            evidence.bounded_githubapp_suffix_authorizations.len(),
            MAX_DYNAMIC_GITHUBAPP_SUFFIX_AUTHORIZATIONS
        );
        assert!(evidence.bounded_githubapp_suffix_authorizations_truncated);
        assert!(!authorized_hostname(
            "nested.hosted-compute.githubapp.com",
            &mut CnameAuthorizationState::default(),
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(!authorized_hostname(
            "hosted-compute.githubapp.com",
            &mut CnameAuthorizationState::default(),
            now,
            &test_hostname_policy(true),
            DnsQueryProvenance::Untrusted,
        ));
        assert!(
            !authorized_domain_patterns(&test_hostname_policy(true)).contains(&"*.githubapp.com")
        );
        let opt_out_policy = test_hostname_policy(true);
        let opt_out_evidence = evidence_from_state_and_authorizations(
            &ObservationState::default(),
            "active",
            DnsEvidenceScope::ProtectedHostBlock,
            &CnameAuthorizationState::default(),
            &opt_out_policy,
            &initial_resident_health(),
        );
        assert!(
            opt_out_evidence
                .limitations
                .contains(&"dynamic_githubapp_suffix_authorization_disabled")
        );
        assert!(
            !opt_out_evidence.limitations.contains(
                &"bounded_githubapp_suffix_dns_authorization_remains_an_egress_limitation"
            )
        );
        assert!(authorized_hostname(
            "actions-results-receiver-production.githubapp.com",
            &mut CnameAuthorizationState::default(),
            now,
            &test_hostname_policy(true),
            DnsQueryProvenance::Untrusted,
        ));
    }

    #[test]
    fn bounds_user_wildcard_names_across_exact_one_and_two_label_patterns() {
        let now = Instant::now();
        let policy = test_user_wildcard_hostname_policy();
        let mut authorizations = CnameAuthorizationState::default();
        for index in 0..MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS - 1 {
            assert!(authorized_hostname(
                &format!("host-{index}.docker.io"),
                &mut authorizations,
                now,
                &policy,
                DnsQueryProvenance::Untrusted,
            ));
        }
        assert!(authorized_hostname(
            "edge.registry.docker.io",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert_eq!(
            authorizations.bounded_user_wildcard.len(),
            MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS
        );
        assert!(authorized_hostname(
            "host-0.docker.io",
            &mut authorizations,
            now + Duration::from_secs(600),
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(!authorized_hostname(
            "overflow.docker.io",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(authorizations.bounded_user_wildcard_truncated);
        assert!(user_wildcard_capacity_rejected(
            "overflow.docker.io",
            &authorizations,
            &policy,
        ));
        assert_eq!(
            policy_classification("host-0.docker.io", &authorizations, &policy),
            "user_wildcard_allowlist"
        );
        let evidence = evidence_from_state_and_authorizations(
            &ObservationState {
                user_wildcard_request_rejections: 1,
                ..ObservationState::default()
            },
            "active",
            DnsEvidenceScope::ProtectedHostBlock,
            &authorizations,
            &policy,
            &initial_resident_health(),
        );
        assert_eq!(
            evidence.bounded_user_wildcard_authorizations.len(),
            MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS
        );
        assert!(evidence.bounded_user_wildcard_authorizations_truncated);
        assert_eq!(evidence.user_wildcard_request_rejections, 1);
        assert!(
            evidence
                .limitations
                .contains(&"bounded_user_wildcard_dns_authorization_remains_an_egress_limitation")
        );
        assert!(evidence.limitations.contains(
            &"configured_user_wildcard_dns_names_and_transports_remain_egress_and_data_channels"
        ));
        for outside in [
            "docker.io",
            "too.deep.edge.registry.docker.io",
            "example.com",
        ] {
            assert!(!authorized_hostname(
                outside,
                &mut CnameAuthorizationState::default(),
                now,
                &policy,
                DnsQueryProvenance::Untrusted,
            ));
        }
    }

    #[test]
    fn user_wildcards_union_transports_and_preserve_results_storage_provenance() {
        let now = Instant::now();
        let policy = test_user_wildcard_hostname_policy();
        let mut authorizations = CnameAuthorizationState::default();
        assert!(authorized_hostname(
            "auth.docker.io",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert_eq!(
            hostname_policy_for_authorized_name("auth.docker.io", &authorizations, &policy)
                .unwrap(),
            (
                vec![HostnamePolicyOrigin::User],
                vec![
                    HostnameTransport {
                        protocol: Protocol::Tcp,
                        port: 443,
                    },
                    HostnameTransport {
                        protocol: Protocol::Tcp,
                        port: 8443,
                    },
                ],
            )
        );

        let results_config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"wildcard-results","allowlist":[{"destination_type":"hostname","destination":"*.blob.core.windows.net","protocol":"tcp","port":443}]}"#,
        )
        .unwrap();
        let results_policy = crate::hostname_policy::build_runtime_hostname_policy(&results_config);
        let results_hostname = "productionresultssa17.blob.core.windows.net";
        let mut results_authorizations = CnameAuthorizationState::default();
        assert!(!authorized_hostname(
            results_hostname,
            &mut results_authorizations,
            now,
            &results_policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(results_authorizations.bounded_user_wildcard.is_empty());
        assert!(authorized_hostname(
            results_hostname,
            &mut results_authorizations,
            now,
            &results_policy,
            DnsQueryProvenance::TrustedRunnerWorker,
        ));
        assert!(
            results_authorizations
                .runner_authorized_results_storage
                .contains(results_hostname)
        );
        assert!(
            results_authorizations
                .bounded_user_wildcard
                .contains(results_hostname)
        );
    }

    #[test]
    fn exact_policy_survives_wildcard_budget_exhaustion_without_wildcard_transports() {
        let config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"wildcard-exact","allowlist":[{"destination_type":"hostname","destination":"auth.docker.io","protocol":"tcp","port":8443},{"destination_type":"hostname","destination":"*.docker.io","protocol":"tcp","port":443}]}"#,
        )
        .unwrap();
        let policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
        let now = Instant::now();
        let mut authorizations = CnameAuthorizationState::default();
        for index in 0..MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS {
            assert!(authorized_hostname(
                &format!("host-{index}.docker.io"),
                &mut authorizations,
                now,
                &policy,
                DnsQueryProvenance::Untrusted,
            ));
        }
        assert!(user_wildcard_capacity_rejected(
            "auth.docker.io",
            &authorizations,
            &policy,
        ));
        assert!(authorized_hostname(
            "auth.docker.io",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert_eq!(
            hostname_policy_for_authorized_name("auth.docker.io", &authorizations, &policy)
                .unwrap()
                .1,
            vec![HostnameTransport {
                protocol: Protocol::Tcp,
                port: 8443,
            }]
        );
    }

    #[test]
    fn platform_policy_survives_wildcard_budget_exhaustion_without_wildcard_transports() {
        let config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"wildcard-platform","allowlist":[{"destination_type":"hostname","destination":"*.github.com","protocol":"tcp","port":8443}]}"#,
        )
        .unwrap();
        let policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
        let now = Instant::now();
        let mut authorizations = CnameAuthorizationState::default();
        for index in 0..MAX_DYNAMIC_USER_WILDCARD_AUTHORIZATIONS {
            assert!(authorized_hostname(
                &format!("host-{index}.github.com"),
                &mut authorizations,
                now,
                &policy,
                DnsQueryProvenance::Untrusted,
            ));
        }
        assert!(user_wildcard_capacity_rejected(
            "api.github.com",
            &authorizations,
            &policy,
        ));
        assert!(authorized_hostname(
            "api.github.com",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert_eq!(
            hostname_policy_for_authorized_name("api.github.com", &authorizations, &policy)
                .unwrap(),
            (
                vec![HostnamePolicyOrigin::Platform],
                vec![HostnameTransport {
                    protocol: Protocol::Tcp,
                    port: 443,
                }],
            )
        );
    }

    #[test]
    fn platform_broad_opt_out_does_not_remove_explicit_user_wildcards() {
        let config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"wildcard-opt-out","disable_broad_github_domains":true,"allowlist":[{"destination_type":"hostname","destination":"*.githubapp.com","protocol":"tcp","port":8443}]}"#,
        )
        .unwrap();
        let policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
        assert!(!policy.allow_dynamic_githubapp_suffix);
        let hostname = "explicit-user.githubapp.com";
        let mut authorizations = CnameAuthorizationState::default();
        assert!(authorized_hostname(
            hostname,
            &mut authorizations,
            Instant::now(),
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert_eq!(
            hostname_policy_for_authorized_name(hostname, &authorizations, &policy).unwrap(),
            (
                vec![HostnamePolicyOrigin::User],
                vec![HostnameTransport {
                    protocol: Protocol::Tcp,
                    port: 8443,
                }],
            )
        );
        let exact_platform = "actions-results-receiver-production.githubapp.com";
        assert!(authorized_hostname(
            exact_platform,
            &mut authorizations,
            Instant::now(),
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert_eq!(
            hostname_policy_for_authorized_name(exact_platform, &authorizations, &policy).unwrap(),
            (
                vec![HostnamePolicyOrigin::Platform, HostnamePolicyOrigin::User],
                vec![
                    HostnameTransport {
                        protocol: Protocol::Tcp,
                        port: 443,
                    },
                    HostnameTransport {
                        protocol: Protocol::Tcp,
                        port: 8443,
                    },
                ],
            )
        );
    }

    #[test]
    fn wildcard_cname_descendants_inherit_transports_with_existing_ttl_bounds() {
        let now = Instant::now();
        let policy = test_user_wildcard_hostname_policy();
        let mut authorizations = CnameAuthorizationState::default();
        let root = "registry.docker.io";
        assert!(authorized_hostname(
            root,
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        commit_test_cname_lineage(
            &mut authorizations,
            root,
            "registry-cdn.example.net",
            60,
            now,
            &policy,
        );
        assert!(authorized_hostname(
            "registry-cdn.example.net",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert_eq!(
            policy_classification("registry-cdn.example.net", &authorizations, &policy,),
            "user_cname_derived"
        );
        assert_eq!(
            hostname_policy_for_authorized_name(
                "registry-cdn.example.net",
                &authorizations,
                &policy,
            )
            .unwrap()
            .1,
            vec![
                HostnameTransport {
                    protocol: Protocol::Tcp,
                    port: 443,
                },
                HostnameTransport {
                    protocol: Protocol::Tcp,
                    port: 8443,
                },
            ]
        );
        assert!(!authorized_hostname(
            "registry-cdn.example.net",
            &mut authorizations,
            now + Duration::from_secs(61),
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
    }

    #[test]
    fn wildcard_matching_cname_descendants_do_not_consume_root_slots() {
        let now = Instant::now();
        let policy = test_user_wildcard_hostname_policy();
        let mut authorizations = CnameAuthorizationState::default();
        let root = "registry.docker.io";
        let descendant = "registry-cdn.docker.io";
        assert!(authorized_hostname(
            root,
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        commit_test_cname_lineage(&mut authorizations, root, descendant, 60, now, &policy);
        assert!(authorized_hostname(
            descendant,
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert_eq!(
            authorizations.bounded_user_wildcard,
            BTreeSet::from([root.to_owned()])
        );
        assert_eq!(
            policy_classification(descendant, &authorizations, &policy),
            "user_cname_derived"
        );
    }

    #[test]
    fn extracts_bounded_dns_answer_addresses_and_ttls() {
        assert_eq!(
            parse_complete_dns_response(
                &response_with_address(
                    "pipelines.actions.githubusercontent.com",
                    1,
                    30,
                    &[192, 0, 2, 10],
                ),
                "pipelines.actions.githubusercontent.com",
                1,
            )
            .unwrap()
            .addresses,
            vec![DnsAddressAnswer {
                hostname: "pipelines.actions.githubusercontent.com".to_owned(),
                address: "192.0.2.10".parse().expect("IPv4 fixture must parse"),
                ttl_seconds: 30,
            }]
        );
        assert_eq!(
            parse_complete_dns_response(
                &response_with_address(
                    "pipelines.actions.githubusercontent.com",
                    28,
                    60,
                    &"2001:db8::1"
                        .parse::<Ipv6Addr>()
                        .expect("IPv6 fixture must parse")
                        .octets(),
                ),
                "pipelines.actions.githubusercontent.com",
                28,
            )
            .unwrap()
            .addresses,
            vec![DnsAddressAnswer {
                hostname: "pipelines.actions.githubusercontent.com".to_owned(),
                address: "2001:db8::1".parse().expect("IPv6 fixture must parse"),
                ttl_seconds: 60,
            }]
        );
        assert!(parse_complete_dns_response(&[], "example.com", 1).is_none());
    }

    #[test]
    fn validates_reordered_duplicate_cname_chain_with_cumulative_ttl() {
        let mut packet = query("github.com", 1);
        packet[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&4_u16.to_be_bytes());
        append_test_ipv4_answer(&mut packet, "edge-two.example", 120, [192, 0, 2, 30]);
        append_test_cname_answer(&mut packet, "edge-one.example", "edge-two.example", 40);
        append_test_cname_answer(&mut packet, "github.com", "edge-one.example", 60);
        append_test_cname_answer(&mut packet, "github.com", "edge-one.example", 30);
        let records = parse_complete_dns_response(&packet, "github.com", 1).unwrap();
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let mut authorizations = CnameAuthorizationState::default();
        let response =
            validate_dns_response_lineage("github.com", &records, &authorizations, now, &policy)
                .unwrap();

        assert_eq!(response.authorizations.len(), 2);
        assert!(
            response
                .authorizations
                .iter()
                .all(|(_, authorization)| authorization.observed_ttl_seconds == 30)
        );
        assert_eq!(response.materializations.len(), 1);
        assert_eq!(response.materializations[0].hostname, "edge-two.example");
        assert_eq!(response.materializations[0].ttl_seconds, 30);
        assert_eq!(response.materializations[0].protocol, Protocol::Tcp);
        assert_eq!(response.materializations[0].port, 443);
        assert_eq!(
            response.materializations[0].origins,
            [HostnamePolicyOrigin::Platform]
        );
        assert!(commit_dns_response_authorizations(
            &mut authorizations,
            response
        ));
        assert!(authorized_hostname(
            "edge-two.example",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
    }

    #[test]
    fn zero_ttl_address_or_cname_caps_derived_authorization_lifetime() {
        let now = Instant::now();
        let records = DnsAnswerRecords {
            aliases: vec![DnsCnameAnswer {
                owner: "github.com".to_owned(),
                target: "short-lived.example".to_owned(),
                ttl_seconds: 60,
            }],
            addresses: vec![DnsAddressAnswer {
                hostname: "short-lived.example".to_owned(),
                address: "192.0.2.36".parse().unwrap(),
                ttl_seconds: 0,
            }],
        };
        let response = validate_dns_response_lineage(
            "github.com",
            &records,
            &CnameAuthorizationState::default(),
            now,
            &test_hostname_policy(false),
        )
        .unwrap();

        assert_eq!(response.authorizations[0].1.observed_ttl_seconds, 1);
        assert_eq!(
            response.authorizations[0].1.expires_at,
            now + Duration::from_secs(1)
        );
        assert_eq!(response.materializations[0].ttl_seconds, 1);
        assert_eq!(response.valid_until, Some(now + Duration::from_secs(1)));

        let zero_middle_edge = DnsAnswerRecords {
            aliases: vec![
                DnsCnameAnswer {
                    owner: "github.com".to_owned(),
                    target: "first.example".to_owned(),
                    ttl_seconds: 60,
                },
                DnsCnameAnswer {
                    owner: "first.example".to_owned(),
                    target: "terminal.example".to_owned(),
                    ttl_seconds: 0,
                },
            ],
            addresses: vec![DnsAddressAnswer {
                hostname: "terminal.example".to_owned(),
                address: "192.0.2.37".parse().unwrap(),
                ttl_seconds: 60,
            }],
        };
        let response = validate_dns_response_lineage(
            "github.com",
            &zero_middle_edge,
            &CnameAuthorizationState::default(),
            now,
            &test_hostname_policy(false),
        )
        .unwrap();
        assert_eq!(response.authorizations.len(), 2);
        assert!(
            response
                .authorizations
                .iter()
                .all(|(_, authorization)| authorization.observed_ttl_seconds == 1)
        );
        assert_eq!(response.materializations[0].ttl_seconds, 1);
        assert_eq!(response.valid_until, Some(now + Duration::from_secs(1)));

        let zero_cname = DnsAnswerRecords {
            aliases: vec![DnsCnameAnswer {
                owner: "github.com".to_owned(),
                target: "short-lived.example".to_owned(),
                ttl_seconds: 0,
            }],
            addresses: vec![DnsAddressAnswer {
                hostname: "short-lived.example".to_owned(),
                address: "192.0.2.36".parse().unwrap(),
                ttl_seconds: 60,
            }],
        };
        let response = validate_dns_response_lineage(
            "github.com",
            &zero_cname,
            &CnameAuthorizationState::default(),
            now,
            &test_hostname_policy(false),
        )
        .unwrap();
        assert_eq!(response.authorizations[0].1.observed_ttl_seconds, 1);
        assert_eq!(
            response.authorizations[0].1.expires_at,
            now + Duration::from_secs(1)
        );
        assert_eq!(response.materializations[0].ttl_seconds, 1);
        assert_eq!(response.valid_until, Some(now + Duration::from_secs(1)));
    }

    #[test]
    fn duplicate_terminal_addresses_use_the_minimum_ttl() {
        let now = Instant::now();
        let address = "192.0.2.37".parse().unwrap();
        let records = DnsAnswerRecords {
            aliases: vec![DnsCnameAnswer {
                owner: "github.com".to_owned(),
                target: "duplicate.example".to_owned(),
                ttl_seconds: 60,
            }],
            addresses: vec![
                DnsAddressAnswer {
                    hostname: "duplicate.example".to_owned(),
                    address,
                    ttl_seconds: 40,
                },
                DnsAddressAnswer {
                    hostname: "duplicate.example".to_owned(),
                    address,
                    ttl_seconds: 5,
                },
            ],
        };
        let response = validate_dns_response_lineage(
            "github.com",
            &records,
            &CnameAuthorizationState::default(),
            now,
            &test_hostname_policy(false),
        )
        .unwrap();

        assert_eq!(response.materializations.len(), 1);
        assert_eq!(response.materializations[0].ttl_seconds, 5);
        assert_eq!(response.authorizations[0].1.observed_ttl_seconds, 5);
        assert_eq!(response.valid_until, Some(now + Duration::from_secs(5)));
    }

    #[test]
    fn derived_query_extension_inherits_depth_policy_and_remaining_lifetime() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let mut authorizations = CnameAuthorizationState::default();
        commit_test_cname_lineage(
            &mut authorizations,
            "github.com",
            "edge-one.example",
            20,
            now,
            &policy,
        );
        let records = DnsAnswerRecords {
            aliases: vec![DnsCnameAnswer {
                owner: "edge-one.example".to_owned(),
                target: "edge-two.example".to_owned(),
                ttl_seconds: 60,
            }],
            addresses: vec![DnsAddressAnswer {
                hostname: "edge-two.example".to_owned(),
                address: "192.0.2.31".parse().unwrap(),
                ttl_seconds: 120,
            }],
        };
        let response = validate_dns_response_lineage(
            "edge-one.example",
            &records,
            &authorizations,
            now + Duration::from_secs(5),
            &policy,
        )
        .unwrap();

        assert_eq!(response.authorizations[0].1.depth, 2);
        assert_eq!(response.authorizations[0].1.observed_ttl_seconds, 15);
        assert_eq!(response.materializations[0].ttl_seconds, 15);
        assert_eq!(
            response.materializations[0].origins,
            [HostnamePolicyOrigin::Platform]
        );
    }

    #[test]
    fn staged_commit_rechecks_derived_root_without_restarting_ttl() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let mut staged_root = CnameAuthorizationState::default();
        commit_test_cname_lineage(
            &mut staged_root,
            "github.com",
            "edge.example",
            20,
            now,
            &policy,
        );
        let direct_records = DnsAnswerRecords {
            aliases: Vec::new(),
            addresses: vec![DnsAddressAnswer {
                hostname: "edge.example".to_owned(),
                address: "192.0.2.34".parse().unwrap(),
                ttl_seconds: 1,
            }],
        };
        let response = validate_dns_response_lineage(
            "edge.example",
            &direct_records,
            &staged_root,
            now,
            &policy,
        )
        .unwrap();
        assert!(response.authorizations.is_empty());
        assert!(!commit_staged_dns_response(
            &mut staged_root,
            "edge.example",
            response,
            now + Duration::from_secs(2),
            &policy,
        ));
        assert!(staged_root.active.contains_key("edge.example"));

        let mut active_root = CnameAuthorizationState::default();
        commit_test_cname_lineage(
            &mut active_root,
            "github.com",
            "edge.example",
            60,
            now,
            &policy,
        );
        let extension = DnsAnswerRecords {
            aliases: vec![DnsCnameAnswer {
                owner: "edge.example".to_owned(),
                target: "terminal.example".to_owned(),
                ttl_seconds: 30,
            }],
            addresses: vec![DnsAddressAnswer {
                hostname: "terminal.example".to_owned(),
                address: "192.0.2.35".parse().unwrap(),
                ttl_seconds: 120,
            }],
        };
        let response =
            validate_dns_response_lineage("edge.example", &extension, &active_root, now, &policy)
                .unwrap();
        let changed_root = active_root.active.get_mut("edge.example").unwrap();
        changed_root.depth = MAX_DERIVED_CNAME_DEPTH;
        changed_root.expires_at = now + Duration::from_secs(15);
        assert!(!commit_staged_dns_response(
            &mut active_root,
            "edge.example",
            response,
            now + Duration::from_secs(10),
            &policy,
        ));
        assert!(!active_root.active.contains_key("terminal.example"));

        let mut active_root = CnameAuthorizationState::default();
        commit_test_cname_lineage(
            &mut active_root,
            "github.com",
            "edge.example",
            60,
            now,
            &policy,
        );
        let response =
            validate_dns_response_lineage("edge.example", &extension, &active_root, now, &policy)
                .unwrap();
        let initial_expiry = response.authorizations[0].1.expires_at;
        assert!(commit_staged_dns_response(
            &mut active_root,
            "edge.example",
            response,
            now + Duration::from_secs(10),
            &policy,
        ));
        assert_eq!(
            active_root
                .active
                .get("terminal.example")
                .unwrap()
                .expires_at,
            initial_expiry
        );
    }

    #[test]
    fn cname_chain_keeps_queried_policy_across_directly_authorized_intermediate() {
        let config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"rooted-policy","allowlist":[{"destination_type":"hostname","destination":"user.example","protocol":"tcp","port":8443}]}"#,
        )
        .unwrap();
        let policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
        let records = DnsAnswerRecords {
            aliases: vec![
                DnsCnameAnswer {
                    owner: "user.example".to_owned(),
                    target: "github.com".to_owned(),
                    ttl_seconds: 60,
                },
                DnsCnameAnswer {
                    owner: "github.com".to_owned(),
                    target: "terminal.example".to_owned(),
                    ttl_seconds: 60,
                },
            ],
            addresses: vec![DnsAddressAnswer {
                hostname: "terminal.example".to_owned(),
                address: "192.0.2.32".parse().unwrap(),
                ttl_seconds: 60,
            }],
        };
        let mut authorizations = CnameAuthorizationState::default();
        let response = validate_dns_response_lineage(
            "user.example",
            &records,
            &authorizations,
            Instant::now(),
            &policy,
        )
        .unwrap();

        assert_eq!(response.materializations[0].port, 8443);
        assert_eq!(
            response.materializations[0].origins,
            [HostnamePolicyOrigin::User]
        );
        assert_eq!(
            response.authorizations[1].1.origins,
            [HostnamePolicyOrigin::User]
        );
        assert!(commit_dns_response_authorizations(
            &mut authorizations,
            response
        ));
        assert_eq!(
            hostname_policy_for_authorized_name("terminal.example", &authorizations, &policy),
            Some((
                vec![HostnamePolicyOrigin::User],
                vec![HostnameTransport {
                    protocol: Protocol::Tcp,
                    port: 8443,
                }],
            ))
        );
    }

    #[test]
    fn conflicting_retained_target_rejects_the_owner_transaction() {
        let now = Instant::now();
        let platform_policy = test_hostname_policy(false);
        let mut authorizations = CnameAuthorizationState::default();
        commit_test_cname_lineage(
            &mut authorizations,
            "github.com",
            "shared.example",
            60,
            now,
            &platform_policy,
        );
        let config = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"retained-policy","allowlist":[{"destination_type":"hostname","destination":"user.example","protocol":"tcp","port":8443}]}"#,
        )
        .unwrap();
        let policy = crate::hostname_policy::build_runtime_hostname_policy(&config);
        let records = DnsAnswerRecords {
            aliases: vec![DnsCnameAnswer {
                owner: "user.example".to_owned(),
                target: "shared.example".to_owned(),
                ttl_seconds: 60,
            }],
            addresses: vec![DnsAddressAnswer {
                hostname: "shared.example".to_owned(),
                address: "192.0.2.33".parse().unwrap(),
                ttl_seconds: 60,
            }],
        };
        let response =
            validate_dns_response_lineage("user.example", &records, &authorizations, now, &policy)
                .unwrap();
        assert_eq!(response.materializations[0].port, 8443);
        let (completion, result) = mpsc::sync_channel(1);
        let (staged, materializations, accepted, rejected, capacity_rejected) =
            stage_materialization_transactions(
                &authorizations,
                &policy,
                BTreeSet::new(),
                vec![MaterializationRequest {
                    queried_hostname: "user.example".to_owned(),
                    response,
                    completion,
                }],
                now,
            );
        assert_eq!(staged, authorizations);
        assert!(materializations.is_empty());
        assert!(accepted.is_empty());
        assert_eq!(rejected.len(), 1);
        assert!(!capacity_rejected);
        complete_materialization_requests(rejected, MaterializationCompletion::Failed);
        assert_eq!(
            result.try_recv().unwrap(),
            MaterializationCompletion::Failed
        );

        let retained = authorizations.active.get("shared.example").unwrap();
        assert_eq!(retained.source_hostname, "github.com");
        assert_eq!(retained.origins, [HostnamePolicyOrigin::Platform]);
        assert_eq!(retained.transports[0].port, 443);
    }

    #[test]
    fn retained_target_accepts_compatible_convergence_and_same_lineage_refresh() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let mut authorizations = CnameAuthorizationState::default();
        commit_test_cname_lineage(
            &mut authorizations,
            "github.com",
            "shared.example",
            20,
            now,
            &policy,
        );

        let different_parent = validate_dns_response_lineage(
            "api.github.com",
            &DnsAnswerRecords {
                aliases: vec![
                    DnsCnameAnswer {
                        owner: "api.github.com".to_owned(),
                        target: "new-intermediate.example".to_owned(),
                        ttl_seconds: 60,
                    },
                    DnsCnameAnswer {
                        owner: "new-intermediate.example".to_owned(),
                        target: "shared.example".to_owned(),
                        ttl_seconds: 60,
                    },
                ],
                addresses: vec![DnsAddressAnswer {
                    hostname: "shared.example".to_owned(),
                    address: "192.0.2.34".parse().unwrap(),
                    ttl_seconds: 60,
                }],
            },
            &authorizations,
            now + Duration::from_secs(5),
            &policy,
        )
        .unwrap();
        let (completion, _result) = mpsc::sync_channel(1);
        let (staged, materializations, accepted, rejected, capacity_rejected) =
            stage_materialization_transactions(
                &authorizations,
                &policy,
                BTreeSet::new(),
                vec![MaterializationRequest {
                    queried_hostname: "api.github.com".to_owned(),
                    response: different_parent,
                    completion,
                }],
                now + Duration::from_secs(5),
            );
        assert_eq!(materializations.len(), 1);
        assert_eq!(accepted.len(), 1);
        assert!(rejected.is_empty());
        assert!(!capacity_rejected);
        assert!(staged.active.contains_key("new-intermediate.example"));
        assert_eq!(
            staged.active.get("shared.example"),
            authorizations.active.get("shared.example")
        );
        let mut expired_convergence = staged.clone();
        remove_expired_cname_authorizations(
            &mut expired_convergence,
            now + Duration::from_secs(21),
        );
        assert!(!expired_convergence.active.contains_key("shared.example"));
        assert!(
            expired_convergence
                .active
                .contains_key("new-intermediate.example")
        );

        let original_expiry = authorizations
            .active
            .get("shared.example")
            .unwrap()
            .expires_at;
        let same_lineage = cname_test_validated_response(
            "github.com",
            "shared.example",
            "192.0.2.35".parse().unwrap(),
            60,
            now + Duration::from_secs(5),
            &policy,
            &authorizations,
        );
        let (completion, _result) = mpsc::sync_channel(1);
        let (staged, materializations, accepted, rejected, capacity_rejected) =
            stage_materialization_transactions(
                &authorizations,
                &policy,
                BTreeSet::new(),
                vec![MaterializationRequest {
                    queried_hostname: "github.com".to_owned(),
                    response: same_lineage,
                    completion,
                }],
                now + Duration::from_secs(5),
            );
        assert!(rejected.is_empty());
        assert_eq!(accepted.len(), 1);
        assert_eq!(materializations.len(), 1);
        assert!(!capacity_rejected);
        assert!(staged.active.get("shared.example").unwrap().expires_at > original_expiry);
    }

    #[test]
    fn rejects_invalid_response_graphs_without_partial_authorization() {
        let policy = test_hostname_policy(false);
        let now = Instant::now();
        let address = |hostname: &str| DnsAddressAnswer {
            hostname: hostname.to_owned(),
            address: "192.0.2.40".parse().unwrap(),
            ttl_seconds: 60,
        };
        let invalid = vec![
            DnsAnswerRecords {
                aliases: vec![
                    DnsCnameAnswer {
                        owner: "github.com".to_owned(),
                        target: "one.example".to_owned(),
                        ttl_seconds: 60,
                    },
                    DnsCnameAnswer {
                        owner: "github.com".to_owned(),
                        target: "two.example".to_owned(),
                        ttl_seconds: 60,
                    },
                ],
                addresses: vec![address("one.example")],
            },
            DnsAnswerRecords {
                aliases: vec![
                    DnsCnameAnswer {
                        owner: "github.com".to_owned(),
                        target: "edge.example".to_owned(),
                        ttl_seconds: 60,
                    },
                    DnsCnameAnswer {
                        owner: "edge.example".to_owned(),
                        target: "github.com".to_owned(),
                        ttl_seconds: 60,
                    },
                ],
                addresses: vec![address("github.com")],
            },
            DnsAnswerRecords {
                aliases: vec![DnsCnameAnswer {
                    owner: "github.com".to_owned(),
                    target: "github.com".to_owned(),
                    ttl_seconds: 60,
                }],
                addresses: vec![address("github.com")],
            },
            DnsAnswerRecords {
                aliases: vec![DnsCnameAnswer {
                    owner: "unrelated.example".to_owned(),
                    target: "edge.example".to_owned(),
                    ttl_seconds: 60,
                }],
                addresses: vec![address("edge.example")],
            },
            DnsAnswerRecords {
                aliases: vec![DnsCnameAnswer {
                    owner: "github.com".to_owned(),
                    target: "edge.example".to_owned(),
                    ttl_seconds: 60,
                }],
                addresses: vec![address("github.com")],
            },
            DnsAnswerRecords {
                aliases: vec![
                    DnsCnameAnswer {
                        owner: "github.com".to_owned(),
                        target: "edge.example".to_owned(),
                        ttl_seconds: 60,
                    },
                    DnsCnameAnswer {
                        owner: "unrelated.example".to_owned(),
                        target: "outside.example".to_owned(),
                        ttl_seconds: 60,
                    },
                ],
                addresses: vec![address("edge.example")],
            },
        ];
        for records in invalid {
            let authorizations = CnameAuthorizationState::default();
            assert_eq!(
                validate_dns_response_lineage(
                    "github.com",
                    &records,
                    &authorizations,
                    now,
                    &policy,
                )
                .unwrap_err(),
                DnsResponseValidationError::Invalid,
            );
            assert!(authorizations.active.is_empty());
        }

        let mut over_depth_aliases = Vec::new();
        let mut owner = "github.com".to_owned();
        for index in 0..=MAX_DERIVED_CNAME_DEPTH {
            let target = format!("edge-{index}.example");
            over_depth_aliases.push(DnsCnameAnswer {
                owner,
                target: target.clone(),
                ttl_seconds: 60,
            });
            owner = target;
        }
        let over_depth = DnsAnswerRecords {
            aliases: over_depth_aliases,
            addresses: vec![address(&owner)],
        };
        assert_eq!(
            validate_dns_response_lineage(
                "github.com",
                &over_depth,
                &CnameAuthorizationState::default(),
                now,
                &policy,
            )
            .unwrap_err(),
            DnsResponseValidationError::Invalid,
        );

        let mut full = CnameAuthorizationState::default();
        for index in 0..MAX_DERIVED_CNAME_AUTHORIZATIONS {
            full.active.insert(
                format!("existing-{index}.example"),
                ActiveCnameAuthorization {
                    source_hostname: "github.com".to_owned(),
                    origins: vec![HostnamePolicyOrigin::Platform],
                    transports: vec![HostnameTransport {
                        protocol: Protocol::Tcp,
                        port: 443,
                    }],
                    requires_runner_provenance: false,
                    observed_ttl_seconds: 60,
                    depth: 1,
                    expires_at: now + Duration::from_secs(60),
                },
            );
        }
        let over_capacity = DnsAnswerRecords {
            aliases: vec![DnsCnameAnswer {
                owner: "github.com".to_owned(),
                target: "new.example".to_owned(),
                ttl_seconds: 60,
            }],
            addresses: vec![address("new.example")],
        };
        assert_eq!(
            validate_dns_response_lineage("github.com", &over_capacity, &full, now, &policy)
                .unwrap_err(),
            DnsResponseValidationError::Capacity,
        );
        assert_eq!(full.active.len(), MAX_DERIVED_CNAME_AUTHORIZATIONS);
    }

    #[test]
    fn accepts_empty_negative_response_and_rejects_cname_outside_answer_section() {
        let mut negative = query("github.com", 1);
        negative[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        let records = parse_complete_dns_response(&negative, "github.com", 1).unwrap();
        let response = validate_dns_response_lineage(
            "github.com",
            &records,
            &CnameAuthorizationState::default(),
            Instant::now(),
            &test_hostname_policy(false),
        )
        .unwrap();
        assert!(response.authorizations.is_empty());
        assert!(response.materializations.is_empty());

        let cname_nodata = response_with_cname("github.com", "edge.example", 60);
        let records = parse_complete_dns_response(&cname_nodata, "github.com", 1).unwrap();
        let response = validate_dns_response_lineage(
            "github.com",
            &records,
            &CnameAuthorizationState::default(),
            Instant::now(),
            &test_hostname_policy(false),
        )
        .unwrap();
        assert!(response.authorizations.is_empty());
        assert!(response.materializations.is_empty());
        assert!(response.valid_until.is_none());

        let mut authority_cname = negative;
        authority_cname[8..10].copy_from_slice(&1_u16.to_be_bytes());
        append_test_cname_answer(&mut authority_cname, "github.com", "edge.example", 60);
        assert!(parse_complete_dns_response(&authority_cname, "github.com", 1).is_none());
    }

    #[test]
    fn authorizes_only_bounded_ttl_cname_descendants_of_exact_roots() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let mut authorizations = CnameAuthorizationState::default();
        assert_eq!(bound_materialization_ttl(0, None), Some(1));
        assert_eq!(
            bound_materialization_ttl(0, Some(Duration::from_secs(20))),
            Some(1)
        );
        assert_eq!(bound_materialization_ttl(600, None), Some(300));
        assert_eq!(
            bound_materialization_ttl(300, Some(Duration::from_secs(20))),
            Some(20)
        );
        assert_eq!(
            bound_materialization_ttl(300, Some(Duration::from_millis(999))),
            None
        );
        assert!(!authorized_hostname(
            "glb-example.github.com",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        commit_test_cname_lineage(
            &mut authorizations,
            "payload.pipelines.actions.githubusercontent.com",
            "glb-example.github.com",
            60,
            now,
            &policy,
        );
        assert!(authorized_hostname(
            "glb-example.github.com",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        assert!(!authorized_hostname(
            "glb-example.github.com",
            &mut authorizations,
            now + Duration::from_secs(61),
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        commit_test_cname_lineage(
            &mut authorizations,
            "payload.pipelines.actions.githubusercontent.com",
            "edge.example.net",
            60,
            now,
            &policy,
        );
        assert!(authorized_hostname(
            "edge.example.net",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        let unrelated = DnsAnswerRecords {
            aliases: vec![DnsCnameAnswer {
                owner: "unrelated.example.net".to_owned(),
                target: "not-derived.example.net".to_owned(),
                ttl_seconds: 60,
            }],
            addresses: vec![DnsAddressAnswer {
                hostname: "not-derived.example.net".to_owned(),
                address: "192.0.2.20".parse().unwrap(),
                ttl_seconds: 60,
            }],
        };
        assert_eq!(
            validate_dns_response_lineage(
                "payload.pipelines.actions.githubusercontent.com",
                &unrelated,
                &authorizations,
                now,
                &policy,
            )
            .unwrap_err(),
            DnsResponseValidationError::Invalid,
        );
        assert!(!authorized_hostname(
            "not-derived.example.net",
            &mut authorizations,
            now,
            &policy,
            DnsQueryProvenance::Untrusted,
        ));
        let mut truncated = response_with_cname(
            "payload.pipelines.actions.githubusercontent.com",
            "glb-example.github.com",
            60,
        );
        truncated.pop();
        assert!(
            parse_complete_dns_response(
                &truncated,
                "payload.pipelines.actions.githubusercontent.com",
                1,
            )
            .is_none()
        );
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
    fn materializes_only_bounded_ttl_transport_rules_and_expires_them() {
        let now = Instant::now();
        let materialization = PendingMaterialization {
            source_hostname: "pipelines.actions.githubusercontent.com".to_owned(),
            hostname: "pipelines.actions.githubusercontent.com".to_owned(),
            address: "192.0.2.10".parse().unwrap(),
            protocol: Protocol::Tcp,
            port: 443,
            origins: vec![HostnamePolicyOrigin::Platform],
            ttl_seconds: 30,
            expires_at: now + Duration::from_secs(30),
        };
        let mut active = BTreeMap::new();
        let mut longer_duplicate = materialization.clone();
        longer_duplicate.ttl_seconds = 90;
        longer_duplicate.expires_at = now + Duration::from_secs(90);
        let merge = merge_materializations(
            &mut active,
            [longer_duplicate, materialization.clone()],
            now,
        );

        assert!(merge.rules_changed);
        assert!(merge.metadata_changed);
        assert_eq!(merge.expired, 0);
        assert_eq!(active.values().next().unwrap().observed_ttl_seconds, 30);
        assert_eq!(
            active.values().next().unwrap().expires_at,
            now + Duration::from_secs(30) + DNS_MATERIALIZATION_REFRESH_OVERLAP,
        );
        assert_eq!(
            effective_allowances_with_materializations(&[], &active),
            vec![EffectiveAllowance {
                destination_type: DestinationType::Ip,
                destination: "192.0.2.10".to_owned(),
                protocol: Protocol::Tcp,
                port: 443,
            }]
        );
        let merge = merge_materializations(
            &mut active,
            [materialization],
            now + Duration::from_secs(31),
        );
        assert!(!merge.rules_changed);
        assert!(!merge.metadata_changed);
        assert_eq!(merge.expired, 0);
        assert_eq!(active.len(), 1);
        let merge = merge_materializations(
            &mut active,
            std::iter::empty(),
            now + Duration::from_secs(61),
        );
        assert!(merge.rules_changed);
        assert!(merge.metadata_changed);
        assert_eq!(merge.expired, 1);
        assert!(active.is_empty());
    }

    #[test]
    fn materialization_transactions_recheck_capacity_roots_and_deadlines_atomically() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let request = |queried_hostname: &str, response: ValidatedDnsResponse| {
            let (completion, _result) = mpsc::sync_channel(1);
            MaterializationRequest {
                queried_hostname: queried_hostname.to_owned(),
                response,
                completion,
            }
        };

        let mut nearly_full = CnameAuthorizationState::default();
        for index in 0..MAX_DERIVED_CNAME_AUTHORIZATIONS - 1 {
            nearly_full.active.insert(
                format!("existing-{index}.example"),
                ActiveCnameAuthorization {
                    source_hostname: "github.com".to_owned(),
                    origins: vec![HostnamePolicyOrigin::Platform],
                    transports: vec![HostnameTransport {
                        protocol: Protocol::Tcp,
                        port: 443,
                    }],
                    requires_runner_provenance: false,
                    observed_ttl_seconds: 60,
                    depth: 1,
                    expires_at: now + Duration::from_secs(60),
                },
            );
        }
        let first = cname_test_validated_response(
            "github.com",
            "first.example",
            "192.0.2.51".parse().unwrap(),
            60,
            now,
            &policy,
            &nearly_full,
        );
        let second = cname_test_validated_response(
            "github.com",
            "second.example",
            "192.0.2.52".parse().unwrap(),
            60,
            now,
            &policy,
            &nearly_full,
        );
        let (staged, materializations, accepted, rejected, materialization_capacity_rejected) =
            stage_materialization_transactions(
                &nearly_full,
                &policy,
                BTreeSet::new(),
                vec![request("github.com", first), request("github.com", second)],
                now,
            );
        assert_eq!(staged.active.len(), MAX_DERIVED_CNAME_AUTHORIZATIONS);
        assert!(staged.active.contains_key("first.example"));
        assert!(!staged.active.contains_key("second.example"));
        assert!(staged.truncated);
        assert!(!materialization_capacity_rejected);
        assert_eq!(accepted.len(), 1);
        assert_eq!(rejected.len(), 1);
        assert_eq!(materializations.len(), 1);
        assert_eq!(
            materializations.iter().next().unwrap().address,
            "192.0.2.51".parse::<IpAddr>().unwrap(),
        );

        let mut original_root = CnameAuthorizationState::default();
        commit_test_cname_lineage(
            &mut original_root,
            "github.com",
            "derived.example",
            60,
            now,
            &policy,
        );
        let extension = cname_test_validated_response(
            "derived.example",
            "extended.example",
            "192.0.2.53".parse().unwrap(),
            60,
            now,
            &policy,
            &original_root,
        );
        let mut changed_root = original_root.clone();
        changed_root
            .active
            .get_mut("derived.example")
            .unwrap()
            .source_hostname = "changed.example".to_owned();
        let (staged, materializations, accepted, rejected, materialization_capacity_rejected) =
            stage_materialization_transactions(
                &changed_root,
                &policy,
                BTreeSet::new(),
                vec![request("derived.example", extension)],
                now,
            );
        assert_eq!(staged.active, changed_root.active);
        assert!(materializations.is_empty());
        assert!(accepted.is_empty());
        assert_eq!(rejected.len(), 1);
        assert!(!materialization_capacity_rejected);

        let expired = direct_test_validated_response(
            "github.com",
            "192.0.2.54".parse().unwrap(),
            5,
            now,
            &policy,
        );
        let (staged, materializations, accepted, rejected, materialization_capacity_rejected) =
            stage_materialization_transactions(
                &CnameAuthorizationState::default(),
                &policy,
                BTreeSet::new(),
                vec![request("github.com", expired)],
                now + Duration::from_secs(6),
            );
        assert!(staged.active.is_empty());
        assert!(materializations.is_empty());
        assert!(accepted.is_empty());
        assert_eq!(rejected.len(), 1);
        assert!(!materialization_capacity_rejected);

        let mut current_authorizations = CnameAuthorizationState::default();
        let mut current_active = BTreeMap::new();
        let mut proposed_authorizations = CnameAuthorizationState::default();
        proposed_authorizations.active.insert(
            "published.example".to_owned(),
            ActiveCnameAuthorization {
                source_hostname: "github.com".to_owned(),
                origins: vec![HostnamePolicyOrigin::Platform],
                transports: vec![HostnameTransport {
                    protocol: Protocol::Tcp,
                    port: 443,
                }],
                requires_runner_provenance: false,
                observed_ttl_seconds: 30,
                depth: 1,
                expires_at: now + Duration::from_secs(30),
            },
        );
        let mut proposed_active = BTreeMap::new();
        merge_materializations(
            &mut proposed_active,
            [PendingMaterialization {
                source_hostname: "github.com".to_owned(),
                hostname: "published.example".to_owned(),
                address: "192.0.2.55".parse().unwrap(),
                protocol: Protocol::Tcp,
                port: 443,
                origins: vec![HostnamePolicyOrigin::Platform],
                ttl_seconds: 30,
                expires_at: now + Duration::from_secs(30),
            }],
            now,
        );
        assert!(!publish_verified_materialization_transaction(
            false,
            &mut current_authorizations,
            &mut current_active,
            proposed_authorizations.clone(),
            proposed_active.clone(),
        ));
        assert!(current_authorizations.active.is_empty());
        assert!(current_active.is_empty());
        assert!(publish_verified_materialization_transaction(
            true,
            &mut current_authorizations,
            &mut current_active,
            proposed_authorizations.clone(),
            proposed_active.clone(),
        ));
        assert_eq!(current_authorizations, proposed_authorizations);
        assert_eq!(current_active, proposed_active);
    }

    #[test]
    fn materialization_transaction_preserves_batch_and_active_capacity_bounds() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let initial = (0..MAX_MATERIALIZATIONS_PER_UPDATE)
            .map(|index| PendingMaterialization {
                source_hostname: format!("source-{index}.example"),
                hostname: format!("target-{index}.example"),
                address: "192.0.2.60".parse().unwrap(),
                protocol: Protocol::Tcp,
                port: 443,
                origins: vec![HostnamePolicyOrigin::Platform],
                ttl_seconds: 60,
                expires_at: now + Duration::from_secs(60),
            })
            .collect::<BTreeSet<_>>();
        let response = direct_test_validated_response(
            "github.com",
            "192.0.2.61".parse().unwrap(),
            60,
            now,
            &policy,
        );
        let (completion, _result) = mpsc::sync_channel(1);
        let (staged, materializations, accepted, rejected, capacity_rejected) =
            stage_materialization_transactions(
                &CnameAuthorizationState::default(),
                &policy,
                initial,
                vec![MaterializationRequest {
                    queried_hostname: "github.com".to_owned(),
                    response,
                    completion,
                }],
                now,
            );
        assert!(staged.active.is_empty());
        assert_eq!(materializations.len(), MAX_MATERIALIZATIONS_PER_UPDATE);
        assert!(accepted.is_empty());
        assert_eq!(rejected.len(), 1);
        assert!(capacity_rejected);

        let address = "192.0.2.62".parse().unwrap();
        let mut active = BTreeMap::new();
        for index in 0..=MAX_ACTIVE_MATERIALIZATIONS {
            let source_hostname = format!("source-{index}.example");
            let hostname = format!("target-{index}.example");
            active.insert(
                (
                    source_hostname.clone(),
                    hostname.clone(),
                    address,
                    Protocol::Tcp,
                    443,
                ),
                ActiveMaterialization {
                    source_hostname,
                    hostname,
                    address,
                    protocol: Protocol::Tcp,
                    port: 443,
                    origins: vec![HostnamePolicyOrigin::Platform],
                    observed_ttl_seconds: 60,
                    expires_at: now + Duration::from_secs(60),
                },
            );
        }
        let effective = effective_allowances_with_materializations(&[], &active);
        assert_eq!(effective.len(), 1);
        assert!(materialization_candidate_exceeds_bounds(
            &active, &effective
        ));
    }

    #[test]
    fn refresh_only_metadata_requires_verification_before_publication() {
        let now = Instant::now();
        let idle = MaterializationMerge {
            rules_changed: false,
            metadata_changed: false,
            expired: 0,
        };
        assert!(!materialization_candidate_requires_verification(0, &idle));
        let pending = |expires_at| PendingMaterialization {
            source_hostname: "github.com".to_owned(),
            hostname: "edge.example".to_owned(),
            address: "192.0.2.63".parse().unwrap(),
            protocol: Protocol::Tcp,
            port: 443,
            origins: vec![HostnamePolicyOrigin::Platform],
            ttl_seconds: 60,
            expires_at,
        };
        let mut current_active = BTreeMap::new();
        merge_materializations(
            &mut current_active,
            [pending(now + Duration::from_secs(30))],
            now,
        );
        let original_active = current_active.clone();
        let mut proposed_active = current_active.clone();
        let merge = merge_materializations(
            &mut proposed_active,
            [pending(now + Duration::from_secs(60))],
            now,
        );
        assert!(!merge.rules_changed);
        assert!(merge.metadata_changed);
        assert!(materialization_candidate_requires_verification(0, &merge));

        let mut current_authorizations = CnameAuthorizationState::default();
        assert!(!publish_verified_materialization_transaction(
            false,
            &mut current_authorizations,
            &mut current_active,
            CnameAuthorizationState::default(),
            proposed_active,
        ));
        assert_eq!(current_active, original_active);
        assert!(current_authorizations.active.is_empty());
    }

    #[test]
    fn prehydrated_bootstrap_materializations_are_deterministic_and_bounded() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let root_materializations = pending_materializations_from_bootstrap_response(
            "github.com",
            1,
            &response_with_address("github.com", 1, 600, &[192, 0, 2, 10]),
            now,
            &policy,
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
            &policy,
        )
        .unwrap();
        let zero_ttl_cname_materializations = pending_materializations_from_bootstrap_response(
            "github.com",
            1,
            &response_with_cname_and_address(
                "github.com",
                "zero-ttl-edge.example.net",
                0,
                120,
                &[192, 0, 2, 21],
            ),
            now,
            &policy,
        )
        .unwrap();
        assert_eq!(zero_ttl_cname_materializations.len(), 1);
        assert_eq!(zero_ttl_cname_materializations[0].ttl_seconds, 1);
        assert_eq!(
            pending_materializations_from_bootstrap_response(
                "github.com",
                1,
                &response_with_unrelated_address(
                    "github.com",
                    1,
                    "unrelated.example.net",
                    &[192, 0, 2, 30],
                ),
                now,
                &policy,
            )
            .unwrap_err()
            .code,
            "dns_block_prehydration_failed"
        );
        let mut materializations = root_materializations;
        materializations.extend(cname_materializations);
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

        let mut active = BTreeMap::new();
        let merge = merge_materializations(&mut active, materializations, Instant::now());
        assert!(merge.rules_changed);
        assert!(merge.metadata_changed);
        assert_eq!(merge.expired, 0);
        assert_eq!(active.len(), 2);
        assert!(active_covers_exact_hostname_policy(
            &active_with_all_bootstrap_roots(now),
            &policy,
        ));
        assert!(!active_covers_exact_hostname_policy(&active, &policy));
        let mut required_only = active_with_all_bootstrap_roots(now);
        required_only
            .retain(|key, _| !is_optional_github_hosted_workflow_bootstrap_hostname(&key.0));
        assert!(active_covers_exact_hostname_policy(&required_only, &policy));
        let mut user_required_policy = policy.clone();
        user_required_policy
            .exact
            .iter_mut()
            .find(|entry| is_optional_github_hosted_workflow_bootstrap_hostname(&entry.hostname))
            .unwrap()
            .origins
            .push(HostnamePolicyOrigin::User);
        assert!(!active_covers_exact_hostname_policy(
            &required_only,
            &user_required_policy,
        ));

        assert_eq!(
            pending_materializations_from_bootstrap_response(
                "api.github.com",
                1,
                &response_with_address("github.com", 1, 60, &[192, 0, 2, 10]),
                now,
                &policy,
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
            pending_materializations_from_bootstrap_response(
                "github.com",
                1,
                &oversized,
                now,
                &policy,
            )
            .unwrap_err()
            .code,
            "dns_block_prehydration_failed"
        );
    }

    #[test]
    fn bootstrap_prehydration_tolerates_one_transient_query_family_failure() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let materializations = materializations_from_bootstrap_query_results(
            "github.com",
            now,
            &policy,
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
            &policy,
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

        let materializations = materializations_from_bootstrap_query_results(
            "github.com",
            now,
            &policy,
            [
                (
                    1,
                    Ok(response_with_address("github.com", 1, 60, &[192, 0, 2, 10])),
                ),
                (
                    28,
                    Ok(response_with_cname_for_type(
                        "github.com",
                        28,
                        "nodata-edge.example",
                        60,
                    )),
                ),
            ],
        )
        .unwrap();
        assert_eq!(materializations.len(), 1);

        let error = materializations_from_bootstrap_query_results(
            "github.com",
            now,
            &policy,
            [
                (
                    1,
                    Ok(response_with_unrelated_address(
                        "github.com",
                        1,
                        "unrelated.example.net",
                        &[192, 0, 2, 30],
                    )),
                ),
                (
                    28,
                    Ok(response_with_unrelated_address(
                        "github.com",
                        28,
                        "unrelated.example.net",
                        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                    )),
                ),
            ],
        )
        .unwrap_err();
        assert!(matches!(error, PrehydrationError::Fatal(_)));
        assert_eq!(
            prehydration_error_code(&error),
            "dns_block_prehydration_failed"
        );

        let error = materializations_from_bootstrap_query_results(
            "github.com",
            now,
            &policy,
            [(
                1,
                Ok(response_with_address(
                    "api.github.com",
                    1,
                    60,
                    &[192, 0, 2, 10],
                )),
            )],
        )
        .unwrap_err();
        assert!(matches!(error, PrehydrationError::Fatal(_)));
        assert_eq!(
            prehydration_error_code(&error),
            "dns_block_prehydration_failed"
        );
    }

    #[test]
    fn startup_prehydration_retries_only_transient_failures_within_fixed_bounds() {
        let policy = test_hostname_policy(false);
        let entry = policy.exact_entry("github.com").unwrap().clone();
        let mut watchdog = policy
            .exact
            .iter()
            .find(|entry| is_optional_github_hosted_workflow_bootstrap_hostname(&entry.hostname))
            .unwrap()
            .clone();
        assert!(is_optional_platform_hostname_entry(&watchdog));
        let ordered = startup_prehydration_entries(&policy).collect::<Vec<_>>();
        assert!(
            ordered[..ordered.len() - 1]
                .iter()
                .all(|entry| !is_optional_platform_hostname_entry(entry))
        );
        assert!(is_optional_platform_hostname_entry(ordered.last().unwrap()));

        watchdog.origins.push(HostnamePolicyOrigin::User);
        assert!(!is_optional_platform_hostname_entry(&watchdog));
        let mut user_required_policy = policy.clone();
        *user_required_policy
            .exact
            .iter_mut()
            .find(|entry| is_optional_github_hosted_workflow_bootstrap_hostname(&entry.hostname))
            .unwrap() = watchdog;
        assert!(
            startup_prehydration_entries(&user_required_policy)
                .all(|entry| !is_optional_platform_hostname_entry(entry))
        );

        assert!(matches!(
            query_fixed_upstream_for_prehydration_with_timeout("github.com", 1, Duration::ZERO),
            Err(PrehydrationQueryError::Transient)
        ));
        let deadline = Instant::now() + STARTUP_PREHYDRATION_TIMEOUT;
        let mut retry_calls = 0;
        let materializations = prehydrate_exact_hostname_for_startup_with_query(
            &entry,
            &policy,
            deadline,
            |hostname, query_type, timeout| {
                retry_calls += 1;
                assert_eq!(hostname, "github.com");
                assert!(!timeout.is_zero());
                assert!(timeout <= DNS_FORWARD_TIMEOUT);
                if retry_calls <= 2 || query_type == 28 {
                    Err(PrehydrationQueryError::Transient)
                } else {
                    Ok(response_with_address("github.com", 1, 60, &[192, 0, 2, 10]))
                }
            },
        )
        .unwrap();
        assert_eq!(retry_calls, 4);
        assert_eq!(materializations.len(), 1);
        assert_eq!(
            materializations[0].address,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
        );

        let mut addressless_calls = 0;
        let materializations = prehydrate_exact_hostname_for_startup_with_query(
            &entry,
            &policy,
            deadline,
            |_, query_type, _| {
                addressless_calls += 1;
                if addressless_calls <= 2 {
                    Ok(response_with_cname_for_type(
                        "github.com",
                        query_type,
                        "nodata-edge.example",
                        60,
                    ))
                } else if query_type == 1 {
                    Ok(response_with_address("github.com", 1, 60, &[192, 0, 2, 11]))
                } else {
                    Err(PrehydrationQueryError::Transient)
                }
            },
        )
        .unwrap();
        assert_eq!(addressless_calls, 4);
        assert_eq!(materializations.len(), 1);
        assert_eq!(
            materializations[0].address,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))
        );

        let mut zero_ttl_cname_calls = 0;
        let materializations = prehydrate_exact_hostname_for_startup_with_query(
            &entry,
            &policy,
            deadline,
            |_, query_type, _| {
                zero_ttl_cname_calls += 1;
                if query_type == 1 {
                    Ok(response_with_cname_and_address(
                        "github.com",
                        "zero-ttl-edge.example.net",
                        0,
                        60,
                        &[192, 0, 2, 13],
                    ))
                } else {
                    Err(PrehydrationQueryError::Transient)
                }
            },
        )
        .unwrap();
        assert_eq!(zero_ttl_cname_calls, 2);
        assert_eq!(materializations.len(), 1);
        assert_eq!(materializations[0].ttl_seconds, 1);

        let mut transient_calls = 0;
        let error = prehydrate_exact_hostname_for_startup_with_query(
            &entry,
            &policy,
            deadline,
            |_, _, _| {
                transient_calls += 1;
                Err(PrehydrationQueryError::Transient)
            },
        )
        .unwrap_err();
        assert_eq!(transient_calls, STARTUP_PREHYDRATION_MAX_ATTEMPTS * 2);
        assert!(matches!(error, PrehydrationError::Transient(_)));

        let mut fatal_calls = 0;
        let error = prehydrate_exact_hostname_for_startup_with_query(
            &entry,
            &policy,
            deadline,
            |_, query_type, _| {
                fatal_calls += 1;
                if query_type == 1 {
                    Err(PrehydrationQueryError::Fatal(DnsMediationError::new(
                        "dns_block_prehydration_failed",
                        "invalid fixed response",
                    )))
                } else {
                    Err(PrehydrationQueryError::Transient)
                }
            },
        )
        .unwrap_err();
        assert_eq!(fatal_calls, 1);
        assert!(matches!(error, PrehydrationError::Fatal(_)));

        let mut invalid_response_calls = 0;
        let error = prehydrate_exact_hostname_for_startup_with_query(
            &entry,
            &policy,
            deadline,
            |_, query_type, _| {
                invalid_response_calls += 1;
                if query_type == 1 {
                    Ok(response_with_unrelated_address(
                        "github.com",
                        1,
                        "unrelated.example.net",
                        &[192, 0, 2, 12],
                    ))
                } else {
                    Err(PrehydrationQueryError::Transient)
                }
            },
        )
        .unwrap_err();
        assert_eq!(invalid_response_calls, 1);
        assert!(matches!(error, PrehydrationError::Fatal(_)));

        let mut expired_calls = 0;
        let expired_deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        let error = prehydrate_exact_hostname_for_startup_with_query(
            &entry,
            &policy,
            expired_deadline,
            |_, _, _| {
                expired_calls += 1;
                Err(PrehydrationQueryError::Transient)
            },
        )
        .unwrap_err();
        assert_eq!(expired_calls, 0);
        assert!(matches!(error, PrehydrationError::Transient(_)));
    }

    #[test]
    fn post_ready_root_refresh_preserves_fatal_error_classification() {
        let now = Instant::now();
        let policy = test_hostname_policy(false);
        let active = active_with_all_bootstrap_roots(now);
        let mut required_only = active.clone();
        required_only
            .retain(|key, _| !is_optional_github_hosted_workflow_bootstrap_hostname(&key.0));
        assert_eq!(
            root_refresh_critical_finding(
                Some(&PrehydrationError::Transient(DnsMediationError::new(
                    "dns_block_prehydration_failed",
                    "optional refresh miss"
                ))),
                &required_only,
                &policy,
            ),
            None
        );
        let mut user_required_policy = policy.clone();
        user_required_policy
            .exact
            .iter_mut()
            .find(|entry| is_optional_github_hosted_workflow_bootstrap_hostname(&entry.hostname))
            .unwrap()
            .origins
            .push(HostnamePolicyOrigin::User);
        assert_eq!(
            root_refresh_critical_finding(
                Some(&PrehydrationError::Transient(DnsMediationError::new(
                    "dns_block_prehydration_failed",
                    "user-required refresh miss"
                ))),
                &required_only,
                &user_required_policy,
            )
            .map(|(code, _)| code),
            Some("dns_block_root_refresh_failed")
        );
        assert_eq!(
            root_refresh_critical_finding(
                Some(&PrehydrationError::Transient(DnsMediationError::new(
                    "dns_block_prehydration_failed",
                    "transient refresh miss"
                ))),
                &active,
                &policy,
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
                &policy,
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
                &policy,
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
        state.excluded_unretained_query_count = 1;
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
        assert_eq!(evidence.excluded_unretained_query_count, 1);
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
                .limitations(true, false)
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
        assert_eq!(
            evidence.host_dns_routing,
            "direct_client_to_root_resident_mediator"
        );
        assert_eq!(evidence.docker_dns_routing, "local_root_resident_mediator");
        assert!(!evidence.protection_available);
        assert!(
            evidence
                .limitations
                .contains(&"audit_observation_only_no_containment_claim")
        );
        assert!(
            protected_audit_limitations(false)
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
    fn resolver_mount_evidence_requires_the_exact_target_and_read_only_options() {
        let mountinfo = concat!(
            "31 22 0:28 / / rw,relatime - ext4 /dev/root rw\n",
            "44 31 0:28 /run/fence/example/resolv.conf /run/systemd/resolve/stub-resolv.conf ro,nosuid,nodev,relatime - ext4 /dev/root rw\n",
        );
        assert!(mountinfo_has_required_options(
            mountinfo,
            "/run/systemd/resolve/stub-resolv.conf"
        ));
        assert!(!mountinfo_has_required_options(
            mountinfo,
            "/run/systemd/resolve/resolv.conf"
        ));
        assert!(!mountinfo_has_required_options(
            "44 31 0:28 /source /run/systemd/resolve/stub-resolv.conf rw,relatime - ext4 /dev/root rw\n",
            "/run/systemd/resolve/stub-resolv.conf"
        ));
    }

    #[test]
    fn resolver_mount_identity_requires_the_same_backing_file() {
        let root = Path::new("target/tmp/dns-mediator-resolver-identity");
        let _ = fs::remove_dir_all(root);
        fs::create_dir_all(root).unwrap();
        let source = root.join("source");
        let same = root.join("same");
        let different = root.join("different");
        fs::write(&source, RESOLVER_SOURCE_CONTENTS).unwrap();
        fs::hard_link(&source, &same).unwrap();
        fs::write(&different, RESOLVER_SOURCE_CONTENTS).unwrap();
        assert!(paths_have_same_identity(&source, &same));
        assert!(!paths_have_same_identity(&source, &different));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolver_layout_rejects_unreviewed_targets_owners_and_modes() {
        let accepted = hosted_runner_fingerprint_requirement().accepted.resolver;
        let accepted_target = Path::new(accepted.canonical_target);
        assert!(resolver_layout_is_supported(
            true,
            accepted_target,
            &accepted,
            true,
            false,
            991,
            0o644,
        ));
        for unsupported in [
            resolver_layout_is_supported(
                false,
                accepted_target,
                &accepted,
                true,
                false,
                991,
                0o644,
            ),
            resolver_layout_is_supported(
                true,
                Path::new("/run/systemd/resolve/resolv.conf"),
                &accepted,
                true,
                false,
                991,
                0o644,
            ),
            resolver_layout_is_supported(
                true,
                accepted_target,
                &accepted,
                false,
                false,
                991,
                0o644,
            ),
            resolver_layout_is_supported(true, accepted_target, &accepted, true, true, 991, 0o644),
            resolver_layout_is_supported(true, accepted_target, &accepted, true, false, 0, 0o644),
            resolver_layout_is_supported(
                true,
                accepted_target,
                &accepted,
                true,
                false,
                1000,
                0o644,
            ),
            resolver_layout_is_supported(true, accepted_target, &accepted, true, false, 991, 0o666),
        ] {
            assert!(!unsupported);
        }
    }

    #[test]
    fn retains_dns_observation_report_write_failures_for_resident_checks() {
        let root = Path::new("target/tmp/dns-mediator-report-write-failure");
        let _ = fs::remove_dir_all(root);
        let recorder = ObservationRecorder {
            state: Arc::new(Mutex::new(ObservationState::default())),
            cname_authorizations: Arc::new(Mutex::new(CnameAuthorizationState::default())),
            report_write_failed: Arc::new(AtomicBool::new(false)),
            resident_health: Arc::new(Mutex::new(initial_resident_health())),
            shutdown: Arc::new(AtomicBool::new(false)),
            report_path: root.join("missing/report.json"),
            scope: DnsEvidenceScope::ProtectedHostAudit,
            hostname_policy: test_hostname_policy(false),
            materializations: None,
            trusted_runner_worker: None,
        };
        recorder.record_query("pipelines.actions.githubusercontent.com", 1, true, None);
        assert!(recorder.take_report_write_failure());
        assert!(!recorder.take_report_write_failure());
    }

    #[test]
    fn resident_worker_supervisor_requires_all_workers_and_reports_fatal_exit() {
        let (sender, receiver) = mpsc::sync_channel(RESIDENT_EVENT_CHANNEL_CAPACITY);
        let mut supervisor = ResidentWorkerSupervisor::new(receiver);
        for worker in REQUIRED_RESIDENT_WORKERS {
            sender.send(ResidentWorkerEvent::Started(worker)).unwrap();
        }
        supervisor.wait_for_startup().unwrap();
        assert!(supervisor.all_healthy());
        assert!(
            supervisor
                .worker_health()
                .iter()
                .all(|worker| worker.status == "running")
        );

        sender
            .send(ResidentWorkerEvent::Fatal {
                worker: "host_udp_dns",
                code: "dns_udp_listener_failed",
                message: "required resident DNS worker encountered a fatal listener failure",
            })
            .unwrap();
        let failures = supervisor.drain_failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].worker, "host_udp_dns");
        assert_eq!(failures[0].code, "dns_udp_listener_failed");
        assert!(!supervisor.all_healthy());
    }

    #[test]
    fn resident_worker_supervisor_reports_channel_disconnect_once() {
        let (sender, receiver) = mpsc::sync_channel(RESIDENT_EVENT_CHANNEL_CAPACITY);
        let mut supervisor = ResidentWorkerSupervisor::new(receiver);
        for worker in REQUIRED_RESIDENT_WORKERS {
            sender.send(ResidentWorkerEvent::Started(worker)).unwrap();
        }
        supervisor.wait_for_startup().unwrap();
        drop(sender);
        let failures = supervisor.drain_failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].code, "resident_worker_channel_disconnected");
        assert!(supervisor.drain_failures().is_empty());
    }

    #[test]
    fn supervised_worker_converts_panics_and_unexpected_exits_to_fatal_events() {
        for panic_worker in [false, true] {
            let stop = Arc::new(AtomicBool::new(false));
            let (sender, receiver) = mpsc::sync_channel(RESIDENT_EVENT_CHANNEL_CAPACITY);
            let mut supervisor = ResidentWorkerSupervisor::new(receiver);
            let worker = if panic_worker {
                ATTRIBUTION_WORKER_NAME
            } else {
                "host_udp_dns"
            };
            let handle = spawn_supervised_worker(
                worker,
                Arc::clone(&stop),
                sender,
                move |_| -> Result<(), DnsMediationError> {
                    if panic_worker {
                        panic!("bounded test panic");
                    }
                    Ok(())
                },
            )
            .unwrap();
            let error = supervisor.wait_for_startup().unwrap_err();
            handle.join().unwrap();
            assert_eq!(
                error.code,
                if panic_worker {
                    "resident_worker_panicked"
                } else {
                    "resident_worker_exited"
                }
            );
        }
    }

    #[test]
    fn resident_verification_sequence_and_timestamp_are_bounded() {
        let mut health = initial_resident_health();
        health.verification_sequence = u64::MAX;
        let workers = health
            .workers
            .iter()
            .map(|worker| ResidentWorkerHealth {
                name: worker.name,
                status: "running",
            })
            .collect();
        advance_resident_health(&mut health, workers, u64::MAX);
        assert_eq!(health.status, "healthy");
        assert_eq!(health.verification_sequence, u64::MAX);
        assert_eq!(
            health.last_successful_verification_unix_milliseconds,
            u64::MAX
        );
        assert!(
            health
                .workers
                .iter()
                .all(|worker| worker.status == "running")
        );
    }
}
