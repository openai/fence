use crate::IMPLEMENTATION_PHASE;
use crate::config::{
    ContainerPolicy, DestinationType, MAX_ALLOWANCES, MAX_EXPANDED_RULES, MAX_FINDINGS,
    MAX_REPORT_BYTES, MAX_RESOLVED_ADDRESSES, Mode, NormalizedAllowance, NormalizedConfig,
    PlatformProfile, Protocol,
};
use crate::error::ErrorDetail;
use crate::nft::{NetworkEnforcementPreview, build_preview, implicit_ipv6_control};
use crate::resolver::{Resolution, ResolveError, Resolver};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::Duration;

pub const PER_HOST_DNS_TIMEOUT: Duration = Duration::from_secs(5);
pub const TOTAL_DNS_BUDGET: Duration = Duration::from_secs(30);
pub const POLICY_HASH_SCHEMA_VERSION: u32 = 2;
pub const GITHUB_HOSTED_HTTPS_ONLY_CANDIDATE_PROFILE_ID: &str =
    "github_hosted_https_only_candidate_v1";
const HOSTED_HTTPS_ONLY_CHANNELS: [(DestinationType, &str, Protocol, u16); 2] = [
    (DestinationType::Cidr, "0.0.0.0/0", Protocol::Tcp, 443),
    (DestinationType::Cidr, "::/0", Protocol::Tcp, 443),
];

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceStatus {
    PlannedBlockContainment,
    PlannedBlockDegradedContainerAccess,
    AuditObservationOnly,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EffectiveAllowance {
    pub destination_type: DestinationType,
    pub destination: String,
    pub protocol: Protocol,
    pub port: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ResolutionResult {
    pub hostname: String,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RuntimePaths {
    pub directory: String,
    pub config: String,
    pub ready: String,
    pub report: String,
    pub state: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct LimitStatus {
    pub max_user_allowances: usize,
    pub declared_user_allowances: usize,
    pub duplicate_requested_allowances_collapsed: usize,
    pub max_addresses_per_hostname: usize,
    pub max_expanded_rules: usize,
    pub expanded_rules_before_deduplication: usize,
    pub duplicate_effective_rules_collapsed: usize,
    pub max_sampled_findings: usize,
    pub max_report_bytes: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FindingState {
    pub retained: Vec<String>,
    pub total: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct PlatformProfilePlan {
    pub id: &'static str,
    pub selection_status: &'static str,
    pub purpose: &'static str,
    pub requested_allowances: Vec<NormalizedAllowance>,
    pub effective_allowances: Vec<EffectiveAllowance>,
    pub frozen_resolution_results: Vec<ResolutionResult>,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct PlanData {
    pub implementation_phase: &'static str,
    pub configuration_schema_version: u32,
    pub selected_mode: Mode,
    pub assurance_status: AssuranceStatus,
    pub invocation_id: String,
    pub platform_profile: PlatformProfilePlan,
    pub container_policy: Option<ContainerPolicy>,
    pub requested_policy: Vec<NormalizedAllowance>,
    pub effective_policy: Vec<EffectiveAllowance>,
    pub frozen_resolution_results: Vec<ResolutionResult>,
    pub derived_runtime_paths: RuntimePaths,
    pub policy_hash_schema_version: u32,
    pub policy_hash: String,
    pub ruleset_hash: String,
    pub network_enforcement_preview: NetworkEnforcementPreview,
    pub limits: LimitStatus,
    pub findings: FindingState,
    pub application_status: &'static str,
    pub verification_status: &'static str,
    pub limitations: Vec<&'static str>,
}

#[derive(Serialize)]
struct PolicyHashInput<'a> {
    policy_hash_schema_version: u32,
    mode: Mode,
    container_policy: Option<ContainerPolicy>,
    platform_profile: &'a str,
    allowances: &'a [EffectiveAllowance],
    implicit_ipv6_control: crate::nft::ImplicitIpv6Control,
}

pub fn build_plan(
    config: NormalizedConfig,
    resolver: &dyn Resolver,
) -> Result<PlanData, ErrorDetail> {
    let platform_requested_policy = platform_requested_allowances(config.platform_profile);
    let mut resolved = BTreeMap::new();
    let hosts = config
        .requested_allowances
        .iter()
        .chain(platform_requested_policy.iter())
        .filter(|allowance| allowance.destination_type == DestinationType::Hostname)
        .map(|allowance| allowance.destination.clone())
        .collect::<BTreeSet<_>>();
    let mut consumed_budget = Duration::ZERO;

    for host in hosts {
        let remaining = TOTAL_DNS_BUDGET.saturating_sub(consumed_budget);
        if remaining.is_zero() {
            return Err(dns_error("dns_budget_exceeded"));
        }
        let timeout = remaining.min(PER_HOST_DNS_TIMEOUT);
        let Resolution {
            mut addresses,
            elapsed,
        } = resolver
            .resolve(&host, timeout)
            .map_err(|failure| match failure {
                ResolveError::Failed => dns_error("dns_resolution_failed"),
                ResolveError::TimedOut => dns_error("dns_resolution_timeout"),
            })?;
        if elapsed > timeout || elapsed > remaining {
            return Err(dns_error("dns_resolution_timeout"));
        }
        consumed_budget += elapsed;
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(dns_error("dns_resolution_failed"));
        }
        if addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(ErrorDetail::new(
                "too_many_resolved_addresses",
                "hostname resolution exceeds the fixed address limit",
            )
            .field("allowances.destination"));
        }
        resolved.insert(host, addresses);
    }

    let mut platform_effective_policy = expand_allowances(&platform_requested_policy, &resolved);
    platform_effective_policy.sort();
    platform_effective_policy.dedup();
    let mut effective_policy = expand_allowances(&config.requested_allowances, &resolved);
    effective_policy.extend(expand_allowances(&platform_requested_policy, &resolved));

    let expanded_rules_before_deduplication = effective_policy.len();
    if expanded_rules_before_deduplication > MAX_EXPANDED_RULES {
        return Err(ErrorDetail::new(
            "too_many_expanded_rules",
            "effective policy exceeds the fixed expanded-rule limit",
        )
        .field("allowances"));
    }
    effective_policy.sort();
    effective_policy.dedup();

    let frozen_resolution_results = resolved
        .iter()
        .map(|(hostname, addresses)| ResolutionResult {
            hostname: hostname.clone(),
            addresses: addresses
                .iter()
                .map(|address| address.to_string())
                .collect(),
        })
        .collect::<Vec<_>>();
    // The current explicit HTTPS-only candidate uses only literal rules.
    let platform_resolution_results = Vec::new();
    let platform_profile = platform_plan(
        config.platform_profile,
        platform_requested_policy,
        platform_effective_policy,
        platform_resolution_results,
    );
    let policy_hash = policy_hash(&config, &effective_policy);
    let network_enforcement_preview = build_preview(config.mode, &effective_policy);
    let ruleset_hash = sha256_hex(network_enforcement_preview.ruleset.as_bytes());
    let assurance_status = assurance_status(config.mode, config.container_policy);
    let limitations = limitations(assurance_status);
    let invocation_id = config.invocation_id.clone();
    let duplicate_effective_rules_collapsed =
        expanded_rules_before_deduplication - effective_policy.len();

    Ok(PlanData {
        implementation_phase: IMPLEMENTATION_PHASE,
        configuration_schema_version: config.schema_version,
        selected_mode: config.mode,
        assurance_status,
        invocation_id: config.invocation_id,
        platform_profile,
        container_policy: config.container_policy,
        requested_policy: config.requested_allowances,
        effective_policy,
        frozen_resolution_results,
        derived_runtime_paths: runtime_paths(&invocation_id),
        policy_hash_schema_version: POLICY_HASH_SCHEMA_VERSION,
        policy_hash,
        ruleset_hash,
        network_enforcement_preview,
        limits: LimitStatus {
            max_user_allowances: MAX_ALLOWANCES,
            declared_user_allowances: config.declared_allowance_count,
            duplicate_requested_allowances_collapsed: config
                .duplicate_requested_allowances_collapsed,
            max_addresses_per_hostname: MAX_RESOLVED_ADDRESSES,
            max_expanded_rules: MAX_EXPANDED_RULES,
            expanded_rules_before_deduplication,
            duplicate_effective_rules_collapsed,
            max_sampled_findings: MAX_FINDINGS,
            max_report_bytes: MAX_REPORT_BYTES,
        },
        findings: FindingState {
            retained: Vec::new(),
            total: 0,
            truncated: false,
        },
        application_status: "not_applied",
        verification_status: "not_verified",
        limitations,
    })
}

fn dns_error(code: &'static str) -> ErrorDetail {
    ErrorDetail::new(
        code,
        "hostname resolution did not complete within fixed bounds",
    )
    .field("allowances.destination")
}

fn effective_from_ip(address: IpAddr, allowance: &NormalizedAllowance) -> EffectiveAllowance {
    EffectiveAllowance {
        destination_type: DestinationType::Ip,
        destination: address.to_string(),
        protocol: allowance.protocol,
        port: allowance.port,
    }
}

fn platform_requested_allowances(profile: PlatformProfile) -> Vec<NormalizedAllowance> {
    match profile {
        PlatformProfile::None => Vec::new(),
        PlatformProfile::GithubHostedHttpsOnlyCandidateV1 => HOSTED_HTTPS_ONLY_CHANNELS
            .iter()
            .map(
                |(destination_type, destination, protocol, port)| NormalizedAllowance {
                    destination_type: *destination_type,
                    destination: (*destination).to_owned(),
                    protocol: *protocol,
                    port: *port,
                },
            )
            .collect(),
    }
}

fn expand_allowances(
    allowances: &[NormalizedAllowance],
    resolved: &BTreeMap<String, Vec<IpAddr>>,
) -> Vec<EffectiveAllowance> {
    let mut effective = Vec::new();
    for allowance in allowances {
        match allowance.destination_type {
            DestinationType::Hostname => {
                let addresses = resolved
                    .get(&allowance.destination)
                    .expect("each validated hostname is resolved before expansion");
                for address in addresses {
                    effective.push(effective_from_ip(*address, allowance));
                }
            }
            DestinationType::Ip | DestinationType::Cidr => {
                effective.push(EffectiveAllowance {
                    destination_type: allowance.destination_type,
                    destination: allowance.destination.clone(),
                    protocol: allowance.protocol,
                    port: allowance.port,
                });
            }
        }
    }
    effective
}

fn platform_plan(
    profile: PlatformProfile,
    requested_allowances: Vec<NormalizedAllowance>,
    effective_allowances: Vec<EffectiveAllowance>,
    frozen_resolution_results: Vec<ResolutionResult>,
) -> PlatformProfilePlan {
    match profile {
        PlatformProfile::None => PlatformProfilePlan {
            id: profile.id(),
            selection_status: "none_current_default",
            purpose: "no_implicit_platform_egress",
            requested_allowances,
            effective_allowances,
            frozen_resolution_results,
            limitations: Vec::new(),
        },
        PlatformProfile::GithubHostedHttpsOnlyCandidateV1 => PlatformProfilePlan {
            id: GITHUB_HOSTED_HTTPS_ONLY_CANDIDATE_PROFILE_ID,
            selection_status: "explicit_open_https_only_not_default",
            purpose: "github_hosted_runner_terminal_https_reduction",
            requested_allowances,
            effective_allowances,
            frozen_resolution_results,
            limitations: vec![
                "candidate_is_intentionally_open_https_only",
                "permitted_platform_destinations_are_available_to_later_workflow_code",
                "candidate_permits_arbitrary_https_egress_for_baseline_only",
                "candidate_removes_explicit_dns_and_host_control_channels",
                "candidate_must_be_reduced_before_any_default_profile_decision",
            ],
        },
    }
}

fn assurance_status(mode: Mode, container_policy: Option<ContainerPolicy>) -> AssuranceStatus {
    match (mode, container_policy) {
        (Mode::Block, Some(ContainerPolicy::UnsafePreserve)) => {
            AssuranceStatus::PlannedBlockDegradedContainerAccess
        }
        (Mode::Block, Some(ContainerPolicy::Disable) | None) => {
            AssuranceStatus::PlannedBlockContainment
        }
        (Mode::Audit, _) => AssuranceStatus::AuditObservationOnly,
    }
}

fn limitations(status: AssuranceStatus) -> Vec<&'static str> {
    let mut limitations = vec!["phase3_lifecycle_not_activated_no_public_enforcement"];
    match status {
        AssuranceStatus::PlannedBlockContainment => {}
        AssuranceStatus::PlannedBlockDegradedContainerAccess => {
            limitations.push("container_access_would_invalidate_ordinary_containment");
        }
        AssuranceStatus::AuditObservationOnly => {
            limitations.push("audit_observes_only_and_never_contains");
        }
    }
    limitations
}

fn runtime_paths(invocation_id: &str) -> RuntimePaths {
    let directory = format!("/run/fence/{invocation_id}");
    RuntimePaths {
        config: format!("{directory}/config.json"),
        ready: format!("{directory}/ready.json"),
        report: format!("{directory}/report.json"),
        state: format!("{directory}/state.json"),
        directory,
    }
}

fn policy_hash(config: &NormalizedConfig, effective_policy: &[EffectiveAllowance]) -> String {
    let bytes = serde_json::to_vec(&PolicyHashInput {
        policy_hash_schema_version: POLICY_HASH_SCHEMA_VERSION,
        mode: config.mode,
        container_policy: config.container_policy,
        platform_profile: config.platform_profile.id(),
        allowances: effective_policy,
        implicit_ipv6_control: implicit_ipv6_control(),
    })
    .expect("typed policy hashing input must serialize");
    sha256_hex(&bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hash = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hash, "{byte:02x}").expect("writing hexadecimal bytes to String must succeed");
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_and_normalize;
    use crate::resolver::Resolution;
    use std::cell::RefCell;

    struct FakeResolver {
        responses: RefCell<Vec<Result<Resolution, ResolveError>>>,
    }

    impl Resolver for FakeResolver {
        fn resolve(&self, _hostname: &str, _timeout: Duration) -> Result<Resolution, ResolveError> {
            self.responses.borrow_mut().remove(0)
        }
    }

    fn parse(json: &str) -> NormalizedConfig {
        parse_and_normalize(json.as_bytes()).unwrap()
    }

    fn resolver(responses: Vec<Result<Resolution, ResolveError>>) -> FakeResolver {
        FakeResolver {
            responses: RefCell::new(responses),
        }
    }

    fn resolved(addresses: &[&str], elapsed: Duration) -> Result<Resolution, ResolveError> {
        Ok(Resolution {
            addresses: addresses
                .iter()
                .map(|address| address.parse().unwrap())
                .collect(),
            elapsed,
        })
    }

    #[test]
    fn renders_sorted_frozen_policy_and_hash_independent_of_invocation() {
        let json = r#"{"schema_version":1,"mode":"block","invocation_id":"one","allowances":[{"destination_type":"hostname","destination":"example.com","protocol":"tcp","port":443},{"destination_type":"ip","destination":"192.0.2.2","protocol":"tcp","port":443}]}"#;
        let plan = build_plan(
            parse(json),
            &resolver(vec![resolved(
                &["192.0.2.2", "2001:db8::1", "192.0.2.2"],
                Duration::from_secs(1),
            )]),
        )
        .unwrap();
        let another = build_plan(
            parse(r#"{"schema_version":1,"mode":"block","invocation_id":"two","allowances":[{"destination_type":"ip","destination":"192.0.2.2","protocol":"tcp","port":443},{"destination_type":"hostname","destination":"example.com","protocol":"tcp","port":443}]}"#),
            &resolver(vec![resolved(
                &["2001:db8::1", "192.0.2.2"],
                Duration::from_secs(1),
            )]),
        )
        .unwrap();

        assert_eq!(plan.policy_hash, another.policy_hash);
        assert_eq!(plan.ruleset_hash, another.ruleset_hash);
        assert_eq!(plan.policy_hash_schema_version, POLICY_HASH_SCHEMA_VERSION);
        assert_eq!(plan.effective_policy.len(), 2);
        assert_eq!(plan.limits.duplicate_effective_rules_collapsed, 1);
        assert_eq!(plan.frozen_resolution_results[0].addresses[0], "192.0.2.2");
        assert_eq!(plan.derived_runtime_paths.directory, "/run/fence/one");
        assert_eq!(
            plan.network_enforcement_preview.owned_table.name,
            crate::nft::NFT_TABLE
        );
        assert_eq!(
            plan.network_enforcement_preview.activation_status,
            "not_applied"
        );
    }

    #[test]
    fn classifies_block_degraded_and_audit_assurance() {
        let standard = build_plan(
            parse(r#"{"schema_version":1,"mode":"block","invocation_id":"x","allowances":[]}"#),
            &resolver(vec![]),
        )
        .unwrap();
        let degraded = build_plan(
            parse(r#"{"schema_version":1,"mode":"block","invocation_id":"x","container_policy":"unsafe_preserve","allowances":[]}"#),
            &resolver(vec![]),
        )
        .unwrap();
        let audit = build_plan(
            parse(r#"{"schema_version":1,"mode":"audit","invocation_id":"x","allowances":[]}"#),
            &resolver(vec![]),
        )
        .unwrap();

        assert_eq!(
            standard.assurance_status,
            AssuranceStatus::PlannedBlockContainment
        );
        assert_eq!(
            degraded.assurance_status,
            AssuranceStatus::PlannedBlockDegradedContainerAccess
        );
        assert_eq!(
            audit.assurance_status,
            AssuranceStatus::AuditObservationOnly
        );
        assert_ne!(standard.policy_hash, audit.policy_hash);
        assert_ne!(standard.ruleset_hash, audit.ruleset_hash);
        assert_eq!(degraded.limitations.len(), 2);
        assert_eq!(audit.limitations.len(), 2);
    }

    #[test]
    fn models_explicit_https_only_candidate_separately_from_user_policy() {
        let candidate = build_plan(
            parse(
                r#"{"schema_version":1,"mode":"block","invocation_id":"candidate","platform_profile":"github_hosted_https_only_candidate_v1","allowances":[]}"#,
            ),
            &resolver(vec![]),
        )
        .unwrap();
        let none = build_plan(
            parse(r#"{"schema_version":1,"mode":"block","invocation_id":"candidate","platform_profile":"none","allowances":[]}"#),
            &resolver(vec![]),
        )
        .unwrap();

        assert!(candidate.requested_policy.is_empty());
        assert_eq!(candidate.limits.declared_user_allowances, 0);
        assert_eq!(
            candidate.platform_profile.id,
            GITHUB_HOSTED_HTTPS_ONLY_CANDIDATE_PROFILE_ID
        );
        assert_eq!(
            candidate.platform_profile.selection_status,
            "explicit_open_https_only_not_default"
        );
        assert_eq!(candidate.platform_profile.requested_allowances.len(), 2);
        assert_eq!(candidate.platform_profile.effective_allowances.len(), 2);
        assert!(
            candidate
                .platform_profile
                .frozen_resolution_results
                .is_empty()
        );
        assert_eq!(candidate.effective_policy.len(), 2);
        assert!(
            candidate
                .platform_profile
                .requested_allowances
                .contains(&NormalizedAllowance {
                    destination_type: DestinationType::Cidr,
                    destination: "0.0.0.0/0".to_owned(),
                    protocol: Protocol::Tcp,
                    port: 443,
                })
        );
        assert_eq!(none.platform_profile.id, "none");
        assert!(none.platform_profile.requested_allowances.is_empty());
        assert_ne!(candidate.policy_hash, none.policy_hash);
        assert_ne!(candidate.ruleset_hash, none.ruleset_hash);
        assert!(
            candidate
                .platform_profile
                .limitations
                .contains(&"candidate_permits_arbitrary_https_egress_for_baseline_only")
        );
        assert!(
            candidate
                .platform_profile
                .limitations
                .contains(&"candidate_removes_explicit_dns_and_host_control_channels")
        );
    }

    #[test]
    fn https_only_candidate_requires_no_hostname_resolution() {
        let candidate = parse(
            r#"{"schema_version":1,"mode":"audit","invocation_id":"candidate","platform_profile":"github_hosted_https_only_candidate_v1","allowances":[]}"#,
        );
        assert!(build_plan(candidate, &resolver(vec![])).is_ok());
    }

    #[test]
    fn rejects_resolution_failures_timeouts_empty_and_address_excess() {
        let config = parse(
            r#"{"schema_version":1,"mode":"block","invocation_id":"x","allowances":[{"destination_type":"hostname","destination":"example.com","protocol":"tcp","port":443}]}"#,
        );
        assert_eq!(
            build_plan(config.clone(), &resolver(vec![Err(ResolveError::Failed)]))
                .unwrap_err()
                .code,
            "dns_resolution_failed"
        );
        assert_eq!(
            build_plan(config.clone(), &resolver(vec![Err(ResolveError::TimedOut)]))
                .unwrap_err()
                .code,
            "dns_resolution_timeout"
        );
        assert_eq!(
            build_plan(
                config.clone(),
                &resolver(vec![resolved(&[], Duration::ZERO)])
            )
            .unwrap_err()
            .code,
            "dns_resolution_failed"
        );
        let too_many = (0..=MAX_RESOLVED_ADDRESSES)
            .map(|n| format!("192.0.2.{n}"))
            .collect::<Vec<_>>();
        let refs = too_many.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            build_plan(
                config,
                &resolver(vec![resolved(&refs, Duration::from_secs(1))])
            )
            .unwrap_err()
            .code,
            "too_many_resolved_addresses"
        );
    }

    #[test]
    fn rejects_consumed_dns_deadlines() {
        let config = parse(
            r#"{"schema_version":1,"mode":"block","invocation_id":"x","allowances":[{"destination_type":"hostname","destination":"a.example","protocol":"tcp","port":443},{"destination_type":"hostname","destination":"b.example","protocol":"tcp","port":443}]}"#,
        );
        assert_eq!(
            build_plan(
                config.clone(),
                &resolver(vec![resolved(&["192.0.2.1"], Duration::from_secs(6))])
            )
            .unwrap_err()
            .code,
            "dns_resolution_timeout"
        );
        assert_eq!(
            build_plan(
                config,
                &resolver(vec![
                    resolved(&["192.0.2.1"], TOTAL_DNS_BUDGET),
                    resolved(&["192.0.2.2"], Duration::ZERO),
                ])
            )
            .unwrap_err()
            .code,
            "dns_resolution_timeout"
        );
    }

    #[test]
    fn rejects_total_dns_budget_and_expanded_policy_amplification() {
        let allowances = (0..33)
            .map(|index| {
                format!(
                    r#"{{"destination_type":"hostname","destination":"host-{index}.example","protocol":"tcp","port":443}}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let config = parse(&format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"x","allowances":[{allowances}]}}"#
        ));
        let addresses = (0..MAX_RESOLVED_ADDRESSES)
            .map(|index| format!("192.0.2.{index}"))
            .collect::<Vec<_>>();
        let address_refs = addresses.iter().map(String::as_str).collect::<Vec<_>>();
        let amplified = (0..33)
            .map(|_| resolved(&address_refs, Duration::ZERO))
            .collect::<Vec<_>>();
        assert_eq!(
            build_plan(config, &resolver(amplified)).unwrap_err().code,
            "too_many_expanded_rules"
        );

        let budget_allowances = (0..7)
            .map(|index| {
                format!(
                    r#"{{"destination_type":"hostname","destination":"budget-{index}.example","protocol":"tcp","port":443}}"#
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let budget_config = parse(&format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"x","allowances":[{budget_allowances}]}}"#
        ));
        let budget_results = (0..6)
            .map(|_| resolved(&["192.0.2.1"], PER_HOST_DNS_TIMEOUT))
            .collect::<Vec<_>>();
        assert_eq!(
            build_plan(budget_config, &resolver(budget_results))
                .unwrap_err()
                .code,
            "dns_budget_exceeded"
        );
    }
}
