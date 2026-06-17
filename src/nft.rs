use crate::config::{Mode, Protocol};
use crate::findings::ConnectionFinding;
use crate::plan::EffectiveAllowance;
use crate::platform_profile::{
    AZURE_WIRESERVER_ADDRESS, AZURE_WIRESERVER_ROOT_UID, AZURE_WIRESERVER_TCP_PORTS,
};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

pub const NFT_BACKEND: &str = "native_nftables";
pub const NFT_FAMILY: &str = "inet";
pub const NFT_TABLE: &str = "fence_v0";
pub const NFT_OUTPUT_CHAIN: &str = "fence_output";
pub const NFT_FORWARD_CHAIN: &str = "fence_forward";
pub const NFT_CLASSIFY_CHAIN: &str = "fence_classify";
pub const NFT_VIOLATION_CHAIN: &str = "fence_violation";
pub const NFT_SAMPLED_VIOLATIONS_COUNTER: &str = "fence_sampled_violations";
pub const NFT_TOTAL_VIOLATIONS_COUNTER: &str = "fence_total_violations";
pub const NFT_HOOK_PRIORITY: i32 = 10;
pub const NFLOG_GROUP: u16 = 4242;
pub const NFLOG_PREFIX_BLOCK: &str = "fence-v0-block";
pub const NFLOG_PREFIX_AUDIT: &str = "fence-v0-audit";
pub const NFLOG_PACKET_PREFIX_BYTES: u32 = 64;
pub const NFLOG_SAMPLE_RATE_PER_SECOND: u32 = 100;
pub const NFLOG_SAMPLE_BURST: u32 = 100;
pub const NETWORK_EVIDENCE_STATUS: &str = "network_enforcement_test_only";
pub const DNS_MEDIATOR_UPSTREAM_ADDRESS: &str = "168.63.129.16";
pub const DNS_MEDIATOR_UPSTREAM_PORT: u16 = 53;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct OwnedTablePreview {
    pub family: &'static str,
    pub name: &'static str,
    pub single_active_invocation: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct HookPreview {
    pub chain: &'static str,
    pub hook: &'static str,
    pub priority: i32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ImplicitIpv6Control {
    pub rule_class: &'static str,
    pub icmpv6_types: Vec<&'static str>,
    pub required_hop_limit: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct NflogPreview {
    pub group: u16,
    pub prefix: &'static str,
    pub packet_prefix_bytes: u32,
    pub sample_rate_per_second: u32,
    pub sample_burst: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct NetworkEnforcementPreview {
    pub backend: &'static str,
    pub activation_status: &'static str,
    pub owned_table: OwnedTablePreview,
    pub hooks: Vec<HookPreview>,
    pub implicit_ipv6_control: ImplicitIpv6Control,
    pub nflog: NflogPreview,
    pub ruleset: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct NetworkEvidence {
    pub status: &'static str,
    pub mode: Mode,
    pub policy_hash: String,
    pub ruleset_hash: String,
    pub apply_status: &'static str,
    pub verification_status: &'static str,
    pub readiness_status: &'static str,
    pub counters: NetworkEvidenceCounters,
    pub findings: Vec<ConnectionFinding>,
    pub findings_truncated: bool,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct NetworkEvidenceCounters {
    pub total_violations: u64,
    pub sampled_violations: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct OwnedNftState {
    pub family: String,
    pub table: String,
    pub chains: Vec<OwnedChain>,
    pub counters: Vec<String>,
    pub rules: Vec<OwnedRule>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "chain_kind", rename_all = "snake_case")]
pub enum OwnedChain {
    Base {
        name: String,
        chain_type: String,
        hook: String,
        priority: i32,
        policy: String,
    },
    Regular {
        name: String,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "rule_class", rename_all = "snake_case")]
pub enum OwnedRule {
    Loopback {
        chain: String,
    },
    EstablishedRelated {
        chain: String,
    },
    ImplicitIpv6Control {
        chain: String,
        icmpv6_types: Vec<String>,
        required_hop_limit: u8,
    },
    ClassifyDispatch {
        chain: String,
    },
    Allowance {
        chain: String,
        address_family: String,
        destination: String,
        protocol: String,
        port: u16,
    },
    DnsMediatorUpstream {
        chain: String,
        uid: u32,
        destination: String,
        protocol: String,
        port: u16,
    },
    WireServerPlatform {
        chain: String,
        uid: u32,
        destination: String,
        protocol: String,
        port: u16,
    },
    ViolationDispatch {
        chain: String,
    },
    SampledViolation {
        chain: String,
        nflog_group: u16,
        prefix: String,
        packet_prefix_bytes: u32,
        sample_rate_per_second: u32,
        sample_burst: u32,
    },
    TerminalViolation {
        chain: String,
        verdict: String,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerificationFailure {
    pub code: &'static str,
    pub message: &'static str,
}

pub fn implicit_ipv6_control() -> ImplicitIpv6Control {
    ImplicitIpv6Control {
        rule_class: "implicit_ipv6_control",
        icmpv6_types: vec![
            "router_solicitation",
            "neighbor_solicitation",
            "neighbor_advertisement",
        ],
        required_hop_limit: 255,
    }
}

pub fn build_preview(mode: Mode, allowances: &[EffectiveAllowance]) -> NetworkEnforcementPreview {
    build_preview_with_dns_mediator(mode, allowances, false)
}

pub fn build_dns_mediated_preview(
    mode: Mode,
    allowances: &[EffectiveAllowance],
) -> NetworkEnforcementPreview {
    build_preview_with_dns_mediator(mode, allowances, true)
}

fn build_preview_with_dns_mediator(
    mode: Mode,
    allowances: &[EffectiveAllowance],
    dns_mediator_upstream: bool,
) -> NetworkEnforcementPreview {
    NetworkEnforcementPreview {
        backend: NFT_BACKEND,
        activation_status: "not_applied",
        owned_table: OwnedTablePreview {
            family: NFT_FAMILY,
            name: NFT_TABLE,
            single_active_invocation: true,
        },
        hooks: hook_preview(),
        implicit_ipv6_control: implicit_ipv6_control(),
        nflog: NflogPreview {
            group: NFLOG_GROUP,
            prefix: nflog_prefix(mode),
            packet_prefix_bytes: NFLOG_PACKET_PREFIX_BYTES,
            sample_rate_per_second: NFLOG_SAMPLE_RATE_PER_SECOND,
            sample_burst: NFLOG_SAMPLE_BURST,
        },
        ruleset: render_ruleset_with_dns_mediator(mode, allowances, dns_mediator_upstream, false),
    }
}

pub fn unapplied_test_evidence_model(
    mode: Mode,
    policy_hash: String,
    ruleset_hash: String,
) -> NetworkEvidence {
    NetworkEvidence {
        status: NETWORK_EVIDENCE_STATUS,
        mode,
        policy_hash,
        ruleset_hash,
        apply_status: "not_applied",
        verification_status: "not_verified",
        readiness_status: "not_emitted",
        counters: NetworkEvidenceCounters {
            total_violations: 0,
            sampled_violations: 0,
        },
        findings: Vec::new(),
        findings_truncated: false,
        limitations: vec![
            "network_test_evidence_only_no_containment",
            "readiness_not_available",
            "packet_prefixes_transiently_inspected_in_memory_not_serialized",
        ],
    }
}

pub fn expected_owned_state(mode: Mode, allowances: &[EffectiveAllowance]) -> OwnedNftState {
    expected_owned_state_with_dns_mediator(mode, allowances, false)
}

pub fn expected_dns_mediated_owned_state(
    mode: Mode,
    allowances: &[EffectiveAllowance],
) -> OwnedNftState {
    expected_owned_state_with_dns_mediator(mode, allowances, true)
}

fn expected_owned_state_with_dns_mediator(
    mode: Mode,
    allowances: &[EffectiveAllowance],
    dns_mediator_upstream: bool,
) -> OwnedNftState {
    OwnedNftState {
        family: NFT_FAMILY.to_owned(),
        table: NFT_TABLE.to_owned(),
        chains: vec![
            OwnedChain::Base {
                name: NFT_OUTPUT_CHAIN.to_owned(),
                chain_type: "filter".to_owned(),
                hook: "output".to_owned(),
                priority: NFT_HOOK_PRIORITY,
                policy: "accept".to_owned(),
            },
            OwnedChain::Base {
                name: NFT_FORWARD_CHAIN.to_owned(),
                chain_type: "filter".to_owned(),
                hook: "forward".to_owned(),
                priority: NFT_HOOK_PRIORITY,
                policy: "accept".to_owned(),
            },
            OwnedChain::Regular {
                name: NFT_CLASSIFY_CHAIN.to_owned(),
            },
            OwnedChain::Regular {
                name: NFT_VIOLATION_CHAIN.to_owned(),
            },
        ],
        counters: vec![
            NFT_SAMPLED_VIOLATIONS_COUNTER.to_owned(),
            NFT_TOTAL_VIOLATIONS_COUNTER.to_owned(),
        ],
        rules: build_rules(mode, allowances, dns_mediator_upstream),
    }
}

pub fn verify_owned_state(
    expected: &OwnedNftState,
    observed: &OwnedNftState,
) -> Result<(), VerificationFailure> {
    if expected == observed {
        Ok(())
    } else {
        Err(VerificationFailure {
            code: "owned_nft_state_mismatch",
            message: "active owned nftables state does not match the generated plan",
        })
    }
}

pub fn render_ruleset(mode: Mode, allowances: &[EffectiveAllowance]) -> String {
    render_ruleset_with_dns_mediator(mode, allowances, false, false)
}

pub fn render_dns_mediated_ruleset(mode: Mode, allowances: &[EffectiveAllowance]) -> String {
    render_ruleset_with_dns_mediator(mode, allowances, true, false)
}

pub fn render_dns_mediated_replacement_ruleset(
    mode: Mode,
    allowances: &[EffectiveAllowance],
) -> String {
    render_ruleset_with_dns_mediator(mode, allowances, true, true)
}

fn render_ruleset_with_dns_mediator(
    mode: Mode,
    allowances: &[EffectiveAllowance],
    dns_mediator_upstream: bool,
    replace_owned_table: bool,
) -> String {
    let mut program = String::new();
    if replace_owned_table {
        writeln!(&mut program, "delete table {NFT_FAMILY} {NFT_TABLE}").unwrap();
    }
    writeln!(&mut program, "create table {NFT_FAMILY} {NFT_TABLE}").unwrap();
    writeln!(
        &mut program,
        "add counter {NFT_FAMILY} {NFT_TABLE} {NFT_SAMPLED_VIOLATIONS_COUNTER}"
    )
    .unwrap();
    writeln!(
        &mut program,
        "add counter {NFT_FAMILY} {NFT_TABLE} {NFT_TOTAL_VIOLATIONS_COUNTER}"
    )
    .unwrap();
    writeln!(
        &mut program,
        "add chain {NFT_FAMILY} {NFT_TABLE} {NFT_OUTPUT_CHAIN} {{ type filter hook output priority {NFT_HOOK_PRIORITY}; policy accept; }}"
    )
    .unwrap();
    writeln!(
        &mut program,
        "add chain {NFT_FAMILY} {NFT_TABLE} {NFT_FORWARD_CHAIN} {{ type filter hook forward priority {NFT_HOOK_PRIORITY}; policy accept; }}"
    )
    .unwrap();
    writeln!(
        &mut program,
        "add chain {NFT_FAMILY} {NFT_TABLE} {NFT_CLASSIFY_CHAIN}"
    )
    .unwrap();
    writeln!(
        &mut program,
        "add chain {NFT_FAMILY} {NFT_TABLE} {NFT_VIOLATION_CHAIN}"
    )
    .unwrap();
    for rule in build_rules(mode, allowances, dns_mediator_upstream) {
        render_rule(&mut program, &rule);
    }
    program
}

fn hook_preview() -> Vec<HookPreview> {
    vec![
        HookPreview {
            chain: NFT_OUTPUT_CHAIN,
            hook: "output",
            priority: NFT_HOOK_PRIORITY,
        },
        HookPreview {
            chain: NFT_FORWARD_CHAIN,
            hook: "forward",
            priority: NFT_HOOK_PRIORITY,
        },
    ]
}

fn nflog_prefix(mode: Mode) -> &'static str {
    match mode {
        Mode::Block => NFLOG_PREFIX_BLOCK,
        Mode::Audit => NFLOG_PREFIX_AUDIT,
    }
}

fn build_rules(
    mode: Mode,
    allowances: &[EffectiveAllowance],
    dns_mediator_upstream: bool,
) -> Vec<OwnedRule> {
    let control = implicit_ipv6_control();
    let mut rules = vec![
        OwnedRule::Loopback {
            chain: NFT_OUTPUT_CHAIN.to_owned(),
        },
        OwnedRule::EstablishedRelated {
            chain: NFT_OUTPUT_CHAIN.to_owned(),
        },
        OwnedRule::ImplicitIpv6Control {
            chain: NFT_OUTPUT_CHAIN.to_owned(),
            icmpv6_types: control
                .icmpv6_types
                .into_iter()
                .map(str::to_owned)
                .collect(),
            required_hop_limit: control.required_hop_limit,
        },
        OwnedRule::ClassifyDispatch {
            chain: NFT_OUTPUT_CHAIN.to_owned(),
        },
        OwnedRule::EstablishedRelated {
            chain: NFT_FORWARD_CHAIN.to_owned(),
        },
        OwnedRule::ClassifyDispatch {
            chain: NFT_FORWARD_CHAIN.to_owned(),
        },
    ];
    if dns_mediator_upstream {
        rules.push(OwnedRule::DnsMediatorUpstream {
            chain: NFT_CLASSIFY_CHAIN.to_owned(),
            uid: 0,
            destination: DNS_MEDIATOR_UPSTREAM_ADDRESS.to_owned(),
            protocol: "udp".to_owned(),
            port: DNS_MEDIATOR_UPSTREAM_PORT,
        });
        rules.extend(
            AZURE_WIRESERVER_TCP_PORTS.map(|port| OwnedRule::WireServerPlatform {
                chain: NFT_CLASSIFY_CHAIN.to_owned(),
                uid: AZURE_WIRESERVER_ROOT_UID,
                destination: AZURE_WIRESERVER_ADDRESS.to_owned(),
                protocol: "tcp".to_owned(),
                port,
            }),
        );
    }
    rules.extend(allowances.iter().map(|allowance| OwnedRule::Allowance {
        chain: NFT_CLASSIFY_CHAIN.to_owned(),
        address_family: if allowance.destination.contains(':') {
            "ip6".to_owned()
        } else {
            "ip".to_owned()
        },
        destination: allowance.destination.clone(),
        protocol: match allowance.protocol {
            Protocol::Tcp => "tcp".to_owned(),
            Protocol::Udp => "udp".to_owned(),
        },
        port: allowance.port,
    }));
    rules.push(OwnedRule::ViolationDispatch {
        chain: NFT_CLASSIFY_CHAIN.to_owned(),
    });
    rules.push(OwnedRule::SampledViolation {
        chain: NFT_VIOLATION_CHAIN.to_owned(),
        nflog_group: NFLOG_GROUP,
        prefix: nflog_prefix(mode).to_owned(),
        packet_prefix_bytes: NFLOG_PACKET_PREFIX_BYTES,
        sample_rate_per_second: NFLOG_SAMPLE_RATE_PER_SECOND,
        sample_burst: NFLOG_SAMPLE_BURST,
    });
    rules.push(OwnedRule::TerminalViolation {
        chain: NFT_VIOLATION_CHAIN.to_owned(),
        verdict: match mode {
            Mode::Block => "reject".to_owned(),
            Mode::Audit => "accept".to_owned(),
        },
    });
    rules
}

fn render_rule(program: &mut String, rule: &OwnedRule) {
    match rule {
        OwnedRule::Loopback { chain } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} oifname \"lo\" accept comment \"fence:loopback\""
            )
            .unwrap();
        }
        OwnedRule::EstablishedRelated { chain } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} ct state established,related accept comment \"fence:established\""
            )
            .unwrap();
        }
        OwnedRule::ImplicitIpv6Control {
            chain,
            required_hop_limit,
            ..
        } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} meta nfproto ipv6 ip6 hoplimit {required_hop_limit} icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} accept comment \"fence:implicit_ipv6_control\""
            )
            .unwrap();
        }
        OwnedRule::ClassifyDispatch { chain } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} jump {NFT_CLASSIFY_CHAIN} comment \"fence:classify\""
            )
            .unwrap();
        }
        OwnedRule::Allowance {
            chain,
            address_family,
            destination,
            protocol,
            port,
        } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} {address_family} daddr {destination} {protocol} dport {port} accept comment \"fence:allowance\""
            )
            .unwrap();
        }
        OwnedRule::DnsMediatorUpstream {
            chain,
            uid,
            destination,
            protocol,
            port,
        } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} meta skuid {uid} ip daddr {destination} {protocol} dport {port} accept comment \"fence:dns_mediator_upstream\""
            )
            .unwrap();
        }
        OwnedRule::WireServerPlatform {
            chain,
            uid,
            destination,
            protocol,
            port,
        } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} meta skuid {uid} ip daddr {destination} {protocol} dport {port} accept comment \"fence:wireserver_platform\""
            )
            .unwrap();
        }
        OwnedRule::ViolationDispatch { chain } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} jump {NFT_VIOLATION_CHAIN} comment \"fence:violation\""
            )
            .unwrap();
        }
        OwnedRule::SampledViolation {
            chain,
            nflog_group,
            prefix,
            packet_prefix_bytes,
            sample_rate_per_second,
            sample_burst,
        } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} limit rate {sample_rate_per_second}/second burst {sample_burst} packets counter name {NFT_SAMPLED_VIOLATIONS_COUNTER} log group {nflog_group} prefix \"{prefix}\" queue-threshold 1 snaplen {packet_prefix_bytes} comment \"fence:sample_violation\""
            )
            .unwrap();
        }
        OwnedRule::TerminalViolation { chain, verdict } => {
            writeln!(
                program,
                "add rule {NFT_FAMILY} {NFT_TABLE} {chain} counter name {NFT_TOTAL_VIOLATIONS_COUNTER} {verdict} comment \"fence:{verdict}_violation\""
            )
            .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DestinationType;

    fn allowances() -> Vec<EffectiveAllowance> {
        vec![
            EffectiveAllowance {
                destination_type: DestinationType::Ip,
                destination: "192.0.2.10".to_owned(),
                protocol: Protocol::Tcp,
                port: 443,
            },
            EffectiveAllowance {
                destination_type: DestinationType::Cidr,
                destination: "2001:db8::/64".to_owned(),
                protocol: Protocol::Udp,
                port: 53,
            },
        ]
    }

    #[test]
    fn renders_fixed_block_ruleset_with_allowances_and_implicit_control() {
        let preview = build_preview(Mode::Block, &allowances());

        assert_eq!(preview.owned_table.name, NFT_TABLE);
        assert!(preview.owned_table.single_active_invocation);
        assert_eq!(preview.hooks[0].priority, NFT_HOOK_PRIORITY);
        assert_eq!(
            preview.implicit_ipv6_control.icmpv6_types,
            vec![
                "router_solicitation",
                "neighbor_solicitation",
                "neighbor_advertisement"
            ]
        );
        assert!(preview.ruleset.starts_with("create table inet fence_v0\n"));
        assert!(
            preview
                .ruleset
                .contains("ip daddr 192.0.2.10 tcp dport 443")
        );
        assert!(
            preview
                .ruleset
                .contains("ip6 daddr 2001:db8::/64 udp dport 53")
        );
        assert!(preview.ruleset.contains("icmpv6 type { nd-router-solicit"));
        assert!(preview.ruleset.contains("prefix \"fence-v0-block\""));
        assert!(
            preview
                .ruleset
                .contains("counter name fence_total_violations reject")
        );
    }

    #[test]
    fn audit_uses_non_blocking_terminal_verdict_and_audit_prefix() {
        let program = render_ruleset(Mode::Audit, &[]);

        assert!(program.contains("prefix \"fence-v0-audit\""));
        assert!(program.contains("counter name fence_total_violations accept"));
        assert!(!program.contains("counter name fence_total_violations reject"));
    }

    #[test]
    fn renders_root_only_platform_service_rules_as_owned_backend_state() {
        let program = render_dns_mediated_ruleset(Mode::Block, &allowances());
        let replacement = render_dns_mediated_replacement_ruleset(Mode::Block, &allowances());
        let expected = expected_dns_mediated_owned_state(Mode::Block, &allowances());

        assert!(program.contains(
            "meta skuid 0 ip daddr 168.63.129.16 udp dport 53 accept comment \"fence:dns_mediator_upstream\""
        ));
        assert_eq!(
            program
                .matches("comment \"fence:wireserver_platform\"")
                .count(),
            2
        );
        assert!(program.contains(
            "meta skuid 0 ip daddr 168.63.129.16 tcp dport 80 accept comment \"fence:wireserver_platform\""
        ));
        assert!(program.contains(
            "meta skuid 0 ip daddr 168.63.129.16 tcp dport 32526 accept comment \"fence:wireserver_platform\""
        ));
        assert!(!program.contains("169.254.169.254"));
        assert!(
            replacement.starts_with("delete table inet fence_v0\ncreate table inet fence_v0\n")
        );
        assert!(expected.rules.iter().any(|rule| matches!(
            rule,
            OwnedRule::DnsMediatorUpstream {
                uid: 0,
                destination,
                port: 53,
                ..
            } if destination == "168.63.129.16"
        )));
        let wireserver = expected
            .rules
            .iter()
            .filter_map(|rule| match rule {
                OwnedRule::WireServerPlatform {
                    uid,
                    destination,
                    protocol,
                    port,
                    ..
                } => Some((*uid, destination.as_str(), protocol.as_str(), *port)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            wireserver,
            vec![
                (0, "168.63.129.16", "tcp", 80),
                (0, "168.63.129.16", "tcp", 32526)
            ]
        );
        let audit = render_dns_mediated_ruleset(Mode::Audit, &[]);
        assert_eq!(
            audit
                .matches("comment \"fence:wireserver_platform\"")
                .count(),
            2
        );
    }

    #[test]
    fn expected_state_is_deterministic_and_verification_detects_drift() {
        let expected = expected_owned_state(Mode::Block, &allowances());
        let identical = expected_owned_state(Mode::Block, &allowances());
        let mut drifted = identical.clone();
        drifted.chains[0] = OwnedChain::Regular {
            name: NFT_OUTPUT_CHAIN.to_owned(),
        };
        let round_trip: OwnedNftState =
            serde_json::from_slice(&serde_json::to_vec(&expected).unwrap()).unwrap();

        assert!(verify_owned_state(&expected, &identical).is_ok());
        assert_eq!(round_trip, expected);
        let failure = verify_owned_state(&expected, &drifted).unwrap_err();
        assert_eq!(failure.code, "owned_nft_state_mismatch");
        assert!(failure.message.contains("does not match"));
        assert!(
            expected
                .rules
                .iter()
                .any(|rule| matches!(rule, OwnedRule::ViolationDispatch { .. }))
        );
        assert_eq!(
            expected.counters,
            vec![
                NFT_SAMPLED_VIOLATIONS_COUNTER.to_owned(),
                NFT_TOTAL_VIOLATIONS_COUNTER.to_owned()
            ]
        );
    }

    #[test]
    fn dns_mediated_verification_rejects_missing_or_broadened_wireserver_rules() {
        let expected = expected_dns_mediated_owned_state(Mode::Block, &[]);
        let mut missing = expected.clone();
        missing
            .rules
            .retain(|rule| !matches!(rule, OwnedRule::WireServerPlatform { port: 80, .. }));
        assert!(verify_owned_state(&expected, &missing).is_err());

        let mut broadened = expected.clone();
        let rule = broadened
            .rules
            .iter_mut()
            .find(|rule| matches!(rule, OwnedRule::WireServerPlatform { port: 32526, .. }))
            .unwrap();
        if let OwnedRule::WireServerPlatform { uid, .. } = rule {
            *uid = 1001;
        }
        assert!(verify_owned_state(&expected, &broadened).is_err());

        let mut duplicated = expected.clone();
        let duplicate = duplicated
            .rules
            .iter()
            .find(|rule| matches!(rule, OwnedRule::WireServerPlatform { port: 80, .. }))
            .unwrap()
            .clone();
        duplicated.rules.push(duplicate);
        assert!(verify_owned_state(&expected, &duplicated).is_err());
    }

    #[test]
    fn evidence_schema_cannot_claim_readiness_or_containment_before_activation() {
        let evidence =
            unapplied_test_evidence_model(Mode::Audit, "policy".to_owned(), "ruleset".to_owned());

        assert_eq!(evidence.status, NETWORK_EVIDENCE_STATUS);
        assert_eq!(evidence.apply_status, "not_applied");
        assert_eq!(evidence.verification_status, "not_verified");
        assert_eq!(evidence.readiness_status, "not_emitted");
        assert_eq!(evidence.counters.total_violations, 0);
        assert!(evidence.findings.is_empty());
        assert!(
            evidence
                .limitations
                .contains(&"network_test_evidence_only_no_containment")
        );
    }
}
