use crate::error::ErrorDetail;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_ALLOWANCES: usize = 64;
pub const MAX_RESOLVED_ADDRESSES: usize = 32;
pub const MAX_EXPANDED_RULES: usize = 1024;
pub const MAX_FINDINGS: usize = 1024;
pub const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigInput {
    schema_version: u64,
    mode: String,
    invocation_id: String,
    #[serde(default)]
    platform_profile: Option<String>,
    #[serde(default)]
    container_policy: Option<String>,
    allowlist: Vec<AllowanceInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowanceInput {
    destination_type: String,
    destination: String,
    protocol: String,
    port: u64,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Block,
    Audit,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerPolicy {
    Disable,
    UnsafePreserve,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformProfile {
    GithubHostedJobStatusV1,
}

impl PlatformProfile {
    pub fn id(self) -> &'static str {
        match self {
            Self::GithubHostedJobStatusV1 => "github_hosted_job_status_v1",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationType {
    Hostname,
    Ip,
    Cidr,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NormalizedAllowance {
    pub destination_type: DestinationType,
    pub destination: String,
    pub protocol: Protocol,
    pub port: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NormalizedConfig {
    pub schema_version: u32,
    pub mode: Mode,
    pub invocation_id: String,
    pub platform_profile: PlatformProfile,
    pub container_policy: Option<ContainerPolicy>,
    pub requested_allowances: Vec<NormalizedAllowance>,
    pub declared_allowance_count: usize,
    pub duplicate_requested_allowances_collapsed: usize,
}

pub fn read_config_bounded(path: &Path) -> Result<Vec<u8>, ErrorDetail> {
    let mut file = File::open(path).map_err(|_| {
        ErrorDetail::new(
            "config_read_failed",
            "configuration file could not be opened",
        )
        .field("config")
    })?;
    read_config_reader_bounded(&mut file)
}

fn read_config_reader_bounded(reader: &mut dyn Read) -> Result<Vec<u8>, ErrorDetail> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            ErrorDetail::new("config_read_failed", "configuration file could not be read")
                .field("config")
        })?;
    check_input_size(&bytes)?;
    Ok(bytes)
}

pub fn parse_and_normalize(bytes: &[u8]) -> Result<NormalizedConfig, ErrorDetail> {
    check_input_size(bytes)?;
    let input: ConfigInput = serde_json::from_slice(bytes).map_err(|_| {
        ErrorDetail::new(
            "invalid_json_configuration",
            "configuration must be strict valid JSON with only recognized fields",
        )
    })?;

    if input.schema_version != u64::from(CONFIG_SCHEMA_VERSION) {
        return Err(
            ErrorDetail::new("invalid_schema_version", "schema_version must be 1")
                .field("schema_version"),
        );
    }
    let mode = match input.mode.as_str() {
        "block" => Mode::Block,
        "audit" => Mode::Audit,
        _ => {
            return Err(
                ErrorDetail::new("invalid_mode", "mode must be block or audit").field("mode"),
            );
        }
    };
    if !valid_invocation_id(&input.invocation_id) {
        return Err(ErrorDetail::new(
            "invalid_invocation_id",
            "invocation_id must be a lowercase slug of 1 through 64 bytes",
        )
        .field("invocation_id"));
    }
    let platform_profile = match input
        .platform_profile
        .as_deref()
        .unwrap_or("github_hosted_job_status_v1")
    {
        "github_hosted_job_status_v1" => PlatformProfile::GithubHostedJobStatusV1,
        _ => {
            return Err(ErrorDetail::new(
                "invalid_platform_profile",
                "platform_profile must be github_hosted_job_status_v1",
            )
            .field("platform_profile"));
        }
    };
    let container_policy = normalize_container_policy(mode, input.container_policy.as_deref())?;
    if input.allowlist.len() > MAX_ALLOWANCES {
        return Err(ErrorDetail::new(
            "too_many_allowlist_entries",
            "allowlist exceeds the fixed v0 limit",
        )
        .field("allowlist"));
    }

    let declared_allowance_count = input.allowlist.len();
    let mut requested_allowances = input
        .allowlist
        .iter()
        .enumerate()
        .map(|(index, allowance)| normalize_allowance(allowance, index))
        .collect::<Result<Vec<_>, _>>()?;
    requested_allowances.sort();
    requested_allowances.dedup();

    Ok(NormalizedConfig {
        schema_version: CONFIG_SCHEMA_VERSION,
        mode,
        invocation_id: input.invocation_id,
        platform_profile,
        container_policy,
        duplicate_requested_allowances_collapsed: declared_allowance_count
            - requested_allowances.len(),
        requested_allowances,
        declared_allowance_count,
    })
}

fn check_input_size(bytes: &[u8]) -> Result<(), ErrorDetail> {
    if bytes.len() > MAX_CONFIG_BYTES {
        Err(ErrorDetail::new(
            "config_too_large",
            "configuration exceeds the 256 KiB input limit",
        )
        .field("config"))
    } else {
        Ok(())
    }
}

fn normalize_container_policy(
    mode: Mode,
    value: Option<&str>,
) -> Result<Option<ContainerPolicy>, ErrorDetail> {
    match (mode, value) {
        (Mode::Block, None | Some("disable")) => Ok(Some(ContainerPolicy::Disable)),
        (Mode::Block, Some("unsafe_preserve")) => Ok(Some(ContainerPolicy::UnsafePreserve)),
        (Mode::Audit, None) => Ok(None),
        (Mode::Audit, Some(_)) => Err(ErrorDetail::new(
            "invalid_container_policy",
            "audit mode does not accept container_policy",
        )
        .field("container_policy")),
        (Mode::Block, Some(_)) => Err(ErrorDetail::new(
            "invalid_container_policy",
            "block container_policy must be disable or unsafe_preserve",
        )
        .field("container_policy")),
    }
}

fn normalize_allowance(
    input: &AllowanceInput,
    index: usize,
) -> Result<NormalizedAllowance, ErrorDetail> {
    let protocol = match input.protocol.as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => {
            return Err(ErrorDetail::new(
                "invalid_protocol",
                "allowlist protocol must be tcp or udp",
            )
            .indexed_field("allowlist.protocol", index));
        }
    };
    let port = u16::try_from(input.port)
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            ErrorDetail::new(
                "invalid_port",
                "allowlist port must be from 1 through 65535",
            )
            .indexed_field("allowlist.port", index)
        })?;
    let (destination_type, destination) = match input.destination_type.as_str() {
        "hostname" => (
            DestinationType::Hostname,
            normalize_hostname(&input.destination).ok_or_else(|| {
                ErrorDetail::new(
                    "invalid_destination",
                    "hostname destination is not a valid explicit DNS name",
                )
                .indexed_field("allowlist.destination", index)
            })?,
        ),
        "ip" => (
            DestinationType::Ip,
            input
                .destination
                .parse::<IpAddr>()
                .map(|ip| ip.to_string())
                .map_err(|_| {
                    ErrorDetail::new(
                        "invalid_destination",
                        "IP destination is not a valid literal address",
                    )
                    .indexed_field("allowlist.destination", index)
                })?,
        ),
        "cidr" => (
            DestinationType::Cidr,
            normalize_cidr(&input.destination).ok_or_else(|| {
                ErrorDetail::new(
                    "invalid_destination",
                    "CIDR destination must identify an explicit canonical network",
                )
                .indexed_field("allowlist.destination", index)
            })?,
        ),
        _ => {
            return Err(ErrorDetail::new(
                "invalid_destination_type",
                "destination_type must be hostname, ip, or cidr",
            )
            .indexed_field("allowlist.destination_type", index));
        }
    };

    Ok(NormalizedAllowance {
        destination_type,
        destination,
        protocol,
        port,
    })
}

fn valid_invocation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.as_bytes().windows(2).any(|pair| pair == b"--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn normalize_hostname(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.ends_with('.')
        || value.parse::<IpAddr>().is_ok()
    {
        return None;
    }
    let normalized = value.to_ascii_lowercase();
    if resembles_numeric_ipv4_address(&normalized) {
        return None;
    }
    if normalized.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    }) {
        Some(normalized)
    } else {
        None
    }
}

// System resolvers accept legacy IPv4 numbers such as 127.1 and 0x7f000001.
fn resembles_numeric_ipv4_address(value: &str) -> bool {
    let mut components = value.split('.');
    let component_count = components.clone().count();
    (1..=4).contains(&component_count) && components.all(is_numeric_ipv4_component)
}

fn is_numeric_ipv4_component(component: &str) -> bool {
    if let Some(hex) = component.strip_prefix("0x") {
        !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    } else {
        !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
    }
}

fn normalize_cidr(value: &str) -> Option<String> {
    let (address, prefix) = value.split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    match address {
        IpAddr::V4(address) => {
            if prefix > 32 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            if u32::from(address) & !mask != 0 {
                return None;
            }
        }
        IpAddr::V6(address) => {
            if prefix > 128 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            if u128::from(address) & !mask != 0 {
                return None;
            }
        }
    }
    Some(format!("{address}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Vec<u8> {
        format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"build-1","allowlist":[]{} }}"#,
            extra
        )
        .into_bytes()
    }

    fn one_allowance(
        destination_type: &str,
        destination: &str,
        protocol: &str,
        port: u64,
    ) -> Vec<u8> {
        format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"build-1","allowlist":[{{"destination_type":"{destination_type}","destination":"{destination}","protocol":"{protocol}","port":{port}}}]}}"#
        )
        .into_bytes()
    }

    #[test]
    fn normalizes_empty_block_policy_and_defaults() {
        let parsed = parse_and_normalize(&config("")).unwrap();

        assert_eq!(parsed.mode, Mode::Block);
        assert_eq!(parsed.container_policy, Some(ContainerPolicy::Disable));
        assert_eq!(
            parsed.platform_profile,
            PlatformProfile::GithubHostedJobStatusV1
        );
        assert!(parsed.requested_allowances.is_empty());
    }

    #[test]
    fn accepts_explicit_selected_profile_audit_without_lockdown_and_degraded_block() {
        let audit = parse_and_normalize(
            br#"{"schema_version":1,"mode":"audit","invocation_id":"audit-1","platform_profile":"github_hosted_job_status_v1","allowlist":[]}"#,
        )
        .unwrap();
        let degraded = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"block-1","platform_profile":"github_hosted_job_status_v1","container_policy":"unsafe_preserve","allowlist":[]}"#,
        )
        .unwrap();

        assert_eq!(audit.container_policy, None);
        assert_eq!(
            audit.platform_profile,
            PlatformProfile::GithubHostedJobStatusV1
        );
        assert_eq!(
            degraded.container_policy,
            Some(ContainerPolicy::UnsafePreserve)
        );
        assert_eq!(
            degraded.platform_profile,
            PlatformProfile::GithubHostedJobStatusV1
        );
    }

    #[test]
    fn rejects_top_level_contract_violations() {
        let invalid_cases = [
            (
                br#"{"schema_version":2,"mode":"block","invocation_id":"x","allowlist":[]}"#
                    .as_slice(),
                "invalid_schema_version",
            ),
            (
                br#"{"schema_version":1,"mode":"observe","invocation_id":"x","allowlist":[]}"#
                    .as_slice(),
                "invalid_mode",
            ),
            (
                br#"{"schema_version":1,"mode":"block","invocation_id":"Bad-ID","allowlist":[]}"#
                    .as_slice(),
                "invalid_invocation_id",
            ),
            (
                br#"{"schema_version":1,"mode":"block","invocation_id":"x","platform_profile":"default","allowlist":[]}"#
                    .as_slice(),
                "invalid_platform_profile",
            ),
            (
                br#"{"schema_version":1,"mode":"block","invocation_id":"x","platform_profile":"none","allowlist":[]}"#
                    .as_slice(),
                "invalid_platform_profile",
            ),
            (
                br#"{"schema_version":1,"mode":"block","invocation_id":"x","platform_profile":"github_hosted_https_udp_dns_candidate_v1","allowlist":[]}"#
                    .as_slice(),
                "invalid_platform_profile",
            ),
            (
                br#"{"schema_version":1,"mode":"audit","invocation_id":"x","container_policy":"disable","allowlist":[]}"#
                    .as_slice(),
                "invalid_container_policy",
            ),
            (
                br#"{"schema_version":1,"mode":"block","invocation_id":"x","container_policy":"other","allowlist":[]}"#
                    .as_slice(),
                "invalid_container_policy",
            ),
        ];

        for (bytes, expected) in invalid_cases {
            assert_eq!(parse_and_normalize(bytes).unwrap_err().code, expected);
        }
    }

    #[test]
    fn rejects_unknown_json_fields_and_oversized_input() {
        assert_eq!(
            parse_and_normalize(&config(r#","unknown":true"#))
                .unwrap_err()
                .code,
            "invalid_json_configuration"
        );
        assert_eq!(
            parse_and_normalize(br#"{"schema_version":1,"invocation_id":"x","allowlist":[]}"#)
                .unwrap_err()
                .code,
            "invalid_json_configuration"
        );
        assert_eq!(
            parse_and_normalize(
                br#"{"schema_version":1,"mode":"block","invocation_id":"x","allowlist":[{"destination_type":"ip","destination":"192.0.2.1","protocol":"tcp","port":443,"unknown":true}]}"#
            )
            .unwrap_err()
            .code,
            "invalid_json_configuration"
        );
        assert_eq!(
            parse_and_normalize(
                br#"{"schema_version":1,"mode":"block","invocation_id":"x","allowances":[]}"#
            )
            .unwrap_err()
            .code,
            "invalid_json_configuration"
        );
        assert_eq!(
            parse_and_normalize(&vec![b' '; MAX_CONFIG_BYTES + 1])
                .unwrap_err()
                .code,
            "config_too_large"
        );
    }

    #[test]
    fn validates_invocation_slug_boundaries() {
        for valid in ["a", "build-012345", &"a".repeat(64)] {
            assert!(valid_invocation_id(valid));
        }
        for invalid in ["", "-a", "a-", "a--b", "A", "a_b", &"a".repeat(65)] {
            assert!(!valid_invocation_id(invalid));
        }
    }

    #[test]
    fn normalizes_typed_destinations_and_deduplicates() {
        let parsed = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"x","allowlist":[{"destination_type":"hostname","destination":"Example.COM","protocol":"tcp","port":443},{"destination_type":"hostname","destination":"example.com","protocol":"tcp","port":443},{"destination_type":"ip","destination":"2001:0db8::1","protocol":"udp","port":53},{"destination_type":"cidr","destination":"192.0.2.0/24","protocol":"tcp","port":443}]}"#,
        )
        .unwrap();
        let zero_prefix_networks = parse_and_normalize(
            br#"{"schema_version":1,"mode":"block","invocation_id":"x","allowlist":[{"destination_type":"cidr","destination":"0.0.0.0/0","protocol":"tcp","port":443},{"destination_type":"cidr","destination":"::/0","protocol":"udp","port":53}]}"#,
        )
        .unwrap();

        assert_eq!(parsed.declared_allowance_count, 4);
        assert_eq!(parsed.duplicate_requested_allowances_collapsed, 1);
        assert_eq!(parsed.requested_allowances.len(), 3);
        assert!(
            parsed
                .requested_allowances
                .iter()
                .any(|rule| rule.destination == "example.com")
        );
        assert!(
            parsed
                .requested_allowances
                .iter()
                .any(|rule| rule.destination == "2001:db8::1")
        );
        assert_eq!(zero_prefix_networks.requested_allowances.len(), 2);
        assert_eq!(
            normalize_hostname("127.1.example.com").as_deref(),
            Some("127.1.example.com")
        );
    }

    #[test]
    fn rejects_invalid_allowance_shapes() {
        let cases = [
            (
                one_allowance("domain", "example.com", "tcp", 443),
                "invalid_destination_type",
            ),
            (
                one_allowance("hostname", "*.example.com", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("hostname", "https://example.com", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("hostname", "192.0.2.1", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("hostname", "2130706433", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("hostname", "127.1", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("hostname", "0X7f000001", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("hostname", "0177.0.0.1", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("ip", "not-an-ip", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("cidr", "192.0.2.1/24", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("cidr", "192.0.2.0/33", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("cidr", "192.0.2.0/24/1", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("cidr", "192.0.2.0", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("cidr", "not-an-ip/24", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("cidr", "2001:db8::1/64", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("cidr", "2001:db8::/129", "tcp", 443),
                "invalid_destination",
            ),
            (
                one_allowance("ip", "192.0.2.1", "icmp", 443),
                "invalid_protocol",
            ),
            (one_allowance("ip", "192.0.2.1", "tcp", 0), "invalid_port"),
            (
                one_allowance("ip", "192.0.2.1", "tcp", 65536),
                "invalid_port",
            ),
        ];

        for (bytes, expected) in cases {
            assert_eq!(parse_and_normalize(&bytes).unwrap_err().code, expected);
        }
    }

    #[test]
    fn rejects_more_than_fixed_allowance_limit() {
        let rule =
            r#"{"destination_type":"ip","destination":"192.0.2.1","protocol":"tcp","port":443}"#;
        let allowances = std::iter::repeat_n(rule, MAX_ALLOWANCES + 1)
            .collect::<Vec<_>>()
            .join(",");
        let bytes = format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"x","allowlist":[{allowances}]}}"#
        );

        assert_eq!(
            parse_and_normalize(bytes.as_bytes()).unwrap_err().code,
            "too_many_allowlist_entries"
        );
    }

    #[test]
    fn reads_bounded_files_and_reports_missing_files() {
        let root = Path::new("target/tmp/config-tests");
        std::fs::create_dir_all(root).unwrap();
        let valid = root.join("valid.json");
        let too_large = root.join("large.json");
        std::fs::write(&valid, config("")).unwrap();
        std::fs::write(&too_large, vec![b'x'; MAX_CONFIG_BYTES + 1]).unwrap();

        assert!(!read_config_bounded(&valid).unwrap().is_empty());
        assert_eq!(
            read_config_bounded(&too_large).unwrap_err().code,
            "config_too_large"
        );
        assert_eq!(
            read_config_bounded(&root.join("missing.json"))
                .unwrap_err()
                .code,
            "config_read_failed"
        );
    }

    #[test]
    fn reports_configuration_reader_failures() {
        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("deliberate read failure"))
            }
        }

        let mut reader = FailingReader;
        assert_eq!(
            read_config_reader_bounded(&mut reader).unwrap_err().code,
            "config_read_failed"
        );
    }
}
