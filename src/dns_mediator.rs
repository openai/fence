use crate::config::{MAX_REPORT_BYTES, Mode};
use crate::lifecycle::{NativeResidentNetwork, ResidentSession, validate_test_service_context};
use crate::plan::PlanData;
use crate::runtime::TestRuntimeStore;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const DNS_MEDIATION_EVIDENCE_STATUS: &str = "dns_mediation_audit_test_only";
pub const DNS_MEDIATED_GITHUB_CANDIDATE_ID: &str = "github_hosted_dns_mediated_candidate_v1";
pub const DNS_CANDIDATE_PATTERNS: [&str; 4] = [
    "*.actions.githubusercontent.com",
    "codeload.github.com",
    "actions-results-receiver-production.githubapp.com",
    "productionresultssa*.blob.core.windows.net",
];
const MAX_RETAINED_DNS_OBSERVATIONS: usize = 256;
const MAX_DNS_PACKET_BYTES: usize = 4096;
const UPSTREAM_DNS: &str = "168.63.129.16:53";
const HOST_DNS_BIND: &str = "127.0.0.1:53";
const DOCKER_DNS_BIND: &str = "172.17.0.1:53";
const RESOLVED_DROP_IN_DIR: &str = "/etc/systemd/resolved.conf.d";
const RESOLVED_DROP_IN_PATH: &str = "/etc/systemd/resolved.conf.d/90-fence-evidence.conf";
const DOCKER_DAEMON_PATH: &str = "/etc/docker/daemon.json";
const DNS_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

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
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsMediationEvidence {
    pub status: &'static str,
    pub candidate_profile_id: &'static str,
    pub candidate_domain_patterns: Vec<&'static str>,
    pub mode: Mode,
    pub protection_available: bool,
    pub routing_status: &'static str,
    pub host_dns_routing: &'static str,
    pub docker_dns_routing: &'static str,
    pub observations: Vec<DnsObservation>,
    pub observations_truncated: bool,
    pub excluded_non_github_query_count: u64,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Default)]
struct ObservationState {
    retained: BTreeMap<(String, u16, &'static str), u64>,
    truncated: bool,
    excluded_non_github_query_count: u64,
}

#[derive(Clone)]
struct ObservationRecorder {
    state: Arc<Mutex<ObservationState>>,
    report_path: PathBuf,
}

impl ObservationRecorder {
    fn record_query(&self, hostname: &str, query_type: u16) {
        let normalized = normalize_hostname(hostname);
        let mut state = self.state.lock().expect("DNS observation lock poisoned");
        if let Some(hostname) = normalized.filter(|name| reportable_github_hostname(name)) {
            let classification = if matches_candidate_pattern(&hostname) {
                "matches_candidate_pattern"
            } else {
                "github_related_outside_candidate"
            };
            let key = (hostname, query_type, classification);
            if let Some(count) = state.retained.get_mut(&key) {
                *count = count.saturating_add(1);
            } else if state.retained.len() < MAX_RETAINED_DNS_OBSERVATIONS {
                state.retained.insert(key, 1);
            } else {
                state.truncated = true;
            }
        } else {
            state.excluded_non_github_query_count =
                state.excluded_non_github_query_count.saturating_add(1);
        }
        let evidence = evidence_from_state(&state, "active_test_only");
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
        let evidence = evidence_from_state(&state, "active_test_only");
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
    fn establish(runtime_directory: &Path) -> Result<Self, DnsMediationError> {
        let report_path = runtime_directory.join("dns-report.json");
        let recorder = ObservationRecorder {
            state: Arc::new(Mutex::new(ObservationState::default())),
            report_path,
        };
        write_report(
            &recorder.report_path,
            &evidence_from_state(
                &recorder
                    .state
                    .lock()
                    .expect("DNS observation lock poisoned"),
                "setting_up",
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
    let mut mediation = DnsMediationSession::establish(&directory)?;
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
        if let Some((hostname, query_type)) = parse_dns_question(bytes) {
            recorder.record_query(&hostname, query_type);
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
            let _ = socket.send_to(&response[..response_length], peer);
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
        if let Some((hostname, query_type)) = parse_dns_question(&query) {
            recorder.record_query(&hostname, query_type);
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
        let _ = client.write_all(&response_length);
        let _ = client.write_all(&response);
    }
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
) -> DnsMediationEvidence {
    DnsMediationEvidence {
        status: DNS_MEDIATION_EVIDENCE_STATUS,
        candidate_profile_id: DNS_MEDIATED_GITHUB_CANDIDATE_ID,
        candidate_domain_patterns: DNS_CANDIDATE_PATTERNS.to_vec(),
        mode: Mode::Audit,
        protection_available: false,
        routing_status,
        host_dns_routing: "local_mediator_test_only",
        docker_dns_routing: "local_mediator_test_only",
        observations: state
            .retained
            .iter()
            .map(
                |((hostname, query_type, classification), occurrences)| DnsObservation {
                    hostname: hostname.clone(),
                    query_type: query_type_name(*query_type),
                    candidate_classification: classification,
                    occurrences: *occurrences,
                },
            )
            .collect(),
        observations_truncated: state.truncated,
        excluded_non_github_query_count: state.excluded_non_github_query_count,
        limitations: vec![
            "dns_mediation_audit_test_only_no_public_activation",
            "candidate_patterns_not_selected_as_platform_profile",
            "audit_observes_queries_without_blocking_names",
            "evidence_collected_before_hosted_job_teardown",
            "terminal_block_success_required_before_default_selection",
        ],
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
    fn builds_bounded_sanitized_evidence() {
        let mut state = ObservationState::default();
        state.retained.insert(
            (
                "pipelines.actions.githubusercontent.com".to_owned(),
                1,
                "matches_candidate_pattern",
            ),
            2,
        );
        state.excluded_non_github_query_count = 1;
        let evidence = evidence_from_state(&state, "active_test_only");
        assert_eq!(evidence.observations.len(), 1);
        assert_eq!(evidence.observations[0].query_type, "a");
        assert_eq!(evidence.observations[0].occurrences, 2);
        assert_eq!(evidence.excluded_non_github_query_count, 1);
        assert!(!evidence.protection_available);
    }
}
