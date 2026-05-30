#![cfg(target_os = "linux")]

use fence::config::{
    DestinationType, MAX_FINDINGS, MAX_REPORT_BYTES, Mode, Protocol, parse_and_normalize,
};
use fence::findings::FindingCollection;
use fence::lifecycle::run_resident_test_service;
use fence::nflog::NflogReader;
use fence::nft::{
    NetworkEvidenceCounters, expected_owned_state, render_ruleset, unapplied_test_evidence_model,
};
use fence::nft_backend::{
    IP_BINARY_PATH, NativeNftBackend, SystemNftExecutor, write_test_evidence,
};
use fence::plan::{EffectiveAllowance, build_plan};
use fence::resolver::{Resolution, ResolveError, Resolver};
use fence::runtime::{RESIDENT_EVIDENCE_STATUS, TEST_READY_STATUS};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static TEST_INDEX: AtomicUsize = AtomicUsize::new(0);
const PYTHON: &str = "/usr/bin/python3";
const PING: &str = "/usr/bin/ping";

struct NoResolver;

impl Resolver for NoResolver {
    fn resolve(&self, _hostname: &str, _timeout: Duration) -> Result<Resolution, ResolveError> {
        panic!("privileged fixtures contain concrete destinations only");
    }
}

struct PeerTopology {
    client: String,
    server: String,
}

impl PeerTopology {
    fn new() -> Self {
        let suffix = unique_suffix();
        let client = format!("fence-c-{suffix}");
        let server = format!("fence-s-{suffix}");
        let client_link = format!("fc{}", &suffix[suffix.len().saturating_sub(6)..]);
        let server_link = format!("fs{}", &suffix[suffix.len().saturating_sub(6)..]);
        ip(&["netns", "add", &client]);
        ip(&["netns", "add", &server]);
        ip(&[
            "link",
            "add",
            &client_link,
            "type",
            "veth",
            "peer",
            "name",
            &server_link,
        ]);
        ip(&["link", "set", &client_link, "netns", &client]);
        ip(&["link", "set", &server_link, "netns", &server]);
        ip(&["-n", &client, "link", "set", "lo", "up"]);
        ip(&["-n", &server, "link", "set", "lo", "up"]);
        ip(&["-n", &client, "link", "set", &client_link, "up"]);
        ip(&["-n", &server, "link", "set", &server_link, "up"]);
        ip(&[
            "-n",
            &client,
            "addr",
            "add",
            "192.0.2.1/24",
            "dev",
            &client_link,
        ]);
        ip(&[
            "-n",
            &server,
            "addr",
            "add",
            "192.0.2.2/24",
            "dev",
            &server_link,
        ]);
        ip(&[
            "-n",
            &client,
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/64",
            "dev",
            &client_link,
            "nodad",
        ]);
        ip(&[
            "-n",
            &server,
            "-6",
            "addr",
            "add",
            "2001:db8:1::2/64",
            "dev",
            &server_link,
            "nodad",
        ]);
        Self { client, server }
    }
}

impl Drop for PeerTopology {
    fn drop(&mut self) {
        let _ = Command::new(IP_BINARY_PATH)
            .args(["netns", "del", &self.client])
            .status();
        let _ = Command::new(IP_BINARY_PATH)
            .args(["netns", "del", &self.server])
            .status();
    }
}

struct RoutedTopology {
    source: String,
    router: String,
    sink: String,
}

impl RoutedTopology {
    fn new() -> Self {
        let suffix = unique_suffix();
        let source = format!("fence-a-{suffix}");
        let router = format!("fence-r-{suffix}");
        let sink = format!("fence-b-{suffix}");
        for namespace in [&source, &router, &sink] {
            ip(&["netns", "add", namespace]);
            ip(&["-n", namespace, "link", "set", "lo", "up"]);
        }
        connect_namespaces(
            &source,
            "as0",
            &router,
            "ra0",
            "198.51.100.2/24",
            "198.51.100.1/24",
        );
        connect_namespaces(
            &router,
            "rb0",
            &sink,
            "bs0",
            "203.0.113.1/24",
            "203.0.113.2/24",
        );
        in_namespace(
            &source,
            "/usr/sbin/ip",
            &["route", "add", "203.0.113.0/24", "via", "198.51.100.1"],
        );
        in_namespace(
            &sink,
            "/usr/sbin/ip",
            &["route", "add", "198.51.100.0/24", "via", "203.0.113.1"],
        );
        in_namespace(
            &router,
            "/usr/sbin/sysctl",
            &["-qw", "net.ipv4.ip_forward=1"],
        );
        Self {
            source,
            router,
            sink,
        }
    }
}

impl Drop for RoutedTopology {
    fn drop(&mut self) {
        for namespace in [&self.source, &self.router, &self.sink] {
            let _ = Command::new(IP_BINARY_PATH)
                .args(["netns", "del", namespace])
                .status();
        }
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct ServiceGuard {
    unit: String,
}

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/systemctl")
            .args(["stop", &self.unit])
            .status();
        let _ = Command::new("/usr/bin/systemctl")
            .args(["reset-failed", &self.unit])
            .status();
    }
}

#[test]
#[ignore = "executed as a helper inside a disposable network namespace"]
fn nflog_worker_collects_bounded_findings() {
    if std::env::var_os("FENCE_NFLOG_WORKER").is_none() {
        return;
    }
    let mode = match std::env::var("FENCE_NFLOG_MODE").unwrap().as_str() {
        "block" => Mode::Block,
        "audit" => Mode::Audit,
        other => panic!("invalid worker mode: {other}"),
    };
    let expected = std::env::var("FENCE_NFLOG_EXPECTED")
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let ready = PathBuf::from(std::env::var_os("FENCE_NFLOG_READY").unwrap());
    let output = PathBuf::from(std::env::var_os("FENCE_NFLOG_OUTPUT").unwrap());
    let reader = NflogReader::bind(mode).unwrap();
    fs::write(&ready, b"bound").unwrap();
    let mut collection = FindingCollection::empty();
    let deadline = Instant::now() + Duration::from_secs(30);
    while collection.sampled_total < expected && Instant::now() < deadline {
        if let Some(finding) = reader.next_finding(Duration::from_millis(100)).unwrap() {
            collection.record_finding(finding);
        }
    }
    assert!(
        collection.sampled_total >= expected,
        "expected {expected} NFLOG findings, received {}",
        collection.sampled_total
    );
    fs::write(output, serde_json::to_vec(&collection).unwrap()).unwrap();
}

#[test]
#[ignore = "executed as a transient systemd service in a disposable network namespace"]
fn resident_service_worker() {
    if std::env::var_os("FENCE_RESIDENT_WORKER").is_none() {
        return;
    }
    require_root();
    let invocation_id = std::env::var("FENCE_RESIDENT_INVOCATION").unwrap();
    let runtime_root = PathBuf::from(std::env::var_os("FENCE_RESIDENT_ROOT").unwrap());
    let unit = std::env::var("FENCE_RESIDENT_UNIT").unwrap();
    let config = format!(
        r#"{{"schema_version":1,"mode":"block","invocation_id":"{invocation_id}","allowlist":[]}}"#
    );
    let plan = build_plan(parse_and_normalize(config.as_bytes()).unwrap(), &NoResolver).unwrap();
    let expected = if std::env::var_os("FENCE_RESIDENT_INJECT_PRE_READY_FAILURE").is_some() {
        Some(expected_owned_state(Mode::Audit, &[]))
    } else {
        None
    };
    let result = run_resident_test_service(&unit, &runtime_root, &plan, expected);
    if std::env::var_os("FENCE_RESIDENT_INJECT_PRE_READY_FAILURE").is_some() {
        assert_eq!(result.unwrap_err().code, "owned_nft_state_mismatch");
    } else {
        result.unwrap();
    }
}

#[test]
#[ignore = "requires Linux root network namespaces and native nftables"]
fn block_and_audit_output_paths_emit_only_test_evidence() {
    require_root();
    let topology = PeerTopology::new();
    let root = evidence_root();
    fs::create_dir_all(&root).unwrap();

    let block_allowances = vec![
        allowance("192.0.2.2", Protocol::Tcp, 18443),
        allowance("192.0.2.2", Protocol::Udp, 18444),
        allowance("2001:db8:1::2", Protocol::Tcp, 18443),
        allowance("2001:db8:1::2", Protocol::Udp, 18444),
    ];
    let (mut block_worker, block_findings_path) =
        start_nflog_worker(&topology.client, Mode::Block, "block-findings", 5);
    let mut block = backend(&topology.client);
    let block_program = render_ruleset(Mode::Block, &block_allowances);
    block.preflight(&block_program).unwrap();
    block.apply_provisional(&block_program).unwrap();
    block
        .verify_owned_state(&expected_owned_state(Mode::Block, &block_allowances))
        .unwrap();
    assert!(traffic_with_listener(&topology, "192.0.2.2", "tcp", 18443));
    assert!(traffic_with_listener(&topology, "192.0.2.2", "udp", 18444));
    assert!(traffic_with_listener(
        &topology,
        "2001:db8:1::2",
        "tcp",
        18443
    ));
    assert!(traffic_with_listener(
        &topology,
        "2001:db8:1::2",
        "udp",
        18444
    ));
    let marker = "fence-private-payload-marker";
    assert!(!traffic_with_listener_payload(
        &topology,
        "192.0.2.2",
        "udp",
        19444,
        marker
    ));
    assert!(!traffic_with_listener(&topology, "192.0.2.2", "tcp", 19443));
    assert!(!traffic_with_listener(
        &topology,
        "2001:db8:1::2",
        "tcp",
        19443
    ));
    assert!(!traffic_with_listener(
        &topology,
        "2001:db8:1::2",
        "udp",
        19444
    ));
    assert!(!in_namespace_status(
        &topology.client,
        PING,
        &["-6", "-c", "1", "-W", "1", "2001:db8:1::2"]
    ));
    let blocked = block.total_violation_packets().unwrap();
    assert!(blocked >= 5);
    let block_findings = finish_nflog_worker(&mut block_worker, &block_findings_path, Some(marker));
    assert!(block_findings.retained.iter().any(|finding| {
        finding.family == "ipv4" && finding.protocol == "udp" && finding.remote_port == Some(19444)
    }));
    assert!(block_findings.retained.iter().any(|finding| {
        finding.family == "ipv6" && finding.protocol == "tcp" && finding.remote_port == Some(19443)
    }));
    assert!(
        !serde_json::to_string(&block_findings)
            .unwrap()
            .contains(marker)
    );
    let planned = build_plan(
        parse_and_normalize(br#"{"schema_version":1,"mode":"block","invocation_id":"block-output","allowlist":[{"destination_type":"ip","destination":"192.0.2.2","protocol":"tcp","port":18443},{"destination_type":"ip","destination":"192.0.2.2","protocol":"udp","port":18444},{"destination_type":"ip","destination":"2001:db8:1::2","protocol":"tcp","port":18443},{"destination_type":"ip","destination":"2001:db8:1::2","protocol":"udp","port":18444}]}"#).unwrap(),
        &NoResolver,
    )
    .unwrap();
    assert_eq!(planned.effective_policy, block_allowances);
    let mut evidence =
        unapplied_test_evidence_model(Mode::Block, planned.policy_hash, planned.ruleset_hash);
    evidence.apply_status = "applied";
    evidence.verification_status = "verified";
    evidence.counters = NetworkEvidenceCounters {
        total_violations: blocked,
        sampled_violations: block_findings.sampled_total,
    };
    evidence.findings = block_findings.retained;
    evidence.findings_truncated = block_findings.truncated;
    let directory = write_test_evidence(
        &root,
        "block-output",
        &evidence,
        &expected_owned_state(Mode::Block, &block_allowances),
    )
    .unwrap();
    assert_eq!(fs::metadata(directory.join("state.json")).unwrap().uid(), 0);
    assert_eq!(
        fs::metadata(directory.join("report.json")).unwrap().uid(),
        0
    );
    assert!(
        !String::from_utf8(fs::read(directory.join("state.json")).unwrap())
            .unwrap()
            .contains(marker)
    );
    assert!(
        !String::from_utf8(fs::read(directory.join("report.json")).unwrap())
            .unwrap()
            .contains(marker)
    );
    assert!(!directory.join("ready.json").exists());
    assert!(block.rollback_pre_activation().unwrap());

    let audit_allowances = Vec::new();
    let (mut audit_worker, audit_findings_path) =
        start_nflog_worker(&topology.client, Mode::Audit, "audit-findings", 2);
    let mut audit = backend(&topology.client);
    let audit_program = render_ruleset(Mode::Audit, &audit_allowances);
    audit.preflight(&audit_program).unwrap();
    audit.apply_provisional(&audit_program).unwrap();
    audit
        .verify_owned_state(&expected_owned_state(Mode::Audit, &audit_allowances))
        .unwrap();
    assert!(traffic_with_listener(&topology, "192.0.2.2", "tcp", 20443));
    assert!(traffic_with_listener(
        &topology,
        "2001:db8:1::2",
        "udp",
        20444
    ));
    assert!(audit.total_violation_packets().unwrap() >= 2);
    let audit_findings = finish_nflog_worker(&mut audit_worker, &audit_findings_path, None);
    assert_eq!(audit_findings.sampled_total, 2);
    assert!(audit_findings.retained.iter().all(
        |finding| finding.classification == fence::findings::FindingClassification::WouldBlock
    ));
    assert!(audit.rollback_pre_activation().unwrap());
}

#[test]
#[ignore = "requires Linux root, transient systemd services, namespaces, and native nftables"]
fn resident_systemd_service_reports_drift_without_restoring_post_ready_state() {
    require_root();
    let topology = PeerTopology::new();
    let invocation = format!("resident-{}", unique_suffix());
    let root = PathBuf::from(format!("/run/fence-resident-evidence-{invocation}"));
    let _service = start_resident_service(&topology.client, &root, &invocation, false);
    let directory = root.join(&invocation);
    wait_for_path(&directory.join("ready.json"));

    let ready = fs::read_to_string(directory.join("ready.json")).unwrap();
    assert!(ready.contains(TEST_READY_STATUS));
    assert!(ready.contains("\"protection_available\":false"));
    assert_eq!(fs::metadata(directory.join("ready.json")).unwrap().uid(), 0);
    assert_eq!(
        fs::metadata(directory.join("report.json")).unwrap().uid(),
        0
    );
    must_succeed(
        Command::new("/usr/bin/sudo")
            .args([
                "--non-interactive",
                "--user",
                "runner",
                "--",
                "/usr/bin/cat",
            ])
            .arg(directory.join("report.json"))
            .output()
            .unwrap(),
    );
    assert!(!Path::new(&format!("/run/fence/{invocation}/ready.json")).exists());

    nft_in_namespace(
        &topology.client,
        &[
            "add",
            "rule",
            "inet",
            "fence_v0",
            "fence_output",
            "counter",
            "comment",
            "\"fence:test_drift\"",
        ],
    );
    wait_for_report_value(&directory.join("report.json"), "resident_network_drift");
    let report = fs::read_to_string(directory.join("report.json")).unwrap();
    assert!(report.contains(RESIDENT_EVIDENCE_STATUS));
    assert!(report.contains("\"verification_status\":\"critical_drift\""));
    assert!(report.contains("\"readiness_status\":\"test_only_ready_no_protection\""));

    drop(_service);
    nft_in_namespace(&topology.client, &["list", "table", "inet", "fence_v0"]);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires Linux root, transient systemd services, namespaces, and native nftables"]
fn resident_pre_ready_verification_failure_rolls_back_owned_state_without_ready() {
    require_root();
    let topology = PeerTopology::new();
    let invocation = format!("resident-fail-{}", unique_suffix());
    let root = PathBuf::from(format!("/run/fence-resident-evidence-{invocation}"));
    let _service = start_resident_service(&topology.client, &root, &invocation, true);
    let directory = root.join(&invocation);
    wait_for_report_value(&directory.join("report.json"), "rolled_back_pre_ready");
    assert!(!directory.join("ready.json").exists());
    assert!(!Path::new(&format!("/run/fence/{invocation}/ready.json")).exists());
    assert!(!in_namespace_status(
        &topology.client,
        "/usr/sbin/nft",
        &["list", "table", "inet", "fence_v0"]
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires Linux root network namespaces and native nftables"]
fn conflict_preflight_and_rollback_are_confined_to_owned_namespace_state() {
    require_root();
    let topology = PeerTopology::new();
    let mut first = backend(&topology.client);
    let program = render_ruleset(Mode::Block, &[]);
    first.preflight(&program).unwrap();
    first.apply_provisional(&program).unwrap();
    let mut conflict = backend(&topology.client);
    assert!(conflict.apply_provisional(&program).is_err());
    assert!(!conflict.rollback_pre_activation().unwrap());
    assert!(first.rollback_pre_activation().unwrap());

    let invalid =
        "create table inet fence_v0\nadd chain inet fence_v0 broken { type filter hook output;";
    let preflight = backend(&topology.client);
    assert!(preflight.preflight(invalid).is_err());

    nft_in_namespace(&topology.client, &["add", "table", "inet", "foreign_test"]);
    let mut applied = backend(&topology.client);
    applied.apply_provisional(&program).unwrap();
    assert!(
        applied
            .verify_owned_state(&expected_owned_state(Mode::Audit, &[]))
            .is_err()
    );
    assert!(applied.rollback_pre_activation().unwrap());
    nft_in_namespace(&topology.client, &["list", "table", "inet", "foreign_test"]);
}

#[test]
#[ignore = "requires Linux root network namespaces and native nftables"]
fn nflog_retention_and_report_bounds_hold_for_privileged_evidence() {
    require_root();
    let topology = PeerTopology::new();
    let root = evidence_root();
    fs::create_dir_all(&root).unwrap();
    let event_count = MAX_FINDINGS as u64 + 1;
    let (mut worker, findings_path) = start_nflog_worker(
        &topology.client,
        Mode::Audit,
        "bounded-findings",
        event_count,
    );
    let allowances = Vec::new();
    let mut audit = backend(&topology.client);
    let program = render_ruleset(Mode::Audit, &allowances);
    audit.preflight(&program).unwrap();
    audit.apply_provisional(&program).unwrap();
    audit
        .verify_owned_state(&expected_owned_state(Mode::Audit, &allowances))
        .unwrap();

    emit_sampled_udp_traffic(&topology.client, "192.0.2.2", 30444, event_count);
    let findings = finish_nflog_worker(&mut worker, &findings_path, None);
    let total_violations = audit.total_violation_packets().unwrap();
    assert_eq!(findings.retained.len(), MAX_FINDINGS);
    assert!(findings.truncated);
    assert!(findings.sampled_total > MAX_FINDINGS as u64);
    assert!(total_violations >= findings.sampled_total);

    let mut evidence =
        unapplied_test_evidence_model(Mode::Audit, "policy".to_owned(), "ruleset".to_owned());
    evidence.apply_status = "applied";
    evidence.verification_status = "verified";
    evidence.counters = NetworkEvidenceCounters {
        total_violations,
        sampled_violations: findings.sampled_total,
    };
    evidence.findings = findings.retained;
    evidence.findings_truncated = findings.truncated;
    let directory = write_test_evidence(
        &root,
        "bounded-output",
        &evidence,
        &expected_owned_state(Mode::Audit, &allowances),
    )
    .unwrap();
    let report = fs::read(directory.join("report.json")).unwrap();
    assert!(report.len() <= MAX_REPORT_BYTES);
    assert!(
        String::from_utf8(report)
            .unwrap()
            .contains("\"findings_truncated\":true")
    );

    let mut oversized = evidence;
    oversized.findings[0].timestamp = "x".repeat(MAX_REPORT_BYTES);
    assert_eq!(
        write_test_evidence(
            &root,
            "oversized-output",
            &oversized,
            &expected_owned_state(Mode::Audit, &allowances)
        )
        .unwrap_err()
        .code,
        "evidence_report_too_large"
    );
    assert!(audit.rollback_pre_activation().unwrap());
}

#[test]
#[ignore = "requires Linux root network namespaces and native nftables"]
fn forward_hook_proves_routed_block_and_audit_behavior_without_containment_claim() {
    require_root();
    let topology = RoutedTopology::new();
    let allowed = vec![allowance("203.0.113.2", Protocol::Tcp, 21443)];
    let mut block = backend(&topology.router);
    let program = render_ruleset(Mode::Block, &allowed);
    block.preflight(&program).unwrap();
    block.apply_provisional(&program).unwrap();
    block
        .verify_owned_state(&expected_owned_state(Mode::Block, &allowed))
        .unwrap();
    assert!(routed_traffic(&topology, 21443));
    assert!(!routed_traffic(&topology, 21444));
    assert!(block.total_violation_packets().unwrap() >= 1);
    assert!(block.rollback_pre_activation().unwrap());

    let mut audit = backend(&topology.router);
    let program = render_ruleset(Mode::Audit, &[]);
    audit.preflight(&program).unwrap();
    audit.apply_provisional(&program).unwrap();
    audit
        .verify_owned_state(&expected_owned_state(Mode::Audit, &[]))
        .unwrap();
    assert!(routed_traffic(&topology, 21445));
    assert!(audit.total_violation_packets().unwrap() >= 1);
    assert!(audit.rollback_pre_activation().unwrap());
}

fn backend(namespace: &str) -> NativeNftBackend<SystemNftExecutor> {
    NativeNftBackend::new(SystemNftExecutor::in_test_network_namespace(namespace).unwrap())
}

fn allowance(destination: &str, protocol: Protocol, port: u16) -> EffectiveAllowance {
    EffectiveAllowance {
        destination_type: DestinationType::Ip,
        destination: destination.to_owned(),
        protocol,
        port,
    }
}

fn unique_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        TEST_INDEX.fetch_add(1, Ordering::Relaxed)
    )
}

fn evidence_root() -> PathBuf {
    PathBuf::from(
        std::env::var_os("FENCE_PRIVILEGED_TEST_ROOT")
            .expect("script/test-privileged must set FENCE_PRIVILEGED_TEST_ROOT"),
    )
}

fn require_root() {
    let output = run_output("/usr/bin/id", &["-u"]);
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "0");
}

fn ip(arguments: &[&str]) {
    must_succeed(run_output(IP_BINARY_PATH, arguments));
}

fn nft_in_namespace(namespace: &str, arguments: &[&str]) {
    let mut args = vec!["netns", "exec", namespace, "/usr/sbin/nft"];
    args.extend_from_slice(arguments);
    must_succeed(run_output(IP_BINARY_PATH, &args));
}

fn connect_namespaces(
    left: &str,
    left_link: &str,
    right: &str,
    right_link: &str,
    left_address: &str,
    right_address: &str,
) {
    ip(&[
        "link", "add", left_link, "type", "veth", "peer", "name", right_link,
    ]);
    ip(&["link", "set", left_link, "netns", left]);
    ip(&["link", "set", right_link, "netns", right]);
    ip(&["-n", left, "link", "set", left_link, "up"]);
    ip(&["-n", right, "link", "set", right_link, "up"]);
    ip(&["-n", left, "addr", "add", left_address, "dev", left_link]);
    ip(&["-n", right, "addr", "add", right_address, "dev", right_link]);
}

fn traffic_with_listener(
    topology: &PeerTopology,
    address: &str,
    protocol: &str,
    port: u16,
) -> bool {
    traffic_with_listener_payload(topology, address, protocol, port, "x")
}

fn traffic_with_listener_payload(
    topology: &PeerTopology,
    address: &str,
    protocol: &str,
    port: u16,
    payload: &str,
) -> bool {
    let ready = evidence_root().join(format!("ready-{protocol}-{port}"));
    let mut listener = start_listener(&topology.server, address, protocol, port, &ready);
    wait_for_path(&ready);
    let success = send_traffic(&topology.client, address, protocol, port, payload);
    let _ = listener.0.kill();
    let _ = listener.0.wait();
    let _ = fs::remove_file(ready);
    success
}

fn routed_traffic(topology: &RoutedTopology, port: u16) -> bool {
    let ready = evidence_root().join(format!("ready-forward-{port}"));
    let mut listener = start_listener(&topology.sink, "203.0.113.2", "tcp", port, &ready);
    wait_for_path(&ready);
    let success = send_traffic(&topology.source, "203.0.113.2", "tcp", port, "x");
    let _ = listener.0.kill();
    let _ = listener.0.wait();
    let _ = fs::remove_file(ready);
    success
}

fn start_listener(
    namespace: &str,
    address: &str,
    protocol: &str,
    port: u16,
    ready: &Path,
) -> ChildGuard {
    let script = r#"
import socket, sys
address, protocol, port, ready = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
family = socket.AF_INET6 if ":" in address else socket.AF_INET
kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
s = socket.socket(family, kind)
s.settimeout(5)
s.bind((address, port))
if protocol == "tcp":
    s.listen(1)
open(ready, "w").write("ready")
if protocol == "tcp":
    c, _ = s.accept()
    c.recv(1)
    c.send(b"ok")
else:
    data, peer = s.recvfrom(8)
    s.sendto(b"ok", peer)
"#;
    let child = Command::new(IP_BINARY_PATH)
        .args([
            "netns",
            "exec",
            namespace,
            PYTHON,
            "-c",
            script,
            address,
            protocol,
            &port.to_string(),
            ready.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    ChildGuard(child)
}

fn send_traffic(namespace: &str, address: &str, protocol: &str, port: u16, payload: &str) -> bool {
    let script = r#"
import socket, sys
address, protocol, port, payload = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
family = socket.AF_INET6 if ":" in address else socket.AF_INET
kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
s = socket.socket(family, kind)
s.settimeout(2)
s.connect((address, port))
s.send(payload.encode("ascii"))
assert s.recv(2) == b"ok"
"#;
    in_namespace_status(
        namespace,
        PYTHON,
        &["-c", script, address, protocol, &port.to_string(), payload],
    )
}

fn emit_sampled_udp_traffic(namespace: &str, address: &str, port: u16, count: u64) {
    let script = r#"
import socket, sys, time
address, port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(count):
    s.sendto(b"x", (address, port))
    time.sleep(0.0125)
"#;
    assert!(in_namespace_status(
        namespace,
        PYTHON,
        &["-c", script, address, &port.to_string(), &count.to_string()],
    ));
}

fn start_nflog_worker(
    namespace: &str,
    mode: Mode,
    label: &str,
    expected: u64,
) -> (ChildGuard, PathBuf) {
    let root = evidence_root();
    let ready = root.join(format!("{label}.ready"));
    let output = root.join(format!("{label}.json"));
    let mode_string = match mode {
        Mode::Block => "block",
        Mode::Audit => "audit",
    };
    let child = Command::new(IP_BINARY_PATH)
        .args(["netns", "exec", namespace])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "nflog_worker_collects_bounded_findings",
            "--nocapture",
        ])
        .env("FENCE_NFLOG_WORKER", "1")
        .env("FENCE_NFLOG_MODE", mode_string)
        .env("FENCE_NFLOG_EXPECTED", expected.to_string())
        .env("FENCE_NFLOG_READY", &ready)
        .env("FENCE_NFLOG_OUTPUT", &output)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_path(&ready);
    (ChildGuard(child), output)
}

fn start_resident_service(
    namespace: &str,
    root: &Path,
    invocation: &str,
    inject_pre_ready_failure: bool,
) -> ServiceGuard {
    let unit = format!("fence-evidence-{invocation}.service");
    let mut command = Command::new("/usr/bin/systemd-run");
    command.args([
        "--quiet",
        "--collect",
        "--property=Type=exec",
        "--unit",
        &unit,
        "--setenv=FENCE_RESIDENT_WORKER=1",
        &format!("--setenv=FENCE_RESIDENT_UNIT={unit}"),
        &format!("--setenv=FENCE_RESIDENT_INVOCATION={invocation}"),
        &format!("--setenv=FENCE_RESIDENT_ROOT={}", root.display()),
    ]);
    if inject_pre_ready_failure {
        command.arg("--setenv=FENCE_RESIDENT_INJECT_PRE_READY_FAILURE=1");
    }
    command
        .arg(IP_BINARY_PATH)
        .args(["netns", "exec", namespace])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "resident_service_worker",
            "--nocapture",
        ]);
    must_succeed(command.output().unwrap());
    ServiceGuard { unit }
}

fn finish_nflog_worker(
    worker: &mut ChildGuard,
    output: &Path,
    forbidden_marker: Option<&str>,
) -> FindingCollection {
    let status = worker.0.wait().unwrap();
    let mut stdout = String::new();
    let mut stderr = String::new();
    worker
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    worker
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        status.success(),
        "NFLOG worker did not complete successfully"
    );
    if let Some(marker) = forbidden_marker {
        assert!(!stdout.contains(marker));
        assert!(!stderr.contains(marker));
    }
    let serialized_findings = fs::read(output).unwrap();
    if let Some(marker) = forbidden_marker {
        assert!(!String::from_utf8_lossy(&serialized_findings).contains(marker));
    }
    serde_json::from_slice(&serialized_findings).unwrap()
}

fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !path.exists() {
        assert!(Instant::now() < deadline, "listener did not become ready");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_report_value(path: &Path, value: &str) {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if fs::read_to_string(path).is_ok_and(|report| report.contains(value)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "resident report did not contain expected value"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn in_namespace(namespace: &str, program: &str, arguments: &[&str]) {
    assert!(in_namespace_status(namespace, program, arguments));
}

fn in_namespace_status(namespace: &str, program: &str, arguments: &[&str]) -> bool {
    let mut args = vec!["netns", "exec", namespace, program];
    args.extend_from_slice(arguments);
    run_output(IP_BINARY_PATH, &args).status.success()
}

fn run_output(program: &str, arguments: &[&str]) -> Output {
    Command::new(program).args(arguments).output().unwrap()
}

fn must_succeed(output: Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
