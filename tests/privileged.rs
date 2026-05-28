#![cfg(target_os = "linux")]

use fence::config::{DestinationType, Mode, Protocol, parse_and_normalize};
use fence::findings::FindingCollection;
use fence::nflog::NflogReader;
use fence::nft::{
    NetworkEvidenceCounters, expected_owned_state, render_ruleset, unapplied_test_evidence_model,
};
use fence::nft_backend::{
    IP_BINARY_PATH, NativeNftBackend, SystemNftExecutor, write_test_evidence,
};
use fence::plan::{EffectiveAllowance, build_plan};
use fence::resolver::{Resolution, ResolveError, Resolver};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
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
    let deadline = Instant::now() + Duration::from_secs(20);
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
    let block_findings = finish_nflog_worker(&mut block_worker, &block_findings_path);
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
        parse_and_normalize(br#"{"schema_version":1,"mode":"block","invocation_id":"block-output","allowances":[{"destination_type":"ip","destination":"192.0.2.2","protocol":"tcp","port":18443},{"destination_type":"ip","destination":"192.0.2.2","protocol":"udp","port":18444},{"destination_type":"ip","destination":"2001:db8:1::2","protocol":"tcp","port":18443},{"destination_type":"ip","destination":"2001:db8:1::2","protocol":"udp","port":18444}]}"#).unwrap(),
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
    let audit_findings = finish_nflog_worker(&mut audit_worker, &audit_findings_path);
    assert_eq!(audit_findings.sampled_total, 2);
    assert!(audit_findings.retained.iter().all(
        |finding| finding.classification == fence::findings::FindingClassification::WouldBlock
    ));
    assert!(audit.rollback_pre_activation().unwrap());
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
        .spawn()
        .unwrap();
    wait_for_path(&ready);
    (ChildGuard(child), output)
}

fn finish_nflog_worker(worker: &mut ChildGuard, output: &Path) -> FindingCollection {
    let status = worker.0.wait().unwrap();
    assert!(
        status.success(),
        "NFLOG worker did not complete successfully"
    );
    serde_json::from_slice(&fs::read(output).unwrap()).unwrap()
}

fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !path.exists() {
        assert!(Instant::now() < deadline, "listener did not become ready");
        thread::sleep(Duration::from_millis(10));
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
