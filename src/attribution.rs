#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Result as IoResult};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::time::Duration;

pub const ATTRIBUTION_WORKER_NAME: &str = "process_attribution";
pub const ATTRIBUTION_QUEUE_CAPACITY: usize = 128;
const MAX_SOCKET_ROWS: usize = 4_096;
const MAX_PROCESSES: usize = 2_048;
const MAX_FILE_DESCRIPTORS: usize = 8_192;
const MAX_PARENT_EXECUTABLES: usize = 4;
const MAX_PROC_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_STATUS_FILE_BYTES: u64 = 64 * 1024;
const MAX_EXECUTABLE_BASENAME_BYTES: usize = 128;
const WORKER_IDLE_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SocketFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SocketProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SocketTuple {
    pub family: SocketFamily,
    pub protocol: SocketProtocol,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionStatus {
    Attributed,
    Ambiguous,
    NotFound,
    ScanLimitExceeded,
    QueueFull,
    WorkerUnavailable,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorClass {
    Runner,
    Root,
    Other,
    Unknown,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalProcessAttribution {
    pub status: AttributionStatus,
    pub actor_class: ActorClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_basename: Option<String>,
    pub parent_executable_basenames: Vec<String>,
}

impl LocalProcessAttribution {
    fn unavailable(status: AttributionStatus) -> Self {
        Self {
            status,
            actor_class: ActorClass::Unknown,
            pid: None,
            executable_basename: None,
            parent_executable_basenames: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AttributionError {
    pub code: &'static str,
    pub message: &'static str,
}

impl AttributionError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

pub(crate) struct AttributionRequest {
    pub finding_index: usize,
    pub tuple: SocketTuple,
}

pub(crate) struct AttributionResult {
    pub finding_index: usize,
    pub attribution: LocalProcessAttribution,
}

pub(crate) enum AttributionSubmission {
    Queued,
    Rejected(LocalProcessAttribution),
}

pub(crate) struct AttributionCoordinator {
    requests: SyncSender<AttributionRequest>,
    results: Receiver<AttributionResult>,
}

pub(crate) struct AttributionWorker {
    requests: Receiver<AttributionRequest>,
    results: SyncSender<AttributionResult>,
    attributor: ProcAttributor,
}

pub(crate) fn attribution_channel()
-> Result<(AttributionCoordinator, AttributionWorker), AttributionError> {
    let attributor = ProcAttributor::system()?;
    let (request_sender, request_receiver) = mpsc::sync_channel(ATTRIBUTION_QUEUE_CAPACITY);
    let (result_sender, result_receiver) = mpsc::sync_channel(ATTRIBUTION_QUEUE_CAPACITY);
    Ok((
        AttributionCoordinator {
            requests: request_sender,
            results: result_receiver,
        },
        AttributionWorker {
            requests: request_receiver,
            results: result_sender,
            attributor,
        },
    ))
}

impl AttributionCoordinator {
    pub fn submit(&self, finding_index: usize, tuple: SocketTuple) -> AttributionSubmission {
        match self.requests.try_send(AttributionRequest {
            finding_index,
            tuple,
        }) {
            Ok(()) => AttributionSubmission::Queued,
            Err(TrySendError::Full(_)) => AttributionSubmission::Rejected(
                LocalProcessAttribution::unavailable(AttributionStatus::QueueFull),
            ),
            Err(TrySendError::Disconnected(_)) => AttributionSubmission::Rejected(
                LocalProcessAttribution::unavailable(AttributionStatus::WorkerUnavailable),
            ),
        }
    }

    pub fn drain(&self) -> Vec<AttributionResult> {
        let mut results = Vec::new();
        while results.len() < ATTRIBUTION_QUEUE_CAPACITY {
            match self.results.try_recv() {
                Ok(result) => results.push(result),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        results
    }
}

impl AttributionWorker {
    pub fn run(self, stop: &AtomicBool) -> Result<(), AttributionError> {
        while !stop.load(Ordering::Relaxed) {
            let request = match self.requests.recv_timeout(WORKER_IDLE_INTERVAL) {
                Ok(request) => request,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) if stop.load(Ordering::Relaxed) => {
                    return Ok(());
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AttributionError::new(
                        "attribution_request_channel_disconnected",
                        "process attribution request channel disconnected",
                    ));
                }
            };
            let attribution = self.attributor.attribute(&request.tuple)?;
            match self.results.try_send(AttributionResult {
                finding_index: request.finding_index,
                attribution,
            }) {
                Ok(()) => {}
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    return Err(AttributionError::new(
                        "attribution_result_channel_failed",
                        "process attribution result channel could not accept bounded evidence",
                    ));
                }
            }
        }
        Ok(())
    }
}

struct ProcAttributor {
    proc_root: PathBuf,
    runner_uid: u32,
}

impl ProcAttributor {
    fn system() -> Result<Self, AttributionError> {
        let runner_uid = runner_uid_from_passwd(Path::new("/etc/passwd"))?;
        Ok(Self {
            proc_root: PathBuf::from("/proc"),
            runner_uid,
        })
    }

    fn attribute(&self, tuple: &SocketTuple) -> Result<LocalProcessAttribution, AttributionError> {
        let inodes = match self.matching_socket_inodes(tuple)? {
            BoundedScan::Values(inodes) => inodes,
            BoundedScan::LimitExceeded => {
                return Ok(LocalProcessAttribution::unavailable(
                    AttributionStatus::ScanLimitExceeded,
                ));
            }
        };
        if inodes.is_empty() {
            return Ok(LocalProcessAttribution::unavailable(
                AttributionStatus::NotFound,
            ));
        }
        if inodes.len() != 1 {
            return Ok(LocalProcessAttribution::unavailable(
                AttributionStatus::Ambiguous,
            ));
        }
        let owners = match self.socket_owners(*inodes.first().expect("one inode exists"))? {
            BoundedScan::Values(owners) => owners,
            BoundedScan::LimitExceeded => {
                return Ok(LocalProcessAttribution::unavailable(
                    AttributionStatus::ScanLimitExceeded,
                ));
            }
        };
        if owners.is_empty() {
            return Ok(LocalProcessAttribution::unavailable(
                AttributionStatus::NotFound,
            ));
        }
        if owners.len() != 1 {
            return Ok(LocalProcessAttribution::unavailable(
                AttributionStatus::Ambiguous,
            ));
        }
        let pid = *owners.first().expect("one owner exists");
        let Some((uid, parent_pid)) = self.process_identity(pid) else {
            return Ok(LocalProcessAttribution::unavailable(
                AttributionStatus::NotFound,
            ));
        };
        let Some(executable_basename) = self.executable_basename(pid) else {
            return Ok(LocalProcessAttribution::unavailable(
                AttributionStatus::NotFound,
            ));
        };
        Ok(LocalProcessAttribution {
            status: AttributionStatus::Attributed,
            actor_class: if uid == 0 {
                ActorClass::Root
            } else if uid == self.runner_uid {
                ActorClass::Runner
            } else {
                ActorClass::Other
            },
            pid: Some(pid),
            executable_basename: Some(executable_basename),
            parent_executable_basenames: self.parent_executables(pid, parent_pid),
        })
    }

    fn matching_socket_inodes(
        &self,
        tuple: &SocketTuple,
    ) -> Result<BoundedScan<u64>, AttributionError> {
        let table = match (tuple.family, tuple.protocol) {
            (SocketFamily::Ipv4, SocketProtocol::Tcp) => "tcp",
            (SocketFamily::Ipv4, SocketProtocol::Udp) => "udp",
            (SocketFamily::Ipv6, SocketProtocol::Tcp) => "tcp6",
            (SocketFamily::Ipv6, SocketProtocol::Udp) => "udp6",
        };
        let contents = read_bounded(&self.proc_root.join("net").join(table), MAX_PROC_FILE_BYTES)
            .map_err(|_| {
            AttributionError::new(
                "attribution_socket_table_failed",
                "process attribution could not read the required socket table",
            )
        })?;
        let local = proc_endpoint(&tuple.local_address, tuple.local_port, tuple.family);
        let remote = proc_endpoint(&tuple.remote_address, tuple.remote_port, tuple.family);
        let mut inodes = BTreeSet::new();
        for (index, line) in contents.lines().skip(1).enumerate() {
            if index >= MAX_SOCKET_ROWS {
                return Ok(BoundedScan::LimitExceeded);
            }
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() > 9
                && fields[1].eq_ignore_ascii_case(&local)
                && fields[2].eq_ignore_ascii_case(&remote)
                && let Ok(inode) = fields[9].parse::<u64>()
            {
                inodes.insert(inode);
            }
        }
        Ok(BoundedScan::Values(inodes))
    }

    fn socket_owners(&self, inode: u64) -> Result<BoundedScan<u32>, AttributionError> {
        let mut process_ids = Vec::new();
        for entry in fs::read_dir(&self.proc_root).map_err(|_| {
            AttributionError::new(
                "attribution_process_scan_failed",
                "process attribution could not enumerate local processes",
            )
        })? {
            let Ok(entry) = entry else { continue };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name.bytes().all(|byte| byte.is_ascii_digit())
                && let Ok(pid) = name.parse::<u32>()
            {
                process_ids.push(pid);
                if process_ids.len() > MAX_PROCESSES {
                    return Ok(BoundedScan::LimitExceeded);
                }
            }
        }
        process_ids.sort_unstable();

        let expected = format!("socket:[{inode}]");
        let mut inspected_descriptors = 0_usize;
        let mut owners = BTreeSet::new();
        for pid in process_ids {
            let Ok(descriptors) = fs::read_dir(self.proc_root.join(pid.to_string()).join("fd"))
            else {
                continue;
            };
            for descriptor in descriptors {
                let Ok(descriptor) = descriptor else { continue };
                inspected_descriptors = inspected_descriptors.saturating_add(1);
                if inspected_descriptors > MAX_FILE_DESCRIPTORS {
                    return Ok(BoundedScan::LimitExceeded);
                }
                if fs::read_link(descriptor.path())
                    .ok()
                    .and_then(|target| target.to_str().map(str::to_owned))
                    .as_deref()
                    == Some(expected.as_str())
                {
                    owners.insert(pid);
                }
            }
        }
        Ok(BoundedScan::Values(owners))
    }

    fn process_identity(&self, pid: u32) -> Option<(u32, u32)> {
        let status = read_bounded(
            &self.proc_root.join(pid.to_string()).join("status"),
            MAX_STATUS_FILE_BYTES,
        )
        .ok()?;
        let uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))?
            .split_ascii_whitespace()
            .next()?
            .parse::<u32>()
            .ok()?;
        let parent = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))?
            .trim()
            .parse::<u32>()
            .ok()?;
        Some((uid, parent))
    }

    fn executable_basename(&self, pid: u32) -> Option<String> {
        let target = fs::read_link(self.proc_root.join(pid.to_string()).join("exe")).ok()?;
        sanitize_executable_basename(target.file_name()?.to_str()?)
    }

    fn parent_executables(&self, pid: u32, mut parent_pid: u32) -> Vec<String> {
        let mut parents = Vec::new();
        let mut visited = BTreeSet::from([pid]);
        while parent_pid > 0 && parents.len() < MAX_PARENT_EXECUTABLES {
            if !visited.insert(parent_pid) {
                break;
            }
            if let Some(executable) = self.executable_basename(parent_pid) {
                parents.push(executable);
            }
            let Some((_, next_parent)) = self.process_identity(parent_pid) else {
                break;
            };
            parent_pid = next_parent;
        }
        parents
    }
}

enum BoundedScan<T> {
    Values(BTreeSet<T>),
    LimitExceeded,
}

fn runner_uid_from_passwd(path: &Path) -> Result<u32, AttributionError> {
    let passwd = read_bounded(path, MAX_STATUS_FILE_BYTES).map_err(|_| {
        AttributionError::new(
            "attribution_runner_identity_failed",
            "process attribution could not resolve the fixed runner principal",
        )
    })?;
    passwd
        .lines()
        .filter_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            (fields.len() >= 3 && fields[0] == "runner")
                .then(|| fields[2].parse::<u32>().ok())
                .flatten()
        })
        .next()
        .ok_or_else(|| {
            AttributionError::new(
                "attribution_runner_identity_failed",
                "process attribution could not resolve the fixed runner principal",
            )
        })
}

fn read_bounded(path: &Path, maximum: u64) -> IoResult<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(std::io::Error::other(
            "bounded process file exceeded its limit",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| std::io::Error::other("bounded process file was not UTF-8"))
}

fn proc_endpoint(address: &IpAddr, port: u16, family: SocketFamily) -> String {
    let address = match (address, family) {
        (IpAddr::V4(address), SocketFamily::Ipv4) => address
            .octets()
            .into_iter()
            .rev()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>(),
        (IpAddr::V6(address), SocketFamily::Ipv6) => address
            .octets()
            .chunks_exact(4)
            .flat_map(|chunk| chunk.iter().rev())
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>(),
        _ => String::new(),
    };
    format!("{address}:{port:04X}")
}

fn sanitize_executable_basename(value: &str) -> Option<String> {
    let sanitized = value
        .bytes()
        .take(MAX_EXECUTABLE_BASENAME_BYTES)
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-') {
                char::from(byte)
            } else {
                '_'
            }
        })
        .collect::<String>();
    (!sanitized.is_empty()).then_some(sanitized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::fs::symlink;
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn root() -> PathBuf {
        let id = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("fence-attribution-{}-{id}", std::process::id()));
        fs::create_dir_all(root.join("net")).unwrap();
        root
    }

    fn tuple(protocol: SocketProtocol) -> SocketTuple {
        SocketTuple {
            family: SocketFamily::Ipv4,
            protocol,
            local_address: "10.0.0.2".parse().unwrap(),
            local_port: 40_000,
            remote_address: "192.0.2.10".parse().unwrap(),
            remote_port: 443,
        }
    }

    fn write_socket(root: &Path, protocol: &str, tuple: &SocketTuple, inode: u64) {
        let local = proc_endpoint(&tuple.local_address, tuple.local_port, tuple.family);
        let remote = proc_endpoint(&tuple.remote_address, tuple.remote_port, tuple.family);
        fs::write(
            root.join("net").join(protocol),
            format!(
                "  sl  local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n   0: {local} {remote} 02 00000000:00000000 00:00000000 00000000 1001 0 {inode}\n"
            ),
        )
        .unwrap();
    }

    fn write_process(root: &Path, pid: u32, uid: u32, parent: u32, executable: &str, inode: u64) {
        let directory = root.join(pid.to_string());
        fs::create_dir_all(directory.join("fd")).unwrap();
        fs::write(
            directory.join("status"),
            format!("Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nPPid:\t{parent}\n"),
        )
        .unwrap();
        symlink(format!("/usr/bin/{executable}"), directory.join("exe")).unwrap();
        symlink(format!("socket:[{inode}]"), directory.join("fd/3")).unwrap();
    }

    #[test]
    fn attributes_unique_ipv4_tcp_owner_and_bounds_parent_metadata() {
        let root = root();
        let tuple = tuple(SocketProtocol::Tcp);
        write_socket(&root, "tcp", &tuple, 42);
        write_process(&root, 200, 1001, 100, "curl --secret", 42);
        write_process(&root, 100, 1001, 1, "bash", 99);
        write_process(&root, 1, 0, 0, "systemd", 98);
        let attributor = ProcAttributor {
            proc_root: root.clone(),
            runner_uid: 1001,
        };
        let attribution = attributor.attribute(&tuple).unwrap();
        assert_eq!(attribution.status, AttributionStatus::Attributed);
        assert_eq!(attribution.actor_class, ActorClass::Runner);
        assert_eq!(attribution.pid, Some(200));
        assert_eq!(
            attribution.executable_basename.as_deref(),
            Some("curl_--secret")
        );
        assert_eq!(attribution.parent_executable_basenames, ["bash", "systemd"]);
        let json = serde_json::to_string(&attribution).unwrap();
        assert!(!json.contains("/usr/bin"));
        assert!(!json.contains("cmdline"));
        assert!(!json.contains("environ"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn handles_ipv6_udp_ambiguity_missing_owners_and_parent_cycles() {
        let root = root();
        let tuple = SocketTuple {
            family: SocketFamily::Ipv6,
            protocol: SocketProtocol::Udp,
            local_address: "2001:db8::1".parse::<Ipv6Addr>().unwrap().into(),
            local_port: 53_000,
            remote_address: "2001:db8::10".parse::<Ipv6Addr>().unwrap().into(),
            remote_port: 53,
        };
        write_socket(&root, "udp6", &tuple, 77);
        let attributor = ProcAttributor {
            proc_root: root.clone(),
            runner_uid: 1001,
        };
        assert_eq!(
            attributor.attribute(&tuple).unwrap().status,
            AttributionStatus::NotFound
        );
        write_process(&root, 300, 0, 300, "root-worker", 77);
        let root_actor = attributor.attribute(&tuple).unwrap();
        assert_eq!(root_actor.actor_class, ActorClass::Root);
        assert!(root_actor.parent_executable_basenames.is_empty());
        write_process(&root, 301, 1002, 1, "other-worker", 77);
        assert_eq!(
            attributor.attribute(&tuple).unwrap().status,
            AttributionStatus::Ambiguous
        );
        assert_eq!(
            proc_endpoint(
                &IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                443,
                SocketFamily::Ipv4
            ),
            "0100007F:01BB"
        );
        assert_eq!(
            proc_endpoint(&"::1".parse().unwrap(), 53, SocketFamily::Ipv6),
            "00000000000000000000000001000000:0035"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_socket_scan_limits_and_runner_identity_failures() {
        let root = root();
        let tuple = tuple(SocketProtocol::Tcp);
        let local = proc_endpoint(&tuple.local_address, tuple.local_port, tuple.family);
        let remote = proc_endpoint(&tuple.remote_address, tuple.remote_port, tuple.family);
        let mut table = String::from("header\n");
        for index in 0..=MAX_SOCKET_ROWS {
            table.push_str(&format!(
                "{index}: {local} {remote} 02 0 0 0 1001 0 {}\n",
                index + 1
            ));
        }
        fs::write(root.join("net/tcp"), table).unwrap();
        let attributor = ProcAttributor {
            proc_root: root.clone(),
            runner_uid: 1001,
        };
        assert_eq!(
            attributor.attribute(&tuple).unwrap().status,
            AttributionStatus::ScanLimitExceeded
        );
        let passwd = root.join("passwd");
        fs::write(
            &passwd,
            "root:x:0:0:root:/root:/bin/bash\nrunner:x:1001:1001::/home/runner:/bin/bash\n",
        )
        .unwrap();
        assert_eq!(runner_uid_from_passwd(&passwd).unwrap(), 1001);
        fs::write(&passwd, "root:x:0:0:root:/root:/bin/bash\n").unwrap();
        assert_eq!(
            runner_uid_from_passwd(&passwd).unwrap_err().code,
            "attribution_runner_identity_failed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounds_attribution_queue_and_delivers_worker_results() {
        let root = root();
        let tuple = tuple(SocketProtocol::Udp);
        write_socket(&root, "udp", &tuple, 55);
        write_process(&root, 400, 1001, 1, "dns-client", 55);
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let coordinator = AttributionCoordinator {
            requests: request_sender,
            results: result_receiver,
        };
        assert!(matches!(
            coordinator.submit(0, tuple.clone()),
            AttributionSubmission::Queued
        ));
        assert!(matches!(
            coordinator.submit(1, tuple),
            AttributionSubmission::Rejected(LocalProcessAttribution {
                status: AttributionStatus::QueueFull,
                ..
            })
        ));
        let worker = AttributionWorker {
            requests: request_receiver,
            results: result_sender,
            attributor: ProcAttributor {
                proc_root: root.clone(),
                runner_uid: 1001,
            },
        };
        let stop = AtomicBool::new(false);
        let worker_result = std::thread::scope(|scope| {
            let handle = scope.spawn(|| worker.run(&stop));
            let deadline = Instant::now() + Duration::from_secs(1);
            let result = loop {
                if let Some(result) = coordinator.drain().into_iter().next() {
                    break result;
                }
                assert!(Instant::now() < deadline, "attribution result timed out");
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(result.finding_index, 0);
            assert_eq!(result.attribution.status, AttributionStatus::Attributed);
            stop.store(true, Ordering::Relaxed);
            handle.join().unwrap()
        });
        assert!(worker_result.is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn process_and_descriptor_scan_caps_fail_closed_to_warning_evidence() {
        let process_root = root();
        for pid in 1..=MAX_PROCESSES + 1 {
            fs::create_dir(process_root.join(pid.to_string())).unwrap();
        }
        let attributor = ProcAttributor {
            proc_root: process_root.clone(),
            runner_uid: 1001,
        };
        assert!(matches!(
            attributor.socket_owners(1).unwrap(),
            BoundedScan::LimitExceeded
        ));
        fs::remove_dir_all(process_root).unwrap();

        let descriptor_root = root();
        let descriptor_directory = descriptor_root.join("1/fd");
        fs::create_dir_all(&descriptor_directory).unwrap();
        for descriptor in 0..=MAX_FILE_DESCRIPTORS {
            symlink(
                format!("socket:[{}]", descriptor + 100),
                descriptor_directory.join(descriptor.to_string()),
            )
            .unwrap();
        }
        let attributor = ProcAttributor {
            proc_root: descriptor_root.clone(),
            runner_uid: 1001,
        };
        assert!(matches!(
            attributor.socket_owners(1).unwrap(),
            BoundedScan::LimitExceeded
        ));
        fs::remove_dir_all(descriptor_root).unwrap();
    }

    #[test]
    fn parses_remaining_ipv4_udp_and_ipv6_tcp_socket_tables() {
        let root = root();
        let ipv4_udp = tuple(SocketProtocol::Udp);
        write_socket(&root, "udp", &ipv4_udp, 81);
        write_process(&root, 500, 1001, 1, "udp-client", 81);
        let ipv6_tcp = SocketTuple {
            family: SocketFamily::Ipv6,
            protocol: SocketProtocol::Tcp,
            local_address: "2001:db8::2".parse().unwrap(),
            local_port: 41_000,
            remote_address: "2001:db8::20".parse().unwrap(),
            remote_port: 8443,
        };
        write_socket(&root, "tcp6", &ipv6_tcp, 82);
        write_process(&root, 501, 1002, 1, "tcp6-client", 82);
        let attributor = ProcAttributor {
            proc_root: root.clone(),
            runner_uid: 1001,
        };
        assert_eq!(
            attributor.attribute(&ipv4_udp).unwrap().actor_class,
            ActorClass::Runner
        );
        assert_eq!(
            attributor.attribute(&ipv6_tcp).unwrap().actor_class,
            ActorClass::Other
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_disconnected_channels_as_bounded_worker_failures() {
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (_result_sender, result_receiver) = mpsc::sync_channel(1);
        drop(request_receiver);
        let coordinator = AttributionCoordinator {
            requests: request_sender,
            results: result_receiver,
        };
        assert!(matches!(
            coordinator.submit(0, tuple(SocketProtocol::Tcp)),
            AttributionSubmission::Rejected(LocalProcessAttribution {
                status: AttributionStatus::WorkerUnavailable,
                ..
            })
        ));

        let root = root();
        let tuple = tuple(SocketProtocol::Tcp);
        write_socket(&root, "tcp", &tuple, 91);
        write_process(&root, 600, 1001, 1, "client", 91);
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        drop(result_receiver);
        request_sender
            .send(AttributionRequest {
                finding_index: 0,
                tuple,
            })
            .unwrap();
        let worker = AttributionWorker {
            requests: request_receiver,
            results: result_sender,
            attributor: ProcAttributor {
                proc_root: root.clone(),
                runner_uid: 1001,
            },
        };
        assert_eq!(
            worker.run(&AtomicBool::new(false)).unwrap_err().code,
            "attribution_result_channel_failed"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
