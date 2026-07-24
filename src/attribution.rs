#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Result as IoResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
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
const MAX_SOCKET_LINE_BYTES: u64 = 16 * 1024;
const MAX_STATUS_FILE_BYTES: u64 = 64 * 1024;
const MAX_EXECUTABLE_BASENAME_BYTES: usize = 128;
const MAX_RUNNER_WORKER_ANCESTRY: usize = 8;
const WORKER_IDLE_INTERVAL: Duration = Duration::from_millis(100);
const RUNNER_WORKER_BASENAME: &str = "Runner.Worker";
const RUNNER_LISTENER_BASENAME: &str = "Runner.Listener";

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct DnsClientSocket {
    pub protocol: SocketProtocol,
    pub peer: SocketAddr,
    pub listener: SocketAddr,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DnsCallerProvenance {
    TrustedRunnerWorker,
    RunnerOwnedWorkflow,
    Untrusted,
    AttributionFailed,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct TrustedRunnerWorkerError {
    pub code: &'static str,
    pub message: &'static str,
}

impl TrustedRunnerWorkerError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TrustedRunnerWorker {
    proc_root: PathBuf,
    runner_uid: u32,
    pid: u32,
    start_time_ticks: u64,
    executable_device: u64,
    executable_inode: u64,
}

impl TrustedRunnerWorker {
    pub(crate) fn discover_system() -> Result<Self, TrustedRunnerWorkerError> {
        let runner_uid = runner_uid_from_passwd(Path::new("/etc/passwd")).map_err(|_| {
            TrustedRunnerWorkerError::new(
                "runner_worker_identity_unavailable",
                "the fixed runner principal could not be resolved",
            )
        })?;
        Self::discover(PathBuf::from("/proc"), runner_uid)
    }

    fn discover(proc_root: PathBuf, runner_uid: u32) -> Result<Self, TrustedRunnerWorkerError> {
        let mut process_ids = numeric_process_ids(&proc_root).map_err(|_| {
            TrustedRunnerWorkerError::new(
                "runner_worker_identity_unavailable",
                "the hosted runner process set could not be inspected",
            )
        })?;
        if process_ids.len() > MAX_PROCESSES {
            return Err(TrustedRunnerWorkerError::new(
                "runner_worker_identity_ambiguous",
                "the hosted runner process set exceeded its fixed bound",
            ));
        }
        process_ids.sort_unstable();
        let candidates = process_ids
            .into_iter()
            .filter_map(|pid| {
                let (uid, _) = process_identity_at(&proc_root, pid)?;
                (uid == runner_uid
                    && executable_basename_at(&proc_root, pid).as_deref()
                        == Some(RUNNER_WORKER_BASENAME)
                    && has_runner_listener_ancestor(&proc_root, pid, runner_uid))
                .then_some(pid)
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err(TrustedRunnerWorkerError::new(
                "runner_worker_identity_ambiguous",
                "exactly one reviewed Runner.Worker process is required",
            ));
        }
        let pid = candidates[0];
        let start_time_ticks = process_start_time_at(&proc_root, pid).ok_or_else(|| {
            TrustedRunnerWorkerError::new(
                "runner_worker_identity_unavailable",
                "Runner.Worker start identity could not be pinned",
            )
        })?;
        let metadata = fs::metadata(proc_root.join(pid.to_string()).join("exe")).map_err(|_| {
            TrustedRunnerWorkerError::new(
                "runner_worker_identity_unavailable",
                "Runner.Worker executable identity could not be pinned",
            )
        })?;
        Ok(Self {
            proc_root,
            runner_uid,
            pid,
            start_time_ticks,
            executable_device: metadata.dev(),
            executable_inode: metadata.ino(),
        })
    }

    pub(crate) fn classify_dns_client(
        &self,
        client: DnsClientSocket,
    ) -> Result<DnsCallerProvenance, TrustedRunnerWorkerError> {
        self.revalidate()?;
        let Some((family, table)) = dns_socket_table(client) else {
            return Ok(DnsCallerProvenance::AttributionFailed);
        };
        let table_path = self.proc_root.join("net").join(table);
        let Ok(contents) = read_bounded(&table_path, MAX_PROC_FILE_BYTES) else {
            return Ok(DnsCallerProvenance::AttributionFailed);
        };
        let Some(inodes) = dns_socket_inodes(&contents, client, family) else {
            return Ok(DnsCallerProvenance::AttributionFailed);
        };
        if inodes.len() != 1 {
            return Ok(DnsCallerProvenance::AttributionFailed);
        }
        let inode = *inodes.first().expect("one inode exists");
        let owners = match socket_inode_owners(&self.proc_root, inode) {
            Ok(BoundedScan::Values(owners)) => owners,
            Ok(BoundedScan::LimitExceeded) | Err(_) => {
                return Ok(DnsCallerProvenance::AttributionFailed);
            }
        };
        if owners.len() != 1 {
            return Ok(DnsCallerProvenance::AttributionFailed);
        }
        let owner = *owners.first().expect("one socket owner exists");
        let (provenance, owner_start_time) = if owner == self.pid {
            (DnsCallerProvenance::TrustedRunnerWorker, None)
        } else {
            let Some((uid, _)) = process_identity_at(&self.proc_root, owner) else {
                return Ok(DnsCallerProvenance::AttributionFailed);
            };
            if uid != self.runner_uid
                || !has_pinned_runner_worker_ancestor(
                    &self.proc_root,
                    owner,
                    self.pid,
                    self.runner_uid,
                )
            {
                return Ok(DnsCallerProvenance::Untrusted);
            }
            let Some(start_time) = process_start_time_at(&self.proc_root, owner) else {
                return Ok(DnsCallerProvenance::AttributionFailed);
            };
            (DnsCallerProvenance::RunnerOwnedWorkflow, Some(start_time))
        };
        self.revalidate()?;
        let Ok(current) = read_bounded(&table_path, MAX_PROC_FILE_BYTES) else {
            return Ok(DnsCallerProvenance::AttributionFailed);
        };
        let current_inodes = dns_socket_inodes(&current, client, family);
        let current_owners = match socket_inode_owners(&self.proc_root, inode) {
            Ok(BoundedScan::Values(owners)) => Some(owners),
            Ok(BoundedScan::LimitExceeded) | Err(_) => None,
        };
        let workflow_identity_unchanged = owner_start_time.is_none_or(|start_time| {
            process_identity_at(&self.proc_root, owner)
                .is_some_and(|(uid, _)| uid == self.runner_uid)
                && process_start_time_at(&self.proc_root, owner) == Some(start_time)
                && has_pinned_runner_worker_ancestor(
                    &self.proc_root,
                    owner,
                    self.pid,
                    self.runner_uid,
                )
        });
        Ok(
            if current_inodes.as_ref() == Some(&inodes)
                && current_owners.as_ref() == Some(&owners)
                && workflow_identity_unchanged
            {
                provenance
            } else {
                DnsCallerProvenance::AttributionFailed
            },
        )
    }

    fn revalidate(&self) -> Result<(), TrustedRunnerWorkerError> {
        let valid_process = process_identity_at(&self.proc_root, self.pid)
            .is_some_and(|(uid, _)| uid == self.runner_uid)
            && process_start_time_at(&self.proc_root, self.pid) == Some(self.start_time_ticks)
            && executable_basename_at(&self.proc_root, self.pid).as_deref()
                == Some(RUNNER_WORKER_BASENAME)
            && has_runner_listener_ancestor(&self.proc_root, self.pid, self.runner_uid);
        let valid_executable = fs::metadata(self.proc_root.join(self.pid.to_string()).join("exe"))
            .is_ok_and(|metadata| {
                metadata.dev() == self.executable_device && metadata.ino() == self.executable_inode
            });
        if valid_process && valid_executable {
            Ok(())
        } else {
            Err(TrustedRunnerWorkerError::new(
                "runner_worker_identity_drift",
                "the pinned Runner.Worker identity changed or disappeared",
            ))
        }
    }
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
        let inodes = match self.matching_socket_inodes(tuple) {
            Ok(BoundedScan::Values(inodes)) => inodes,
            Ok(BoundedScan::LimitExceeded) => {
                return Ok(LocalProcessAttribution::unavailable(
                    AttributionStatus::ScanLimitExceeded,
                ));
            }
            Err(_) => {
                return Ok(LocalProcessAttribution::unavailable(
                    AttributionStatus::WorkerUnavailable,
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
        let owners = match self.socket_owners(*inodes.first().expect("one inode exists")) {
            Ok(BoundedScan::Values(owners)) => owners,
            Ok(BoundedScan::LimitExceeded) => {
                return Ok(LocalProcessAttribution::unavailable(
                    AttributionStatus::ScanLimitExceeded,
                ));
            }
            Err(_) => {
                return Ok(LocalProcessAttribution::unavailable(
                    AttributionStatus::WorkerUnavailable,
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
        let file = File::open(self.proc_root.join("net").join(table)).map_err(|_| {
            AttributionError::new(
                "attribution_socket_table_failed",
                "process attribution could not read the required socket table",
            )
        })?;
        let mut reader = BufReader::new(file);
        let local = proc_endpoint(&tuple.local_address, tuple.local_port, tuple.family);
        let remote = proc_endpoint(&tuple.remote_address, tuple.remote_port, tuple.family);
        let unspecified = match tuple.family {
            SocketFamily::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketFamily::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let wildcard_local = proc_endpoint(&unspecified, tuple.local_port, tuple.family);
        let wildcard_remote = proc_endpoint(&unspecified, 0, tuple.family);
        let mut inodes = BTreeSet::new();
        let mut line = Vec::new();
        let mut bytes_read = 0_u64;
        let mut rows_read = 0_usize;
        let mut header_read = false;
        loop {
            line.clear();
            let count = (&mut reader)
                .take(MAX_SOCKET_LINE_BYTES.saturating_add(1))
                .read_until(b'\n', &mut line)
                .map_err(|_| {
                    AttributionError::new(
                        "attribution_socket_table_failed",
                        "process attribution could not read the required socket table",
                    )
                })?;
            if count == 0 {
                break;
            }
            let count = u64::try_from(count).unwrap_or(u64::MAX);
            bytes_read = bytes_read.saturating_add(count);
            if count > MAX_SOCKET_LINE_BYTES || bytes_read > MAX_PROC_FILE_BYTES {
                return Ok(BoundedScan::LimitExceeded);
            }
            let line = std::str::from_utf8(&line).map_err(|_| {
                AttributionError::new(
                    "attribution_socket_table_failed",
                    "process attribution could not read the required socket table",
                )
            })?;
            if !header_read {
                header_read = true;
                continue;
            }
            if rows_read >= MAX_SOCKET_ROWS {
                return Ok(BoundedScan::LimitExceeded);
            }
            rows_read += 1;
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            let local_matches = fields.len() > 9
                && (fields[1].eq_ignore_ascii_case(&local)
                    || (tuple.protocol == SocketProtocol::Udp
                        && fields[1].eq_ignore_ascii_case(&wildcard_local)));
            let remote_matches = local_matches
                && (fields[2].eq_ignore_ascii_case(&remote)
                    || (tuple.protocol == SocketProtocol::Udp
                        && fields[2].eq_ignore_ascii_case(&wildcard_remote)));
            if remote_matches && let Ok(inode) = fields[9].parse::<u64>() {
                inodes.insert(inode);
            }
        }
        Ok(BoundedScan::Values(inodes))
    }

    fn socket_owners(&self, inode: u64) -> Result<BoundedScan<u32>, AttributionError> {
        socket_inode_owners(&self.proc_root, inode)
    }

    fn process_identity(&self, pid: u32) -> Option<(u32, u32)> {
        process_identity_at(&self.proc_root, pid)
    }

    fn executable_basename(&self, pid: u32) -> Option<String> {
        executable_basename_at(&self.proc_root, pid)
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

fn numeric_process_ids(proc_root: &Path) -> IoResult<Vec<u32>> {
    let mut process_ids = Vec::new();
    for entry in fs::read_dir(proc_root)? {
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.bytes().all(|byte| byte.is_ascii_digit())
            && let Ok(pid) = name.parse::<u32>()
        {
            process_ids.push(pid);
        }
    }
    Ok(process_ids)
}

fn socket_inode_owners(proc_root: &Path, inode: u64) -> Result<BoundedScan<u32>, AttributionError> {
    let mut process_ids = numeric_process_ids(proc_root).map_err(|_| {
        AttributionError::new(
            "attribution_process_scan_failed",
            "process attribution could not enumerate local processes",
        )
    })?;
    if process_ids.len() > MAX_PROCESSES {
        return Ok(BoundedScan::LimitExceeded);
    }
    process_ids.sort_unstable();

    let expected = format!("socket:[{inode}]");
    let mut inspected_descriptors = 0_usize;
    let mut owners = BTreeSet::new();
    for pid in process_ids {
        let Ok(descriptors) = fs::read_dir(proc_root.join(pid.to_string()).join("fd")) else {
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

fn process_identity_at(proc_root: &Path, pid: u32) -> Option<(u32, u32)> {
    let status = read_bounded(
        &proc_root.join(pid.to_string()).join("status"),
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

fn process_start_time_at(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = read_bounded(
        &proc_root.join(pid.to_string()).join("stat"),
        MAX_STATUS_FILE_BYTES,
    )
    .ok()?;
    let end = stat.rfind(')')?;
    stat.get(end + 1..)?
        .split_ascii_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
}

fn executable_basename_at(proc_root: &Path, pid: u32) -> Option<String> {
    let target = fs::read_link(proc_root.join(pid.to_string()).join("exe")).ok()?;
    sanitize_executable_basename(target.file_name()?.to_str()?)
}

fn has_runner_listener_ancestor(proc_root: &Path, pid: u32, runner_uid: u32) -> bool {
    let Some((_, mut parent)) = process_identity_at(proc_root, pid) else {
        return false;
    };
    let mut visited = BTreeSet::from([pid]);
    for _ in 0..MAX_RUNNER_WORKER_ANCESTRY {
        if parent == 0 || !visited.insert(parent) {
            return false;
        }
        let Some((uid, next_parent)) = process_identity_at(proc_root, parent) else {
            return false;
        };
        if uid == runner_uid
            && executable_basename_at(proc_root, parent).as_deref()
                == Some(RUNNER_LISTENER_BASENAME)
        {
            return true;
        }
        parent = next_parent;
    }
    false
}

fn has_pinned_runner_worker_ancestor(
    proc_root: &Path,
    pid: u32,
    runner_worker_pid: u32,
    runner_uid: u32,
) -> bool {
    let Some((uid, mut parent)) = process_identity_at(proc_root, pid) else {
        return false;
    };
    if uid != runner_uid {
        return false;
    }
    let mut visited = BTreeSet::from([pid]);
    for _ in 0..MAX_RUNNER_WORKER_ANCESTRY {
        if parent == 0 || !visited.insert(parent) {
            return false;
        }
        let Some((uid, next_parent)) = process_identity_at(proc_root, parent) else {
            return false;
        };
        if uid != runner_uid {
            return false;
        }
        if parent == runner_worker_pid {
            return true;
        }
        parent = next_parent;
    }
    false
}

fn dns_socket_table(client: DnsClientSocket) -> Option<(SocketFamily, &'static str)> {
    let family = match (client.peer, client.listener) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => SocketFamily::Ipv4,
        (SocketAddr::V6(_), SocketAddr::V6(_)) => SocketFamily::Ipv6,
        _ => return None,
    };
    let table = match (family, client.protocol) {
        (SocketFamily::Ipv4, SocketProtocol::Tcp) => "tcp",
        (SocketFamily::Ipv4, SocketProtocol::Udp) => "udp",
        (SocketFamily::Ipv6, SocketProtocol::Tcp) => "tcp6",
        (SocketFamily::Ipv6, SocketProtocol::Udp) => "udp6",
    };
    Some((family, table))
}

fn dns_socket_inodes(
    contents: &str,
    client: DnsClientSocket,
    family: SocketFamily,
) -> Option<BTreeSet<u64>> {
    let local = proc_endpoint(&client.peer.ip(), client.peer.port(), family);
    let unspecified = match family {
        SocketFamily::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketFamily::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let wildcard_local = proc_endpoint(&unspecified, client.peer.port(), family);
    let remote = proc_endpoint(&client.listener.ip(), client.listener.port(), family);
    let wildcard_remote = proc_endpoint(&unspecified, 0, family);
    let mut inodes = BTreeSet::new();
    for (index, line) in contents.lines().skip(1).enumerate() {
        if index >= MAX_SOCKET_ROWS {
            return None;
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let local_matches = fields.len() > 9
            && (fields[1].eq_ignore_ascii_case(&local)
                || (client.protocol == SocketProtocol::Udp
                    && fields[1].eq_ignore_ascii_case(&wildcard_local)));
        if !local_matches {
            continue;
        }
        let remote_matches = fields[2].eq_ignore_ascii_case(&remote)
            || (client.protocol == SocketProtocol::Udp
                && fields[2].eq_ignore_ascii_case(&wildcard_remote));
        if remote_matches && let Ok(inode) = fields[9].parse::<u64>() {
            inodes.insert(inode);
        }
    }
    Some(inodes)
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

    fn write_oversized_socket_table(root: &Path, protocol: &str, tuple: &SocketTuple) {
        let local = proc_endpoint(&tuple.local_address, tuple.local_port, tuple.family);
        let remote = proc_endpoint(&tuple.remote_address, tuple.remote_port, tuple.family);
        let padding = "x".repeat(1024);
        let mut table = String::from("header\n");
        for index in 0..MAX_SOCKET_ROWS {
            table.push_str(&format!(
                "{index}: {local} {remote} 02 0 0 0 1001 0 {} {padding}\n",
                index + 1
            ));
        }
        assert!(u64::try_from(table.len()).unwrap() > MAX_PROC_FILE_BYTES);
        fs::write(root.join("net").join(protocol), table).unwrap();
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

    fn write_trusted_process(
        root: &Path,
        pid: u32,
        uid: u32,
        parent: u32,
        executable: &str,
        start_time: u64,
        socket_inode: Option<u64>,
    ) {
        let directory = root.join(pid.to_string());
        fs::create_dir_all(directory.join("fd")).unwrap();
        fs::write(
            directory.join("status"),
            format!("Name:\t{executable}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nPPid:\t{parent}\n"),
        )
        .unwrap();
        let mut stat_fields = vec!["0".to_owned(); 20];
        stat_fields[0] = "S".to_owned();
        stat_fields[1] = parent.to_string();
        stat_fields[19] = start_time.to_string();
        fs::write(
            directory.join("stat"),
            format!("{pid} ({executable}) {}\n", stat_fields.join(" ")),
        )
        .unwrap();
        let executables = root.join("executables");
        fs::create_dir_all(&executables).unwrap();
        let executable_path = executables.join(executable);
        if !executable_path.exists() {
            fs::write(&executable_path, b"test executable").unwrap();
        }
        symlink(&executable_path, directory.join("exe")).unwrap();
        if let Some(inode) = socket_inode {
            symlink(format!("socket:[{inode}]"), directory.join("fd/3")).unwrap();
        }
    }

    fn write_dns_client_socket(
        root: &Path,
        client: DnsClientSocket,
        inode: u64,
        wildcard_udp_endpoints: bool,
    ) {
        let (family, table) = dns_socket_table(client).unwrap();
        let unspecified = match family {
            SocketFamily::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketFamily::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let local = if wildcard_udp_endpoints {
            proc_endpoint(&unspecified, client.peer.port(), family)
        } else {
            proc_endpoint(&client.peer.ip(), client.peer.port(), family)
        };
        let remote = if wildcard_udp_endpoints {
            proc_endpoint(&unspecified, 0, family)
        } else {
            proc_endpoint(&client.listener.ip(), client.listener.port(), family)
        };
        fs::write(
            root.join("net").join(table),
            format!(
                "  sl  local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n   0: {local} {remote} 01 00000000:00000000 00:00000000 00000000 1001 0 {inode}\n"
            ),
        )
        .unwrap();
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
    fn oversized_socket_tables_degrade_to_bounded_attribution() {
        let root = root();
        let tuple = tuple(SocketProtocol::Tcp);
        write_oversized_socket_table(&root, "tcp", &tuple);
        let attributor = ProcAttributor {
            proc_root: root.clone(),
            runner_uid: 1001,
        };
        let attribution = attributor.attribute(&tuple).unwrap();
        assert_eq!(attribution.status, AttributionStatus::ScanLimitExceeded);
        assert_eq!(attribution.actor_class, ActorClass::Unknown);
        assert!(attribution.pid.is_none());
        assert!(attribution.executable_basename.is_none());

        let mut table = b"header\n".to_vec();
        table.extend(std::iter::repeat_n(
            b'x',
            usize::try_from(MAX_SOCKET_LINE_BYTES).unwrap() + 1,
        ));
        table.push(b'\n');
        fs::write(root.join("net/tcp"), table).unwrap();
        assert_eq!(
            attributor.attribute(&tuple).unwrap().status,
            AttributionStatus::ScanLimitExceeded
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unavailable_advisory_socket_tables_do_not_fail_attribution() {
        let root = root();
        let tuple = tuple(SocketProtocol::Tcp);
        let attributor = ProcAttributor {
            proc_root: root.clone(),
            runner_uid: 1001,
        };

        assert_eq!(
            attributor.attribute(&tuple).unwrap(),
            LocalProcessAttribution::unavailable(AttributionStatus::WorkerUnavailable)
        );
        fs::write(root.join("net/tcp"), b"header\n\xff\n").unwrap();
        assert_eq!(
            attributor.attribute(&tuple).unwrap(),
            LocalProcessAttribution::unavailable(AttributionStatus::WorkerUnavailable)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attribution_worker_survives_oversized_tables_and_processes_later_findings() {
        let root = root();
        let oversized = tuple(SocketProtocol::Tcp);
        let next = tuple(SocketProtocol::Udp);
        write_oversized_socket_table(&root, "tcp", &oversized);
        write_socket(&root, "udp", &next, 55);
        write_process(&root, 400, 1001, 1, "dns-client", 55);

        let (request_sender, request_receiver) = mpsc::sync_channel(2);
        let (result_sender, result_receiver) = mpsc::sync_channel(2);
        let coordinator = AttributionCoordinator {
            requests: request_sender,
            results: result_receiver,
        };
        assert!(matches!(
            coordinator.submit(0, oversized),
            AttributionSubmission::Queued
        ));
        assert!(matches!(
            coordinator.submit(1, next),
            AttributionSubmission::Queued
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
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut results = Vec::new();
            while results.len() < 2 {
                results.extend(coordinator.drain());
                if Instant::now() >= deadline {
                    stop.store(true, Ordering::Relaxed);
                    panic!("bounded attribution results timed out");
                }
                if results.len() < 2 {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            results.sort_by_key(|result| result.finding_index);
            assert_eq!(results[0].finding_index, 0);
            assert_eq!(
                results[0].attribution.status,
                AttributionStatus::ScanLimitExceeded
            );
            assert_eq!(results[1].finding_index, 1);
            assert_eq!(results[1].attribution.status, AttributionStatus::Attributed);
            assert_eq!(results[1].attribution.actor_class, ActorClass::Runner);
            stop.store(true, Ordering::Relaxed);
            handle.join().unwrap()
        });
        assert!(worker_result.is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_socket_tables_cannot_authorize_trusted_dns_clients() {
        let root = root();
        write_trusted_process(&root, 100, 1001, 1, RUNNER_LISTENER_BASENAME, 10, None);
        write_trusted_process(&root, 200, 1001, 100, RUNNER_WORKER_BASENAME, 20, Some(501));
        let worker = TrustedRunnerWorker::discover(root.clone(), 1001).unwrap();
        let client = DnsClientSocket {
            protocol: SocketProtocol::Udp,
            peer: "127.0.0.1:40000".parse().unwrap(),
            listener: "127.0.0.1:53".parse().unwrap(),
        };
        write_dns_client_socket(&root, client, 501, true);
        assert_eq!(
            worker.classify_dns_client(client).unwrap(),
            DnsCallerProvenance::TrustedRunnerWorker
        );

        write_oversized_socket_table(&root, "udp", &tuple(SocketProtocol::Udp));
        assert!(read_bounded(&root.join("net/udp"), MAX_PROC_FILE_BYTES).is_err());
        assert_eq!(
            worker.classify_dns_client(client).unwrap(),
            DnsCallerProvenance::AttributionFailed
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
    fn attributes_unconnected_ipv4_and_ipv6_udp_sockets() {
        let root = root();
        let ipv4_packet = tuple(SocketProtocol::Udp);
        let ipv4_socket = SocketTuple {
            local_address: Ipv4Addr::UNSPECIFIED.into(),
            remote_address: Ipv4Addr::UNSPECIFIED.into(),
            remote_port: 0,
            ..ipv4_packet.clone()
        };
        write_socket(&root, "udp", &ipv4_socket, 83);
        write_process(&root, 502, 1001, 1, "udp-client", 83);

        let ipv6_packet = SocketTuple {
            family: SocketFamily::Ipv6,
            protocol: SocketProtocol::Udp,
            local_address: "2001:db8::2".parse().unwrap(),
            local_port: 42_000,
            remote_address: "2001:db8::20".parse().unwrap(),
            remote_port: 123,
        };
        let ipv6_socket = SocketTuple {
            local_address: Ipv6Addr::UNSPECIFIED.into(),
            remote_address: Ipv6Addr::UNSPECIFIED.into(),
            remote_port: 0,
            ..ipv6_packet.clone()
        };
        write_socket(&root, "udp6", &ipv6_socket, 84);
        write_process(&root, 503, 1002, 1, "udp6-client", 84);

        let attributor = ProcAttributor {
            proc_root: root.clone(),
            runner_uid: 1001,
        };
        assert_eq!(
            attributor.attribute(&ipv4_packet).unwrap().actor_class,
            ActorClass::Runner
        );
        assert_eq!(
            attributor.attribute(&ipv6_packet).unwrap().actor_class,
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

    #[test]
    fn pins_one_runner_worker_and_attributes_udp_and_tcp_dns_sockets() {
        let root = root();
        write_trusted_process(&root, 100, 1001, 1, RUNNER_LISTENER_BASENAME, 10, None);
        write_trusted_process(&root, 200, 1001, 100, RUNNER_WORKER_BASENAME, 20, Some(501));
        let worker = TrustedRunnerWorker::discover(root.clone(), 1001).unwrap();

        let udp = DnsClientSocket {
            protocol: SocketProtocol::Udp,
            peer: "127.0.0.1:40000".parse().unwrap(),
            listener: "127.0.0.1:53".parse().unwrap(),
        };
        write_dns_client_socket(&root, udp, 501, true);
        assert_eq!(
            worker.classify_dns_client(udp).unwrap(),
            DnsCallerProvenance::TrustedRunnerWorker
        );

        fs::remove_file(root.join("200/fd/3")).unwrap();
        write_trusted_process(&root, 250, 1001, 100, "workflow", 25, Some(501));
        assert_eq!(
            worker.classify_dns_client(udp).unwrap(),
            DnsCallerProvenance::Untrusted
        );
        fs::remove_file(root.join("250/fd/3")).unwrap();
        let tcp = DnsClientSocket {
            protocol: SocketProtocol::Tcp,
            peer: "127.0.0.1:40001".parse().unwrap(),
            listener: "127.0.0.1:53".parse().unwrap(),
        };
        write_dns_client_socket(&root, tcp, 502, false);
        write_trusted_process(&root, 300, 1001, 100, "workflow", 30, Some(502));
        assert_eq!(
            worker.classify_dns_client(tcp).unwrap(),
            DnsCallerProvenance::Untrusted
        );
        symlink("socket:[502]", root.join("200/fd/4")).unwrap();
        assert_eq!(
            worker.classify_dns_client(tcp).unwrap(),
            DnsCallerProvenance::AttributionFailed
        );
        fs::remove_file(root.join("300/fd/3")).unwrap();
        assert_eq!(
            worker.classify_dns_client(tcp).unwrap(),
            DnsCallerProvenance::TrustedRunnerWorker
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attributes_only_unique_runner_owned_worker_descendant_dns_sockets() {
        let root = root();
        write_trusted_process(&root, 100, 1001, 1, RUNNER_LISTENER_BASENAME, 10, None);
        write_trusted_process(&root, 200, 1001, 100, RUNNER_WORKER_BASENAME, 20, None);
        let worker = TrustedRunnerWorker::discover(root.clone(), 1001).unwrap();

        let udp = DnsClientSocket {
            protocol: SocketProtocol::Udp,
            peer: "127.0.0.1:43000".parse().unwrap(),
            listener: "127.0.0.1:53".parse().unwrap(),
        };
        write_dns_client_socket(&root, udp, 801, true);
        write_trusted_process(&root, 300, 1001, 200, "node", 30, Some(801));
        assert_eq!(
            worker.classify_dns_client(udp).unwrap(),
            DnsCallerProvenance::RunnerOwnedWorkflow
        );

        let tcp = DnsClientSocket {
            protocol: SocketProtocol::Tcp,
            peer: "127.0.0.1:43001".parse().unwrap(),
            listener: "127.0.0.1:53".parse().unwrap(),
        };
        write_dns_client_socket(&root, tcp, 802, false);
        write_trusted_process(&root, 301, 1001, 300, "artifact-node", 31, Some(802));
        assert_eq!(
            worker.classify_dns_client(tcp).unwrap(),
            DnsCallerProvenance::RunnerOwnedWorkflow
        );

        symlink("socket:[802]", root.join("300/fd/4")).unwrap();
        assert_eq!(
            worker.classify_dns_client(tcp).unwrap(),
            DnsCallerProvenance::AttributionFailed
        );
        fs::remove_file(root.join("300/fd/4")).unwrap();
        fs::remove_file(root.join("301/fd/3")).unwrap();
        assert_eq!(
            worker.classify_dns_client(tcp).unwrap(),
            DnsCallerProvenance::AttributionFailed
        );

        write_dns_client_socket(&root, udp, 803, true);
        write_trusted_process(&root, 302, 1002, 200, "other-node", 32, Some(803));
        assert_eq!(
            worker.classify_dns_client(udp).unwrap(),
            DnsCallerProvenance::Untrusted
        );

        write_dns_client_socket(&root, udp, 804, true);
        write_trusted_process(&root, 303, 1001, 100, "unrelated-node", 33, Some(804));
        assert_eq!(
            worker.classify_dns_client(udp).unwrap(),
            DnsCallerProvenance::Untrusted
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runner_worker_identity_drift_and_ambiguity_fail_closed() {
        let root = root();
        write_trusted_process(&root, 100, 1001, 1, RUNNER_LISTENER_BASENAME, 10, None);
        write_trusted_process(&root, 200, 1001, 100, RUNNER_WORKER_BASENAME, 20, Some(601));
        let worker = TrustedRunnerWorker::discover(root.clone(), 1001).unwrap();
        let client = DnsClientSocket {
            protocol: SocketProtocol::Udp,
            peer: "127.0.0.1:41000".parse().unwrap(),
            listener: "127.0.0.1:53".parse().unwrap(),
        };
        write_dns_client_socket(&root, client, 601, false);
        let mut stat_fields = vec!["0".to_owned(); 20];
        stat_fields[0] = "S".to_owned();
        stat_fields[1] = "100".to_owned();
        stat_fields[19] = "21".to_owned();
        fs::write(
            root.join("200/stat"),
            format!("200 ({RUNNER_WORKER_BASENAME}) {}\n", stat_fields.join(" ")),
        )
        .unwrap();
        assert_eq!(
            worker.classify_dns_client(client).unwrap_err().code,
            "runner_worker_identity_drift"
        );

        stat_fields[19] = "20".to_owned();
        fs::write(
            root.join("200/stat"),
            format!("200 ({RUNNER_WORKER_BASENAME}) {}\n", stat_fields.join(" ")),
        )
        .unwrap();
        let alternate = root.join("alternate").join(RUNNER_WORKER_BASENAME);
        fs::create_dir_all(alternate.parent().unwrap()).unwrap();
        fs::write(&alternate, b"replacement executable").unwrap();
        fs::remove_file(root.join("200/exe")).unwrap();
        symlink(&alternate, root.join("200/exe")).unwrap();
        assert_eq!(
            worker.classify_dns_client(client).unwrap_err().code,
            "runner_worker_identity_drift"
        );

        write_trusted_process(&root, 201, 1001, 100, RUNNER_WORKER_BASENAME, 30, None);
        assert_eq!(
            TrustedRunnerWorker::discover(root.clone(), 1001)
                .unwrap_err()
                .code,
            "runner_worker_identity_ambiguous"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ambiguous_dns_socket_ownership_is_not_attributed() {
        let root = root();
        write_trusted_process(&root, 100, 1001, 1, RUNNER_LISTENER_BASENAME, 10, None);
        write_trusted_process(&root, 200, 1001, 100, RUNNER_WORKER_BASENAME, 20, Some(701));
        let worker = TrustedRunnerWorker::discover(root.clone(), 1001).unwrap();
        let client = DnsClientSocket {
            protocol: SocketProtocol::Udp,
            peer: "127.0.0.1:42000".parse().unwrap(),
            listener: "127.0.0.1:53".parse().unwrap(),
        };
        let (family, table) = dns_socket_table(client).unwrap();
        let local = proc_endpoint(&client.peer.ip(), client.peer.port(), family);
        let remote = proc_endpoint(&client.listener.ip(), client.listener.port(), family);
        fs::write(
            root.join("net").join(table),
            format!(
                "  sl  local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n   0: {local} {remote} 01 00000000:00000000 00:00000000 00000000 1001 0 701\n   1: {local} {remote} 01 00000000:00000000 00:00000000 00000000 1001 0 702\n"
            ),
        )
        .unwrap();
        assert_eq!(
            worker.classify_dns_client(client).unwrap(),
            DnsCallerProvenance::AttributionFailed
        );
        fs::remove_dir_all(root).unwrap();
    }
}
