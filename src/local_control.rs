use crate::hosted_runner::{
    AcceptedLocalControlInventoryV2, AcceptedLocalControlOwnerV2, UNIX_NAME_HASH_SCHEMA_V1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt::{Display, Formatter};
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub const MAX_PROCESSES: usize = 2_048;
pub const MAX_FILE_DESCRIPTORS_PER_PROCESS: usize = 2_048;
pub const MAX_TOTAL_FILE_DESCRIPTORS: usize = 32_768;
pub const MAX_OWNERS_PER_SOCKET: usize = 4;
pub const MAX_UNIX_LISTENERS: usize = 40;
pub const MAX_TCP_LISTENERS: usize = 40;
pub const MAX_CONTAINER_PROCESSES: usize = 16;
pub const STABILITY_ATTEMPTS: u32 = 3;
pub const STABILITY_INTERVAL_MILLISECONDS: u64 = 50;
pub const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);
pub const SOCKET_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

const MAX_PROC_NET_TABLE_BYTES: u64 = 1024 * 1024;
const MAX_PROCESS_FILE_BYTES: u64 = 4_096;
const UNIX_LISTEN_FLAG: u64 = 0x0001_0000;
const UNIX_STREAM: u64 = 1;
const UNIX_SEQPACKET: u64 = 5;
const TCP_LISTEN_STATE: u8 = 0x0a;
const UNREVIEWED_EXECUTABLE_PATH: &str = "unreviewed_executable_path";
const UNREVIEWED_CGROUP: &str = "unreviewed_cgroup";

const REVIEWED_EXECUTABLE_PATHS: &[&str] = &[
    "/usr/bin/containerd",
    "/usr/bin/dbus-daemon",
    "/usr/bin/dockerd",
    "/usr/lib/systemd/systemd",
    "/usr/lib/systemd/systemd-journald",
    "/usr/lib/systemd/systemd-networkd",
    "/usr/lib/systemd/systemd-resolved",
    "/usr/lib/systemd/systemd-udevd",
    "/usr/sbin/multipathd",
];

const REVIEWED_CGROUPS: &[&str] = &[
    "/",
    "/azure.slice/walinuxagent.service",
    "/init.scope",
    "/system.slice/containerd.service",
    "/system.slice/dbus.service",
    "/system.slice/docker.service",
    "/system.slice/multipathd.service",
    "/system.slice/systemd-journald.service",
    "/system.slice/systemd-networkd.service",
    "/system.slice/systemd-resolved.service",
    "/system.slice/systemd-udevd.service",
    "/system.slice/walinuxagent.service",
];

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Stable,
    Unstable,
    BoundsExceeded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    WithinBounds,
    BoundsExceeded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundReason {
    ContainerProcesses,
    FdsPerProcess,
    Processes,
    SocketOwners,
    TcpListeners,
    TotalFds,
    UnixListeners,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    CgroupIdentity,
    Ipv4Table,
    Ipv6Table,
    MalformedRows,
    Proc,
    ProcScan,
    ProcessFdReadlink,
    ProcessFdScan,
    ProcessIdentity,
    ProcessIdentityDrift,
    SocketOwnership,
    UnixReachability,
    UnixTable,
}

impl UnavailableReason {
    fn is_acquisition(self) -> bool {
        matches!(
            self,
            Self::Proc
                | Self::ProcScan
                | Self::ProcessIdentity
                | Self::ProcessIdentityDrift
                | Self::ProcessFdScan
                | Self::ProcessFdReadlink
                | Self::CgroupIdentity
                | Self::UnixTable
                | Self::Ipv4Table
                | Self::Ipv6Table
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InternetAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindClass {
    Loopback,
    OtherLocal,
    Wildcard,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixSocketType {
    Seqpacket,
    Stream,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixNameKind {
    Abstract,
    Filesystem,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LocalControlOwner {
    pub uid: u32,
    pub executable_basename: String,
    pub canonical_executable: String,
    pub unified_cgroup: String,
    pub processes: u32,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RootContainerProcess {
    pub uid: u32,
    pub executable_basename: String,
    pub canonical_executable: String,
    pub unified_cgroup: String,
    pub instances: u32,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct UnixListener {
    pub socket_type: UnixSocketType,
    pub name_kind: UnixNameKind,
    pub name_sha256: String,
    pub runner_reachable: bool,
    pub owners: Vec<LocalControlOwner>,
    pub ownership_complete: bool,
    pub instances: u32,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TcpListener {
    pub family: InternetAddressFamily,
    pub bind_class: BindClass,
    pub port: u16,
    pub owners: Vec<LocalControlOwner>,
    pub ownership_complete: bool,
    pub instances: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct LocalControlSnapshot {
    pub scan_status: ScanStatus,
    pub bounds_exceeded: Vec<BoundReason>,
    pub unavailable_inputs: Vec<UnavailableReason>,
    pub malformed_row_count: u64,
    pub unresolved_unix_listener_count: u64,
    pub inaccessible_root_filesystem_listener_count: u64,
    pub reachability_complete: bool,
    pub ownership_complete: bool,
    pub root_container_processes: Vec<RootContainerProcess>,
    pub unix_listeners: Vec<UnixListener>,
    pub tcp_listeners: Vec<TcpListener>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct LocalControlLimits {
    pub processes: usize,
    pub file_descriptors_per_process: usize,
    pub total_file_descriptors: usize,
    pub owners_per_socket: usize,
    pub unix_listeners: usize,
    pub tcp_listeners: usize,
    pub container_processes: usize,
}

impl LocalControlLimits {
    pub const fn reviewed() -> Self {
        Self {
            processes: MAX_PROCESSES,
            file_descriptors_per_process: MAX_FILE_DESCRIPTORS_PER_PROCESS,
            total_file_descriptors: MAX_TOTAL_FILE_DESCRIPTORS,
            owners_per_socket: MAX_OWNERS_PER_SOCKET,
            unix_listeners: MAX_UNIX_LISTENERS,
            tcp_listeners: MAX_TCP_LISTENERS,
            container_processes: MAX_CONTAINER_PROCESSES,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct LocalControlObservation {
    pub status: ObservationStatus,
    pub stable: bool,
    pub attempts: u32,
    pub interval_milliseconds: u64,
    pub limits: LocalControlLimits,
    pub snapshot: LocalControlSnapshot,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FilesystemSocketAccess {
    Reachable { owner_uid: u32 },
    Unreachable { owner_uid: u32 },
    Absent,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FilesystemSocketIdentity {
    Present { owner_uid: u32 },
    Absent,
    Unavailable,
}

pub trait UnixSocketAccess {
    fn inspect(&self, path: &OsStr) -> FilesystemSocketAccess;

    fn identity(&self, path: &OsStr) -> FilesystemSocketIdentity {
        match self.inspect(path) {
            FilesystemSocketAccess::Reachable { owner_uid }
            | FilesystemSocketAccess::Unreachable { owner_uid } => {
                FilesystemSocketIdentity::Present { owner_uid }
            }
            FilesystemSocketAccess::Absent => FilesystemSocketIdentity::Absent,
            FilesystemSocketAccess::Unavailable => FilesystemSocketIdentity::Unavailable,
        }
    }
}

pub struct SystemUnixSocketAccess<Probe> {
    runner_writable: Probe,
}

impl<Probe> SystemUnixSocketAccess<Probe> {
    pub fn new(runner_writable: Probe) -> Self {
        Self { runner_writable }
    }
}

impl<Probe> UnixSocketAccess for SystemUnixSocketAccess<Probe>
where
    Probe: Fn(&OsStr) -> Option<bool>,
{
    fn inspect(&self, path: &OsStr) -> FilesystemSocketAccess {
        let owner_uid = match self.identity(path) {
            FilesystemSocketIdentity::Present { owner_uid } => owner_uid,
            FilesystemSocketIdentity::Absent => return FilesystemSocketAccess::Absent,
            FilesystemSocketIdentity::Unavailable => {
                return FilesystemSocketAccess::Unavailable;
            }
        };
        match (self.runner_writable)(path) {
            Some(true) => FilesystemSocketAccess::Reachable { owner_uid },
            Some(false) => FilesystemSocketAccess::Unreachable { owner_uid },
            None => FilesystemSocketAccess::Unavailable,
        }
    }

    fn identity(&self, path: &OsStr) -> FilesystemSocketIdentity {
        if !Path::new(path).is_absolute() {
            return FilesystemSocketIdentity::Unavailable;
        }
        let metadata = match fs::symlink_metadata(Path::new(path)) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return FilesystemSocketIdentity::Absent;
            }
            Err(_) => return FilesystemSocketIdentity::Unavailable,
        };
        if !metadata.file_type().is_socket() {
            return FilesystemSocketIdentity::Unavailable;
        }
        FilesystemSocketIdentity::Present {
            owner_uid: metadata.uid(),
        }
    }
}

pub trait CurrentFenceOwner {
    fn owns_process(
        &self,
        pid: u32,
        start_time_ticks: u64,
        executable_device: u64,
        executable_inode: u64,
    ) -> bool;
}

#[derive(Debug, Default)]
pub struct NoCurrentFenceOwner;

impl CurrentFenceOwner for NoCurrentFenceOwner {
    fn owns_process(
        &self,
        _pid: u32,
        _start_time_ticks: u64,
        _executable_device: u64,
        _executable_inode: u64,
    ) -> bool {
        false
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PinnedCurrentFenceOwner {
    pin: ProcessPin,
}

impl PinnedCurrentFenceOwner {
    pub fn capture(proc_root: &Path) -> Result<Self, LocalControlVerificationError> {
        let pid = std::process::id();
        let process_root = proc_root.join(pid.to_string());
        let before = observe_process(&process_root).map_err(|_| {
            verification_error(
                LocalControlVerificationErrorKind::Unavailable,
                "local_control_current_process_unavailable",
                "current Fence process identity could not be pinned",
            )
        })?;
        let after = observe_process(&process_root).map_err(|_| {
            verification_error(
                LocalControlVerificationErrorKind::Unavailable,
                "local_control_current_process_unavailable",
                "current Fence process identity could not be pinned",
            )
        })?;
        if before != after {
            return Err(verification_error(
                LocalControlVerificationErrorKind::Unavailable,
                "local_control_current_process_unavailable",
                "current Fence process identity could not be pinned",
            ));
        }
        Ok(Self {
            pin: before.pin(pid),
        })
    }
}

impl CurrentFenceOwner for PinnedCurrentFenceOwner {
    fn owns_process(
        &self,
        pid: u32,
        start_time_ticks: u64,
        executable_device: u64,
        executable_inode: u64,
    ) -> bool {
        self.pin
            == (ProcessPin {
                pid,
                start_time_ticks,
                executable_device,
                executable_inode,
            })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LocalControlDriftKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LocalControlVerificationErrorKind {
    InvalidAcceptedFingerprint,
    Unstable,
    BoundsExceeded,
    Unavailable,
    Incomplete,
    Drift(LocalControlDriftKind),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LocalControlVerificationError {
    pub kind: LocalControlVerificationErrorKind,
    pub code: &'static str,
    pub message: &'static str,
}

impl Display for LocalControlVerificationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for LocalControlVerificationError {}

pub fn verify_local_control_observation(
    accepted: &LocalControlSnapshot,
    observed: &LocalControlObservation,
) -> Result<(), LocalControlVerificationError> {
    verify_complete_local_control_observation(observed)?;
    compare_local_control_snapshots(accepted, &observed.snapshot)
}

fn verify_complete_local_control_observation(
    observed: &LocalControlObservation,
) -> Result<(), LocalControlVerificationError> {
    if !observed.stable || observed.status == ObservationStatus::Unstable {
        return Err(verification_error(
            LocalControlVerificationErrorKind::Unstable,
            "local_control_inventory_unstable",
            "local control inventory did not stabilize",
        ));
    }
    if observed.status == ObservationStatus::BoundsExceeded
        || observed.snapshot.scan_status == ScanStatus::BoundsExceeded
        || !observed.snapshot.bounds_exceeded.is_empty()
    {
        return Err(verification_error(
            LocalControlVerificationErrorKind::BoundsExceeded,
            "local_control_inventory_bounds_exceeded",
            "local control inventory exceeded a fixed bound",
        ));
    }
    if observed.status == ObservationStatus::Unavailable
        || observed.snapshot.scan_status == ScanStatus::Unavailable
        || !observed.snapshot.unavailable_inputs.is_empty()
    {
        return Err(verification_error(
            LocalControlVerificationErrorKind::Unavailable,
            "local_control_inventory_unavailable",
            "local control inventory acquisition was unavailable",
        ));
    }
    if !observed.snapshot.reachability_complete || !observed.snapshot.ownership_complete {
        return Err(verification_error(
            LocalControlVerificationErrorKind::Incomplete,
            "local_control_inventory_incomplete",
            "local control inventory was incomplete",
        ));
    }
    Ok(())
}

pub fn verify_no_additive_local_control_observation(
    accepted: &LocalControlSnapshot,
    observed: &LocalControlObservation,
) -> Result<(), LocalControlVerificationError> {
    verify_complete_local_control_observation(observed)?;
    let snapshot = &observed.snapshot;
    let containers_are_subset = root_container_processes_are_subset(
        &snapshot.root_container_processes,
        &accepted.root_container_processes,
    );
    let tcp_is_subset = tcp_listeners_are_subset(&snapshot.tcp_listeners, &accepted.tcp_listeners);
    let unix_is_subset =
        unix_listeners_are_subset(&snapshot.unix_listeners, &accepted.unix_listeners);
    if !containers_are_subset || !tcp_is_subset || !unix_is_subset {
        return Err(verification_error(
            LocalControlVerificationErrorKind::Drift(LocalControlDriftKind::Added),
            "local_control_inventory_additive_drift",
            "local control inventory gained an endpoint or owner outside the accepted fingerprint",
        ));
    }

    let reviewed_containers = &accepted.root_container_processes;
    if non_container_tcp_projection(&snapshot.tcp_listeners, reviewed_containers)
        != non_container_tcp_projection(&accepted.tcp_listeners, reviewed_containers)
        || non_container_unix_projection(&snapshot.unix_listeners, reviewed_containers)
            != non_container_unix_projection(&accepted.unix_listeners, reviewed_containers)
    {
        return Err(verification_error(
            LocalControlVerificationErrorKind::Drift(LocalControlDriftKind::Removed),
            "local_control_inventory_unreviewed_reduction",
            "local control inventory lost a non-container endpoint or owner",
        ));
    }

    Ok(())
}

fn non_container_tcp_projection(
    listeners: &[TcpListener],
    reviewed_containers: &[RootContainerProcess],
) -> Vec<TcpListener> {
    listeners
        .iter()
        .cloned()
        .map(|mut projected| {
            projected
                .owners
                .retain(|owner| !is_reviewed_container_owner(owner, reviewed_containers));
            projected
        })
        .collect()
}

fn non_container_unix_projection(
    listeners: &[UnixListener],
    reviewed_containers: &[RootContainerProcess],
) -> Vec<UnixListener> {
    listeners
        .iter()
        .cloned()
        .map(|mut projected| {
            projected
                .owners
                .retain(|owner| !is_reviewed_container_owner(owner, reviewed_containers));
            projected
        })
        .collect()
}

fn is_reviewed_container_owner(
    owner: &LocalControlOwner,
    reviewed_containers: &[RootContainerProcess],
) -> bool {
    reviewed_containers.iter().any(|container| {
        owner.uid == container.uid
            && owner.executable_basename == container.executable_basename
            && owner.canonical_executable == container.canonical_executable
            && owner.unified_cgroup == container.unified_cgroup
    })
}

fn root_container_processes_are_subset(
    observed: &[RootContainerProcess],
    accepted: &[RootContainerProcess],
) -> bool {
    if contains_duplicate_root_container_key(accepted)
        || observed.iter().any(|item| {
            item.instances == 0
                || !accepted
                    .iter()
                    .any(|expected| same_root_container_key(item, expected))
        })
    {
        return false;
    }

    accepted.iter().all(|expected| {
        observed
            .iter()
            .filter(|item| same_root_container_key(item, expected))
            .map(|item| u64::from(item.instances))
            .sum::<u64>()
            <= u64::from(expected.instances)
    })
}

fn tcp_listeners_are_subset(observed: &[TcpListener], accepted: &[TcpListener]) -> bool {
    if contains_duplicate_tcp_key(accepted)
        || observed.iter().any(|item| {
            item.instances == 0
                || item.owners.is_empty()
                || !item.ownership_complete
                || !accepted.iter().any(|expected| {
                    same_tcp_key(item, expected)
                        && owners_are_subset(&item.owners, &expected.owners)
                })
        })
    {
        return false;
    }

    accepted.iter().all(|expected| {
        observed
            .iter()
            .filter(|item| same_tcp_key(item, expected))
            .map(|item| u64::from(item.instances))
            .sum::<u64>()
            <= u64::from(expected.instances)
    })
}

fn unix_listeners_are_subset(observed: &[UnixListener], accepted: &[UnixListener]) -> bool {
    if contains_duplicate_unix_key(accepted)
        || observed.iter().any(|item| {
            item.instances == 0
                || item.owners.is_empty()
                || !item.runner_reachable
                || !item.ownership_complete
                || !accepted.iter().any(|expected| {
                    same_unix_key(item, expected)
                        && owners_are_subset(&item.owners, &expected.owners)
                })
        })
    {
        return false;
    }

    accepted.iter().all(|expected| {
        observed
            .iter()
            .filter(|item| same_unix_key(item, expected))
            .map(|item| u64::from(item.instances))
            .sum::<u64>()
            <= u64::from(expected.instances)
    })
}

fn owners_are_subset(observed: &[LocalControlOwner], accepted: &[LocalControlOwner]) -> bool {
    if contains_duplicate_owner_key(accepted)
        || observed.iter().any(|item| {
            item.processes == 0
                || !accepted
                    .iter()
                    .any(|expected| same_owner_key(item, expected))
        })
    {
        return false;
    }

    accepted.iter().all(|expected| {
        observed
            .iter()
            .filter(|item| same_owner_key(item, expected))
            .map(|item| u64::from(item.processes))
            .sum::<u64>()
            <= u64::from(expected.processes)
    })
}

fn contains_duplicate_root_container_key(items: &[RootContainerProcess]) -> bool {
    items.iter().enumerate().any(|(index, item)| {
        items[..index]
            .iter()
            .any(|other| same_root_container_key(item, other))
    })
}

fn same_root_container_key(left: &RootContainerProcess, right: &RootContainerProcess) -> bool {
    left.uid == right.uid
        && left.executable_basename == right.executable_basename
        && left.canonical_executable == right.canonical_executable
        && left.unified_cgroup == right.unified_cgroup
}

fn contains_duplicate_tcp_key(items: &[TcpListener]) -> bool {
    items
        .iter()
        .enumerate()
        .any(|(index, item)| items[..index].iter().any(|other| same_tcp_key(item, other)))
}

fn same_tcp_key(left: &TcpListener, right: &TcpListener) -> bool {
    left.family == right.family && left.bind_class == right.bind_class && left.port == right.port
}

fn contains_duplicate_unix_key(items: &[UnixListener]) -> bool {
    items.iter().enumerate().any(|(index, item)| {
        items[..index]
            .iter()
            .any(|other| same_unix_key(item, other))
    })
}

fn same_unix_key(left: &UnixListener, right: &UnixListener) -> bool {
    left.socket_type == right.socket_type
        && left.name_kind == right.name_kind
        && left.name_sha256 == right.name_sha256
}

fn contains_duplicate_owner_key(items: &[LocalControlOwner]) -> bool {
    items.iter().enumerate().any(|(index, item)| {
        items[..index]
            .iter()
            .any(|other| same_owner_key(item, other))
    })
}

fn same_owner_key(left: &LocalControlOwner, right: &LocalControlOwner) -> bool {
    left.uid == right.uid
        && left.executable_basename == right.executable_basename
        && left.canonical_executable == right.canonical_executable
        && left.unified_cgroup == right.unified_cgroup
}

pub fn accepted_local_control_snapshot(
    accepted: &AcceptedLocalControlInventoryV2,
) -> Result<LocalControlSnapshot, LocalControlVerificationError> {
    if accepted.unix_name_hash_schema != UNIX_NAME_HASH_SCHEMA_V1 {
        return Err(invalid_accepted_fingerprint());
    }
    let root_container_processes: Vec<RootContainerProcess> = accepted
        .root_container_processes
        .iter()
        .map(|process| RootContainerProcess {
            uid: process.uid,
            executable_basename: process.executable_basename.to_owned(),
            canonical_executable: process.canonical_executable.to_owned(),
            unified_cgroup: process.unified_cgroup.to_owned(),
            instances: process.instances,
        })
        .collect();
    let tcp_listeners = accepted
        .tcp_listeners
        .iter()
        .map(|listener| {
            Ok(TcpListener {
                family: parse_family(listener.family)?,
                bind_class: parse_bind_class(listener.bind_class)?,
                port: listener.port,
                owners: accepted_owners(&listener.owners),
                ownership_complete: true,
                instances: listener.instances,
            })
        })
        .collect::<Result<Vec<_>, LocalControlVerificationError>>()?;
    let unix_listeners = accepted
        .unix_listeners
        .iter()
        .map(|listener| {
            Ok(UnixListener {
                socket_type: parse_socket_type(listener.socket_type)?,
                name_kind: parse_name_kind(listener.name_kind)?,
                name_sha256: listener.name_sha256.to_owned(),
                runner_reachable: true,
                owners: accepted_owners(&listener.owners),
                ownership_complete: true,
                instances: listener.instances,
            })
        })
        .collect::<Result<Vec<_>, LocalControlVerificationError>>()?;
    if root_container_processes
        .iter()
        .any(|process: &RootContainerProcess| process.instances == 0)
        || contains_duplicate_root_container_key(&root_container_processes)
        || tcp_listeners.iter().any(|listener| {
            listener.instances == 0
                || listener.owners.is_empty()
                || listener.owners.iter().any(|owner| owner.processes == 0)
                || contains_duplicate_owner_key(&listener.owners)
        })
        || contains_duplicate_tcp_key(&tcp_listeners)
        || unix_listeners.iter().any(|listener| {
            listener.instances == 0
                || listener.owners.is_empty()
                || listener.owners.iter().any(|owner| owner.processes == 0)
                || contains_duplicate_owner_key(&listener.owners)
                || listener.name_sha256.len() != 64
                || !listener
                    .name_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        || contains_duplicate_unix_key(&unix_listeners)
    {
        return Err(invalid_accepted_fingerprint());
    }
    Ok(LocalControlSnapshot {
        scan_status: ScanStatus::WithinBounds,
        bounds_exceeded: Vec::new(),
        unavailable_inputs: Vec::new(),
        malformed_row_count: 0,
        unresolved_unix_listener_count: 0,
        inaccessible_root_filesystem_listener_count: 0,
        reachability_complete: true,
        ownership_complete: true,
        root_container_processes,
        unix_listeners,
        tcp_listeners,
    })
}

fn accepted_owners(owners: &[AcceptedLocalControlOwnerV2]) -> Vec<LocalControlOwner> {
    owners
        .iter()
        .map(|owner| LocalControlOwner {
            uid: owner.uid,
            executable_basename: owner.executable_basename.to_owned(),
            canonical_executable: owner.canonical_executable.to_owned(),
            unified_cgroup: owner.unified_cgroup.to_owned(),
            processes: owner.processes,
        })
        .collect()
}

fn parse_family(value: &str) -> Result<InternetAddressFamily, LocalControlVerificationError> {
    match value {
        "ipv4" => Ok(InternetAddressFamily::Ipv4),
        "ipv6" => Ok(InternetAddressFamily::Ipv6),
        _ => Err(invalid_accepted_fingerprint()),
    }
}

fn parse_bind_class(value: &str) -> Result<BindClass, LocalControlVerificationError> {
    match value {
        "wildcard" => Ok(BindClass::Wildcard),
        "loopback" => Ok(BindClass::Loopback),
        "other_local" => Ok(BindClass::OtherLocal),
        _ => Err(invalid_accepted_fingerprint()),
    }
}

fn parse_socket_type(value: &str) -> Result<UnixSocketType, LocalControlVerificationError> {
    match value {
        "stream" => Ok(UnixSocketType::Stream),
        "seqpacket" => Ok(UnixSocketType::Seqpacket),
        _ => Err(invalid_accepted_fingerprint()),
    }
}

fn parse_name_kind(value: &str) -> Result<UnixNameKind, LocalControlVerificationError> {
    match value {
        "abstract" => Ok(UnixNameKind::Abstract),
        "filesystem" => Ok(UnixNameKind::Filesystem),
        _ => Err(invalid_accepted_fingerprint()),
    }
}

fn invalid_accepted_fingerprint() -> LocalControlVerificationError {
    verification_error(
        LocalControlVerificationErrorKind::InvalidAcceptedFingerprint,
        "local_control_accepted_fingerprint_invalid",
        "accepted local control fingerprint is invalid",
    )
}

pub fn compare_local_control_snapshots(
    accepted: &LocalControlSnapshot,
    observed: &LocalControlSnapshot,
) -> Result<(), LocalControlVerificationError> {
    if local_control_snapshots_match(accepted, observed) {
        return Ok(());
    }
    let accepted_endpoints = public_endpoint_keys(accepted);
    let observed_endpoints = public_endpoint_keys(observed);
    let kind = if observed_endpoints
        .iter()
        .any(|endpoint| !accepted_endpoints.contains(endpoint))
    {
        LocalControlDriftKind::Added
    } else if accepted_endpoints
        .iter()
        .any(|endpoint| !observed_endpoints.contains(endpoint))
    {
        LocalControlDriftKind::Removed
    } else {
        LocalControlDriftKind::Changed
    };
    Err(verification_error(
        LocalControlVerificationErrorKind::Drift(kind),
        "local_control_inventory_drift",
        "local control inventory did not match the accepted fingerprint",
    ))
}

fn local_control_snapshots_match(
    accepted: &LocalControlSnapshot,
    observed: &LocalControlSnapshot,
) -> bool {
    accepted.scan_status == observed.scan_status
        && accepted.bounds_exceeded == observed.bounds_exceeded
        && accepted.unavailable_inputs == observed.unavailable_inputs
        && accepted.malformed_row_count == observed.malformed_row_count
        && accepted.unresolved_unix_listener_count == observed.unresolved_unix_listener_count
        && accepted.reachability_complete == observed.reachability_complete
        && accepted.ownership_complete == observed.ownership_complete
        && accepted.root_container_processes == observed.root_container_processes
        && accepted.unix_listeners == observed.unix_listeners
        && accepted.tcp_listeners == observed.tcp_listeners
}

fn verification_error(
    kind: LocalControlVerificationErrorKind,
    code: &'static str,
    message: &'static str,
) -> LocalControlVerificationError {
    LocalControlVerificationError {
        kind,
        code,
        message,
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
enum PublicEndpointKey {
    Container(String, String),
    Unix(UnixSocketType, UnixNameKind, String),
    Tcp(InternetAddressFamily, BindClass, u16),
}

fn public_endpoint_keys(snapshot: &LocalControlSnapshot) -> BTreeSet<PublicEndpointKey> {
    let mut keys = BTreeSet::new();
    keys.extend(snapshot.root_container_processes.iter().map(|process| {
        PublicEndpointKey::Container(
            process.executable_basename.clone(),
            process.canonical_executable.clone(),
        )
    }));
    keys.extend(snapshot.unix_listeners.iter().map(|listener| {
        PublicEndpointKey::Unix(
            listener.socket_type,
            listener.name_kind,
            listener.name_sha256.clone(),
        )
    }));
    keys.extend(snapshot.tcp_listeners.iter().map(|listener| {
        PublicEndpointKey::Tcp(listener.family, listener.bind_class, listener.port)
    }));
    keys
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ProcessPin {
    pid: u32,
    start_time_ticks: u64,
    executable_device: u64,
    executable_inode: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProcessObservation {
    uid: u32,
    start_time_ticks: u64,
    executable_device: u64,
    executable_inode: u64,
    executable_basename: String,
    canonical_executable: String,
    executable_path_fingerprint: String,
}

impl ProcessObservation {
    fn pin(&self, pid: u32) -> ProcessPin {
        ProcessPin {
            pid,
            start_time_ticks: self.start_time_ticks,
            executable_device: self.executable_device,
            executable_inode: self.executable_inode,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CgroupObservation {
    unified_cgroup: String,
    fingerprint: Option<String>,
    reviewed: bool,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct PrivateOwnerKey {
    uid: u32,
    executable_basename: String,
    canonical_executable: String,
    unified_cgroup: String,
    executable_path_fingerprint: String,
    cgroup_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PrivateOwner {
    key: PrivateOwnerKey,
    identity_complete: bool,
    process_pins: BTreeSet<ProcessPin>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PrivateContainer {
    key: PrivateOwnerKey,
    identity_complete: bool,
    process_pin: ProcessPin,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PrivateUnixListener {
    socket_inode: u64,
    socket_type: UnixSocketType,
    name_kind: UnixNameKind,
    name_sha256: String,
    owners: Vec<PrivateOwner>,
    ownership_complete: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PrivateTcpListener {
    socket_inode: u64,
    socket_uid: u32,
    family: InternetAddressFamily,
    bind_class: BindClass,
    port: u16,
    owners: Vec<PrivateOwner>,
    ownership_complete: bool,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum ExcludedAccessState {
    AbstractOwnerUnresolved,
    Unreachable,
    AbsentUnreachable,
    Unavailable,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ExcludedUnixListener {
    socket_inode: u64,
    socket_type: UnixSocketType,
    name_kind: UnixNameKind,
    name_sha256: String,
    access_state: ExcludedAccessState,
    root_control_candidate: bool,
    owners: Vec<PrivateOwner>,
    ownership_complete: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PrivateSnapshot {
    bounds_exceeded: BTreeSet<BoundReason>,
    unavailable_inputs: BTreeSet<UnavailableReason>,
    malformed_row_count: u64,
    unresolved_unix_listener_count: u64,
    inaccessible_root_filesystem_listener_count: u64,
    excluded_unix_listeners: Vec<ExcludedUnixListener>,
    root_container_processes: Vec<PrivateContainer>,
    unix_listeners: Vec<PrivateUnixListener>,
    tcp_listeners: Vec<PrivateTcpListener>,
}

impl PrivateSnapshot {
    fn unavailable(reason: UnavailableReason) -> Self {
        Self {
            bounds_exceeded: BTreeSet::new(),
            unavailable_inputs: BTreeSet::from([reason]),
            malformed_row_count: 0,
            unresolved_unix_listener_count: 0,
            inaccessible_root_filesystem_listener_count: 0,
            excluded_unix_listeners: Vec::new(),
            root_container_processes: Vec::new(),
            unix_listeners: Vec::new(),
            tcp_listeners: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedTcpListener {
    inode: u64,
    socket_uid: u32,
    family: InternetAddressFamily,
    bind_class: BindClass,
    port: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedUnixListener {
    inode: u64,
    socket_type: UnixSocketType,
    name_kind: UnixNameKind,
    raw_name: OsString,
    name_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedTable<T> {
    rows: Vec<T>,
    malformed_rows: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AcquisitionError {
    Missing,
    Unavailable,
    Malformed,
    TooLarge,
}

pub fn observe_local_control_inventory(
    proc_root: &Path,
    socket_access: &dyn UnixSocketAccess,
    current_fence: &dyn CurrentFenceOwner,
) -> LocalControlObservation {
    observe_local_control_with(
        || collect_private_snapshot(proc_root, socket_access, current_fence),
        || thread::sleep(Duration::from_millis(STABILITY_INTERVAL_MILLISECONDS)),
    )
}

fn observe_local_control_with<C, S>(mut capture: C, mut sleep: S) -> LocalControlObservation
where
    C: FnMut() -> PrivateSnapshot,
    S: FnMut(),
{
    let mut last = PrivateSnapshot::unavailable(UnavailableReason::Proc);
    for attempt in 1..=STABILITY_ATTEMPTS {
        let first = capture();
        sleep();
        let second = capture();
        last = second.clone();
        if first == second {
            let snapshot = public_snapshot(second);
            let status = match snapshot.scan_status {
                ScanStatus::WithinBounds => ObservationStatus::Stable,
                ScanStatus::BoundsExceeded => ObservationStatus::BoundsExceeded,
                ScanStatus::Unavailable => ObservationStatus::Unavailable,
            };
            return LocalControlObservation {
                status,
                stable: true,
                attempts: attempt,
                interval_milliseconds: STABILITY_INTERVAL_MILLISECONDS,
                limits: LocalControlLimits::reviewed(),
                snapshot,
            };
        }
    }
    LocalControlObservation {
        status: ObservationStatus::Unstable,
        stable: false,
        attempts: STABILITY_ATTEMPTS,
        interval_milliseconds: STABILITY_INTERVAL_MILLISECONDS,
        limits: LocalControlLimits::reviewed(),
        snapshot: public_snapshot(last),
    }
}

fn collect_private_snapshot(
    proc_root: &Path,
    socket_access: &dyn UnixSocketAccess,
    current_fence: &dyn CurrentFenceOwner,
) -> PrivateSnapshot {
    let mut unavailable = BTreeSet::new();
    let mut malformed_row_count = 0_u64;
    let mut unix = match read_bounded(&proc_root.join("net/unix"), MAX_PROC_NET_TABLE_BYTES)
        .and_then(|contents| parse_unix_table(&contents))
    {
        Ok(parsed) => {
            malformed_row_count = malformed_row_count.saturating_add(parsed.malformed_rows);
            parsed.rows
        }
        Err(_) => {
            unavailable.insert(UnavailableReason::UnixTable);
            Vec::new()
        }
    };
    let tcp = match read_bounded(&proc_root.join("net/tcp"), MAX_PROC_NET_TABLE_BYTES)
        .and_then(|contents| parse_tcp_table(&contents, InternetAddressFamily::Ipv4))
    {
        Ok(parsed) => {
            malformed_row_count = malformed_row_count.saturating_add(parsed.malformed_rows);
            parsed.rows
        }
        Err(_) => {
            unavailable.insert(UnavailableReason::Ipv4Table);
            Vec::new()
        }
    };
    let tcp6 = match read_bounded(&proc_root.join("net/tcp6"), MAX_PROC_NET_TABLE_BYTES)
        .and_then(|contents| parse_tcp_table(&contents, InternetAddressFamily::Ipv6))
    {
        Ok(parsed) => {
            malformed_row_count = malformed_row_count.saturating_add(parsed.malformed_rows);
            parsed.rows
        }
        Err(_) => {
            unavailable.insert(UnavailableReason::Ipv6Table);
            Vec::new()
        }
    };

    let mut all_tcp = tcp;
    all_tcp.extend(tcp6);
    let mut seen_inodes = BTreeSet::new();
    unix.retain(|listener| {
        if listener.inode == 0 || !seen_inodes.insert(listener.inode) {
            malformed_row_count = malformed_row_count.saturating_add(1);
            false
        } else {
            true
        }
    });
    all_tcp.retain(|listener| {
        if listener.inode == 0 || !seen_inodes.insert(listener.inode) {
            malformed_row_count = malformed_row_count.saturating_add(1);
            false
        } else {
            true
        }
    });
    let relevant_inodes = unix
        .iter()
        .map(|listener| listener.inode)
        .chain(all_tcp.iter().map(|listener| listener.inode))
        .collect::<BTreeSet<_>>();
    let scan = scan_processes(proc_root, &relevant_inodes);
    unavailable.extend(scan.unavailable_inputs.iter().copied());
    let mut bounds = scan.bounds_exceeded.clone();

    let mut unresolved_unix_listener_count = 0_u64;
    let mut inaccessible_root_filesystem_listener_count = 0_u64;
    let mut excluded_unix_listeners = Vec::new();
    let mut unix_listeners = Vec::new();
    let mut filesystem_probe_candidates = 0_usize;
    for row in unix {
        let (owners, owners_truncated) = bounded_owners(&scan.owners, row.inode, &mut bounds);
        let owner_enumeration_complete = socket_owner_enumeration_complete(
            row.inode,
            &owners,
            owners_truncated,
            &scan.unresolved_owner_inodes,
        );
        let ownership_complete =
            owner_enumeration_complete && owners.iter().all(|owner| owner.identity_complete);
        let has_root_owner = owners.iter().any(|owner| owner.key.uid == 0);
        if exclusively_current_fence_owned(owner_enumeration_complete, &owners, current_fence) {
            continue;
        }
        if row.name_kind == UnixNameKind::Abstract {
            if scan.unresolved_root_inodes.contains(&row.inode) && !has_root_owner {
                unresolved_unix_listener_count = unresolved_unix_listener_count.saturating_add(1);
                excluded_unix_listeners.push(excluded_unix_listener(
                    &row,
                    owners,
                    ownership_complete,
                    ExcludedAccessState::AbstractOwnerUnresolved,
                    true,
                ));
            } else if owners.is_empty() {
                if !scan.known_nonroot_drift_inodes.contains(&row.inode) {
                    unresolved_unix_listener_count =
                        unresolved_unix_listener_count.saturating_add(1);
                    excluded_unix_listeners.push(excluded_unix_listener(
                        &row,
                        owners,
                        ownership_complete,
                        ExcludedAccessState::AbstractOwnerUnresolved,
                        false,
                    ));
                }
            } else if has_root_owner {
                unix_listeners.push(PrivateUnixListener {
                    socket_inode: row.inode,
                    socket_type: row.socket_type,
                    name_kind: row.name_kind,
                    name_sha256: row.name_sha256,
                    owners,
                    ownership_complete,
                });
            }
            continue;
        }

        let identity = socket_access.identity(row.raw_name.as_os_str());
        let root_control_candidate = filesystem_root_control_candidate(
            has_root_owner,
            scan.unresolved_root_inodes.contains(&row.inode),
            identity,
        );
        if !root_control_candidate {
            continue;
        }
        if !reserve_filesystem_probe(&mut filesystem_probe_candidates, &mut bounds) {
            continue;
        }
        let access = socket_access.inspect(row.raw_name.as_os_str());
        match access {
            FilesystemSocketAccess::Reachable { .. } => {
                if root_control_candidate {
                    unix_listeners.push(PrivateUnixListener {
                        socket_inode: row.inode,
                        socket_type: row.socket_type,
                        name_kind: row.name_kind,
                        name_sha256: row.name_sha256,
                        owners,
                        ownership_complete,
                    });
                }
            }
            FilesystemSocketAccess::Unreachable { .. } | FilesystemSocketAccess::Absent => {
                if root_control_candidate {
                    inaccessible_root_filesystem_listener_count =
                        inaccessible_root_filesystem_listener_count.saturating_add(1);
                }
                excluded_unix_listeners.push(excluded_unix_listener(
                    &row,
                    owners,
                    ownership_complete,
                    if access == FilesystemSocketAccess::Absent {
                        ExcludedAccessState::AbsentUnreachable
                    } else {
                        ExcludedAccessState::Unreachable
                    },
                    root_control_candidate,
                ));
            }
            FilesystemSocketAccess::Unavailable => {
                unresolved_unix_listener_count = unresolved_unix_listener_count.saturating_add(1);
                excluded_unix_listeners.push(excluded_unix_listener(
                    &row,
                    owners,
                    ownership_complete,
                    ExcludedAccessState::Unavailable,
                    root_control_candidate,
                ));
                break;
            }
        }
    }

    let mut tcp_listeners = Vec::new();
    for row in all_tcp {
        let (owners, owners_truncated) = bounded_owners(&scan.owners, row.inode, &mut bounds);
        let has_root_owner = owners.iter().any(|owner| owner.key.uid == 0);
        let root_control_candidate = row.socket_uid == 0
            || has_root_owner
            || scan.unresolved_root_inodes.contains(&row.inode);
        let owner_enumeration_complete = socket_owner_enumeration_complete(
            row.inode,
            &owners,
            owners_truncated,
            &scan.unresolved_owner_inodes,
        );
        let ownership_complete =
            owner_enumeration_complete && owners.iter().all(|owner| owner.identity_complete);
        if !retain_tcp_listener(
            root_control_candidate,
            owner_enumeration_complete,
            &owners,
            current_fence,
        ) {
            continue;
        }
        tcp_listeners.push(PrivateTcpListener {
            socket_inode: row.inode,
            socket_uid: row.socket_uid,
            family: row.family,
            bind_class: row.bind_class,
            port: row.port,
            owners,
            ownership_complete,
        });
    }

    unix_listeners.sort_by(private_unix_sort);
    tcp_listeners.sort_by(private_tcp_sort);
    excluded_unix_listeners.sort_by(excluded_unix_sort);
    if unix_listeners.len() > MAX_UNIX_LISTENERS {
        bounds.insert(BoundReason::UnixListeners);
        unix_listeners.truncate(MAX_UNIX_LISTENERS);
    }
    if tcp_listeners.len() > MAX_TCP_LISTENERS {
        bounds.insert(BoundReason::TcpListeners);
        tcp_listeners.truncate(MAX_TCP_LISTENERS);
    }

    PrivateSnapshot {
        bounds_exceeded: bounds,
        unavailable_inputs: unavailable,
        malformed_row_count,
        unresolved_unix_listener_count,
        inaccessible_root_filesystem_listener_count,
        excluded_unix_listeners,
        root_container_processes: scan.root_container_processes,
        unix_listeners,
        tcp_listeners,
    }
}

fn excluded_unix_listener(
    row: &ParsedUnixListener,
    owners: Vec<PrivateOwner>,
    ownership_complete: bool,
    access_state: ExcludedAccessState,
    root_control_candidate: bool,
) -> ExcludedUnixListener {
    ExcludedUnixListener {
        socket_inode: row.inode,
        socket_type: row.socket_type,
        name_kind: row.name_kind,
        name_sha256: row.name_sha256.clone(),
        access_state,
        root_control_candidate,
        owners,
        ownership_complete,
    }
}

fn reserve_filesystem_probe(candidates: &mut usize, bounds: &mut BTreeSet<BoundReason>) -> bool {
    if *candidates == MAX_UNIX_LISTENERS {
        bounds.insert(BoundReason::UnixListeners);
        false
    } else {
        *candidates += 1;
        true
    }
}

fn filesystem_root_control_candidate(
    has_root_owner: bool,
    unresolved_root_owner: bool,
    identity: FilesystemSocketIdentity,
) -> bool {
    has_root_owner
        || unresolved_root_owner
        || matches!(
            identity,
            FilesystemSocketIdentity::Present { owner_uid: 0 }
                | FilesystemSocketIdentity::Unavailable
        )
}

fn retain_tcp_listener(
    root_control_candidate: bool,
    owner_enumeration_complete: bool,
    owners: &[PrivateOwner],
    current_fence: &dyn CurrentFenceOwner,
) -> bool {
    root_control_candidate
        && !exclusively_current_fence_owned(owner_enumeration_complete, owners, current_fence)
}

fn exclusively_current_fence_owned(
    ownership_complete: bool,
    owners: &[PrivateOwner],
    current_fence: &dyn CurrentFenceOwner,
) -> bool {
    ownership_complete
        && !owners.is_empty()
        && owners.iter().all(|owner| {
            !owner.process_pins.is_empty()
                && owner.process_pins.iter().all(|pin| {
                    current_fence.owns_process(
                        pin.pid,
                        pin.start_time_ticks,
                        pin.executable_device,
                        pin.executable_inode,
                    )
                })
        })
}

fn socket_owner_enumeration_complete(
    inode: u64,
    owners: &[PrivateOwner],
    owners_truncated: bool,
    unresolved_owner_inodes: &BTreeSet<u64>,
) -> bool {
    !owners.is_empty() && !owners_truncated && !unresolved_owner_inodes.contains(&inode)
}

fn bounded_owners(
    owners_by_inode: &BTreeMap<u64, BTreeMap<PrivateOwnerKey, PrivateOwner>>,
    inode: u64,
    bounds: &mut BTreeSet<BoundReason>,
) -> (Vec<PrivateOwner>, bool) {
    let mut owners = owners_by_inode
        .get(&inode)
        .map(|values| values.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    owners.sort_by(|left, right| left.key.cmp(&right.key));
    let truncated = owners.len() > MAX_OWNERS_PER_SOCKET;
    if truncated {
        bounds.insert(BoundReason::SocketOwners);
        owners.truncate(MAX_OWNERS_PER_SOCKET);
    }
    (owners, truncated)
}

#[derive(Default)]
struct ProcessScan {
    owners: BTreeMap<u64, BTreeMap<PrivateOwnerKey, PrivateOwner>>,
    unresolved_owner_inodes: BTreeSet<u64>,
    unresolved_root_inodes: BTreeSet<u64>,
    known_nonroot_drift_inodes: BTreeSet<u64>,
    root_container_processes: Vec<PrivateContainer>,
    bounds_exceeded: BTreeSet<BoundReason>,
    unavailable_inputs: BTreeSet<UnavailableReason>,
}

fn scan_processes(proc_root: &Path, relevant_inodes: &BTreeSet<u64>) -> ProcessScan {
    let mut scan = ProcessScan::default();
    let mut process_entries = match numeric_process_entries(proc_root, &mut scan) {
        Some(entries) => entries,
        None => return scan,
    };
    process_entries.sort_by_key(|(pid, _)| *pid);
    let mut total_descriptors = 0_usize;
    'processes: for (pid, process_root) in process_entries {
        let before = match observe_process(&process_root) {
            Ok(observation) => observation,
            Err(AcquisitionError::Missing) => continue,
            Err(_) => {
                scan.unavailable_inputs
                    .insert(UnavailableReason::ProcessIdentity);
                continue;
            }
        };
        let before_cgroup = observe_cgroup(&process_root);
        let mut socket_inodes = BTreeSet::new();
        let descriptors = match fs::read_dir(process_root.join("fd")) {
            Ok(descriptors) => descriptors,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => {
                scan.unavailable_inputs
                    .insert(UnavailableReason::ProcessFdScan);
                continue;
            }
        };
        for (process_descriptors, descriptor) in descriptors.enumerate() {
            if process_descriptors >= MAX_FILE_DESCRIPTORS_PER_PROCESS {
                scan.bounds_exceeded.insert(BoundReason::FdsPerProcess);
                break;
            }
            if total_descriptors >= MAX_TOTAL_FILE_DESCRIPTORS {
                scan.bounds_exceeded.insert(BoundReason::TotalFds);
                break;
            }
            total_descriptors += 1;
            let descriptor = match descriptor {
                Ok(descriptor) => descriptor,
                Err(_) => {
                    scan.unavailable_inputs
                        .insert(UnavailableReason::ProcessFdScan);
                    continue;
                }
            };
            let target = match fs::read_link(descriptor.path()) {
                Ok(target) => target,
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(_) => {
                    scan.unavailable_inputs
                        .insert(UnavailableReason::ProcessFdReadlink);
                    continue;
                }
            };
            if let Some(inode) = socket_inode_from_target(target.as_os_str())
                && relevant_inodes.contains(&inode)
            {
                socket_inodes.insert(inode);
            }
        }
        let is_root_container = before.uid == 0
            && matches!(
                before.executable_basename.as_str(),
                "containerd" | "dockerd"
            );
        if socket_inodes.is_empty() && !is_root_container {
            if scan.bounds_exceeded.contains(&BoundReason::TotalFds) {
                break 'processes;
            }
            continue;
        }

        let after = match observe_process(&process_root) {
            Ok(observation) => observation,
            Err(AcquisitionError::Missing) => {
                mark_process_drift(
                    &mut scan,
                    &socket_inodes,
                    if before.uid == 0 {
                        ProcessDriftScope::RootOrAmbiguous
                    } else {
                        ProcessDriftScope::KnownNonRoot
                    },
                );
                continue;
            }
            Err(_) => {
                mark_process_drift(
                    &mut scan,
                    &socket_inodes,
                    ProcessDriftScope::RootOrAmbiguous,
                );
                continue;
            }
        };
        let after_cgroup = observe_cgroup(&process_root);
        if before != after {
            let scope = if before.uid == 0 || after.uid == 0 {
                ProcessDriftScope::RootOrAmbiguous
            } else {
                ProcessDriftScope::KnownNonRoot
            };
            mark_process_drift(&mut scan, &socket_inodes, scope);
            continue;
        }
        let cgroup_matches = compare_process_cgroup_identity(
            &mut scan,
            is_root_container,
            &before_cgroup,
            &after_cgroup,
        );
        let executable_reviewed = before.canonical_executable != UNREVIEWED_EXECUTABLE_PATH;
        let identity_complete = before_cgroup.reviewed && cgroup_matches && executable_reviewed;
        let key = PrivateOwnerKey {
            uid: before.uid,
            executable_basename: before.executable_basename.clone(),
            canonical_executable: before.canonical_executable.clone(),
            unified_cgroup: before_cgroup.unified_cgroup.clone(),
            executable_path_fingerprint: before.executable_path_fingerprint.clone(),
            cgroup_fingerprint: before_cgroup.fingerprint.clone(),
        };
        let pin = before.pin(pid);
        for inode in socket_inodes {
            let owner = scan
                .owners
                .entry(inode)
                .or_default()
                .entry(key.clone())
                .or_insert_with(|| PrivateOwner {
                    key: key.clone(),
                    identity_complete: true,
                    process_pins: BTreeSet::new(),
                });
            owner.identity_complete &= identity_complete;
            owner.process_pins.insert(pin.clone());
        }
        if is_root_container {
            scan.root_container_processes.push(PrivateContainer {
                key,
                identity_complete,
                process_pin: pin,
            });
        }
        if scan.bounds_exceeded.contains(&BoundReason::TotalFds) {
            break 'processes;
        }
    }

    scan.root_container_processes.sort_by(|left, right| {
        (&left.key, &left.process_pin, left.identity_complete).cmp(&(
            &right.key,
            &right.process_pin,
            right.identity_complete,
        ))
    });
    if scan.root_container_processes.len() > MAX_CONTAINER_PROCESSES {
        scan.bounds_exceeded.insert(BoundReason::ContainerProcesses);
        scan.root_container_processes
            .truncate(MAX_CONTAINER_PROCESSES);
    }
    scan
}

fn compare_process_cgroup_identity(
    scan: &mut ProcessScan,
    is_root_container: bool,
    before: &CgroupObservation,
    after: &CgroupObservation,
) -> bool {
    let matches = before == after;
    if is_root_container && !matches {
        scan.unavailable_inputs
            .insert(UnavailableReason::CgroupIdentity);
    }
    matches
}

fn numeric_process_entries(
    proc_root: &Path,
    scan: &mut ProcessScan,
) -> Option<Vec<(u32, PathBuf)>> {
    let entries = match fs::read_dir(proc_root) {
        Ok(entries) => entries,
        Err(_) => {
            scan.unavailable_inputs.insert(UnavailableReason::Proc);
            return None;
        }
    };
    let mut processes = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                scan.unavailable_inputs.insert(UnavailableReason::ProcScan);
                continue;
            }
        };
        let name = entry.file_name();
        let bytes = name.as_bytes();
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
            continue;
        }
        let Ok(pid) = std::str::from_utf8(bytes)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(())
        else {
            continue;
        };
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => {}
            Ok(_) => continue,
            Err(_) => {
                scan.unavailable_inputs.insert(UnavailableReason::ProcScan);
                continue;
            }
        }
        if processes.len() >= MAX_PROCESSES {
            scan.bounds_exceeded.insert(BoundReason::Processes);
            break;
        }
        processes.push((pid, entry.path()));
    }
    Some(processes)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProcessDriftScope {
    KnownNonRoot,
    RootOrAmbiguous,
}

fn mark_process_drift(scan: &mut ProcessScan, inodes: &BTreeSet<u64>, scope: ProcessDriftScope) {
    scan.unresolved_owner_inodes.extend(inodes.iter().copied());
    match scope {
        ProcessDriftScope::KnownNonRoot => {
            scan.known_nonroot_drift_inodes
                .extend(inodes.iter().copied());
        }
        ProcessDriftScope::RootOrAmbiguous => {
            scan.unavailable_inputs
                .insert(UnavailableReason::ProcessIdentityDrift);
            scan.unresolved_root_inodes.extend(inodes.iter().copied());
        }
    }
}

fn observe_process(process_root: &Path) -> Result<ProcessObservation, AcquisitionError> {
    let process_metadata = fs::metadata(process_root).map_err(acquisition_io)?;
    let stat_contents = read_bounded(&process_root.join("stat"), MAX_PROCESS_FILE_BYTES)?;
    let start_time_ticks = parse_process_start_time(&stat_contents)?;
    let executable_link = process_root.join("exe");
    let executable_metadata = fs::metadata(&executable_link).map_err(acquisition_io)?;
    if !executable_metadata.is_file() {
        return Err(AcquisitionError::Malformed);
    }
    let executable_target = fs::read_link(executable_link).map_err(acquisition_io)?;
    let executable_bytes = strip_deleted_suffix(executable_target.as_os_str().as_bytes());
    Ok(ProcessObservation {
        uid: process_metadata.uid(),
        start_time_ticks,
        executable_device: executable_metadata.dev(),
        executable_inode: executable_metadata.ino(),
        executable_basename: safe_basename(executable_bytes),
        canonical_executable: reviewed_executable(executable_bytes),
        executable_path_fingerprint: domain_hash(b"fence-executable-path-v1\0", executable_bytes),
    })
}

fn observe_cgroup(process_root: &Path) -> CgroupObservation {
    let contents = match read_bounded(&process_root.join("cgroup"), MAX_PROCESS_FILE_BYTES) {
        Ok(contents) => contents,
        Err(_) => {
            return CgroupObservation {
                unified_cgroup: UNREVIEWED_CGROUP.to_string(),
                fingerprint: None,
                reviewed: false,
            };
        }
    };
    let fingerprint = domain_hash(b"fence-cgroup-v1\0", &contents);
    let Some(cgroup) = parse_unified_cgroup(&contents) else {
        return CgroupObservation {
            unified_cgroup: UNREVIEWED_CGROUP.to_string(),
            fingerprint: Some(fingerprint),
            reviewed: false,
        };
    };
    let Some(reviewed) = REVIEWED_CGROUPS
        .iter()
        .find(|candidate| candidate.as_bytes() == cgroup)
    else {
        return CgroupObservation {
            unified_cgroup: UNREVIEWED_CGROUP.to_string(),
            fingerprint: Some(fingerprint),
            reviewed: false,
        };
    };
    CgroupObservation {
        unified_cgroup: (*reviewed).to_string(),
        fingerprint: Some(fingerprint),
        reviewed: true,
    }
}

fn parse_process_start_time(contents: &[u8]) -> Result<u64, AcquisitionError> {
    let closing = contents
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or(AcquisitionError::Malformed)?;
    let remaining = std::str::from_utf8(&contents[closing + 1..])
        .map_err(|_| AcquisitionError::Malformed)?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    remaining
        .get(19)
        .ok_or(AcquisitionError::Malformed)?
        .parse::<u64>()
        .map_err(|_| AcquisitionError::Malformed)
}

fn parse_unified_cgroup(contents: &[u8]) -> Option<&[u8]> {
    let text = std::str::from_utf8(contents).ok()?;
    let mut unified = None;
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        if hierarchy == "0" && controllers.is_empty() {
            if unified.is_some() {
                return None;
            }
            let start = path.as_ptr() as usize - text.as_ptr() as usize;
            unified = Some(&contents[start..start + path.len()]);
        }
    }
    unified
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, AcquisitionError> {
    let file = File::open(path).map_err(acquisition_io)?;
    let mut contents = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut contents)
        .map_err(|_| AcquisitionError::Unavailable)?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > maximum {
        return Err(AcquisitionError::TooLarge);
    }
    Ok(contents)
}

fn acquisition_io(error: std::io::Error) -> AcquisitionError {
    if error.kind() == ErrorKind::NotFound {
        AcquisitionError::Missing
    } else {
        AcquisitionError::Unavailable
    }
}

fn parse_tcp_table(
    contents: &[u8],
    family: InternetAddressFamily,
) -> Result<ParsedTable<ParsedTcpListener>, AcquisitionError> {
    let text = std::str::from_utf8(contents).map_err(|_| AcquisitionError::Malformed)?;
    let mut lines = text.lines();
    let header = lines.next().ok_or(AcquisitionError::Malformed)?;
    let expected = match family {
        InternetAddressFamily::Ipv4 => [
            "sl",
            "local_address",
            "rem_address",
            "st",
            "tx_queue",
            "rx_queue",
            "tr",
            "tm->when",
            "retrnsmt",
            "uid",
            "timeout",
            "inode",
        ],
        InternetAddressFamily::Ipv6 => [
            "sl",
            "local_address",
            "remote_address",
            "st",
            "tx_queue",
            "rx_queue",
            "tr",
            "tm->when",
            "retrnsmt",
            "uid",
            "timeout",
            "inode",
        ],
    };
    if header.split_ascii_whitespace().collect::<Vec<_>>() != expected {
        return Err(AcquisitionError::Malformed);
    }
    let mut rows = Vec::new();
    let mut malformed_rows = 0_u64;
    for line in lines.filter(|line| !line.trim().is_empty()) {
        match parse_tcp_row(line, family) {
            Ok(Some(row)) => rows.push(row),
            Ok(None) => {}
            Err(_) => malformed_rows = malformed_rows.saturating_add(1),
        }
    }
    Ok(ParsedTable {
        rows,
        malformed_rows,
    })
}

fn parse_tcp_row(
    line: &str,
    family: InternetAddressFamily,
) -> Result<Option<ParsedTcpListener>, AcquisitionError> {
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() < 10 || !fields[0].ends_with(':') {
        return Err(AcquisitionError::Malformed);
    }
    parse_bounded_decimal(&fields[0][..fields[0].len() - 1], 10)?;
    let (address, port) = parse_proc_endpoint(fields[1], family)?;
    parse_proc_endpoint(fields[2], family)?;
    let state =
        u8::try_from(parse_bounded_hex(fields[3], 2)?).map_err(|_| AcquisitionError::Malformed)?;
    parse_hex_pair(fields[4], 8, 8)?;
    parse_hex_pair(fields[5], 2, 8)?;
    parse_bounded_hex(fields[6], 8)?;
    let socket_uid = u32::try_from(parse_bounded_decimal(fields[7], 20)?)
        .map_err(|_| AcquisitionError::Malformed)?;
    parse_bounded_decimal(fields[8], 20)?;
    let inode = parse_bounded_decimal(fields[9], 20)?;
    if state != TCP_LISTEN_STATE {
        return Ok(None);
    }
    Ok(Some(ParsedTcpListener {
        inode,
        socket_uid,
        family,
        bind_class: bind_class(address),
        port,
    }))
}

fn parse_hex_pair(
    value: &str,
    left_maximum: usize,
    right_maximum: usize,
) -> Result<(), AcquisitionError> {
    let (left, right) = value.split_once(':').ok_or(AcquisitionError::Malformed)?;
    parse_bounded_hex(left, left_maximum)?;
    parse_bounded_hex(right, right_maximum)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ParsedAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

fn parse_proc_endpoint(
    value: &str,
    family: InternetAddressFamily,
) -> Result<(ParsedAddress, u16), AcquisitionError> {
    let (address, port) = value.split_once(':').ok_or(AcquisitionError::Malformed)?;
    let port =
        u16::try_from(parse_bounded_hex(port, 4)?).map_err(|_| AcquisitionError::Malformed)?;
    let bytes = decode_hex(address)?;
    match family {
        InternetAddressFamily::Ipv4 if bytes.len() == 4 => {
            let mut octets = [0_u8; 4];
            for (index, byte) in bytes.into_iter().rev().enumerate() {
                octets[index] = byte;
            }
            Ok((ParsedAddress::Ipv4(Ipv4Addr::from(octets)), port))
        }
        InternetAddressFamily::Ipv6 if bytes.len() == 16 => {
            let mut octets = [0_u8; 16];
            for (source, destination) in bytes.chunks_exact(4).zip(octets.chunks_exact_mut(4)) {
                for (index, byte) in source.iter().rev().enumerate() {
                    destination[index] = *byte;
                }
            }
            Ok((ParsedAddress::Ipv6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(AcquisitionError::Malformed),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AcquisitionError> {
    if !value.len().is_multiple_of(2) {
        return Err(AcquisitionError::Malformed);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| AcquisitionError::Malformed)?;
            u8::from_str_radix(pair, 16).map_err(|_| AcquisitionError::Malformed)
        })
        .collect()
}

fn bind_class(address: ParsedAddress) -> BindClass {
    match address {
        ParsedAddress::Ipv4(address) if address.is_unspecified() => BindClass::Wildcard,
        ParsedAddress::Ipv6(address) if address.is_unspecified() => BindClass::Wildcard,
        ParsedAddress::Ipv4(address) if address.is_loopback() => BindClass::Loopback,
        ParsedAddress::Ipv6(address) if address.is_loopback() => BindClass::Loopback,
        ParsedAddress::Ipv4(_) | ParsedAddress::Ipv6(_) => BindClass::OtherLocal,
    }
}

fn parse_unix_table(contents: &[u8]) -> Result<ParsedTable<ParsedUnixListener>, AcquisitionError> {
    let mut lines = contents.split(|byte| *byte == b'\n');
    let header = lines.next().ok_or(AcquisitionError::Malformed)?;
    let expected = [
        b"Num".as_slice(),
        b"RefCount".as_slice(),
        b"Protocol".as_slice(),
        b"Flags".as_slice(),
        b"Type".as_slice(),
        b"St".as_slice(),
        b"Inode".as_slice(),
        b"Path".as_slice(),
    ];
    if ascii_fields(header) != expected {
        return Err(AcquisitionError::Malformed);
    }
    let mut rows = Vec::new();
    let mut malformed_rows = 0_u64;
    for line in lines.filter(|line| line.iter().any(|byte| !byte.is_ascii_whitespace())) {
        match parse_unix_row(line) {
            Ok(Some(row)) => rows.push(row),
            Ok(None) => {}
            Err(_) => malformed_rows = malformed_rows.saturating_add(1),
        }
    }
    Ok(ParsedTable {
        rows,
        malformed_rows,
    })
}

fn parse_unix_row(line: &[u8]) -> Result<Option<ParsedUnixListener>, AcquisitionError> {
    let fields = ascii_field_ranges(line);
    if fields.len() < 7 {
        return Err(AcquisitionError::Malformed);
    }
    let field = |index: usize| &line[fields[index].clone()];
    if !field(0).ends_with(b":") {
        return Err(AcquisitionError::Malformed);
    }
    parse_bounded_ascii_hex(&field(0)[..field(0).len() - 1], 16)?;
    parse_bounded_ascii_hex(field(1), 8)?;
    parse_bounded_ascii_hex(field(2), 8)?;
    let flags = parse_bounded_ascii_hex(field(3), 8)?;
    let socket_type = parse_bounded_ascii_hex(field(4), 4)?;
    parse_bounded_ascii_hex(field(5), 2)?;
    let inode = parse_bounded_ascii_decimal(field(6), 20)?;
    if flags & UNIX_LISTEN_FLAG == 0 || !matches!(socket_type, UNIX_STREAM | UNIX_SEQPACKET) {
        return Ok(None);
    }
    let Some(path_start) = fields.get(7).map(|range| range.start) else {
        return Ok(None);
    };
    let raw_name = trim_ascii_end(&line[path_start..]);
    if raw_name.is_empty() {
        return Ok(None);
    }
    let name_kind = if raw_name.starts_with(b"@") {
        UnixNameKind::Abstract
    } else {
        UnixNameKind::Filesystem
    };
    Ok(Some(ParsedUnixListener {
        inode,
        socket_type: if socket_type == UNIX_STREAM {
            UnixSocketType::Stream
        } else {
            UnixSocketType::Seqpacket
        },
        name_kind,
        raw_name: OsString::from_vec(raw_name.to_vec()),
        name_sha256: unix_name_sha256(raw_name),
    }))
}

fn ascii_fields(line: &[u8]) -> Vec<&[u8]> {
    ascii_field_ranges(line)
        .into_iter()
        .map(|range| &line[range])
        .collect()
}

fn ascii_field_ranges(line: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut fields = Vec::new();
    let mut index = 0;
    while index < line.len() {
        while index < line.len() && line[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == line.len() {
            break;
        }
        let start = index;
        while index < line.len() && !line[index].is_ascii_whitespace() {
            index += 1;
        }
        fields.push(start..index);
    }
    fields
}

fn trim_ascii_end(value: &[u8]) -> &[u8] {
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1);
    &value[..end]
}

fn parse_bounded_ascii_hex(value: &[u8], maximum: usize) -> Result<u64, AcquisitionError> {
    let value = std::str::from_utf8(value).map_err(|_| AcquisitionError::Malformed)?;
    parse_bounded_hex(value, maximum)
}

fn parse_bounded_ascii_decimal(value: &[u8], maximum: usize) -> Result<u64, AcquisitionError> {
    let value = std::str::from_utf8(value).map_err(|_| AcquisitionError::Malformed)?;
    parse_bounded_decimal(value, maximum)
}

fn parse_bounded_hex(value: &str, maximum: usize) -> Result<u64, AcquisitionError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        return Err(AcquisitionError::Malformed);
    }
    u64::from_str_radix(value, 16).map_err(|_| AcquisitionError::Malformed)
}

fn parse_bounded_decimal(value: &str, maximum: usize) -> Result<u64, AcquisitionError> {
    if value.is_empty() || value.len() > maximum || !value.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(AcquisitionError::Malformed);
    }
    value
        .parse::<u64>()
        .map_err(|_| AcquisitionError::Malformed)
}

fn socket_inode_from_target(target: &OsStr) -> Option<u64> {
    let bytes = target.as_bytes();
    let inode = bytes.strip_prefix(b"socket:[")?.strip_suffix(b"]")?;
    std::str::from_utf8(inode).ok()?.parse::<u64>().ok()
}

fn strip_deleted_suffix(value: &[u8]) -> &[u8] {
    value.strip_suffix(b" (deleted)").unwrap_or(value)
}

fn safe_basename(path: &[u8]) -> String {
    let basename = path.rsplit(|byte| *byte == b'/').next().unwrap_or_default();
    if !basename.is_empty()
        && basename.len() <= 128
        && basename
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(byte))
    {
        String::from_utf8(basename.to_vec()).unwrap_or_else(|_| "unreportable".to_string())
    } else {
        "unreportable".to_string()
    }
}

fn reviewed_executable(path: &[u8]) -> String {
    REVIEWED_EXECUTABLE_PATHS
        .iter()
        .find(|candidate| candidate.as_bytes() == path)
        .map_or_else(
            || UNREVIEWED_EXECUTABLE_PATH.to_string(),
            |candidate| (*candidate).to_string(),
        )
}

fn unix_name_sha256(raw_name: &[u8]) -> String {
    domain_hash(b"fence-unix-name-v1\0", raw_name)
}

fn domain_hash(domain: &[u8], value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    let digest = digest.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn private_unix_sort(
    left: &PrivateUnixListener,
    right: &PrivateUnixListener,
) -> std::cmp::Ordering {
    (
        left.socket_type,
        left.name_kind,
        &left.name_sha256,
        left.socket_inode,
        left.ownership_complete,
    )
        .cmp(&(
            right.socket_type,
            right.name_kind,
            &right.name_sha256,
            right.socket_inode,
            right.ownership_complete,
        ))
}

fn private_tcp_sort(left: &PrivateTcpListener, right: &PrivateTcpListener) -> std::cmp::Ordering {
    (
        left.family,
        left.bind_class,
        left.port,
        left.socket_inode,
        left.socket_uid,
        left.ownership_complete,
    )
        .cmp(&(
            right.family,
            right.bind_class,
            right.port,
            right.socket_inode,
            right.socket_uid,
            right.ownership_complete,
        ))
}

fn excluded_unix_sort(
    left: &ExcludedUnixListener,
    right: &ExcludedUnixListener,
) -> std::cmp::Ordering {
    (
        left.socket_type,
        left.name_kind,
        &left.name_sha256,
        left.access_state,
        left.root_control_candidate,
        left.ownership_complete,
        left.socket_inode,
    )
        .cmp(&(
            right.socket_type,
            right.name_kind,
            &right.name_sha256,
            right.access_state,
            right.root_control_candidate,
            right.ownership_complete,
            right.socket_inode,
        ))
}

fn public_snapshot(private: PrivateSnapshot) -> LocalControlSnapshot {
    let root_container_processes = aggregate_containers(&private.root_container_processes);
    let unix_listeners = aggregate_unix_listeners(&private.unix_listeners);
    let tcp_listeners = aggregate_tcp_listeners(&private.tcp_listeners);
    let mut unavailable_inputs = private.unavailable_inputs;
    if private.malformed_row_count > 0 {
        unavailable_inputs.insert(UnavailableReason::MalformedRows);
    }
    let reachability_failures = [
        UnavailableReason::Proc,
        UnavailableReason::UnixTable,
        UnavailableReason::MalformedRows,
    ];
    let reachability_complete = private.unresolved_unix_listener_count == 0
        && reachability_failures
            .iter()
            .all(|reason| !unavailable_inputs.contains(reason));
    if !reachability_complete {
        unavailable_inputs.insert(UnavailableReason::UnixReachability);
    }
    let identities_reviewed = root_container_processes
        .iter()
        .all(root_container_identity_reviewed)
        && unix_listeners
            .iter()
            .flat_map(|listener| &listener.owners)
            .all(owner_identity_reviewed)
        && tcp_listeners
            .iter()
            .flat_map(|listener| &listener.owners)
            .all(owner_identity_reviewed);
    let ownership_failure = unavailable_inputs
        .iter()
        .any(|reason| reason.is_acquisition() || *reason == UnavailableReason::MalformedRows);
    let ownership_complete = reachability_complete
        && !ownership_failure
        && identities_reviewed
        && unix_listeners
            .iter()
            .all(|listener| listener.ownership_complete)
        && tcp_listeners
            .iter()
            .all(|listener| listener.ownership_complete);
    if !ownership_complete {
        unavailable_inputs.insert(UnavailableReason::SocketOwnership);
    }
    let scan_status = if unavailable_inputs.is_empty() {
        if private.bounds_exceeded.is_empty() {
            ScanStatus::WithinBounds
        } else {
            ScanStatus::BoundsExceeded
        }
    } else {
        ScanStatus::Unavailable
    };
    LocalControlSnapshot {
        scan_status,
        bounds_exceeded: private.bounds_exceeded.into_iter().collect(),
        unavailable_inputs: unavailable_inputs.into_iter().collect(),
        malformed_row_count: private.malformed_row_count,
        unresolved_unix_listener_count: private.unresolved_unix_listener_count,
        inaccessible_root_filesystem_listener_count: private
            .inaccessible_root_filesystem_listener_count,
        reachability_complete,
        ownership_complete,
        root_container_processes,
        unix_listeners,
        tcp_listeners,
    }
}

fn aggregate_containers(processes: &[PrivateContainer]) -> Vec<RootContainerProcess> {
    let mut grouped = BTreeMap::<(u32, String, String, String), u32>::new();
    for process in processes {
        let key = (
            process.key.uid,
            process.key.executable_basename.clone(),
            process.key.canonical_executable.clone(),
            process.key.unified_cgroup.clone(),
        );
        let count = grouped.entry(key).or_default();
        *count = count.saturating_add(1);
    }
    let mut public = grouped
        .into_iter()
        .map(
            |((uid, executable_basename, canonical_executable, unified_cgroup), instances)| {
                RootContainerProcess {
                    uid,
                    executable_basename,
                    canonical_executable,
                    unified_cgroup,
                    instances,
                }
            },
        )
        .collect::<Vec<_>>();
    public.sort_by(|left, right| {
        (
            &left.executable_basename,
            &left.canonical_executable,
            &left.unified_cgroup,
            left.instances,
        )
            .cmp(&(
                &right.executable_basename,
                &right.canonical_executable,
                &right.unified_cgroup,
                right.instances,
            ))
    });
    public
}

fn public_owners(owners: &[PrivateOwner]) -> Vec<LocalControlOwner> {
    let mut grouped = BTreeMap::<(u32, String, String, String), u32>::new();
    for owner in owners {
        let key = (
            owner.key.uid,
            owner.key.executable_basename.clone(),
            owner.key.canonical_executable.clone(),
            owner.key.unified_cgroup.clone(),
        );
        let count = grouped.entry(key).or_default();
        *count = count.saturating_add(u32::try_from(owner.process_pins.len()).unwrap_or(u32::MAX));
    }
    grouped
        .into_iter()
        .map(
            |((uid, executable_basename, canonical_executable, unified_cgroup), processes)| {
                LocalControlOwner {
                    uid,
                    executable_basename,
                    canonical_executable,
                    unified_cgroup,
                    processes,
                }
            },
        )
        .collect()
}

fn aggregate_unix_listeners(listeners: &[PrivateUnixListener]) -> Vec<UnixListener> {
    let mut grouped = BTreeMap::<
        (
            UnixSocketType,
            UnixNameKind,
            String,
            bool,
            Vec<LocalControlOwner>,
        ),
        u32,
    >::new();
    for listener in listeners {
        let key = (
            listener.socket_type,
            listener.name_kind,
            listener.name_sha256.clone(),
            listener.ownership_complete,
            public_owners(&listener.owners),
        );
        let count = grouped.entry(key).or_default();
        *count = count.saturating_add(1);
    }
    grouped
        .into_iter()
        .map(
            |((socket_type, name_kind, name_sha256, ownership_complete, owners), instances)| {
                UnixListener {
                    socket_type,
                    name_kind,
                    name_sha256,
                    runner_reachable: true,
                    owners,
                    ownership_complete,
                    instances,
                }
            },
        )
        .collect()
}

fn aggregate_tcp_listeners(listeners: &[PrivateTcpListener]) -> Vec<TcpListener> {
    let mut grouped = BTreeMap::<
        (
            InternetAddressFamily,
            BindClass,
            u16,
            bool,
            Vec<LocalControlOwner>,
        ),
        u32,
    >::new();
    for listener in listeners {
        let key = (
            listener.family,
            listener.bind_class,
            listener.port,
            listener.ownership_complete,
            public_owners(&listener.owners),
        );
        let count = grouped.entry(key).or_default();
        *count = count.saturating_add(1);
    }
    grouped
        .into_iter()
        .map(
            |((family, bind_class, port, ownership_complete, owners), instances)| TcpListener {
                family,
                bind_class,
                port,
                owners,
                ownership_complete,
                instances,
            },
        )
        .collect()
}

fn owner_identity_reviewed(owner: &LocalControlOwner) -> bool {
    REVIEWED_EXECUTABLE_PATHS.contains(&owner.canonical_executable.as_str())
        && REVIEWED_CGROUPS.contains(&owner.unified_cgroup.as_str())
}

fn root_container_identity_reviewed(process: &RootContainerProcess) -> bool {
    REVIEWED_EXECUTABLE_PATHS.contains(&process.canonical_executable.as_str())
        && REVIEWED_CGROUPS.contains(&process.unified_cgroup.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fence-local-control-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(path.join("net")).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct TestSocketAccess {
        states: BTreeMap<Vec<u8>, FilesystemSocketAccess>,
    }

    impl UnixSocketAccess for TestSocketAccess {
        fn inspect(&self, path: &OsStr) -> FilesystemSocketAccess {
            self.states
                .get(path.as_bytes())
                .copied()
                .unwrap_or(FilesystemSocketAccess::Unavailable)
        }
    }

    struct EveryFenceProcess;

    impl CurrentFenceOwner for EveryFenceProcess {
        fn owns_process(
            &self,
            _pid: u32,
            _start_time_ticks: u64,
            _executable_device: u64,
            _executable_inode: u64,
        ) -> bool {
            true
        }
    }

    fn owner(
        uid: u32,
        executable_basename: &str,
        canonical_executable: &str,
        unified_cgroup: &str,
    ) -> LocalControlOwner {
        LocalControlOwner {
            uid,
            executable_basename: executable_basename.to_string(),
            canonical_executable: canonical_executable.to_string(),
            unified_cgroup: unified_cgroup.to_string(),
            processes: 1,
        }
    }

    fn systemd_owner() -> LocalControlOwner {
        owner(0, "systemd", "/usr/lib/systemd/systemd", "/init.scope")
    }

    fn accepted_observation() -> LocalControlObservation {
        let systemd = systemd_owner();
        let multipathd = owner(
            0,
            "multipathd",
            "/usr/sbin/multipathd",
            "/system.slice/multipathd.service",
        );
        let dockerd = owner(
            0,
            "dockerd",
            "/usr/bin/dockerd",
            "/system.slice/docker.service",
        );
        let journald = owner(
            0,
            "systemd-journald",
            "/usr/lib/systemd/systemd-journald",
            "/system.slice/systemd-journald.service",
        );
        let dbus = owner(
            101,
            "dbus-daemon",
            "/usr/bin/dbus-daemon",
            "/system.slice/dbus.service",
        );
        let unix = [
            (
                UnixNameKind::Abstract,
                "2098ac544ed7672deda4863cf7f1ec11fd3916b31f7f02f8b1190394218612ec",
                vec![multipathd, systemd.clone()],
            ),
            (
                UnixNameKind::Abstract,
                "caf0d5ac99f3b95f921556138b2adbf4ceb0e8d48c61ef23d5180aa480b45743",
                vec![systemd.clone()],
            ),
            (
                UnixNameKind::Filesystem,
                "1f76b0a726958dc80a872b9ae4fb414457f7ee9cc80f419ff7dfc509f236e469",
                vec![systemd.clone()],
            ),
            (
                UnixNameKind::Filesystem,
                "2a5962ed41259a31b1587bcae589fcee6b9d6767ef064ac317e6d398b96a81f2",
                vec![dockerd, systemd.clone()],
            ),
            (
                UnixNameKind::Filesystem,
                "68c0b0a26da3ac420889ddd0ab629df3f9defb482cf5a9daf7fdcd28ee545f29",
                vec![systemd.clone(), journald],
            ),
            (
                UnixNameKind::Filesystem,
                "8b5e213b2b72a7033476e1f46afb302f0e4123c6e6fd746f77eeb744050e3b91",
                vec![systemd.clone(), dbus],
            ),
            (
                UnixNameKind::Filesystem,
                "ac10a069436547a18b02df8078e06421de7fc8953887fcc32f817af06b1b09bb",
                vec![systemd.clone()],
            ),
            (
                UnixNameKind::Filesystem,
                "ded56518cb66a7ddcdf9434f3280745cbb457869ea692d34cf0df494949bca96",
                vec![systemd.clone()],
            ),
            (
                UnixNameKind::Filesystem,
                "e84916b142c7b55bdf364843e9360867ec403fc602cfb662c95d6299ebfb8e77",
                vec![systemd.clone()],
            ),
            (
                UnixNameKind::Filesystem,
                "f7978cc2493e0ecd56d54a3f49e36c3bde79b3ac281baa0a0aed0efab0898c23",
                vec![systemd.clone()],
            ),
        ]
        .into_iter()
        .map(|(name_kind, name_sha256, owners)| UnixListener {
            socket_type: UnixSocketType::Stream,
            name_kind,
            name_sha256: name_sha256.to_string(),
            runner_reachable: true,
            owners,
            ownership_complete: true,
            instances: 1,
        })
        .collect();
        LocalControlObservation {
            status: ObservationStatus::Stable,
            stable: true,
            attempts: 1,
            interval_milliseconds: 50,
            limits: LocalControlLimits::reviewed(),
            snapshot: LocalControlSnapshot {
                scan_status: ScanStatus::WithinBounds,
                bounds_exceeded: Vec::new(),
                unavailable_inputs: Vec::new(),
                malformed_row_count: 0,
                unresolved_unix_listener_count: 0,
                inaccessible_root_filesystem_listener_count: 14,
                reachability_complete: true,
                ownership_complete: true,
                root_container_processes: vec![
                    RootContainerProcess {
                        uid: 0,
                        executable_basename: "containerd".to_string(),
                        canonical_executable: "/usr/bin/containerd".to_string(),
                        unified_cgroup: "/system.slice/containerd.service".to_string(),
                        instances: 1,
                    },
                    RootContainerProcess {
                        uid: 0,
                        executable_basename: "dockerd".to_string(),
                        canonical_executable: "/usr/bin/dockerd".to_string(),
                        unified_cgroup: "/system.slice/docker.service".to_string(),
                        instances: 1,
                    },
                ],
                unix_listeners: unix,
                tcp_listeners: vec![
                    TcpListener {
                        family: InternetAddressFamily::Ipv4,
                        bind_class: BindClass::Wildcard,
                        port: 22,
                        owners: vec![systemd.clone()],
                        ownership_complete: true,
                        instances: 1,
                    },
                    TcpListener {
                        family: InternetAddressFamily::Ipv6,
                        bind_class: BindClass::Wildcard,
                        port: 22,
                        owners: vec![systemd],
                        ownership_complete: true,
                        instances: 1,
                    },
                ],
            },
        }
    }

    fn empty_private() -> PrivateSnapshot {
        PrivateSnapshot {
            bounds_exceeded: BTreeSet::new(),
            unavailable_inputs: BTreeSet::new(),
            malformed_row_count: 0,
            unresolved_unix_listener_count: 0,
            inaccessible_root_filesystem_listener_count: 0,
            excluded_unix_listeners: Vec::new(),
            root_container_processes: Vec::new(),
            unix_listeners: Vec::new(),
            tcp_listeners: Vec::new(),
        }
    }

    fn private_owner(uid: u32, reviewed: bool, pins: &[u32]) -> PrivateOwner {
        let (executable, cgroup) = if reviewed {
            ("/usr/lib/systemd/systemd", "/init.scope")
        } else {
            (UNREVIEWED_EXECUTABLE_PATH, UNREVIEWED_CGROUP)
        };
        PrivateOwner {
            key: PrivateOwnerKey {
                uid,
                executable_basename: "systemd".to_string(),
                canonical_executable: executable.to_string(),
                unified_cgroup: cgroup.to_string(),
                executable_path_fingerprint: "private-executable-fingerprint".to_string(),
                cgroup_fingerprint: Some("private-cgroup-fingerprint".to_string()),
            },
            identity_complete: reviewed,
            process_pins: pins
                .iter()
                .map(|pid| ProcessPin {
                    pid: *pid,
                    start_time_ticks: u64::from(*pid) + 100,
                    executable_device: 7,
                    executable_inode: 9,
                })
                .collect(),
        }
    }

    #[test]
    fn hash_domains_match_the_reviewed_observer_contract() {
        assert_eq!(
            unix_name_sha256(b"@root-control"),
            "94e42880b01c85d2d11cccb5c2846e5863baf3d2a7a032443dedbb2e2d97473c"
        );
        assert_eq!(
            unix_name_sha256(b"root-control"),
            "f277e7437ceed4cdfaff0fd695c13e3f50def1b2edff4c474579f7e609b0095e"
        );
        assert_ne!(
            unix_name_sha256(b"@root-control"),
            unix_name_sha256(b"root-control")
        );
        assert_eq!(
            domain_hash(b"fence-executable-path-v1\0", b"/usr/bin/dockerd"),
            "7d0a151fa9518d080ef7cbe10629f032313d14ed5080f9dc7b3df240f983cf69"
        );
        assert_eq!(
            domain_hash(b"fence-cgroup-v1\0", b"0::/system.slice/docker.service\n"),
            "ca00cb68788a89432d58b2e6a72a2afbf0b1ad745effd63b1ba5d96a86f37376"
        );
    }

    #[test]
    fn parsers_preserve_complete_unix_names_and_count_malformed_rows() {
        let mut unix = b"Num RefCount Protocol Flags Type St Inode Path\n".to_vec();
        unix.extend_from_slice(b"0: 2 0 00010000 0001 01 42 @root-control\n1: malformed\n");
        let parsed = parse_unix_table(&unix).unwrap();
        assert_eq!(parsed.malformed_rows, 1);
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.rows[0].raw_name.as_bytes(), b"@root-control");
        assert_eq!(
            parsed.rows[0].name_sha256,
            "94e42880b01c85d2d11cccb5c2846e5863baf3d2a7a032443dedbb2e2d97473c"
        );

        let tcp = b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n\
0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 43\n\
1: malformed\n";
        let parsed = parse_tcp_table(tcp, InternetAddressFamily::Ipv4).unwrap();
        assert_eq!(parsed.malformed_rows, 1);
        assert_eq!(parsed.rows[0].port, 22);
        assert_eq!(parsed.rows[0].bind_class, BindClass::Wildcard);

        let tcp6 = b"sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
        assert!(parse_tcp_table(tcp6, InternetAddressFamily::Ipv6).is_ok());
        assert!(parse_tcp_table(tcp, InternetAddressFamily::Ipv6).is_err());
    }

    #[test]
    fn private_process_and_cgroup_pins_detect_drift_without_public_values() {
        let before = ProcessObservation {
            uid: 0,
            start_time_ticks: 100,
            executable_device: 7,
            executable_inode: 9,
            executable_basename: "dockerd".to_string(),
            canonical_executable: "/usr/bin/dockerd".to_string(),
            executable_path_fingerprint: "private-a".to_string(),
        };
        let mut after = before.clone();
        after.start_time_ticks += 1;
        assert_ne!(before, after);
        assert_ne!(before.pin(10), after.pin(10));

        let first_cgroup = CgroupObservation {
            unified_cgroup: "/system.slice/docker.service".to_string(),
            fingerprint: Some("private-cgroup-a".to_string()),
            reviewed: true,
        };
        let second_cgroup = CgroupObservation {
            unified_cgroup: "/init.scope".to_string(),
            fingerprint: Some("private-cgroup-b".to_string()),
            reviewed: true,
        };
        assert_ne!(first_cgroup, second_cgroup);

        let mut scan = ProcessScan::default();
        assert!(!compare_process_cgroup_identity(
            &mut scan,
            true,
            &first_cgroup,
            &second_cgroup,
        ));
        assert_eq!(
            scan.unavailable_inputs,
            BTreeSet::from([UnavailableReason::CgroupIdentity])
        );
        let mut nonroot_scan = ProcessScan::default();
        assert!(!compare_process_cgroup_identity(
            &mut nonroot_scan,
            false,
            &first_cgroup,
            &second_cgroup,
        ));
        assert!(nonroot_scan.unavailable_inputs.is_empty());

        let mut snapshot = empty_private();
        snapshot.unavailable_inputs = scan.unavailable_inputs;
        snapshot.root_container_processes.push(PrivateContainer {
            key: PrivateOwnerKey {
                uid: 0,
                executable_basename: "dockerd".to_string(),
                canonical_executable: "/usr/bin/dockerd".to_string(),
                unified_cgroup: "/system.slice/docker.service".to_string(),
                executable_path_fingerprint: "private-a".to_string(),
                cgroup_fingerprint: first_cgroup.fingerprint,
            },
            identity_complete: false,
            process_pin: before.pin(10),
        });
        let public = public_snapshot(snapshot);
        assert_eq!(public.scan_status, ScanStatus::Unavailable);
        assert!(!public.ownership_complete);
        assert!(
            serde_json::to_string(&public)
                .unwrap()
                .contains("cgroup_identity")
        );
    }

    #[test]
    fn known_nonroot_process_drift_does_not_poison_root_control_acquisition() {
        let inodes = BTreeSet::from([42_u64]);
        let mut nonroot = ProcessScan::default();
        mark_process_drift(&mut nonroot, &inodes, ProcessDriftScope::KnownNonRoot);
        assert!(nonroot.unavailable_inputs.is_empty());
        assert_eq!(nonroot.unresolved_owner_inodes, inodes);
        assert_eq!(nonroot.known_nonroot_drift_inodes, inodes);
        assert!(nonroot.unresolved_root_inodes.is_empty());

        let mut ambiguous = ProcessScan::default();
        mark_process_drift(&mut ambiguous, &inodes, ProcessDriftScope::RootOrAmbiguous);
        assert_eq!(
            ambiguous.unavailable_inputs,
            BTreeSet::from([UnavailableReason::ProcessIdentityDrift])
        );
        assert_eq!(ambiguous.unresolved_root_inodes, inodes);
        assert!(ambiguous.known_nonroot_drift_inodes.is_empty());
    }

    #[test]
    fn stability_uses_private_identity_and_fails_closed_after_three_pairs() {
        let stable = empty_private();
        let mut changed = empty_private();
        changed.inaccessible_root_filesystem_listener_count = 1;
        let samples = RefCell::new(
            [
                changed.clone(),
                stable.clone(),
                stable.clone(),
                stable.clone(),
            ]
            .into_iter(),
        );
        let sleeps = Cell::new(0_u32);
        let observation = observe_local_control_with(
            || samples.borrow_mut().next().unwrap(),
            || sleeps.set(sleeps.get() + 1),
        );
        assert_eq!(observation.status, ObservationStatus::Stable);
        assert_eq!(observation.attempts, 2);
        assert_eq!(sleeps.get(), 2);

        let calls = Cell::new(0_u32);
        let observation = observe_local_control_with(
            || {
                let call = calls.get();
                calls.set(call + 1);
                if call.is_multiple_of(2) {
                    stable.clone()
                } else {
                    changed.clone()
                }
            },
            || {},
        );
        assert_eq!(observation.status, ObservationStatus::Unstable);
        assert!(!observation.stable);
        assert_eq!(calls.get(), STABILITY_ATTEMPTS * 2);
    }

    #[test]
    fn bounds_malformed_ownership_and_reachability_gaps_are_explicit() {
        let mut bounded = empty_private();
        bounded.bounds_exceeded.insert(BoundReason::TcpListeners);
        let bounded = public_snapshot(bounded);
        assert_eq!(bounded.scan_status, ScanStatus::BoundsExceeded);
        assert!(bounded.ownership_complete);

        let mut malformed = empty_private();
        malformed.malformed_row_count = 1;
        let malformed = public_snapshot(malformed);
        assert_eq!(malformed.scan_status, ScanStatus::Unavailable);
        assert!(!malformed.reachability_complete);
        assert!(!malformed.ownership_complete);
        assert_eq!(
            malformed.unavailable_inputs,
            vec![
                UnavailableReason::MalformedRows,
                UnavailableReason::SocketOwnership,
                UnavailableReason::UnixReachability,
            ]
        );

        let mut missing_owner = empty_private();
        missing_owner.tcp_listeners.push(PrivateTcpListener {
            socket_inode: 42,
            socket_uid: 0,
            family: InternetAddressFamily::Ipv4,
            bind_class: BindClass::Wildcard,
            port: 22,
            owners: Vec::new(),
            ownership_complete: false,
        });
        let missing_owner = public_snapshot(missing_owner);
        assert!(missing_owner.reachability_complete);
        assert!(!missing_owner.ownership_complete);
        assert_eq!(missing_owner.scan_status, ScanStatus::Unavailable);

        let mut unresolved = empty_private();
        unresolved.unresolved_unix_listener_count = 1;
        let unresolved = public_snapshot(unresolved);
        assert!(!unresolved.reachability_complete);
        assert!(!unresolved.ownership_complete);
        assert_eq!(unresolved.scan_status, ScanStatus::Unavailable);
    }

    #[test]
    fn root_file_ownership_fallback_is_retained_but_incomplete_without_process_owners() {
        let root = TestRoot::new();
        fs::write(
            root.0.join("net/tcp"),
            b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n",
        )
        .unwrap();
        fs::write(
            root.0.join("net/tcp6"),
            b"sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n",
        )
        .unwrap();
        fs::write(
            root.0.join("net/unix"),
            b"Num RefCount Protocol Flags Type St Inode Path\n\
0: 2 0 00010000 0001 01 42 /run/root-owned.sock\n",
        )
        .unwrap();
        let access = TestSocketAccess {
            states: BTreeMap::from([(
                b"/run/root-owned.sock".to_vec(),
                FilesystemSocketAccess::Reachable { owner_uid: 0 },
            )]),
        };
        let private = collect_private_snapshot(&root.0, &access, &NoCurrentFenceOwner);
        assert_eq!(private.unix_listeners.len(), 1);
        assert!(!private.unix_listeners[0].ownership_complete);
        let public = public_snapshot(private);
        assert_eq!(public.unix_listeners.len(), 1);
        assert!(!public.ownership_complete);
        assert_eq!(public.scan_status, ScanStatus::Unavailable);
    }

    #[test]
    fn multiplicity_aggregates_without_serializing_private_pins_or_paths() {
        let owner = private_owner(0, false, &[10, 11]);
        let mut private = empty_private();
        private.tcp_listeners.push(PrivateTcpListener {
            socket_inode: 42,
            socket_uid: 0,
            family: InternetAddressFamily::Ipv4,
            bind_class: BindClass::Loopback,
            port: 1234,
            owners: vec![owner],
            ownership_complete: false,
        });
        let public = public_snapshot(private);
        assert_eq!(public.tcp_listeners[0].owners[0].processes, 2);
        let encoded = serde_json::to_string(&public).unwrap();
        for private_value in [
            "private-executable-fingerprint",
            "private-cgroup-fingerprint",
            "\"pid\"",
            "start_time_ticks",
            "executable_device",
            "executable_inode",
        ] {
            assert!(!encoded.contains(private_value));
        }
        assert!(encoded.contains(UNREVIEWED_EXECUTABLE_PATH));
        assert!(encoded.contains(UNREVIEWED_CGROUP));
    }

    #[test]
    fn current_fence_exclusion_requires_complete_owner_enumeration() {
        let owner = private_owner(0, false, &[10]);
        assert!(exclusively_current_fence_owned(
            true,
            std::slice::from_ref(&owner),
            &EveryFenceProcess,
        ));
        assert!(!exclusively_current_fence_owned(
            false,
            std::slice::from_ref(&owner),
            &EveryFenceProcess,
        ));
        assert!(!exclusively_current_fence_owned(
            true,
            &[],
            &EveryFenceProcess,
        ));
    }

    #[test]
    fn root_tcp_collector_excludes_only_completely_enumerated_current_fence_owners() {
        let unreviewed_fence_owner = private_owner(0, false, &[10]);
        assert!(!retain_tcp_listener(
            true,
            true,
            std::slice::from_ref(&unreviewed_fence_owner),
            &EveryFenceProcess,
        ));
        assert!(retain_tcp_listener(
            true,
            false,
            std::slice::from_ref(&unreviewed_fence_owner),
            &EveryFenceProcess,
        ));
        assert!(!retain_tcp_listener(
            false,
            true,
            &[unreviewed_fence_owner],
            &EveryFenceProcess,
        ));
    }

    #[test]
    fn relative_filesystem_socket_names_fail_without_running_the_probe() {
        let probes = Cell::new(0_u32);
        let access = SystemUnixSocketAccess::new(|_: &OsStr| -> Option<bool> {
            probes.set(probes.get() + 1);
            Some(true)
        });
        assert_eq!(
            access.identity(OsStr::new("relative-control.sock")),
            FilesystemSocketIdentity::Unavailable
        );
        assert_eq!(
            access.inspect(OsStr::new("relative-control.sock")),
            FilesystemSocketAccess::Unavailable
        );
        assert_eq!(probes.get(), 0);
    }

    #[test]
    fn filesystem_reachability_probes_have_a_fixed_fail_closed_bound() {
        let mut probes = 0_usize;
        let mut bounds = BTreeSet::new();
        for _ in 0..MAX_UNIX_LISTENERS {
            assert!(reserve_filesystem_probe(&mut probes, &mut bounds));
        }
        assert!(!reserve_filesystem_probe(&mut probes, &mut bounds));
        assert_eq!(probes, MAX_UNIX_LISTENERS);
        assert_eq!(bounds, BTreeSet::from([BoundReason::UnixListeners]));
    }

    #[test]
    fn only_possible_root_control_filesystem_sockets_require_a_probe() {
        assert!(!filesystem_root_control_candidate(
            false,
            false,
            FilesystemSocketIdentity::Present { owner_uid: 1_001 },
        ));
        assert!(!filesystem_root_control_candidate(
            false,
            false,
            FilesystemSocketIdentity::Absent,
        ));
        assert!(filesystem_root_control_candidate(
            true,
            false,
            FilesystemSocketIdentity::Present { owner_uid: 1_001 },
        ));
        assert!(filesystem_root_control_candidate(
            false,
            true,
            FilesystemSocketIdentity::Present { owner_uid: 1_001 },
        ));
        assert!(filesystem_root_control_candidate(
            false,
            false,
            FilesystemSocketIdentity::Present { owner_uid: 0 },
        ));
        assert!(filesystem_root_control_candidate(
            false,
            false,
            FilesystemSocketIdentity::Unavailable,
        ));
    }

    #[test]
    fn missing_proc_acquisition_is_stably_unavailable_and_rejected() {
        let root = TestRoot::new();
        fs::remove_dir_all(&root.0).unwrap();
        let observation = observe_local_control_inventory(
            &root.0,
            &TestSocketAccess::default(),
            &NoCurrentFenceOwner,
        );
        assert_eq!(observation.status, ObservationStatus::Unavailable);
        assert!(observation.stable);
        assert_eq!(observation.snapshot.scan_status, ScanStatus::Unavailable);
        let accepted = accepted_observation();
        assert_eq!(
            verify_local_control_observation(&accepted.snapshot, &observation)
                .unwrap_err()
                .kind,
            LocalControlVerificationErrorKind::Unavailable
        );
    }

    #[test]
    fn verification_rejects_every_non_complete_state_and_classifies_drift() {
        let accepted = accepted_observation();
        assert!(verify_local_control_observation(&accepted.snapshot, &accepted).is_ok());

        let mut unstable = accepted.clone();
        unstable.status = ObservationStatus::Unstable;
        unstable.stable = false;
        assert_eq!(
            verify_local_control_observation(&accepted.snapshot, &unstable)
                .unwrap_err()
                .kind,
            LocalControlVerificationErrorKind::Unstable
        );

        let mut bounded = accepted.clone();
        bounded.status = ObservationStatus::BoundsExceeded;
        bounded.snapshot.scan_status = ScanStatus::BoundsExceeded;
        bounded.snapshot.bounds_exceeded = vec![BoundReason::Processes];
        assert_eq!(
            verify_local_control_observation(&accepted.snapshot, &bounded)
                .unwrap_err()
                .kind,
            LocalControlVerificationErrorKind::BoundsExceeded
        );

        let mut incomplete = accepted.clone();
        incomplete.snapshot.ownership_complete = false;
        assert_eq!(
            verify_local_control_observation(&accepted.snapshot, &incomplete)
                .unwrap_err()
                .kind,
            LocalControlVerificationErrorKind::Incomplete
        );

        let mut added = accepted.clone();
        added.snapshot.tcp_listeners.push(TcpListener {
            family: InternetAddressFamily::Ipv4,
            bind_class: BindClass::Loopback,
            port: 80,
            owners: vec![systemd_owner()],
            ownership_complete: true,
            instances: 1,
        });
        assert_eq!(
            verify_local_control_observation(&accepted.snapshot, &added)
                .unwrap_err()
                .kind,
            LocalControlVerificationErrorKind::Drift(LocalControlDriftKind::Added)
        );
    }

    #[test]
    fn accepted_fixture_matches_all_three_reviewed_schema4_observations_exactly() {
        const EXPECTED: &str = r#"{
          "attempts":1,
          "interval_milliseconds":50,
          "limits":{"container_processes":16,"file_descriptors_per_process":2048,"owners_per_socket":4,"processes":2048,"tcp_listeners":40,"total_file_descriptors":32768,"unix_listeners":40},
          "snapshot":{
            "bounds_exceeded":[],"inaccessible_root_filesystem_listener_count":14,"malformed_row_count":0,"ownership_complete":true,"reachability_complete":true,
            "root_container_processes":[
              {"canonical_executable":"/usr/bin/containerd","executable_basename":"containerd","instances":1,"uid":0,"unified_cgroup":"/system.slice/containerd.service"},
              {"canonical_executable":"/usr/bin/dockerd","executable_basename":"dockerd","instances":1,"uid":0,"unified_cgroup":"/system.slice/docker.service"}
            ],
            "scan_status":"within_bounds",
            "tcp_listeners":[
              {"bind_class":"wildcard","family":"ipv4","instances":1,"owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"port":22},
              {"bind_class":"wildcard","family":"ipv6","instances":1,"owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"port":22}
            ],
            "unavailable_inputs":[],
            "unix_listeners":[
              {"instances":1,"name_kind":"abstract","name_sha256":"2098ac544ed7672deda4863cf7f1ec11fd3916b31f7f02f8b1190394218612ec","owners":[{"canonical_executable":"/usr/sbin/multipathd","executable_basename":"multipathd","processes":1,"uid":0,"unified_cgroup":"/system.slice/multipathd.service"},{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"},
              {"instances":1,"name_kind":"abstract","name_sha256":"caf0d5ac99f3b95f921556138b2adbf4ceb0e8d48c61ef23d5180aa480b45743","owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"},
              {"instances":1,"name_kind":"filesystem","name_sha256":"1f76b0a726958dc80a872b9ae4fb414457f7ee9cc80f419ff7dfc509f236e469","owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"},
              {"instances":1,"name_kind":"filesystem","name_sha256":"2a5962ed41259a31b1587bcae589fcee6b9d6767ef064ac317e6d398b96a81f2","owners":[{"canonical_executable":"/usr/bin/dockerd","executable_basename":"dockerd","processes":1,"uid":0,"unified_cgroup":"/system.slice/docker.service"},{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"},
              {"instances":1,"name_kind":"filesystem","name_sha256":"68c0b0a26da3ac420889ddd0ab629df3f9defb482cf5a9daf7fdcd28ee545f29","owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"},{"canonical_executable":"/usr/lib/systemd/systemd-journald","executable_basename":"systemd-journald","processes":1,"uid":0,"unified_cgroup":"/system.slice/systemd-journald.service"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"},
              {"instances":1,"name_kind":"filesystem","name_sha256":"8b5e213b2b72a7033476e1f46afb302f0e4123c6e6fd746f77eeb744050e3b91","owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"},{"canonical_executable":"/usr/bin/dbus-daemon","executable_basename":"dbus-daemon","processes":1,"uid":101,"unified_cgroup":"/system.slice/dbus.service"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"},
              {"instances":1,"name_kind":"filesystem","name_sha256":"ac10a069436547a18b02df8078e06421de7fc8953887fcc32f817af06b1b09bb","owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"},
              {"instances":1,"name_kind":"filesystem","name_sha256":"ded56518cb66a7ddcdf9434f3280745cbb457869ea692d34cf0df494949bca96","owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"},
              {"instances":1,"name_kind":"filesystem","name_sha256":"e84916b142c7b55bdf364843e9360867ec403fc602cfb662c95d6299ebfb8e77","owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"},
              {"instances":1,"name_kind":"filesystem","name_sha256":"f7978cc2493e0ecd56d54a3f49e36c3bde79b3ac281baa0a0aed0efab0898c23","owners":[{"canonical_executable":"/usr/lib/systemd/systemd","executable_basename":"systemd","processes":1,"uid":0,"unified_cgroup":"/init.scope"}],"ownership_complete":true,"runner_reachable":true,"socket_type":"stream"}
            ],
            "unresolved_unix_listener_count":0
          },
          "stable":true,"status":"stable"
        }"#;
        let expected: Value = serde_json::from_str(EXPECTED).unwrap();
        let actual = serde_json::to_value(accepted_observation()).unwrap();
        assert_eq!(actual, expected);

        let canonical = serde_json::to_vec(&expected).unwrap();
        assert_eq!(
            domain_hash(b"", &canonical),
            "ab072e89d886125ce287354f12c4459be515f5e20bc9993b1742758c1ecfc77f"
        );
    }

    #[test]
    fn fingerprint_v2_converts_to_the_reviewed_enforced_inventory() {
        let fingerprint = crate::hosted_runner::hosted_runner_fingerprint_requirement();
        let accepted =
            accepted_local_control_snapshot(&fingerprint.accepted.local_control_inventory).unwrap();
        let observed = accepted_observation();

        assert_eq!(
            accepted.root_container_processes,
            observed.snapshot.root_container_processes
        );
        assert_eq!(accepted.tcp_listeners, observed.snapshot.tcp_listeners);
        assert_eq!(accepted.unix_listeners, observed.snapshot.unix_listeners);
        assert_eq!(accepted.inaccessible_root_filesystem_listener_count, 0);
        assert_eq!(
            observed
                .snapshot
                .inaccessible_root_filesystem_listener_count,
            14
        );
        verify_local_control_observation(&accepted, &observed).unwrap();
    }

    #[test]
    fn standard_lockdown_allows_only_reviewed_container_reductions() {
        let accepted = accepted_observation().snapshot;
        let mut reduced = accepted_observation();
        reduced.snapshot.root_container_processes.clear();
        let dockerd_listener = reduced
            .snapshot
            .unix_listeners
            .iter_mut()
            .find(|listener| {
                listener
                    .owners
                    .iter()
                    .any(|owner| owner.executable_basename == "dockerd")
            })
            .unwrap();
        dockerd_listener
            .owners
            .retain(|owner| owner.executable_basename != "dockerd");
        verify_no_additive_local_control_observation(&accepted, &reduced).unwrap();

        let mut missing_tcp = accepted_observation();
        missing_tcp.snapshot.tcp_listeners.remove(0);
        let error =
            verify_no_additive_local_control_observation(&accepted, &missing_tcp).unwrap_err();
        assert_eq!(
            error.kind,
            LocalControlVerificationErrorKind::Drift(LocalControlDriftKind::Removed)
        );
        assert_eq!(error.code, "local_control_inventory_unreviewed_reduction");

        let mut missing_non_container_owner = accepted_observation();
        missing_non_container_owner
            .snapshot
            .unix_listeners
            .iter_mut()
            .find(|listener| {
                listener
                    .owners
                    .iter()
                    .any(|owner| owner.executable_basename == "multipathd")
            })
            .unwrap()
            .owners
            .retain(|owner| owner.executable_basename == "multipathd");
        let error =
            verify_no_additive_local_control_observation(&accepted, &missing_non_container_owner)
                .unwrap_err();
        assert_eq!(
            error.kind,
            LocalControlVerificationErrorKind::Drift(LocalControlDriftKind::Removed)
        );
        assert_eq!(error.code, "local_control_inventory_unreviewed_reduction");

        let mut missing_mixed_container_listener = accepted_observation();
        let dockerd_listener = missing_mixed_container_listener
            .snapshot
            .unix_listeners
            .iter()
            .position(|listener| {
                listener
                    .owners
                    .iter()
                    .any(|owner| owner.executable_basename == "dockerd")
            })
            .unwrap();
        missing_mixed_container_listener
            .snapshot
            .unix_listeners
            .remove(dockerd_listener);
        let error = verify_no_additive_local_control_observation(
            &accepted,
            &missing_mixed_container_listener,
        )
        .unwrap_err();
        assert_eq!(
            error.kind,
            LocalControlVerificationErrorKind::Drift(LocalControlDriftKind::Removed)
        );
        assert_eq!(error.code, "local_control_inventory_unreviewed_reduction");

        let mut missing_mixed_container_co_owner = accepted_observation();
        missing_mixed_container_co_owner
            .snapshot
            .unix_listeners
            .iter_mut()
            .find(|listener| {
                listener
                    .owners
                    .iter()
                    .any(|owner| owner.executable_basename == "dockerd")
            })
            .unwrap()
            .owners
            .retain(|owner| owner.executable_basename == "dockerd");
        let error = verify_no_additive_local_control_observation(
            &accepted,
            &missing_mixed_container_co_owner,
        )
        .unwrap_err();
        assert_eq!(
            error.kind,
            LocalControlVerificationErrorKind::Drift(LocalControlDriftKind::Removed)
        );
        assert_eq!(error.code, "local_control_inventory_unreviewed_reduction");

        reduced.snapshot.tcp_listeners.push(TcpListener {
            family: InternetAddressFamily::Ipv4,
            bind_class: BindClass::Loopback,
            port: 2_376,
            owners: vec![systemd_owner()],
            ownership_complete: true,
            instances: 1,
        });
        assert_eq!(
            verify_no_additive_local_control_observation(&accepted, &reduced)
                .unwrap_err()
                .kind,
            LocalControlVerificationErrorKind::Drift(LocalControlDriftKind::Added)
        );
    }

    #[test]
    fn standard_lockdown_rejects_split_endpoint_instance_amplification() {
        let accepted = accepted_observation().snapshot;
        let mut split = accepted_observation();
        let index = split
            .snapshot
            .unix_listeners
            .iter()
            .position(|listener| listener.owners.len() == 2)
            .unwrap();
        let original = split.snapshot.unix_listeners.remove(index);
        let mut first = original.clone();
        first.owners.truncate(1);
        let mut second = original;
        second.owners.remove(0);
        split.snapshot.unix_listeners.push(first);
        split.snapshot.unix_listeners.push(second);

        assert_eq!(
            verify_no_additive_local_control_observation(&accepted, &split)
                .unwrap_err()
                .kind,
            LocalControlVerificationErrorKind::Drift(LocalControlDriftKind::Added)
        );
    }

    #[test]
    fn accepted_fingerprint_rejects_duplicate_endpoint_keys() {
        let mut inventory = crate::hosted_runner::hosted_runner_fingerprint_requirement()
            .accepted
            .local_control_inventory;
        inventory
            .tcp_listeners
            .push(inventory.tcp_listeners[0].clone());

        assert_eq!(
            accepted_local_control_snapshot(&inventory)
                .unwrap_err()
                .kind,
            LocalControlVerificationErrorKind::InvalidAcceptedFingerprint
        );
    }
}
