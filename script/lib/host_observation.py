#!/usr/bin/env python3

# Device and inode values in this module describe one observation only. They
# are not accepted fingerprint values and must not be serialized as host pins.

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock


MAX_PROCESSES = 2048
MAX_FDS_PER_PROCESS = 2048
MAX_TOTAL_FDS = 32768
MAX_SOCKET_OWNERS = 4
MAX_UNIX_LISTENERS = 40
MAX_TCP_LISTENERS = 40
MAX_CONTAINER_PROCESSES = 16
MAX_INVENTORY_BYTES = 192 * 1024
MAX_PROC_NET_TABLE_BYTES = 1024 * 1024
POST_KILL_REAP_SECONDS = 1
PUBLIC_COUNTER_MAXIMUMS = {
    "malformed_row_count": 3 * MAX_PROC_NET_TABLE_BYTES,
    "unresolved_unix_listener_count": MAX_PROC_NET_TABLE_BYTES,
    "inaccessible_root_filesystem_listener_count": MAX_PROC_NET_TABLE_BYTES,
}
STABILITY_ATTEMPTS = 3
STABILITY_INTERVAL_SECONDS = 0.05
TCP_TABLE_HEADER = (
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
)
UNIX_TABLE_HEADER = (
    b"Num",
    b"RefCount",
    b"Protocol",
    b"Flags",
    b"Type",
    b"St",
    b"Inode",
    b"Path",
)

SCHEMA4_REQUIRED_PATHS = (
    "/usr/bin/docker",
    "/usr/bin/id",
    "/usr/bin/mount",
    "/usr/bin/stat",
    "/usr/bin/sudo",
    "/usr/bin/systemctl",
    "/usr/bin/systemd-run",
    "/usr/bin/test",
    "/usr/bin/true",
    "/usr/bin/umount",
    "/usr/sbin/visudo",
    "/usr/sbin/nft",
)
SCHEMA4_ANCESTOR_DIRECTORIES = (
    "/",
    "/etc",
    "/etc/sudoers.d",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
)
SCHEMA4_FIXED_UNITS = (
    "docker.service",
    "docker.socket",
    "containerd.service",
    "containerd.socket",
    "walinuxagent.service",
)
SCHEMA4_FIXED_SOCKETS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
)
SCHEMA4_PROBE_RESULTS = {
    "created_and_removed",
    "created_and_root_removed",
    "denied",
    "unavailable",
}
SCHEMA4_REVIEWED_OS_ID = "ubuntu"
SCHEMA4_REVIEWED_OS_VERSION_ID = "24.04"
SCHEMA4_REVIEWED_ARCHITECTURE = "x86_64"
SCHEMA4_REVIEWED_RUNNER_PRINCIPAL = "runner"
SCHEMA4_REVIEWED_RUNNER_GROUPS = frozenset(
    {"adm", "users", "docker", "systemd-journal", "runner"}
)
SCHEMA4_REVIEWED_RESOLVER_TARGET = "/run/systemd/resolve/stub-resolv.conf"
SCHEMA4_REVIEWED_SUDO_SOURCE_TARGETS = {
    "sudoers": "/etc/sudoers",
    "90-cloud-init-users": "/etc/sudoers.d/90-cloud-init-users",
    "README": "/etc/sudoers.d/README",
    "runner": "/etc/sudoers.d/runner",
}
SCHEMA4_REVIEWED_UNIT_STATES = {
    "docker.service": {
        "load_state": "loaded",
        "active_state": "active",
        "unit_file_state": "enabled",
    },
    "docker.socket": {
        "load_state": "loaded",
        "active_state": "active",
        "unit_file_state": "enabled",
    },
    "containerd.service": {
        "load_state": "loaded",
        "active_state": "active",
        "unit_file_state": "enabled",
    },
    "containerd.socket": {
        "load_state": "not-found",
        "active_state": "inactive",
        "unit_file_state": "",
    },
    "walinuxagent.service": {
        "load_state": "loaded",
        "active_state": "active",
        "unit_file_state": "enabled",
    },
}
SCHEMA4_REVIEWED_SOCKET_IDENTITIES = {
    "/var/run/docker.sock": {"owner": "root", "group": "docker"},
    "/run/docker.sock": {"owner": "root", "group": "docker"},
    "/run/containerd/containerd.sock": {"owner": "root", "group": "root"},
}
UNREVIEWED_OS_ID = "unreviewed_os_id"
UNREVIEWED_OS_VERSION_ID = "unreviewed_os_version_id"
UNREVIEWED_ARCHITECTURE = "unreviewed_architecture"
UNREVIEWED_RUNNER_PRINCIPAL = "unreviewed_runner_principal"
UNREVIEWED_METADATA_TARGET = "unreviewed_canonical_target"
UNREVIEWED_RESOLVER_TARGET = "unreviewed_resolver_target"
UNREVIEWED_SUDO_SOURCE_TARGET = "unreviewed_sudo_source_target"
UNREVIEWED_UNIT_STATE = "unreviewed_unit_state"
UNREVIEWED_SOCKET_OWNER = "unreviewed_socket_owner"
UNREVIEWED_SOCKET_GROUP = "unreviewed_socket_group"
UNREVIEWED_NAME_PREFIX = "unreviewed_sha256_"
SCHEMA4_TOP_LEVEL_FIELDS = {
    "schema_version",
    "observation",
    "status",
    "protected_target",
    "host",
    "required_paths",
    "permission_ancestor_directories",
    "resolver",
    "systemd",
    "sudo",
    "container_runtime",
    "local_control_inventory",
    "next_step",
}
MAX_SCHEMA4_OUTPUT_BYTES = 256 * 1024
MAX_SCHEMA4_POLICY_SOURCES = 64
MAX_SCHEMA4_AZURE_PROCESSES = 16
BOUND_REASONS = {
    "processes",
    "fds_per_process",
    "total_fds",
    "socket_owners",
    "unix_listeners",
    "tcp_listeners",
    "container_processes",
}
ACQUISITION_UNAVAILABLE_REASONS = {
    "proc",
    "proc_scan",
    "process_identity",
    "process_identity_drift",
    "process_fd_scan",
    "process_fd_readlink",
    "cgroup_identity",
    "unix_table",
    "ipv4_table",
    "ipv6_table",
}
DERIVED_UNAVAILABLE_REASONS = {
    "malformed_rows",
    "unix_reachability",
    "socket_ownership",
}

UNREVIEWED_EXECUTABLE_PATH = "unreviewed_executable_path"
REVIEWED_EXECUTABLE_PATHS = frozenset(
    {
        "/usr/bin/containerd",
        "/usr/bin/dockerd",
        "/usr/lib/systemd/systemd",
        "/usr/lib/systemd/systemd-journald",
        "/usr/lib/systemd/systemd-networkd",
        "/usr/lib/systemd/systemd-resolved",
        "/usr/lib/systemd/systemd-udevd",
    }
)
REVIEWED_CGROUPS = {
    "/",
    "/init.scope",
    "/system.slice/containerd.service",
    "/system.slice/docker.service",
    "/system.slice/systemd-journald.service",
    "/system.slice/systemd-networkd.service",
    "/system.slice/systemd-resolved.service",
    "/system.slice/systemd-udevd.service",
    "/system.slice/walinuxagent.service",
    "/azure.slice/walinuxagent.service",
}


def _domain_separated_name(domain, value):
    encoded = os.fsencode(value)
    digest = hashlib.sha256(domain + b"\0" + encoded).hexdigest()
    return f"{UNREVIEWED_NAME_PREFIX}{digest}"


def public_runner_group_name(value):
    if value in SCHEMA4_REVIEWED_RUNNER_GROUPS:
        return value
    return _domain_separated_name(b"fence-runner-group-v1", value)


def public_sudo_source_name(value):
    if value in SCHEMA4_REVIEWED_SUDO_SOURCE_TARGETS:
        return value
    return _domain_separated_name(b"fence-sudo-source-v1", value)


def canonical_sudo_sources(sources):
    return sorted(
        sources,
        key=lambda source: (
            0 if source["path_class"] == "main_policy" else 1,
            source["name"],
        ),
    )


def public_host_identity(value, reviewed, unreviewed):
    return value if value == reviewed else unreviewed


def public_fixed_canonical_target(value, expected_path):
    rendered = str(value)
    reviewed = set(SCHEMA4_REQUIRED_PATHS) | set(SCHEMA4_ANCESTOR_DIRECTORIES)
    if expected_path in reviewed and rendered == expected_path:
        return expected_path
    return UNREVIEWED_METADATA_TARGET


def public_sudo_source_target(value):
    rendered = str(value)
    if rendered in SCHEMA4_REVIEWED_SUDO_SOURCE_TARGETS.values():
        return rendered
    return UNREVIEWED_SUDO_SOURCE_TARGET


def public_resolver_target(value):
    rendered = str(value)
    if rendered == SCHEMA4_REVIEWED_RESOLVER_TARGET:
        return rendered
    return UNREVIEWED_RESOLVER_TARGET


def public_unit_state(unit, field, value):
    reviewed = SCHEMA4_REVIEWED_UNIT_STATES[unit][field]
    return value if value == reviewed else UNREVIEWED_UNIT_STATE


def public_socket_identity(path, field, value):
    reviewed = SCHEMA4_REVIEWED_SOCKET_IDENTITIES[path][field]
    if value == reviewed:
        return value
    return UNREVIEWED_SOCKET_OWNER if field == "owner" else UNREVIEWED_SOCKET_GROUP


def _bounded_read(path, maximum):
    with pathlib.Path(path).open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("bounded proc input exceeded")
    return data


def bounded_file_lines(path, maximum_bytes, maximum_lines):
    contents = _bounded_read(path, maximum_bytes).decode("utf-8", errors="strict")
    lines = contents.splitlines()
    return lines[:maximum_lines], len(lines) > maximum_lines


def bounded_directory_entries(path, maximum_entries):
    entries = []
    with os.scandir(path) as candidates:
        for candidate in candidates:
            if len(entries) >= maximum_entries:
                return sorted(entries), True
            entries.append(pathlib.Path(candidate.path))
    return sorted(entries), False


def bounded_command_output(args, maximum=4096, timeout=5):
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            cwd="/",
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/usr/sbin:/bin:/sbin",
            },
            start_new_session=True,
        )
    except OSError:
        return None
    selector = selectors.DefaultSelector()
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if not selector.select(remaining):
                return None
            chunk = os.read(process.stdout.fileno(), min(65536, maximum + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > maximum:
                return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        return_code = process.wait(timeout=remaining)
        if return_code not in (0, 1, 3, 4):
            return None
        decoded = output.decode("utf-8", errors="strict")
        return decoded
    except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired):
        return None
    finally:
        selector.close()
        cleanup_failed = False
        try:
            direct_exited = process.poll() is not None
        except OSError:
            direct_exited = False
            cleanup_failed = True
        if not direct_exited:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            cleanup_failed = True
        # Recheck after reaping because a group containing only a zombie may
        # reject signals even though it has no surviving process.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            cleanup_failed = True
        try:
            process.stdout.close()
        except OSError:
            cleanup_failed = True
        if cleanup_failed:
            raise RuntimeError("bounded command cleanup failed")


def bounded_waitpid(pid, timeout=5):
    deadline = time.monotonic() + timeout
    while True:
        try:
            waited_pid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return None
        if waited_pid == pid:
            return status
        if time.monotonic() >= deadline:
            break
        time.sleep(0.01)

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    reap_deadline = time.monotonic() + POST_KILL_REAP_SECONDS
    while True:
        try:
            waited_pid, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return None
        if waited_pid == pid or time.monotonic() >= reap_deadline:
            return None
        time.sleep(0.01)


def _safe_basename(value):
    if re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", value):
        return value
    return "unreportable"


def _reviewed_executable_path(path):
    candidate = pathlib.Path(path)
    if (
        not candidate.is_absolute()
        or ".." in candidate.parts
        or str(candidate) != str(path)
    ):
        return UNREVIEWED_EXECUTABLE_PATH
    rendered = str(candidate)
    if rendered in REVIEWED_EXECUTABLE_PATHS:
        return rendered
    return UNREVIEWED_EXECUTABLE_PATH


def _unified_cgroup(process_root):
    try:
        contents = _bounded_read(process_root / "cgroup", 4096).decode(
            "utf-8", errors="strict"
        )
    except (FileNotFoundError, OSError, UnicodeDecodeError, ValueError):
        return None
    for line in contents.splitlines():
        try:
            hierarchy, controllers, path = line.split(":", 2)
        except ValueError:
            continue
        if hierarchy == "0" and controllers == "":
            return path if path in REVIEWED_CGROUPS else None
    return None


def _process_start_time(process_root):
    contents = _bounded_read(process_root / "stat", 4096).decode(
        "utf-8", errors="strict"
    )
    fields = contents.rsplit(")", 1)
    if len(fields) != 2:
        raise ValueError("process stat is malformed")
    remaining = fields[1].split()
    if len(remaining) <= 19:
        raise ValueError("process stat is incomplete")
    return int(remaining[19])


def _process_observation(process_root):
    process_metadata = process_root.stat()
    executable_link = process_root / "exe"
    executable_metadata = executable_link.stat()
    if not stat.S_ISREG(executable_metadata.st_mode):
        raise ValueError("process executable is not regular")
    executable_target = os.readlink(executable_link)
    executable_path = pathlib.Path(executable_target.removesuffix(" (deleted)"))
    basename = _safe_basename(executable_path.name)
    return {
        "uid": process_metadata.st_uid,
        "start_time_ticks": _process_start_time(process_root),
        "executable_device": executable_metadata.st_dev,
        "executable_inode": executable_metadata.st_ino,
        "executable_basename": basename,
        "canonical_executable": _reviewed_executable_path(executable_path),
    }


def _process_pin(pid, observation):
    return (
        pid,
        observation["start_time_ticks"],
        observation["executable_device"],
        observation["executable_inode"],
    )


def _same_process(first, second):
    return all(
        first[key] == second[key]
        for key in (
            "uid",
            "start_time_ticks",
            "executable_device",
            "executable_inode",
            "executable_basename",
            "canonical_executable",
        )
    )


def _public_owner(identity):
    return {
        key: identity[key]
        for key in (
            "uid",
            "executable_basename",
            "canonical_executable",
            "unified_cgroup",
        )
    }


def _owner_key(identity):
    public = _public_owner(identity)
    return tuple(public[key] for key in sorted(public))


def _socket_inode(target):
    match = re.fullmatch(r"socket:\[([0-9]{1,20})\]", target)
    if match is None:
        return None
    return int(match.group(1))


def _scan_process_owners(proc_root):
    bounds = set()
    unavailable = set()
    owners = {}
    nonroot_owned_inodes = set()
    unresolved_root_inodes = set()
    containers = []
    processes_seen = 0
    fds_seen = 0
    process_entries = []
    try:
        with os.scandir(proc_root) as entries:
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                try:
                    is_directory = entry.is_dir(follow_symlinks=False)
                except OSError:
                    unavailable.add("proc_scan")
                    continue
                if not is_directory:
                    continue
                if len(process_entries) >= MAX_PROCESSES:
                    bounds.add("processes")
                    break
                process_entries.append(entry)
    except OSError:
        return {}, set(), set(), [], set(), {"proc"}, 0, 0
    process_entries.sort(key=lambda entry: int(entry.name))

    for entry in process_entries:
        process_root_path = pathlib.Path(entry.path)
        pid = int(entry.name)
        try:
            before = _process_observation(process_root_path)
        except FileNotFoundError:
            continue
        except (OSError, UnicodeDecodeError, ValueError):
            unavailable.add("process_identity")
            continue
        processes_seen += 1
        before_cgroup = _unified_cgroup(process_root_path) if before["uid"] == 0 else None
        socket_inodes = set()
        try:
            with os.scandir(process_root_path / "fd") as descriptors:
                process_fds = 0
                for descriptor in descriptors:
                    if process_fds >= MAX_FDS_PER_PROCESS:
                        bounds.add("fds_per_process")
                        break
                    process_fds += 1
                    if fds_seen >= MAX_TOTAL_FDS:
                        bounds.add("total_fds")
                        break
                    fds_seen += 1
                    try:
                        target = os.readlink(descriptor.path)
                    except FileNotFoundError:
                        continue
                    except OSError:
                        unavailable.add("process_fd_readlink")
                        continue
                    inode = _socket_inode(target)
                    if inode is not None:
                        socket_inodes.add(inode)
        except FileNotFoundError:
            continue
        except OSError:
            unavailable.add("process_fd_scan")
            continue

        try:
            after = _process_observation(process_root_path)
        except FileNotFoundError:
            continue
        except (OSError, UnicodeDecodeError, ValueError):
            unavailable.add("process_identity_drift")
            if before["uid"] == 0:
                unresolved_root_inodes.update(socket_inodes)
            continue
        after_cgroup = _unified_cgroup(process_root_path) if after["uid"] == 0 else None
        if not _same_process(before, after):
            unavailable.add("process_identity_drift")
            if before["uid"] == 0 or after["uid"] == 0:
                unresolved_root_inodes.update(socket_inodes)
            continue

        if before["uid"] != 0:
            nonroot_owned_inodes.update(socket_inodes)
        else:
            identity = {
                "uid": 0,
                "executable_basename": before["executable_basename"],
                "canonical_executable": before["canonical_executable"],
                "unified_cgroup": before_cgroup,
            }
            if before_cgroup is None or after_cgroup != before_cgroup:
                if socket_inodes or before["executable_basename"] in {
                    "containerd",
                    "dockerd",
                }:
                    unavailable.add("cgroup_identity")
                unresolved_root_inodes.update(socket_inodes)
            else:
                pin = _process_pin(pid, before)
                for inode in socket_inodes:
                    key = _owner_key(identity)
                    owner = owners.setdefault(inode, {}).setdefault(
                        key, {**_public_owner(identity), "_process_pins": set()}
                    )
                    owner["_process_pins"].add(pin)
                if before["executable_basename"] in {"containerd", "dockerd"}:
                    containers.append(
                        {
                            **_public_owner(identity),
                            "_process_pin": pin,
                        }
                    )
        if "total_fds" in bounds:
            break

    container_processes = sorted(
        containers,
        key=lambda item: (
            item["executable_basename"],
            item["canonical_executable"],
            item["unified_cgroup"],
            item["_process_pin"],
        ),
    )
    if len(container_processes) > MAX_CONTAINER_PROCESSES:
        bounds.add("container_processes")
        container_processes = container_processes[:MAX_CONTAINER_PROCESSES]
    return (
        owners,
        nonroot_owned_inodes,
        unresolved_root_inodes,
        container_processes,
        bounds,
        unavailable,
        processes_seen,
        fds_seen,
    )


def _bounded_owners(owners_by_inode, inode, bounds):
    values = [
        {
            **{key: value for key, value in owner.items() if key != "_process_pins"},
            "_process_pins": sorted(owner["_process_pins"]),
            "processes": len(owner["_process_pins"]),
        }
        for owner in owners_by_inode.get(inode, {}).values()
    ]
    values = sorted(
        values,
        key=lambda item: (
            item["executable_basename"],
            item["canonical_executable"],
            item["unified_cgroup"],
            item["processes"],
        ),
    )
    if len(values) > MAX_SOCKET_OWNERS:
        bounds.add("socket_owners")
        values = values[:MAX_SOCKET_OWNERS]
    return values


def _reported_unix_listener(row, owners, ownership_complete):
    return {
        "_socket_inode": row["inode"],
        "socket_type": row["socket_type"],
        "name_kind": row["name_kind"],
        "name_sha256": row["name_sha256"],
        "runner_reachable": True,
        "owners": owners,
        "ownership_complete": ownership_complete,
    }


def _socket_ownership_complete(
    inode,
    owners,
    nonroot_owned_inodes,
    unresolved_root_inodes,
):
    return (
        bool(owners)
        and inode not in nonroot_owned_inodes
        and inode not in unresolved_root_inodes
    )


def _unix_name(raw_name):
    if raw_name.startswith(b"@"):
        kind = "abstract"
    elif raw_name:
        kind = "filesystem"
    else:
        kind = "unnamed"
    digest = hashlib.sha256(b"fence-unix-name-v1\0" + raw_name).hexdigest()
    return kind, digest


def parse_unix_table(contents):
    listeners = []
    malformed = 0
    lines = contents.splitlines()
    if not lines or tuple(lines[0].split()) != UNIX_TABLE_HEADER:
        raise ValueError("Unix table header is invalid")
    for line in lines[1:]:
        fields = line.split(maxsplit=7)
        if len(fields) < 7:
            malformed += 1
            continue
        try:
            if (
                re.fullmatch(rb"[0-9A-Fa-f]{1,16}:", fields[0]) is None
                or re.fullmatch(rb"[0-9A-Fa-f]{1,8}", fields[1]) is None
                or re.fullmatch(rb"[0-9A-Fa-f]{1,8}", fields[2]) is None
                or re.fullmatch(rb"[0-9A-Fa-f]{1,8}", fields[3]) is None
                or re.fullmatch(rb"[0-9A-Fa-f]{1,4}", fields[4]) is None
                or re.fullmatch(rb"[0-9A-Fa-f]{1,2}", fields[5]) is None
                or re.fullmatch(rb"[0-9]{1,20}", fields[6]) is None
            ):
                raise ValueError("invalid Unix row prefix")
            flags = int(fields[3], 16)
            socket_type = int(fields[4], 16)
            inode = int(fields[6], 10)
        except ValueError:
            malformed += 1
            continue
        if flags & 0x00010000 == 0 or socket_type not in {1, 5}:
            continue
        raw_name = fields[7] if len(fields) == 8 else b""
        name_kind, name_sha256 = _unix_name(raw_name)
        listeners.append(
            {
                "inode": inode,
                "socket_type": "stream" if socket_type == 1 else "seqpacket",
                "name_kind": name_kind,
                "name_sha256": name_sha256,
                "raw_name": raw_name,
            }
        )
    return listeners, malformed


def _decode_proc_address(value, family):
    raw = bytes.fromhex(value)
    if family == "ipv4":
        if len(raw) != 4:
            raise ValueError("invalid IPv4 address")
        return ipaddress.IPv4Address(raw[::-1])
    if len(raw) != 16:
        raise ValueError("invalid IPv6 address")
    reordered = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
    return ipaddress.IPv6Address(reordered)


def _decode_proc_endpoint(value, family):
    address_hex, port_hex = value.split(":", 1)
    if re.fullmatch(r"[0-9A-Fa-f]{1,4}", port_hex) is None:
        raise ValueError("invalid proc endpoint port")
    address = _decode_proc_address(address_hex, family)
    port = int(port_hex, 16)
    if port > 65535:
        raise ValueError("invalid proc endpoint port")
    return address, port


def _bind_class(address):
    if address.is_unspecified:
        return "wildcard"
    if address.is_loopback:
        return "loopback"
    return "other_local"


def parse_tcp_table(contents, family):
    listeners = []
    malformed = 0
    lines = contents.decode("ascii", errors="strict").splitlines()
    if not lines or tuple(lines[0].split()) != TCP_TABLE_HEADER:
        raise ValueError("TCP table header is invalid")
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            malformed += 1
            continue
        try:
            if (
                re.fullmatch(r"[0-9]{1,10}:", fields[0]) is None
                or re.fullmatch(r"[0-9A-Fa-f]{2}", fields[3]) is None
                or re.fullmatch(
                    r"[0-9A-Fa-f]{1,8}:[0-9A-Fa-f]{1,8}", fields[4]
                )
                is None
                or re.fullmatch(
                    r"[0-9A-Fa-f]{1,2}:[0-9A-Fa-f]{1,8}", fields[5]
                )
                is None
                or re.fullmatch(r"[0-9A-Fa-f]{1,8}", fields[6]) is None
                or re.fullmatch(r"[0-9]{1,20}", fields[7]) is None
                or re.fullmatch(r"[0-9]{1,20}", fields[8]) is None
                or re.fullmatch(r"[0-9]{1,20}", fields[9]) is None
            ):
                raise ValueError("invalid TCP row prefix")
            address, port = _decode_proc_endpoint(fields[1], family)
            _decode_proc_endpoint(fields[2], family)
            uid = int(fields[7], 10)
            inode = int(fields[9], 10)
        except (ValueError, IndexError):
            malformed += 1
            continue
        if fields[3].upper() != "0A":
            continue
        listeners.append(
            {
                "family": family,
                "bind_class": _bind_class(address),
                "port": port,
                "inode": inode,
                "socket_uid": uid,
            }
        )
    return listeners, malformed


def _filesystem_socket_state(raw_name, runner_access):
    if not raw_name.startswith(b"/"):
        return "unknown", "unavailable"
    try:
        metadata = os.stat(raw_name, follow_symlinks=False)
    except (FileNotFoundError, OSError, ValueError):
        return "unknown", "unavailable"
    if not stat.S_ISSOCK(metadata.st_mode):
        return "unknown", "not_socket"
    owner_class = "root" if metadata.st_uid == 0 else "nonroot"
    if runner_access is None:
        return owner_class, "unavailable"
    accessible = runner_access(raw_name)
    if accessible is True:
        return owner_class, "reachable"
    if accessible is False:
        return owner_class, "unreachable"
    return owner_class, "unavailable"


def _collect_snapshot(
    proc_root=pathlib.Path("/proc"), filesystem_socket_access=None
):
    (
        owners,
        nonroot_owned_inodes,
        unresolved_root_inodes,
        container_processes,
        bounds,
        process_unavailable,
        _,
        _,
    ) = _scan_process_owners(proc_root)
    unavailable = set(process_unavailable)
    malformed_rows = 0

    try:
        unix_rows, malformed = parse_unix_table(
            _bounded_read(proc_root / "net/unix", MAX_PROC_NET_TABLE_BYTES)
        )
        malformed_rows += malformed
    except (FileNotFoundError, OSError, ValueError):
        unavailable.add("unix_table")
        unix_rows = []

    unix_listeners = []
    unresolved_unix = 0
    inaccessible_root_filesystem = 0
    for row in unix_rows:
        row_owners = _bounded_owners(owners, row["inode"], bounds)
        ownership_complete = _socket_ownership_complete(
            row["inode"],
            row_owners,
            nonroot_owned_inodes,
            unresolved_root_inodes,
        )
        if row["name_kind"] == "abstract":
            if not row_owners:
                if row["inode"] in nonroot_owned_inodes:
                    continue
                unresolved_unix += 1
                continue
            unix_listeners.append(
                _reported_unix_listener(row, row_owners, ownership_complete)
            )
            continue
        if row["name_kind"] == "unnamed":
            continue

        file_owner_class, access_state = _filesystem_socket_state(
            row["raw_name"], filesystem_socket_access
        )
        root_identity = (
            bool(row_owners)
            or row["inode"] in unresolved_root_inodes
            or file_owner_class == "root"
        )
        if access_state == "unreachable" and root_identity:
            inaccessible_root_filesystem += 1
            continue
        if access_state != "reachable":
            unresolved_unix += 1
            continue
        if not root_identity:
            continue
        unix_listeners.append(
            _reported_unix_listener(row, row_owners, ownership_complete)
        )
    unix_listeners.sort(
        key=lambda item: (
            item["socket_type"],
            item["name_kind"],
            item["name_sha256"],
            item["_socket_inode"],
        )
    )
    if len(unix_listeners) > MAX_UNIX_LISTENERS:
        bounds.add("unix_listeners")
        unix_listeners = unix_listeners[:MAX_UNIX_LISTENERS]

    tcp_listeners = []
    for filename, family in (("tcp", "ipv4"), ("tcp6", "ipv6")):
        try:
            rows, malformed = parse_tcp_table(
                _bounded_read(proc_root / f"net/{filename}", MAX_PROC_NET_TABLE_BYTES),
                family,
            )
            malformed_rows += malformed
        except (FileNotFoundError, OSError, UnicodeDecodeError, ValueError):
            unavailable.add(f"{family}_table")
            continue
        for row in rows:
            row_owners = _bounded_owners(owners, row["inode"], bounds)
            root_identity = (
                row["socket_uid"] == 0
                or bool(row_owners)
                or row["inode"] in unresolved_root_inodes
            )
            if not root_identity:
                continue
            ownership_complete = _socket_ownership_complete(
                row["inode"],
                row_owners,
                nonroot_owned_inodes,
                unresolved_root_inodes,
            )
            tcp_listeners.append(
                {
                    "_socket_inode": row["inode"],
                    "_socket_uid": row["socket_uid"],
                    "family": row["family"],
                    "bind_class": row["bind_class"],
                    "port": row["port"],
                    "owners": row_owners,
                    "ownership_complete": ownership_complete,
                }
            )
    tcp_listeners.sort(
        key=lambda item: (
            item["family"],
            item["bind_class"],
            item["port"],
            item["_socket_inode"],
        )
    )
    if len(tcp_listeners) > MAX_TCP_LISTENERS:
        bounds.add("tcp_listeners")
        tcp_listeners = tcp_listeners[:MAX_TCP_LISTENERS]

    return {
        "_bounds_exceeded": sorted(bounds),
        "_unavailable_inputs": sorted(unavailable),
        "malformed_row_count": malformed_rows,
        "unresolved_unix_listener_count": unresolved_unix,
        "inaccessible_root_filesystem_listener_count": inaccessible_root_filesystem,
        "root_container_processes": container_processes,
        "unix_listeners": unix_listeners,
        "tcp_listeners": tcp_listeners,
    }


def _public_owner_record(owner):
    return {
        "uid": owner["uid"],
        "executable_basename": owner["executable_basename"],
        "canonical_executable": owner["canonical_executable"],
        "unified_cgroup": owner["unified_cgroup"],
        "processes": owner["processes"],
    }


def _owner_sort_key(owner):
    return (
        owner["executable_basename"],
        owner["canonical_executable"],
        owner["unified_cgroup"],
        owner["processes"],
    )


def _public_owners(owners):
    aggregated = {}
    pins = set()
    for owner in owners:
        for pin in owner["_process_pins"]:
            if pin in pins:
                raise ValueError("listener owner process pin was duplicated")
            pins.add(pin)
        public = _public_owner_record(owner)
        processes = public.pop("processes")
        key = tuple(public[field] for field in sorted(public))
        aggregated.setdefault(key, {**public, "processes": 0})[
            "processes"
        ] += processes
    if sum(owner["processes"] for owner in aggregated.values()) > MAX_PROCESSES:
        raise ValueError("listener owner process count exceeded its bound")
    return sorted(aggregated.values(), key=_owner_sort_key)


def _owners_key(owners):
    return tuple(_owner_sort_key(owner) for owner in owners)


def _unix_listener_sort_key(listener):
    return (
        listener["socket_type"],
        listener["name_kind"],
        listener["name_sha256"],
        listener["runner_reachable"],
        listener["ownership_complete"],
        listener["instances"],
        _owners_key(listener["owners"]),
    )


def _tcp_listener_sort_key(listener):
    return (
        listener["family"],
        listener["bind_class"],
        listener["port"],
        listener["ownership_complete"],
        listener["instances"],
        _owners_key(listener["owners"]),
    )


def _aggregate_containers(processes):
    aggregated = {}
    private_pins = set()
    for process in processes:
        pin = process["_process_pin"]
        if pin in private_pins:
            raise ValueError("container process pin was duplicated")
        private_pins.add(pin)
        public = _public_owner_record({**process, "processes": 1})
        public.pop("processes")
        key = tuple(public[field] for field in sorted(public))
        aggregated.setdefault(key, {**public, "instances": 0})["instances"] += 1
    return sorted(
        aggregated.values(),
        key=lambda item: (
            item["executable_basename"],
            item["canonical_executable"],
            item["unified_cgroup"],
            item["instances"],
        ),
    )


def _aggregate_listeners(listeners, public_fields, sort_key):
    aggregated = {}
    socket_inodes = set()
    for listener in listeners:
        inode = listener["_socket_inode"]
        if inode in socket_inodes:
            raise ValueError("listener socket inode was duplicated")
        socket_inodes.add(inode)
        public = {field: listener[field] for field in public_fields}
        public["owners"] = _public_owners(listener["owners"])
        owner_key = tuple(
            tuple(owner[field] for field in sorted(owner))
            for owner in public["owners"]
        )
        key = (
            *(public[field] for field in public_fields),
            owner_key,
        )
        aggregated.setdefault(key, {**public, "instances": 0})["instances"] += 1
    return sorted(aggregated.values(), key=sort_key)


def _summarize_public_snapshot(snapshot):
    unavailable = set(snapshot["unavailable_inputs"])
    if snapshot["malformed_row_count"]:
        unavailable.add("malformed_rows")
    reachability_failures = {"proc", "unix_table", "malformed_rows"}
    reachability_complete = (
        snapshot["unresolved_unix_listener_count"] == 0
        and unavailable.isdisjoint(reachability_failures)
    )
    if not reachability_complete:
        unavailable.add("unix_reachability")
    ownership_failures = ACQUISITION_UNAVAILABLE_REASONS | {"malformed_rows"}
    ownership_complete = (
        reachability_complete
        and unavailable.isdisjoint(ownership_failures)
        and all(
            listener["ownership_complete"]
            for listener in [
                *snapshot["unix_listeners"],
                *snapshot["tcp_listeners"],
            ]
        )
    )
    if not ownership_complete:
        unavailable.add("socket_ownership")
    if unavailable:
        scan_status = "unavailable"
    elif snapshot["bounds_exceeded"]:
        scan_status = "bounds_exceeded"
    else:
        scan_status = "within_bounds"
    return {
        **snapshot,
        "scan_status": scan_status,
        "unavailable_inputs": sorted(unavailable),
        "reachability_complete": reachability_complete,
        "ownership_complete": ownership_complete,
    }


def _public_snapshot(snapshot):
    public = {
        "bounds_exceeded": snapshot["_bounds_exceeded"],
        "unavailable_inputs": snapshot["_unavailable_inputs"],
        "malformed_row_count": snapshot["malformed_row_count"],
        "unresolved_unix_listener_count": snapshot[
            "unresolved_unix_listener_count"
        ],
        "inaccessible_root_filesystem_listener_count": snapshot[
            "inaccessible_root_filesystem_listener_count"
        ],
        "root_container_processes": _aggregate_containers(
            snapshot["root_container_processes"]
        ),
        "unix_listeners": _aggregate_listeners(
            snapshot["unix_listeners"],
            (
                "socket_type",
                "name_kind",
                "name_sha256",
                "runner_reachable",
                "ownership_complete",
            ),
            _unix_listener_sort_key,
        ),
        "tcp_listeners": _aggregate_listeners(
            snapshot["tcp_listeners"],
            ("family", "bind_class", "port", "ownership_complete"),
            _tcp_listener_sort_key,
        ),
    }
    return _summarize_public_snapshot(public)


def observe_local_control_inventory(
    filesystem_socket_access=None, sample=None, sleeper=time.sleep
):
    if sample is None:
        sample = lambda: _collect_snapshot(
            filesystem_socket_access=filesystem_socket_access
        )
    last = None
    for attempt in range(1, STABILITY_ATTEMPTS + 1):
        first = sample()
        sleeper(STABILITY_INTERVAL_SECONDS)
        second = sample()
        last = second
        if first == second:
            public = _public_snapshot(second)
            status = {
                "within_bounds": "stable",
                "bounds_exceeded": "bounds_exceeded",
                "unavailable": "unavailable",
            }[public["scan_status"]]
            return {
                "status": status,
                "stable": True,
                "attempts": attempt,
                "interval_milliseconds": 50,
                "limits": observation_limits(),
                "snapshot": public,
            }
    return {
        "status": "unstable",
        "stable": False,
        "attempts": STABILITY_ATTEMPTS,
        "interval_milliseconds": 50,
        "limits": observation_limits(),
        "snapshot": _public_snapshot(last),
    }


def observation_limits():
    return {
        "processes": MAX_PROCESSES,
        "file_descriptors_per_process": MAX_FDS_PER_PROCESS,
        "total_file_descriptors": MAX_TOTAL_FDS,
        "owners_per_socket": MAX_SOCKET_OWNERS,
        "unix_listeners": MAX_UNIX_LISTENERS,
        "tcp_listeners": MAX_TCP_LISTENERS,
        "container_processes": MAX_CONTAINER_PROCESSES,
    }


def _is_integer(value, minimum=0):
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _is_bool(value):
    return isinstance(value, bool)


def _is_optional_bool(value):
    return value is None or _is_bool(value)


def _reviewed_reported_path(value):
    return value == UNREVIEWED_EXECUTABLE_PATH or value in REVIEWED_EXECUTABLE_PATHS


def _is_unreviewed_name(value):
    return isinstance(value, str) and re.fullmatch(
        rf"{UNREVIEWED_NAME_PREFIX}[0-9a-f]{{64}}", value
    ) is not None


def _validate_schema4_metadata(
    item, expected_path, extra_fields, canonical_targets=None
):
    base_fields = {"path", "present", *extra_fields}
    metadata_fields = {
        "path_type",
        "canonical_target",
        "target_type",
        "owner_class",
        "group_class",
        "mode",
        "device",
        "inode",
        "runner_writable",
    }
    if (
        not isinstance(item, dict)
        or item.get("path") != expected_path
        or not _is_bool(item.get("present"))
        or set(item) != base_fields | (metadata_fields if item["present"] else set())
    ):
        raise ValueError("schema 4 metadata shape is invalid")
    if not item["present"]:
        return
    if canonical_targets is None:
        canonical_targets = {expected_path, UNREVIEWED_METADATA_TARGET}
    metadata_types = {
        "regular",
        "directory",
        "symlink",
        "socket",
        "character_device",
        "block_device",
        "fifo",
        "other",
    }
    canonical = item["canonical_target"]
    if (
        item["path_type"] not in metadata_types
        or item["target_type"] not in metadata_types
        or item["owner_class"] not in {"root", "runner", "other"}
        or item["group_class"]
        not in {"root", "runner_primary", "runner_member", "other"}
        or not isinstance(item["mode"], str)
        or re.fullmatch(r"[0-7]{4}", item["mode"]) is None
        or not _is_integer(item["device"])
        or not _is_integer(item["inode"])
        or not _is_optional_bool(item["runner_writable"])
        or canonical not in canonical_targets
    ):
        raise ValueError("schema 4 metadata value is invalid")


def _validate_schema4_agent(agent):
    required = {
        "name",
        "status",
        "load_state",
        "active_state",
        "sub_state",
        "unit_file_state",
        "configured_user_class",
        "control_group",
        "main_pid",
        "processes_truncated",
        "processes",
        "process_status",
        "process_owner_class",
        "process_start_time_ticks",
        "executable_basename",
        "executable_device",
        "executable_inode",
    }
    if not isinstance(agent, dict) or set(agent) != required:
        raise ValueError("schema 4 Azure platform agent shape is invalid")
    if (
        agent["name"] != "walinuxagent.service"
        or agent["status"] != "observed"
        or agent["load_state"] != "loaded"
        or agent["active_state"] != "active"
        or agent["sub_state"] != "running"
        or agent["unit_file_state"]
        not in {
            SCHEMA4_REVIEWED_UNIT_STATES["walinuxagent.service"][
                "unit_file_state"
            ],
            UNREVIEWED_UNIT_STATE,
        }
        or agent["configured_user_class"] != "root_or_default"
        or agent["control_group"] != "/azure.slice/walinuxagent.service"
        or agent["process_status"] != "observed"
        or agent["process_owner_class"] != "root"
        or agent["processes_truncated"] is not False
        or not _is_integer(agent["main_pid"], 1)
        or not _is_integer(agent["process_start_time_ticks"], 1)
        or not isinstance(agent["executable_basename"], str)
        or re.fullmatch(
            r"python3(?:\.[0-9]+)?", agent["executable_basename"]
        )
        is None
        or not _is_integer(agent["executable_device"])
        or not _is_integer(agent["executable_inode"])
    ):
        raise ValueError("schema 4 Azure platform agent state is invalid")
    processes = agent["processes"]
    if (
        not isinstance(processes, list)
        or not processes
        or len(processes) > MAX_SCHEMA4_AZURE_PROCESSES
    ):
        raise ValueError("schema 4 Azure platform process set is invalid")
    for process in processes:
        if (
            not isinstance(process, dict)
            or set(process)
            != {
                "pid",
                "owner_class",
                "start_time_ticks",
                "executable_basename",
                "executable_device",
                "executable_inode",
            }
            or process["owner_class"] != "root"
            or not _is_integer(process["pid"], 1)
            or not _is_integer(process["start_time_ticks"], 1)
            or not isinstance(process["executable_basename"], str)
            or re.fullmatch(
                r"python3(?:\.[0-9]+)?", process["executable_basename"]
            )
            is None
            or not _is_integer(process["executable_device"])
            or not _is_integer(process["executable_inode"])
        ):
            raise ValueError("schema 4 Azure platform process is invalid")
    if agent["main_pid"] not in {process["pid"] for process in processes}:
        raise ValueError("schema 4 Azure platform MainPID is missing")


def _validate_schema4_host(host):
    if not isinstance(host, dict) or set(host) != {
        "os_id",
        "os_version_id",
        "architecture",
        "runner_principal",
        "runner_groups",
    }:
        raise ValueError("schema 4 host shape is invalid")
    if (
        host["os_id"] not in {SCHEMA4_REVIEWED_OS_ID, UNREVIEWED_OS_ID}
        or host["os_version_id"]
        not in {SCHEMA4_REVIEWED_OS_VERSION_ID, UNREVIEWED_OS_VERSION_ID}
        or host["architecture"]
        not in {SCHEMA4_REVIEWED_ARCHITECTURE, UNREVIEWED_ARCHITECTURE}
        or host["runner_principal"]
        not in {SCHEMA4_REVIEWED_RUNNER_PRINCIPAL, UNREVIEWED_RUNNER_PRINCIPAL}
    ):
        raise ValueError("schema 4 host identity is invalid")
    groups = host["runner_groups"]
    if (
        not isinstance(groups, list)
        or len(groups) > 64
        or groups != sorted(set(groups))
        or not all(
            group in SCHEMA4_REVIEWED_RUNNER_GROUPS or _is_unreviewed_name(group)
            for group in groups
        )
    ):
        raise ValueError("schema 4 runner groups are invalid")


def _validate_schema4_units(units):
    if not isinstance(units, list) or [
        unit.get("name") if isinstance(unit, dict) else None for unit in units
    ] != list(SCHEMA4_FIXED_UNITS):
        raise ValueError("schema 4 systemd unit set is invalid")
    for unit in units:
        if set(unit) != {"name", "load_state", "active_state", "unit_file_state"}:
            raise ValueError("schema 4 systemd unit shape is invalid")
        reviewed = SCHEMA4_REVIEWED_UNIT_STATES[unit["name"]]
        if any(
            unit[key] not in {reviewed[key], UNREVIEWED_UNIT_STATE}
            for key in ("load_state", "active_state", "unit_file_state")
        ):
            raise ValueError("schema 4 systemd unit value is invalid")


def _validate_schema4_resolver(resolver):
    if not isinstance(resolver, dict):
        raise ValueError("schema 4 resolver shape is invalid")
    if resolver.get("status") == "unavailable":
        if set(resolver) != {"status"}:
            raise ValueError("schema 4 unavailable resolver shape is invalid")
        return
    if set(resolver) != {
        "status",
        "path",
        "is_symlink",
        "canonical_target",
        "target_type",
        "target_mode",
        "target_uid",
    } or resolver.get("status") != "observed":
        raise ValueError("schema 4 resolver shape is invalid")
    if (
        resolver["path"] != "/etc/resolv.conf"
        or not _is_bool(resolver["is_symlink"])
        or resolver["canonical_target"]
        not in {SCHEMA4_REVIEWED_RESOLVER_TARGET, UNREVIEWED_RESOLVER_TARGET}
        or resolver["target_type"] not in {"regular", "unexpected_type"}
        or not isinstance(resolver["target_mode"], str)
        or re.fullmatch(r"[0-7]{4}", resolver["target_mode"]) is None
        or not _is_integer(resolver["target_uid"])
    ):
        raise ValueError("schema 4 resolver value is invalid")


def _validate_schema4_sudo_source(source):
    common = {
        "name",
        "canonical_target",
        "target_type",
        "owner_class",
        "group_class",
        "mode",
        "device",
        "inode",
        "runner_writable",
        "path_class",
    }
    if not isinstance(source, dict) or not common.issubset(source):
        raise ValueError("schema 4 sudo source shape is invalid")
    if source["path_class"] not in {"main_policy", "drop_in"} or not (
        source["name"] in SCHEMA4_REVIEWED_SUDO_SOURCE_TARGETS
        or _is_unreviewed_name(source["name"])
    ):
        raise ValueError("schema 4 sudo source identity is invalid")
    synthetic = {
        "path": "/etc/sudoers",
        "present": True,
        "path_type": "regular",
        **{key: source[key] for key in common - {"name", "path_class"}},
    }
    _validate_schema4_metadata(
        synthetic,
        "/etc/sudoers",
        set(),
        canonical_targets={
            *SCHEMA4_REVIEWED_SUDO_SOURCE_TARGETS.values(),
            UNREVIEWED_SUDO_SOURCE_TARGET,
        },
    )
    if source["path_class"] == "main_policy":
        expected_target = SCHEMA4_REVIEWED_SUDO_SOURCE_TARGETS["sudoers"]
        if source["name"] != "sudoers" or source["canonical_target"] != expected_target:
            raise ValueError("schema 4 sudo source target is invalid")
    elif source["name"] in {
        "90-cloud-init-users",
        "README",
        "runner",
    }:
        if (
            source["canonical_target"]
            != SCHEMA4_REVIEWED_SUDO_SOURCE_TARGETS[source["name"]]
        ):
            raise ValueError("schema 4 sudo source target is invalid")
    elif source["canonical_target"] != UNREVIEWED_SUDO_SOURCE_TARGET:
        raise ValueError("schema 4 sudo source target is invalid")
    if source.get("status") == "oversized":
        if set(source) != common | {"status"}:
            raise ValueError("schema 4 oversized sudo source shape is invalid")
        return
    if set(source) != common | {
        "sha256",
        "contains_nopasswd_directive",
        "runner_nopasswd_markers",
    } or not isinstance(source["sha256"], str) or re.fullmatch(
        r"[0-9a-f]{64}", source["sha256"]
    ) is None or not _is_bool(source["contains_nopasswd_directive"]):
        raise ValueError("schema 4 sudo source value is invalid")
    markers = source["runner_nopasswd_markers"]
    if (
        not isinstance(markers, list)
        or markers != sorted(set(markers))
        or not set(markers).issubset({"principal", "group"})
    ):
        raise ValueError("schema 4 sudo source markers are invalid")


def _validate_schema4_sudo(sudo):
    if not isinstance(sudo, dict) or set(sudo) != {
        "noninteractive_root_observation_succeeded",
        "policy_source_hashes",
        "policy_sources_truncated",
        "grant_source_review_required",
    }:
        raise ValueError("schema 4 sudo shape is invalid")
    sources = sudo["policy_source_hashes"]
    if (
        sudo["noninteractive_root_observation_succeeded"] is not True
        or sudo["grant_source_review_required"] is not True
        or not _is_bool(sudo["policy_sources_truncated"])
        or not isinstance(sources, list)
        or len(sources) > MAX_SCHEMA4_POLICY_SOURCES
    ):
        raise ValueError("schema 4 sudo state is invalid")
    for source in sources:
        _validate_schema4_sudo_source(source)
    identities = [(source["path_class"], source["name"]) for source in sources]
    expected = [
        (source["path_class"], source["name"])
        for source in canonical_sudo_sources(sources)
    ]
    if identities != expected or len(identities) != len(set(identities)):
        raise ValueError("schema 4 sudo source set is not canonical")


def _validate_schema4_container_socket(socket, path):
    if not isinstance(socket, dict) or socket.get("path") != path or not _is_bool(
        socket.get("present")
    ):
        raise ValueError("schema 4 container socket identity is invalid")
    if not socket["present"]:
        if set(socket) != {"path", "present"}:
            raise ValueError("schema 4 absent container socket shape is invalid")
        return
    if set(socket) != {"path", "present", "type", "mode", "owner", "group"}:
        raise ValueError("schema 4 container socket shape is invalid")
    if (
        socket["type"] not in {"socket", "unexpected_type"}
        or not isinstance(socket["mode"], str)
        or re.fullmatch(r"[0-7]{4}", socket["mode"]) is None
        or socket["owner"]
        not in {
            SCHEMA4_REVIEWED_SOCKET_IDENTITIES[path]["owner"],
            UNREVIEWED_SOCKET_OWNER,
        }
        or socket["group"]
        not in {
            SCHEMA4_REVIEWED_SOCKET_IDENTITIES[path]["group"],
            UNREVIEWED_SOCKET_GROUP,
        }
    ):
        raise ValueError("schema 4 container socket value is invalid")


def _validate_schema4_container_runtime(runtime):
    if not isinstance(runtime, dict) or set(runtime) != {
        "sockets",
        "docker_running_workload_count",
    }:
        raise ValueError("schema 4 container runtime shape is invalid")
    sockets = runtime["sockets"]
    if not isinstance(sockets, list) or [
        socket.get("path") if isinstance(socket, dict) else None for socket in sockets
    ] != list(SCHEMA4_FIXED_SOCKETS):
        raise ValueError("schema 4 container socket set is invalid")
    for socket, path in zip(sockets, SCHEMA4_FIXED_SOCKETS):
        _validate_schema4_container_socket(socket, path)
    count = runtime["docker_running_workload_count"]
    if count is not None and not _is_integer(count):
        raise ValueError("schema 4 Docker workload count is invalid")


def validate_schema4_observation(observation):
    if not isinstance(observation, dict) or set(observation) != SCHEMA4_TOP_LEVEL_FIELDS:
        raise ValueError("schema 4 observation shape is invalid")
    expected_values = {
        "schema_version": 4,
        "observation": "hosted_runner_fingerprint_candidate",
        "status": "observation_only_no_protection",
        "protected_target": "github_hosted_ubuntu_24_04_x86_64",
        "next_step": "review_closed_host_invariants_before_any_enforcement_change",
    }
    if any(observation[key] != value for key, value in expected_values.items()):
        raise ValueError("schema 4 observation identity is invalid")
    _validate_schema4_host(observation["host"])
    systemd = observation["systemd"]
    if not isinstance(systemd, dict) or set(systemd) != {
        "units",
        "azure_platform_agent",
    }:
        raise ValueError("schema 4 systemd shape is invalid")
    _validate_schema4_units(systemd["units"])
    _validate_schema4_agent(systemd["azure_platform_agent"])
    _validate_schema4_resolver(observation["resolver"])
    _validate_schema4_sudo(observation["sudo"])
    _validate_schema4_container_runtime(observation["container_runtime"])

    required_paths = observation["required_paths"]
    if not isinstance(required_paths, list) or [
        item.get("path") if isinstance(item, dict) else None for item in required_paths
    ] != list(SCHEMA4_REQUIRED_PATHS):
        raise ValueError("schema 4 required path set is invalid")
    for item, path in zip(required_paths, SCHEMA4_REQUIRED_PATHS):
        _validate_schema4_metadata(item, path, {"executable", "runner_executable"})
        if not _is_bool(item["executable"]) or not _is_optional_bool(
            item["runner_executable"]
        ):
            raise ValueError("schema 4 executable state is invalid")
        if not item["present"] and (
            item["executable"] is not False
            or item["runner_executable"] is not False
        ):
            raise ValueError("schema 4 absent executable state is invalid")

    ancestors = observation["permission_ancestor_directories"]
    if not isinstance(ancestors, list) or [
        item.get("path") if isinstance(item, dict) else None for item in ancestors
    ] != list(SCHEMA4_ANCESTOR_DIRECTORIES):
        raise ValueError("schema 4 ancestor path set is invalid")
    for item, path in zip(ancestors, SCHEMA4_ANCESTOR_DIRECTORIES):
        _validate_schema4_metadata(
            item, path, {"runner_searchable", "synthetic_create_delete_probe"}
        )
        if not _is_optional_bool(item["runner_searchable"]) or item[
            "synthetic_create_delete_probe"
        ] not in SCHEMA4_PROBE_RESULTS:
            raise ValueError("schema 4 ancestor permission state is invalid")
        if not item["present"] and (
            item["runner_searchable"] is not False
            or item["synthetic_create_delete_probe"] != "unavailable"
        ):
            raise ValueError("schema 4 absent ancestor state is invalid")

    validate_local_control_inventory(observation["local_control_inventory"])
    encoded = json.dumps(observation, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_SCHEMA4_OUTPUT_BYTES:
        raise ValueError("schema 4 observation exceeds its output bound")
    return observation


def _validate_owner(owner):
    expected = {
        "uid",
        "executable_basename",
        "canonical_executable",
        "unified_cgroup",
        "processes",
    }
    if not isinstance(owner, dict) or set(owner) != expected or owner["uid"] != 0:
        raise ValueError("local control owner identity is invalid")
    if not isinstance(owner["executable_basename"], str) or not re.fullmatch(
        r"(?:[A-Za-z0-9._+-]{1,128}|unreportable)",
        owner["executable_basename"],
    ):
        raise ValueError("local control owner basename is invalid")
    executable = owner["canonical_executable"]
    if not _reviewed_reported_path(executable):
        raise ValueError("local control owner executable is invalid")
    if owner["unified_cgroup"] not in REVIEWED_CGROUPS:
        raise ValueError("local control owner cgroup is invalid")
    if (
        not _is_integer(owner["processes"], 1)
        or owner["processes"] > MAX_PROCESSES
    ):
        raise ValueError("local control owner process state is invalid")


def _validate_owner_list(owners):
    if not isinstance(owners, list) or len(owners) > MAX_SOCKET_OWNERS:
        raise ValueError("local control owner set is invalid")
    for owner in owners:
        _validate_owner(owner)
    if sum(owner["processes"] for owner in owners) > MAX_PROCESSES:
        raise ValueError("local control owner process count exceeded its bound")
    if owners != sorted(owners, key=_owner_sort_key):
        raise ValueError("local control owner set is not canonical")
    identities = [
        (
            owner["uid"],
            owner["executable_basename"],
            owner["canonical_executable"],
            owner["unified_cgroup"],
        )
        for owner in owners
    ]
    if len(identities) != len(set(identities)):
        raise ValueError("local control owner identity is duplicated")


def _validate_reason_list(value, allowed, label):
    if (
        not isinstance(value, list)
        or value != sorted(set(value))
        or not set(value).issubset(allowed)
    ):
        raise ValueError(f"local control {label} set is invalid")


def _validate_public_snapshot(snapshot):
    expected_fields = {
        "scan_status",
        "bounds_exceeded",
        "unavailable_inputs",
        "malformed_row_count",
        "unresolved_unix_listener_count",
        "inaccessible_root_filesystem_listener_count",
        "reachability_complete",
        "ownership_complete",
        "root_container_processes",
        "unix_listeners",
        "tcp_listeners",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != expected_fields:
        raise ValueError("local control inventory snapshot shape is invalid")
    for key in (
        "malformed_row_count",
        "unresolved_unix_listener_count",
        "inaccessible_root_filesystem_listener_count",
    ):
        if (
            not _is_integer(snapshot[key])
            or snapshot[key] > PUBLIC_COUNTER_MAXIMUMS[key]
        ):
            raise ValueError("local control inventory counter is invalid")
    _validate_reason_list(snapshot["bounds_exceeded"], BOUND_REASONS, "bound")
    _validate_reason_list(
        snapshot["unavailable_inputs"],
        ACQUISITION_UNAVAILABLE_REASONS | DERIVED_UNAVAILABLE_REASONS,
        "unavailable input",
    )
    if not _is_bool(snapshot["reachability_complete"]) or not _is_bool(
        snapshot["ownership_complete"]
    ):
        raise ValueError("local control inventory completeness state is invalid")

    containers = snapshot["root_container_processes"]
    if not isinstance(containers, list):
        raise ValueError("local control container process set is invalid")
    container_keys = []
    for process in containers:
        if not isinstance(process, dict) or set(process) != {
            "uid",
            "executable_basename",
            "canonical_executable",
            "unified_cgroup",
            "instances",
        }:
            raise ValueError("local control container process shape is invalid")
        _validate_owner(
            {
                "uid": process["uid"],
                "executable_basename": process["executable_basename"],
                "canonical_executable": process["canonical_executable"],
                "unified_cgroup": process["unified_cgroup"],
                "processes": process["instances"],
            }
        )
        if process["executable_basename"] not in {"containerd", "dockerd"}:
            raise ValueError("local control container process name is invalid")
        container_keys.append(
            (
                process["uid"],
                process["executable_basename"],
                process["canonical_executable"],
                process["unified_cgroup"],
            )
        )
    if (
        sum(process["instances"] for process in containers)
        > MAX_CONTAINER_PROCESSES
        or len(container_keys) != len(set(container_keys))
        or containers
        != sorted(
            containers,
            key=lambda item: (
                item["executable_basename"],
                item["canonical_executable"],
                item["unified_cgroup"],
                item["instances"],
            ),
        )
    ):
        raise ValueError("local control container process set is not canonical")

    unix_listeners = snapshot["unix_listeners"]
    tcp_listeners = snapshot["tcp_listeners"]
    if not isinstance(unix_listeners, list) or not isinstance(tcp_listeners, list):
        raise ValueError("local control listener set is invalid")
    unix_keys = []
    for listener in unix_listeners:
        if not isinstance(listener, dict) or set(listener) != {
            "socket_type",
            "name_kind",
            "name_sha256",
            "runner_reachable",
            "owners",
            "ownership_complete",
            "instances",
        }:
            raise ValueError("local control Unix listener shape is invalid")
        if (
            listener["socket_type"] not in {"stream", "seqpacket"}
            or listener["name_kind"] not in {"abstract", "filesystem"}
            or listener["runner_reachable"] is not True
            or not isinstance(listener["name_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", listener["name_sha256"]) is None
            or not _is_bool(listener["ownership_complete"])
            or not _is_integer(listener["instances"], 1)
        ):
            raise ValueError("local control Unix listener value is invalid")
        _validate_owner_list(listener["owners"])
        if listener["ownership_complete"] and not listener["owners"]:
            raise ValueError("local control Unix listener ownership is invalid")
        unix_keys.append(
            (
                listener["socket_type"],
                listener["name_kind"],
                listener["name_sha256"],
                listener["runner_reachable"],
                listener["ownership_complete"],
                _owners_key(listener["owners"]),
            )
        )
    if (
        sum(listener["instances"] for listener in unix_listeners)
        > MAX_UNIX_LISTENERS
        or len(unix_keys) != len(set(unix_keys))
        or unix_listeners != sorted(unix_listeners, key=_unix_listener_sort_key)
    ):
        raise ValueError("local control Unix listener set is not canonical")

    tcp_keys = []
    for listener in tcp_listeners:
        if not isinstance(listener, dict) or set(listener) != {
            "family",
            "bind_class",
            "port",
            "owners",
            "ownership_complete",
            "instances",
        }:
            raise ValueError("local control TCP listener shape is invalid")
        if (
            listener["family"] not in {"ipv4", "ipv6"}
            or listener["bind_class"]
            not in {"wildcard", "loopback", "other_local"}
            or not _is_integer(listener["port"])
            or listener["port"] > 65535
            or not _is_bool(listener["ownership_complete"])
            or not _is_integer(listener["instances"], 1)
        ):
            raise ValueError("local control TCP listener value is invalid")
        _validate_owner_list(listener["owners"])
        if listener["ownership_complete"] and not listener["owners"]:
            raise ValueError("local control TCP listener ownership is invalid")
        tcp_keys.append(
            (
                listener["family"],
                listener["bind_class"],
                listener["port"],
                listener["ownership_complete"],
                _owners_key(listener["owners"]),
            )
        )
    if (
        sum(listener["instances"] for listener in tcp_listeners)
        > MAX_TCP_LISTENERS
        or len(tcp_keys) != len(set(tcp_keys))
        or tcp_listeners != sorted(tcp_listeners, key=_tcp_listener_sort_key)
    ):
        raise ValueError("local control TCP listener set is not canonical")

    base_unavailable = [
        reason
        for reason in snapshot["unavailable_inputs"]
        if reason not in DERIVED_UNAVAILABLE_REASONS
    ]
    payload = {
        key: value
        for key, value in snapshot.items()
        if key not in {"scan_status", "reachability_complete", "ownership_complete"}
    }
    payload["unavailable_inputs"] = base_unavailable
    if _summarize_public_snapshot(payload) != snapshot:
        raise ValueError("local control inventory summary is inconsistent")


def validate_local_control_inventory(inventory):
    if not isinstance(inventory, dict):
        raise ValueError("local control inventory is missing")
    if set(inventory) != {
        "status",
        "stable",
        "attempts",
        "interval_milliseconds",
        "limits",
        "snapshot",
    }:
        raise ValueError("local control inventory shape is invalid")
    if inventory.get("status") not in {
        "stable",
        "unstable",
        "bounds_exceeded",
        "unavailable",
    }:
        raise ValueError("local control inventory status is invalid")
    if not _is_bool(inventory.get("stable")):
        raise ValueError("local control inventory stability is invalid")
    if not _is_integer(inventory.get("attempts"), 1) or inventory["attempts"] > 3:
        raise ValueError("local control inventory attempts are invalid")
    if inventory.get("interval_milliseconds") != 50:
        raise ValueError("local control inventory interval is invalid")
    if inventory.get("limits") != observation_limits():
        raise ValueError("local control inventory limits are invalid")
    snapshot = inventory.get("snapshot")
    _validate_public_snapshot(snapshot)
    scan_status = snapshot.get("scan_status")
    expected_status = {
        "within_bounds": "stable",
        "bounds_exceeded": "bounds_exceeded",
        "unavailable": "unavailable",
    }
    if scan_status not in expected_status:
        raise ValueError("local control inventory scan status is invalid")
    if inventory["stable"]:
        if expected_status.get(scan_status) != inventory["status"]:
            raise ValueError("local control inventory status is inconsistent")
    elif inventory["status"] != "unstable" or inventory["attempts"] != 3:
        raise ValueError("local control inventory unstable status is inconsistent")
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_INVENTORY_BYTES:
        raise ValueError("local control inventory exceeds its output bound")
    return inventory


class HostObservationTests(unittest.TestCase):
    @staticmethod
    def _tcp_header():
        return (" ".join(TCP_TABLE_HEADER) + "\n").encode()

    @staticmethod
    def _private_owner(pin=(10, 100, 1, 2)):
        return {
            "uid": 0,
            "executable_basename": "rootd",
            "canonical_executable": UNREVIEWED_EXECUTABLE_PATH,
            "unified_cgroup": "/init.scope",
            "_process_pins": [pin],
            "processes": 1,
        }

    @staticmethod
    def _private_snapshot(**updates):
        snapshot = {
            "_bounds_exceeded": [],
            "_unavailable_inputs": [],
            "malformed_row_count": 0,
            "unresolved_unix_listener_count": 0,
            "inaccessible_root_filesystem_listener_count": 0,
            "root_container_processes": [],
            "unix_listeners": [],
            "tcp_listeners": [],
        }
        snapshot.update(updates)
        return snapshot

    def _collect_tcp(self, scan, socket_uid=0):
        tcp = self._tcp_header() + (
            "0: 0100007F:1F90 00000000:0000 0A "
            "00000000:00000000 00:00000000 00000000 "
            f"{socket_uid} 0 42\n"
        ).encode()
        unix = b"Num RefCount Protocol Flags Type St Inode Path\n"

        def bounded_read(path, _maximum):
            name = pathlib.Path(path).name
            if name == "tcp":
                return tcp
            if name == "tcp6":
                return self._tcp_header()
            return unix

        with mock.patch.object(
            os.sys.modules[__name__], "_scan_process_owners", return_value=scan
        ), mock.patch.object(
            os.sys.modules[__name__], "_bounded_read", side_effect=bounded_read
        ):
            return _collect_snapshot(pathlib.Path("/proc"))

    @staticmethod
    def _process_observation_fixture(start=100, device=1, inode=2):
        return {
            "uid": 0,
            "start_time_ticks": start,
            "executable_device": device,
            "executable_inode": inode,
            "executable_basename": "rootd",
            "canonical_executable": UNREVIEWED_EXECUTABLE_PATH,
        }

    def test_unix_names_and_header_are_bounded(self):
        contents = (
            b"Num RefCount Protocol Flags Type St Inode Path\n"
            b"0: 2 0 00010000 0001 01 42 /run/example.sock\n"
            b"1: 2 0 00010000 0005 01 43 @example\n"
            b"2: 2 0 00000000 0002 01 44 ignored\n"
        )
        rows, malformed = parse_unix_table(contents)
        self.assertEqual(malformed, 0)
        self.assertEqual([row["socket_type"] for row in rows], ["stream", "seqpacket"])
        self.assertEqual([row["name_kind"] for row in rows], ["filesystem", "abstract"])
        self.assertNotIn(b"/run/example.sock", repr(_reported_unix_listener(rows[0], [], False)).encode())
        with self.assertRaises(ValueError):
            parse_unix_table(contents.split(b"\n", 1)[1])
        _, malformed = parse_unix_table(
            contents.splitlines()[0] + b"\n0: incomplete\n"
        )
        self.assertEqual(malformed, 1)
        _, malformed = parse_unix_table(
            contents.splitlines()[0]
            + b"\n3: invalid-refcount 0 00010000 0001 01 45 @ignored\n"
        )
        self.assertEqual(malformed, 1)

    def test_tcp_parser_validates_header_rows_and_socket_uid(self):
        table = self._tcp_header() + (
            b"0: 0100007F:1F90 00000000:0000 0A "
            b"00000000:00000000 00:00000000 00000000 1001 0 42\n"
            b"1: truncated 0 0A\n"
            b"2: malformed 00000000:0000 01 "
            b"00000000:00000000 00:00000000 00000000 1001 0 43\n"
            b"3: 0100007F:1F91 invalid-remote 0A "
            b"00000000:00000000 00:00000000 00000000 1001 0 44\n"
            b"4: 0100007F:1F92 00000000:0000 0A "
            b"invalid-queue 00:00000000 00000000 1001 0 45\n"
            b"BAD: 0100007F:1F93 00000000:0000 0A "
            b"00000000:00000000 00:00000000 00000000 1001 0 46\n"
        )
        rows, malformed = parse_tcp_table(table, "ipv4")
        self.assertEqual(malformed, 5)
        self.assertEqual(
            rows,
            [
                {
                    "family": "ipv4",
                    "bind_class": "loopback",
                    "port": 8080,
                    "inode": 42,
                    "socket_uid": 1001,
                }
            ],
        )
        with self.assertRaises(ValueError):
            parse_tcp_table(table.split(b"\n", 1)[1], "ipv4")
        ipv6, malformed = parse_tcp_table(
            self._tcp_header()
            + b"0: 00000000000000000000000000000000:01BB "
            + b"00000000000000000000000000000000:0000 0A "
            + b"00000000:00000000 00:00000000 00000000 0 0 43\n",
            "ipv6",
        )
        self.assertEqual(malformed, 0)
        self.assertEqual((ipv6[0]["bind_class"], ipv6[0]["port"]), ("wildcard", 443))

    def test_tcp_root_inclusion_and_owner_completeness(self):
        owner = self._private_owner()
        base_scan = ({42: {("rootd",): owner}}, set(), set(), [], set(), set(), 1, 1)
        public = _public_snapshot(self._collect_tcp(base_scan, socket_uid=1001))
        self.assertEqual(public["scan_status"], "within_bounds")
        self.assertTrue(public["tcp_listeners"][0]["ownership_complete"])

        nonroot_only = ({}, {42}, set(), [], set(), set(), 1, 1)
        self.assertEqual(
            _public_snapshot(self._collect_tcp(nonroot_only, socket_uid=1001))[
                "tcp_listeners"
            ],
            [],
        )

        for nonroot, unresolved in (({42}, set()), (set(), {42})):
            scan = ({42: {("rootd",): owner}}, nonroot, unresolved, [], set(), set(), 2, 2)
            public = _public_snapshot(self._collect_tcp(scan))
            self.assertEqual(public["scan_status"], "unavailable")
            self.assertFalse(public["tcp_listeners"][0]["ownership_complete"])
            self.assertIn("socket_ownership", public["unavailable_inputs"])

        root_uid_without_owner = ({}, set(), set(), [], set(), set(), 1, 1)
        public = _public_snapshot(self._collect_tcp(root_uid_without_owner))
        self.assertEqual(len(public["tcp_listeners"]), 1)
        self.assertFalse(public["tcp_listeners"][0]["ownership_complete"])

    def test_process_scan_rechecks_identity_and_exposes_persistent_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = pathlib.Path(directory)
            process_root = proc_root / "123"
            descriptors = process_root / "fd"
            descriptors.mkdir(parents=True)
            (process_root / "cgroup").write_text("0::/init.scope\n", encoding="utf-8")
            (descriptors / "3").symlink_to("socket:[42]")
            before = self._process_observation_fixture()
            after = self._process_observation_fixture(start=101)
            with mock.patch.object(
                os.sys.modules[__name__],
                "_process_observation",
                side_effect=[before, after],
            ):
                result = _scan_process_owners(proc_root)
            self.assertIn("process_identity_drift", result[5])
            self.assertEqual(result[2], {42})

            real_scandir = os.scandir

            def failed_fd_scan(path):
                if pathlib.Path(path).name == "fd":
                    raise PermissionError("denied")
                return real_scandir(path)

            with mock.patch.object(
                os.sys.modules[__name__],
                "_process_observation",
                return_value=before,
            ), mock.patch.object(os, "scandir", side_effect=failed_fd_scan):
                result = _scan_process_owners(proc_root)
            self.assertIn("process_fd_scan", result[5])

            with mock.patch.object(
                os.sys.modules[__name__],
                "_process_observation",
                side_effect=[before, before],
            ), mock.patch.object(os, "readlink", side_effect=PermissionError("denied")):
                result = _scan_process_owners(proc_root)
            self.assertIn("process_fd_readlink", result[5])

            (process_root / "cgroup").write_text(
                "0::/system.slice/unreviewed.service\n", encoding="utf-8"
            )
            with mock.patch.object(
                os.sys.modules[__name__],
                "_process_observation",
                side_effect=[before, before],
            ):
                result = _scan_process_owners(proc_root)
            self.assertIn("cgroup_identity", result[5])
            self.assertEqual(result[2], {42})

    def test_process_identity_uses_the_proc_executable_object_without_resolving_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            process_root = root / "123"
            process_root.mkdir()
            executable = root / "rootd"
            executable.write_bytes(b"executable")
            (process_root / "exe").symlink_to(executable)
            (process_root / "stat").write_text(
                "123 (rootd) S " + " ".join(str(value) for value in range(1, 20)),
                encoding="utf-8",
            )
            with mock.patch.object(
                pathlib.Path,
                "resolve",
                side_effect=AssertionError("process executable path was re-resolved"),
            ):
                observation = _process_observation(process_root)
            metadata = executable.stat()
            self.assertEqual(observation["start_time_ticks"], 19)
            self.assertEqual(observation["executable_device"], metadata.st_dev)
            self.assertEqual(observation["executable_inode"], metadata.st_ino)
            self.assertEqual(
                observation["canonical_executable"],
                UNREVIEWED_EXECUTABLE_PATH,
            )
            self.assertEqual(
                _reviewed_executable_path(pathlib.Path("/usr/bin/dockerd")),
                "/usr/bin/dockerd",
            )
            self.assertEqual(
                _reviewed_executable_path(
                    pathlib.Path("/usr/bin/arbitrary-host-specific-daemon")
                ),
                UNREVIEWED_EXECUTABLE_PATH,
            )
            self.assertEqual(
                _reviewed_executable_path(
                    pathlib.Path("/usr/bin/") / f"unreportable-{chr(0xDCFF)}"
                ),
                UNREVIEWED_EXECUTABLE_PATH,
            )
            self.assertFalse(
                _reviewed_reported_path("/usr/bin/arbitrary-host-specific-daemon")
            )

    def test_public_host_strings_are_reviewed_or_reduced(self):
        self.assertEqual(public_runner_group_name("docker"), "docker")
        private_group = public_runner_group_name("private-project-group")
        self.assertTrue(_is_unreviewed_name(private_group))
        self.assertNotIn("private-project", private_group)

        self.assertEqual(public_sudo_source_name("runner"), "runner")
        private_source = public_sudo_source_name("private-project-policy")
        self.assertTrue(_is_unreviewed_name(private_source))
        self.assertNotIn("private-project", private_source)
        ordered_sources = canonical_sudo_sources(
            [
                {"path_class": "drop_in", "name": private_source},
                {"path_class": "drop_in", "name": "runner"},
                {"path_class": "main_policy", "name": "sudoers"},
            ]
        )
        self.assertEqual(
            [(source["path_class"], source["name"]) for source in ordered_sources],
            [
                ("main_policy", "sudoers"),
                ("drop_in", "runner"),
                ("drop_in", private_source),
            ],
        )

        self.assertEqual(
            public_fixed_canonical_target(
                pathlib.Path("/usr/bin/docker"), "/usr/bin/docker"
            ),
            "/usr/bin/docker",
        )
        self.assertEqual(
            public_fixed_canonical_target(
                pathlib.Path("/usr/bin/private-project-helper"),
                "/usr/bin/docker",
            ),
            UNREVIEWED_METADATA_TARGET,
        )
        self.assertEqual(
            public_resolver_target(pathlib.Path("/run/private-project/resolv.conf")),
            UNREVIEWED_RESOLVER_TARGET,
        )
        self.assertEqual(
            public_sudo_source_target(
                pathlib.Path("/etc/sudoers.d/private-project-policy")
            ),
            UNREVIEWED_SUDO_SOURCE_TARGET,
        )
        self.assertEqual(
            public_unit_state("docker.service", "load_state", "private-state"),
            UNREVIEWED_UNIT_STATE,
        )
        self.assertEqual(
            public_socket_identity(
                "/run/docker.sock", "owner", "private-project-account"
            ),
            UNREVIEWED_SOCKET_OWNER,
        )
    def test_process_disappearance_is_discarded_without_unavailable_state(self):
        with tempfile.TemporaryDirectory() as directory:
            proc_root = pathlib.Path(directory)
            (proc_root / "123" / "fd").mkdir(parents=True)
            before = self._process_observation_fixture()
            real_scandir = os.scandir

            def disappeared(path):
                if pathlib.Path(path).name == "fd":
                    raise FileNotFoundError("gone")
                return real_scandir(path)

            with mock.patch.object(
                os.sys.modules[__name__],
                "_process_observation",
                return_value=before,
            ), mock.patch.object(os, "scandir", side_effect=disappeared):
                result = _scan_process_owners(proc_root)
            self.assertEqual(result[5], set())

            with mock.patch.object(
                os.sys.modules[__name__],
                "_process_observation",
                side_effect=[before, FileNotFoundError("gone")],
            ):
                result = _scan_process_owners(proc_root)
            self.assertEqual(result[5], set())

    def test_private_identity_controls_stability_but_is_never_public(self):
        first_owner = self._private_owner(pin=(10, 100, 1, 2))
        stable_owner = self._private_owner(pin=(11, 101, 1, 2))
        first = self._private_snapshot(
            root_container_processes=[
                {
                    "uid": 0,
                    "executable_basename": "dockerd",
                    "canonical_executable": "/usr/bin/dockerd",
                    "unified_cgroup": "/system.slice/docker.service",
                    "_process_pin": pin,
                }
                for pin in ((18, 198, 3, 4), (19, 199, 3, 4))
            ],
            tcp_listeners=[
                {
                    "_socket_inode": inode,
                    "_socket_uid": 0,
                    "family": "ipv4",
                    "bind_class": "loopback",
                    "port": 8080,
                    "owners": [first_owner],
                    "ownership_complete": True,
                }
                for inode in (40, 41)
            ]
        )
        stable = self._private_snapshot(
            root_container_processes=[
                {
                    "uid": 0,
                    "executable_basename": "dockerd",
                    "canonical_executable": "/usr/bin/dockerd",
                    "unified_cgroup": "/system.slice/docker.service",
                    "_process_pin": (20, 200, 3, 4),
                },
                {
                    "uid": 0,
                    "executable_basename": "dockerd",
                    "canonical_executable": "/usr/bin/dockerd",
                    "unified_cgroup": "/system.slice/docker.service",
                    "_process_pin": (21, 201, 3, 4),
                },
            ],
            tcp_listeners=[
                {
                    "_socket_inode": inode,
                    "_socket_uid": 0,
                    "family": "ipv4",
                    "bind_class": "loopback",
                    "port": 8080,
                    "owners": [stable_owner],
                    "ownership_complete": True,
                }
                for inode in (42, 43)
            ],
        )
        self.assertEqual(_public_snapshot(first), _public_snapshot(stable))
        values = iter([first, stable, stable, stable])
        inventory = observe_local_control_inventory(
            sample=lambda: next(values), sleeper=lambda _: None
        )
        self.assertEqual(inventory["attempts"], 2)
        self.assertEqual(inventory["snapshot"]["tcp_listeners"][0]["instances"], 2)
        self.assertEqual(
            inventory["snapshot"]["root_container_processes"][0]["instances"], 2
        )
        encoded = json.dumps(inventory, sort_keys=True)
        for forbidden in (
            "_socket_inode",
            "_socket_uid",
            "_process_pin",
            "start_time_ticks",
            "executable_device",
            "executable_inode",
            "current_fence_process",
        ):
            self.assertNotIn(forbidden, encoded)
        validate_local_control_inventory(inventory)

    def test_summary_multiplicity_and_raw_fields_fail_closed(self):
        owner = self._private_owner()
        private = self._private_snapshot(
            root_container_processes=[
                {
                    "uid": 0,
                    "executable_basename": "dockerd",
                    "canonical_executable": "/usr/bin/dockerd",
                    "unified_cgroup": "/system.slice/docker.service",
                    "_process_pin": (20, 200, 3, 4),
                }
            ],
            tcp_listeners=[
                {
                    "_socket_inode": 42,
                    "_socket_uid": 0,
                    "family": "ipv4",
                    "bind_class": "loopback",
                    "port": 8080,
                    "owners": [owner],
                    "ownership_complete": True,
                }
            ],
        )
        inventory = observe_local_control_inventory(
            sample=lambda: private, sleeper=lambda _: None
        )
        validate_local_control_inventory(inventory)
        mutations = {
            "derived summary": lambda value: value["snapshot"].__setitem__(
                "ownership_complete", False
            ),
            "private socket identity": lambda value: value["snapshot"].__setitem__(
                "_socket_inode", 42
            ),
            "unknown bound reason": lambda value: value["snapshot"][
                "bounds_exceeded"
            ].append("unknown"),
            "zero multiplicity": lambda value: value["snapshot"][
                "root_container_processes"
            ][0].__setitem__("instances", 0),
            "owner process count above bound": lambda value: value["snapshot"][
                "tcp_listeners"
            ][0]["owners"][0].__setitem__("processes", MAX_PROCESSES + 1),
            "public counter above input bound": lambda value: value[
                "snapshot"
            ].__setitem__(
                "inaccessible_root_filesystem_listener_count",
                MAX_PROC_NET_TABLE_BYTES + 1,
            ),
            "duplicate public identity": lambda value: value["snapshot"][
                "tcp_listeners"
            ].append(dict(value["snapshot"]["tcp_listeners"][0])),
            "unreviewed cgroup": lambda value: value["snapshot"]["tcp_listeners"][
                0
            ]["owners"][0].__setitem__(
                "unified_cgroup", "/system.slice/unreviewed.service"
            ),
            "non-normalized executable": lambda value: value["snapshot"][
                "tcp_listeners"
            ][0]["owners"][0].__setitem__(
                "canonical_executable", "/usr/bin/../../private/rootd"
            ),
            "unreviewed absolute executable": lambda value: value["snapshot"][
                "tcp_listeners"
            ][0]["owners"][0].__setitem__(
                "canonical_executable", "/usr/bin/arbitrary-host-specific-daemon"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                candidate = json.loads(json.dumps(inventory))
                mutate(candidate)
                with self.assertRaises(ValueError):
                    validate_local_control_inventory(candidate)

    def test_bounded_helpers_cap_output_entries_lines_and_children(self):
        self.assertEqual(
            bounded_command_output(["/usr/bin/printf", "1234"], maximum=4),
            "1234",
        )
        self.assertIsNone(
            bounded_command_output(["/usr/bin/printf", "12345"], maximum=4)
        )
        self.assertIsNone(
            bounded_command_output(
                [os.sys.executable, "-c", "import time; time.sleep(1)"],
                timeout=0.01,
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            descendant_started = root / "descendant-started"
            descendant_survived = root / "descendant-survived"
            fork_descendant = """
import os
import pathlib
import sys
import time

started = pathlib.Path(sys.argv[1])
survived = pathlib.Path(sys.argv[2])
child = os.fork()
if child == 0:
    started.write_text(str(time.monotonic()), encoding="utf-8")
    time.sleep(0.5)
    survived.write_text("survived", encoding="utf-8")
    os._exit(0)
deadline = time.monotonic() + 1
while not started.exists() and time.monotonic() < deadline:
    time.sleep(0.005)
os._exit(0 if started.exists() else 2)
"""
            self.assertIsNone(
                bounded_command_output(
                    [
                        os.sys.executable,
                        "-c",
                        fork_descendant,
                        str(descendant_started),
                        str(descendant_survived),
                    ],
                    timeout=0.5,
                )
            )
            self.assertTrue(descendant_started.is_file())
            descendant_deadline = (
                float(descendant_started.read_text(encoding="utf-8")) + 0.7
            )
            time.sleep(max(0, descendant_deadline - time.monotonic()))
            self.assertFalse(descendant_survived.exists())

            successful_started = root / "successful-descendant-started"
            successful_survived = root / "successful-descendant-survived"
            successful_parent = """
import os
import pathlib
import sys
import time

started = pathlib.Path(sys.argv[1])
survived = pathlib.Path(sys.argv[2])
child = os.fork()
if child == 0:
    os.close(1)
    started.write_text(str(time.monotonic()), encoding="utf-8")
    time.sleep(0.5)
    survived.write_text("survived", encoding="utf-8")
    os._exit(0)
deadline = time.monotonic() + 1
while not started.exists() and time.monotonic() < deadline:
    time.sleep(0.005)
os._exit(0 if started.exists() else 2)
"""
            self.assertEqual(
                bounded_command_output(
                    [
                        os.sys.executable,
                        "-c",
                        successful_parent,
                        str(successful_started),
                        str(successful_survived),
                    ],
                    timeout=1,
                ),
                "",
            )
            self.assertTrue(successful_started.is_file())
            successful_deadline = (
                float(successful_started.read_text(encoding="utf-8")) + 0.7
            )
            time.sleep(max(0, successful_deadline - time.monotonic()))
            self.assertFalse(successful_survived.exists())

            (root / "a").touch()
            (root / "b").mkdir()
            (root / "c").symlink_to(root / "a")
            entries, truncated = bounded_directory_entries(root, 2)
            self.assertEqual(len(entries), 2)
            self.assertTrue(truncated)
            lines = root / "lines"
            lines.write_text("1\n2\n3\n", encoding="utf-8")
            retained, truncated = bounded_file_lines(lines, 32, 2)
            self.assertEqual(retained, ["1", "2"])
            self.assertTrue(truncated)
        pid = os.fork()
        if pid == 0:
            time.sleep(1)
            os._exit(0)
        self.assertIsNone(bounded_waitpid(pid, timeout=0.01))

    def test_bounded_command_cleanup_fails_closed(self):
        def fake_process(wait_result):
            read_descriptor, write_descriptor = os.pipe()
            os.write(write_descriptor, b"x")
            os.close(write_descriptor)
            process = mock.Mock()
            process.pid = 123
            process.stdout = os.fdopen(read_descriptor, "rb")
            if isinstance(wait_result, BaseException):
                process.wait.side_effect = wait_result
            else:
                process.wait.return_value = wait_result
            return process

        process = fake_process(subprocess.TimeoutExpired("fake", 1))
        with mock.patch.object(subprocess, "Popen", return_value=process), mock.patch.object(
            os, "killpg"
        ):
            with self.assertRaisesRegex(RuntimeError, "bounded command cleanup failed"):
                bounded_command_output(["fake"], maximum=0)

        process = fake_process(0)
        with mock.patch.object(subprocess, "Popen", return_value=process), mock.patch.object(
            os, "killpg", side_effect=PermissionError("denied")
        ):
            with self.assertRaisesRegex(RuntimeError, "bounded command cleanup failed"):
                bounded_command_output(["fake"], maximum=0)

    def test_bounded_waitpid_post_kill_reap_stays_bounded(self):
        with mock.patch.object(
            os, "waitpid", return_value=(0, 0)
        ) as waitpid, mock.patch.object(os, "kill") as kill, mock.patch.object(
            time, "monotonic", side_effect=[0, 2, 2, 4]
        ), mock.patch.object(time, "sleep"):
            self.assertIsNone(bounded_waitpid(123, timeout=1))
        self.assertEqual(
            waitpid.call_args_list,
            [mock.call(123, os.WNOHANG), mock.call(123, os.WNOHANG)],
        )
        kill.assert_called_once_with(123, signal.SIGKILL)

    def test_filesystem_socket_reachability_uses_runner_access(self):
        metadata = mock.Mock(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
        with mock.patch.object(os, "stat", return_value=metadata):
            self.assertEqual(
                _filesystem_socket_state(
                    b"/run/example.sock", lambda path: path == b"/run/example.sock"
                ),
                ("root", "reachable"),
            )
            self.assertEqual(
                _filesystem_socket_state(b"/run/example.sock", lambda _: False),
                ("root", "unreachable"),
            )


def main(arguments):
    if arguments == ["--self-test"]:
        program = unittest.main(argv=[__file__], exit=False)
        return 0 if program.result.wasSuccessful() else 1
    raise SystemExit("usage: host_observation.py --self-test")


if __name__ == "__main__":
    raise SystemExit(main(os.sys.argv[1:]))
