#!/usr/bin/env python3

import json
import pathlib
import sys
import unittest

from host_observation import (
    MAX_PROC_NET_TABLE_BYTES,
    SCHEMA4_ANCESTOR_DIRECTORIES,
    SCHEMA4_FIXED_SOCKETS,
    SCHEMA4_FIXED_UNITS,
    SCHEMA4_REVIEWED_RESOLVER_TARGET,
    SCHEMA4_REVIEWED_UNIT_STATES,
    SCHEMA4_REQUIRED_PATHS,
    UNREVIEWED_ARCHITECTURE,
    UNREVIEWED_METADATA_TARGET,
    UNREVIEWED_OS_ID,
    UNREVIEWED_OS_VERSION_ID,
    UNREVIEWED_RESOLVER_TARGET,
    UNREVIEWED_RUNNER_PRINCIPAL,
    UNREVIEWED_SOCKET_OWNER,
    UNREVIEWED_SUDO_SOURCE_TARGET,
    UNREVIEWED_UNIT_STATE,
    observation_limits,
    public_runner_group_name,
    public_sudo_source_name,
    validate_schema4_observation,
)


class ClassificationError(ValueError):
    pass


UNIX_NAME_HASH_SCHEMA_V1 = "fence-unix-name-v1"
SCHEMA2_EVIDENCE_ONLY_UNITS = {"walinuxagent.service"}
FIXTURE_ACCEPTED_DIGEST = "0" * 64
FIXTURE_TRANSITION_DIGEST = "1" * 64
FIXTURE_UNKNOWN_DIGEST = "2" * 64


def require(condition, message):
    if not condition:
        raise ClassificationError(message)


def index_by(items, *keys):
    require(isinstance(items, list), "fingerprint item set is not a list")
    indexed = {}
    for item in items:
        require(isinstance(item, dict), "fingerprint item is not an object")
        key = tuple(item.get(name) for name in keys)
        require(None not in key, "fingerprint item omitted a required identity field")
        require(key not in indexed, "fingerprint item identity was duplicated")
        indexed[key] = item
    return indexed


def accepted_digests(source):
    return {source["sha256"], *source.get("alternate_sha256", [])}


def is_sha256(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def is_mode(value):
    return (
        isinstance(value, str)
        and len(value) == 4
        and all(character in "01234567" for character in value)
    )


def is_integer(value, minimum=0, maximum=None):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= minimum
        and (maximum is None or value <= maximum)
    )


def require_fields(value, fields, message):
    require(isinstance(value, dict) and set(value) == set(fields), message)


def validate_owner(owner):
    require_fields(
        owner,
        {
            "uid",
            "executable_basename",
            "canonical_executable",
            "unified_cgroup",
            "processes",
        },
        "bundle local control owner shape mismatch",
    )
    require(
        is_integer(owner["uid"], maximum=0xFFFFFFFF)
        and isinstance(owner["executable_basename"], str)
        and isinstance(owner["canonical_executable"], str)
        and isinstance(owner["unified_cgroup"], str)
        and is_integer(owner["processes"], 1),
        "bundle local control owner value mismatch",
    )


def validate_owner_list(owners):
    require(isinstance(owners, list) and owners, "bundle local control owner set mismatch")
    for owner in owners:
        validate_owner(owner)
    index_by(
        owners,
        "uid",
        "executable_basename",
        "canonical_executable",
        "unified_cgroup",
    )


def validate_schema2_local_control_inventory(inventory):
    require_fields(
        inventory,
        {
            "unix_name_hash_schema",
            "root_container_processes",
            "tcp_listeners",
            "unix_listeners",
            "standard_lockdown_removable_unix_listener_name_sha256",
        },
        "bundle local control inventory shape mismatch",
    )
    require(
        inventory["unix_name_hash_schema"] == UNIX_NAME_HASH_SCHEMA_V1,
        "bundle Unix name hash schema mismatch",
    )

    containers = inventory["root_container_processes"]
    require(isinstance(containers, list), "bundle root container set mismatch")
    for process in containers:
        require_fields(
            process,
            {
                "uid",
                "executable_basename",
                "canonical_executable",
                "unified_cgroup",
                "instances",
            },
            "bundle root container shape mismatch",
        )
        require(
            is_integer(process["uid"], maximum=0xFFFFFFFF)
            and isinstance(process["executable_basename"], str)
            and isinstance(process["canonical_executable"], str)
            and isinstance(process["unified_cgroup"], str)
            and is_integer(process["instances"], 1),
            "bundle root container value mismatch",
        )
    index_by(
        containers,
        "uid",
        "executable_basename",
        "canonical_executable",
        "unified_cgroup",
    )

    tcp_listeners = inventory["tcp_listeners"]
    require(isinstance(tcp_listeners, list), "bundle TCP listener set mismatch")
    for listener in tcp_listeners:
        require_fields(
            listener,
            {"family", "bind_class", "port", "owners", "instances"},
            "bundle TCP listener shape mismatch",
        )
        require(
            listener["family"] in {"ipv4", "ipv6"}
            and listener["bind_class"] in {"wildcard", "loopback", "other_local"}
            and is_integer(listener["port"], maximum=65535)
            and is_integer(listener["instances"], 1),
            "bundle TCP listener value mismatch",
        )
        validate_owner_list(listener["owners"])
    index_by(tcp_listeners, "family", "bind_class", "port")

    unix_listeners = inventory["unix_listeners"]
    require(isinstance(unix_listeners, list), "bundle Unix listener set mismatch")
    for listener in unix_listeners:
        require_fields(
            listener,
            {
                "socket_type",
                "name_kind",
                "name_sha256",
                "owners",
                "instances",
            },
            "bundle Unix listener shape mismatch",
        )
        require(
            listener["socket_type"] in {"stream", "seqpacket"}
            and listener["name_kind"] in {"abstract", "filesystem"}
            and is_sha256(listener["name_sha256"])
            and is_integer(listener["instances"], 1),
            "bundle Unix listener value mismatch",
        )
        validate_owner_list(listener["owners"])
    index_by(unix_listeners, "socket_type", "name_kind", "name_sha256")

    removable = inventory["standard_lockdown_removable_unix_listener_name_sha256"]
    require(is_sha256(removable), "bundle removable Unix listener identity mismatch")
    matching = [
        listener for listener in unix_listeners if listener["name_sha256"] == removable
    ]
    require(len(matching) == 1, "bundle removable Unix listener is not unique")
    dockerd_owners = [
        owner
        for owner in matching[0]["owners"]
        if owner["uid"] == 0 and owner["executable_basename"] == "dockerd"
    ]
    require(len(dockerd_owners) == 1, "bundle removable Unix listener owner mismatch")
    dockerd = dockerd_owners[0]
    require(
        any(
            process["uid"] == dockerd["uid"]
            and process["executable_basename"] == dockerd["executable_basename"]
            and process["canonical_executable"] == dockerd["canonical_executable"]
            and process["unified_cgroup"] == dockerd["unified_cgroup"]
            for process in containers
        ),
        "bundle removable Unix listener container identity mismatch",
    )


def validate_schema2_fingerprint(fingerprint):
    require_fields(
        fingerprint,
        {
            "schema_version",
            "protected_target",
            "status",
            "observation_method",
            "accepted",
        },
        "bundle fingerprint shape mismatch",
    )
    require(fingerprint["schema_version"] == 2, "bundle fingerprint schema mismatch")
    require(
        fingerprint["protected_target"] == "github_hosted_ubuntu_24_04_x86_64",
        "bundle fingerprint target mismatch",
    )
    require(
        fingerprint["status"] == "accepted_reference_not_checked",
        "bundle fingerprint status mismatch",
    )
    require(
        fingerprint["observation_method"] == "integration_read_only_observation",
        "bundle fingerprint observation method mismatch",
    )
    accepted = fingerprint["accepted"]
    require_fields(
        accepted,
        {
            "os_id",
            "os_version_id",
            "architecture",
            "expected_principal",
            "required_runner_groups",
            "trusted_executables",
            "permission_ancestor_directories",
            "resolver",
            "sudo_policy_sources",
            "container_units",
            "container_sockets",
            "required_docker_running_workload_count",
            "local_control_inventory",
        },
        "bundle accepted fingerprint shape mismatch",
    )
    for field in ("os_id", "os_version_id", "architecture", "expected_principal"):
        require(isinstance(accepted[field], str), "bundle host identity shape mismatch")
    groups = accepted["required_runner_groups"]
    require(
        isinstance(groups, list)
        and groups
        and len(groups) == len(set(groups))
        and all(isinstance(group, str) for group in groups),
        "bundle runner group set mismatch",
    )

    executables = accepted["trusted_executables"]
    require(isinstance(executables, list), "bundle executable set mismatch")
    for executable in executables:
        require_fields(
            executable,
            {"path", "canonical_target", "mode"},
            "bundle executable shape mismatch",
        )
        require(
            isinstance(executable["path"], str)
            and isinstance(executable["canonical_target"], str)
            and is_mode(executable["mode"]),
            "bundle executable value mismatch",
        )
    index_by(executables, "path")

    ancestors = accepted["permission_ancestor_directories"]
    require(isinstance(ancestors, list), "bundle ancestor set mismatch")
    for ancestor in ancestors:
        require_fields(
            ancestor,
            {"path", "canonical_target", "mode", "runner_searchable"},
            "bundle ancestor shape mismatch",
        )
        require(
            isinstance(ancestor["path"], str)
            and isinstance(ancestor["canonical_target"], str)
            and is_mode(ancestor["mode"])
            and isinstance(ancestor["runner_searchable"], bool),
            "bundle ancestor value mismatch",
        )
    index_by(ancestors, "path")

    resolver = accepted["resolver"]
    require_fields(
        resolver,
        {"resolv_conf_path", "canonical_target", "target_uid", "target_mode"},
        "bundle resolver shape mismatch",
    )
    require(
        isinstance(resolver["resolv_conf_path"], str)
        and isinstance(resolver["canonical_target"], str)
        and is_integer(resolver["target_uid"], maximum=0xFFFFFFFF)
        and is_mode(resolver["target_mode"]),
        "bundle resolver value mismatch",
    )

    sources = accepted["sudo_policy_sources"]
    require(isinstance(sources, list), "bundle sudo source set mismatch")
    source_fields = {
        "path_class",
        "name",
        "canonical_target",
        "mode",
        "sha256",
        "runner_nopasswd_markers",
    }
    for source in sources:
        require(
            isinstance(source, dict)
            and frozenset(source)
            in {
                frozenset(source_fields),
                frozenset(source_fields | {"alternate_sha256"}),
            },
            "bundle sudo source shape mismatch",
        )
        require(
            source["path_class"] in {"main_policy", "drop_in"}
            and isinstance(source["name"], str)
            and isinstance(source["canonical_target"], str)
            and is_mode(source["mode"])
            and is_sha256(source["sha256"]),
            "bundle sudo source value mismatch",
        )
        markers = source["runner_nopasswd_markers"]
        require(
            isinstance(markers, list)
            and markers == sorted(set(markers))
            and set(markers).issubset({"principal", "group"}),
            "bundle sudo source marker mismatch",
        )
        alternate = source.get("alternate_sha256", [])
        require(
            isinstance(alternate, list)
            and len(alternate) == len(set(alternate))
            and source["sha256"] not in alternate
            and all(is_sha256(digest) for digest in alternate),
            "bundle sudo alternate digest mismatch",
        )
    index_by(sources, "path_class", "name")

    units = accepted["container_units"]
    require(isinstance(units, list), "bundle container unit set mismatch")
    for unit in units:
        require_fields(
            unit,
            {"name", "load_state", "active_state", "unit_file_state"},
            "bundle container unit shape mismatch",
        )
        require(
            all(isinstance(unit[field], str) for field in unit),
            "bundle container unit value mismatch",
        )
    index_by(units, "name")
    require(
        {unit["name"] for unit in units}
        == set(SCHEMA4_FIXED_UNITS) - SCHEMA2_EVIDENCE_ONLY_UNITS,
        "bundle container unit identity set mismatch",
    )

    sockets = accepted["container_sockets"]
    require(isinstance(sockets, list), "bundle container socket set mismatch")
    for socket in sockets:
        require_fields(
            socket,
            {"path", "present", "kind", "mode", "owner", "group"},
            "bundle container socket shape mismatch",
        )
        require(
            isinstance(socket["path"], str)
            and isinstance(socket["present"], bool)
            and isinstance(socket["kind"], str)
            and is_mode(socket["mode"])
            and isinstance(socket["owner"], str)
            and isinstance(socket["group"], str),
            "bundle container socket value mismatch",
        )
    index_by(sockets, "path")
    require(
        {socket["path"] for socket in sockets} == set(SCHEMA4_FIXED_SOCKETS),
        "bundle container socket identity set mismatch",
    )
    require(
        is_integer(accepted["required_docker_running_workload_count"]),
        "bundle Docker workload count mismatch",
    )
    validate_schema2_local_control_inventory(accepted["local_control_inventory"])
    return accepted


def expected_schema2_local_control_snapshot(inventory):
    return {
        "scan_status": "within_bounds",
        "bounds_exceeded": [],
        "unavailable_inputs": [],
        "malformed_row_count": 0,
        "unresolved_unix_listener_count": 0,
        "reachability_complete": True,
        "ownership_complete": True,
        "root_container_processes": inventory["root_container_processes"],
        "unix_listeners": [
            {
                **listener,
                "runner_reachable": True,
                "ownership_complete": True,
            }
            for listener in inventory["unix_listeners"]
        ],
        "tcp_listeners": [
            {**listener, "ownership_complete": True}
            for listener in inventory["tcp_listeners"]
        ],
    }


def validate_transitions(transitions, accepted_sources):
    require_fields(
        transitions,
        {"schema_version", "transitions"},
        "transition file shape mismatch",
    )
    require(transitions["schema_version"] == 1, "transition schema mismatch")
    entries = transitions["transitions"]
    require(isinstance(entries, list), "transition set mismatch")
    accepted_identities = {
        (source["path_class"], source["name"]) for source in accepted_sources
    }
    for entry in entries:
        require_fields(
            entry,
            {"path_class", "name", "sha256"},
            "transition entry shape mismatch",
        )
        require(
            (entry["path_class"], entry["name"]) in accepted_identities
            and is_sha256(entry["sha256"]),
            "transition entry value mismatch",
        )
    return index_by(entries, "path_class", "name", "sha256")


def compare_schema4_observation_to_schema2(observation, accepted):
    try:
        validate_schema4_observation(observation)
    except ValueError as error:
        raise ClassificationError(
            f"host schema 4 observation is invalid: {error}"
        ) from error
    require(
        observation["sudo"]["policy_sources_truncated"] is False,
        "host sudo policy observation is truncated",
    )
    require(
        all(
            source.get("status") != "oversized"
            for source in observation["sudo"]["policy_source_hashes"]
        ),
        "host sudo policy observation is oversized",
    )

    host = observation["host"]
    require(host["os_id"] == accepted["os_id"], "host OS identity drifted")
    require(
        host["os_version_id"] == accepted["os_version_id"],
        "host OS version drifted",
    )
    require(
        host["architecture"] == accepted["architecture"],
        "host architecture drifted",
    )
    require(
        host["runner_principal"] == accepted["expected_principal"],
        "runner principal drifted",
    )
    require(
        set(host["runner_groups"]) == set(accepted["required_runner_groups"]),
        "runner groups drifted",
    )

    required_paths = index_by(observation["required_paths"], "path")
    accepted_executables = index_by(accepted["trusted_executables"], "path")
    require(
        set(required_paths) == set(accepted_executables),
        "fixed executable path set drifted",
    )
    for key, expected in accepted_executables.items():
        item = required_paths[key]
        require(item["present"] is True, "fixed executable is absent")
        require(
            item["canonical_target"] == expected["canonical_target"],
            "fixed executable target drifted",
        )
        require(item["path_type"] == "regular", "fixed executable path type drifted")
        require(item["target_type"] == "regular", "fixed executable target type drifted")
        require(item["owner_class"] == "root", "fixed executable owner drifted")
        require(item["group_class"] == "root", "fixed executable group drifted")
        require(item["mode"] == expected["mode"], "fixed executable mode drifted")
        require(item["runner_writable"] is False, "fixed executable became runner writable")
        require(item["executable"] is True, "fixed executable lost execute permission")
        require(
            item["runner_executable"] is True,
            "fixed executable is unavailable to the runner",
        )

    observed_ancestors = index_by(observation["permission_ancestor_directories"], "path")
    accepted_ancestors = index_by(accepted["permission_ancestor_directories"], "path")
    require(set(observed_ancestors) == set(accepted_ancestors), "ancestor path set drifted")
    for key, expected in accepted_ancestors.items():
        item = observed_ancestors[key]
        require(item["present"] is True, "permission ancestor is absent")
        require(
            item["canonical_target"] == expected["canonical_target"],
            "permission ancestor target drifted",
        )
        require(
            item["path_type"] == "directory" and item["target_type"] == "directory",
            "permission ancestor type drifted",
        )
        require(
            item["owner_class"] == "root" and item["group_class"] == "root",
            "permission ancestor ownership drifted",
        )
        require(item["mode"] == expected["mode"], "permission ancestor mode drifted")
        require(
            item["runner_writable"] is False,
            "permission ancestor became runner writable",
        )
        require(
            item["runner_searchable"] == expected["runner_searchable"],
            "permission ancestor searchability drifted",
        )

    resolver = observation["resolver"]
    expected_resolver = accepted["resolver"]
    require(resolver["status"] == "observed", "resolver observation is unavailable")
    require(resolver["is_symlink"] is True, "resolver path is not the reviewed symlink")
    require(
        resolver["path"] == expected_resolver["resolv_conf_path"],
        "resolver path drifted",
    )
    require(
        resolver["canonical_target"] == expected_resolver["canonical_target"],
        "resolver target drifted",
    )
    require(resolver["target_type"] == "regular", "resolver target type drifted")
    require(
        resolver["target_uid"] == expected_resolver["target_uid"],
        "resolver target owner drifted",
    )
    require(
        resolver["target_mode"] == expected_resolver["target_mode"],
        "resolver target mode drifted",
    )

    observed_sources = index_by(
        observation["sudo"]["policy_source_hashes"], "path_class", "name"
    )
    accepted_sources = index_by(
        accepted["sudo_policy_sources"], "path_class", "name"
    )
    require(
        set(observed_sources) == set(accepted_sources),
        "sudo policy source set drifted",
    )
    digest_mismatches = []
    for key, source in accepted_sources.items():
        observed = observed_sources[key]
        require(
            observed["canonical_target"] == source["canonical_target"],
            "sudo policy target drifted",
        )
        require(observed["target_type"] == "regular", "sudo policy type drifted")
        require(observed["owner_class"] == "root", "sudo policy owner drifted")
        require(observed["group_class"] == "root", "sudo policy group drifted")
        require(observed["mode"] == source["mode"], "sudo policy mode drifted")
        require(observed["runner_writable"] is False, "sudo policy became runner writable")
        require(
            observed["runner_nopasswd_markers"]
            == source["runner_nopasswd_markers"],
            "sudo policy marker classification drifted",
        )
        if observed["sha256"] not in accepted_digests(source):
            digest_mismatches.append((*key, observed["sha256"]))

    observed_units = index_by(observation["systemd"]["units"], "name")
    accepted_units = index_by(accepted["container_units"], "name")
    require(
        set(accepted_units)
        == set(observed_units) - {(name,) for name in SCHEMA2_EVIDENCE_ONLY_UNITS},
        "fixed container unit set drifted",
    )
    for key, unit in accepted_units.items():
        observed = observed_units[key]
        require(
            (
                observed["load_state"],
                observed["active_state"],
                observed["unit_file_state"],
            )
            == (
                unit["load_state"],
                unit["active_state"],
                unit["unit_file_state"],
            ),
            "fixed container unit state drifted",
        )

    observed_sockets = index_by(observation["container_runtime"]["sockets"], "path")
    accepted_sockets = index_by(accepted["container_sockets"], "path")
    require(set(observed_sockets) == set(accepted_sockets), "container socket set drifted")
    for key, socket in accepted_sockets.items():
        observed = observed_sockets[key]
        require(
            observed["present"] == socket["present"],
            "container socket state drifted",
        )
        if not observed["present"]:
            continue
        require(
            (
                observed["type"],
                observed["mode"],
                observed["owner"],
                observed["group"],
            )
            == (
                socket["kind"],
                socket["mode"],
                socket["owner"],
                socket["group"],
            ),
            "container socket state drifted",
        )
    require(
        observation["container_runtime"]["docker_running_workload_count"]
        == accepted["required_docker_running_workload_count"],
        "Docker workload count drifted",
    )

    inventory = observation["local_control_inventory"]
    snapshot = inventory["snapshot"]
    require(
        inventory["status"] == "stable" and inventory["stable"] is True,
        "local control inventory did not stabilize",
    )
    observed_snapshot = {
        key: value
        for key, value in snapshot.items()
        if key != "inaccessible_root_filesystem_listener_count"
    }
    require(
        observed_snapshot
        == expected_schema2_local_control_snapshot(accepted["local_control_inventory"]),
        "local control inventory drifted",
    )
    return digest_mismatches


def classify(observation, support, transitions):
    require(isinstance(support, dict), "bundle support response is not an object")
    require(support.get("schema_version") == 1, "bundle support schema mismatch")
    require(support.get("command") == "check-support", "bundle support command mismatch")
    require(support.get("status") == "success", "bundle support command failed")
    data = support.get("data")
    require(
        isinstance(data, dict) and "hosted_runner_fingerprint" in data,
        "bundle support fingerprint is missing",
    )
    fingerprint = data["hosted_runner_fingerprint"]
    accepted = validate_schema2_fingerprint(fingerprint)
    transition_index = validate_transitions(
        transitions, accepted["sudo_policy_sources"]
    )
    mismatches = compare_schema4_observation_to_schema2(observation, accepted)
    if not mismatches:
        return {"run_bundle": True, "classification": "bundle_compatible"}
    for mismatch in mismatches:
        require(
            mismatch in transition_index,
            "live host fingerprint drift is not an approved source-known bundle transition",
        )
    return {
        "run_bundle": False,
        "classification": "source_known_bundle_old_sudo_policy",
    }


def fixture():
    def clone(value):
        return json.loads(json.dumps(value))

    def metadata(path, target_type="regular"):
        executable_modes = {
            "/usr/bin/mount": "4755",
            "/usr/bin/sudo": "4755",
            "/usr/bin/umount": "4755",
        }
        return {
            "path": path,
            "present": True,
            "canonical_target": path,
            "path_type": target_type,
            "target_type": target_type,
            "owner_class": "root",
            "group_class": "root",
            "mode": executable_modes.get(path, "0755"),
            "device": 1,
            "inode": 1,
            "runner_writable": False,
        }

    def command_metadata(path):
        return {
            **metadata(path),
            "executable": True,
            "runner_executable": True,
        }

    systemd_owner = {
        "uid": 0,
        "executable_basename": "systemd",
        "canonical_executable": "/usr/lib/systemd/systemd",
        "unified_cgroup": "/init.scope",
        "processes": 1,
    }
    dockerd_owner = {
        "uid": 0,
        "executable_basename": "dockerd",
        "canonical_executable": "/usr/bin/dockerd",
        "unified_cgroup": "/system.slice/docker.service",
        "processes": 1,
    }
    multipathd_owner = {
        "uid": 0,
        "executable_basename": "multipathd",
        "canonical_executable": "/usr/sbin/multipathd",
        "unified_cgroup": "/system.slice/multipathd.service",
        "processes": 1,
    }
    journald_owner = {
        "uid": 0,
        "executable_basename": "systemd-journald",
        "canonical_executable": "/usr/lib/systemd/systemd-journald",
        "unified_cgroup": "/system.slice/systemd-journald.service",
        "processes": 1,
    }
    dbus_owner = {
        "uid": 101,
        "executable_basename": "dbus-daemon",
        "canonical_executable": "/usr/bin/dbus-daemon",
        "unified_cgroup": "/system.slice/dbus.service",
        "processes": 1,
    }
    root_containers = [
        {
            "uid": 0,
            "executable_basename": "containerd",
            "canonical_executable": "/usr/bin/containerd",
            "unified_cgroup": "/system.slice/containerd.service",
            "instances": 1,
        },
        {
            "uid": 0,
            "executable_basename": "dockerd",
            "canonical_executable": "/usr/bin/dockerd",
            "unified_cgroup": "/system.slice/docker.service",
            "instances": 1,
        },
    ]
    tcp_listeners = [
        {
            "family": family,
            "bind_class": "wildcard",
            "port": 22,
            "owners": [clone(systemd_owner)],
            "instances": 1,
        }
        for family in ("ipv4", "ipv6")
    ]
    unix_owner_sets = [
        [multipathd_owner, systemd_owner],
        [systemd_owner],
        [systemd_owner],
        [dockerd_owner, systemd_owner],
        [systemd_owner, journald_owner],
        [systemd_owner, dbus_owner],
        [systemd_owner],
        [systemd_owner],
        [systemd_owner],
        [systemd_owner],
    ]
    unix_hashes = [
        ("abstract", "2098ac544ed7672deda4863cf7f1ec11fd3916b31f7f02f8b1190394218612ec"),
        ("abstract", "caf0d5ac99f3b95f921556138b2adbf4ceb0e8d48c61ef23d5180aa480b45743"),
        ("filesystem", "1f76b0a726958dc80a872b9ae4fb414457f7ee9cc80f419ff7dfc509f236e469"),
        ("filesystem", "2a5962ed41259a31b1587bcae589fcee6b9d6767ef064ac317e6d398b96a81f2"),
        ("filesystem", "68c0b0a26da3ac420889ddd0ab629df3f9defb482cf5a9daf7fdcd28ee545f29"),
        ("filesystem", "8b5e213b2b72a7033476e1f46afb302f0e4123c6e6fd746f77eeb744050e3b91"),
        ("filesystem", "ac10a069436547a18b02df8078e06421de7fc8953887fcc32f817af06b1b09bb"),
        ("filesystem", "ded56518cb66a7ddcdf9434f3280745cbb457869ea692d34cf0df494949bca96"),
        ("filesystem", "e84916b142c7b55bdf364843e9360867ec403fc602cfb662c95d6299ebfb8e77"),
        ("filesystem", "f7978cc2493e0ecd56d54a3f49e36c3bde79b3ac281baa0a0aed0efab0898c23"),
    ]
    unix_listeners = [
        {
            "socket_type": "stream",
            "name_kind": name_kind,
            "name_sha256": name_sha256,
            "owners": clone(owners),
            "instances": 1,
        }
        for (name_kind, name_sha256), owners in zip(unix_hashes, unix_owner_sets)
    ]
    local_control_inventory = {
        "unix_name_hash_schema": UNIX_NAME_HASH_SCHEMA_V1,
        "root_container_processes": clone(root_containers),
        "tcp_listeners": clone(tcp_listeners),
        "unix_listeners": clone(unix_listeners),
        "standard_lockdown_removable_unix_listener_name_sha256": unix_hashes[3][1],
    }

    source_specs = [
        (
            "main_policy",
            "sudoers",
            "/etc/sudoers",
            "0440",
            "3" * 64,
            ["4" * 64],
            [],
        ),
        (
            "drop_in",
            "90-cloud-init-users",
            "/etc/sudoers.d/90-cloud-init-users",
            "0440",
            "5" * 64,
            [],
            [],
        ),
        (
            "drop_in",
            "README",
            "/etc/sudoers.d/README",
            "0440",
            "6" * 64,
            [],
            [],
        ),
        (
            "drop_in",
            "runner",
            "/etc/sudoers.d/runner",
            "0644",
            FIXTURE_ACCEPTED_DIGEST,
            [],
            ["principal"],
        ),
    ]
    accepted_sources = []
    observed_sources = []
    for path_class, name, target, mode, digest, alternate, markers in source_specs:
        accepted_source = {
            "path_class": path_class,
            "name": name,
            "canonical_target": target,
            "mode": mode,
            "sha256": digest,
            "runner_nopasswd_markers": markers,
        }
        if alternate:
            accepted_source["alternate_sha256"] = alternate
        accepted_sources.append(accepted_source)
        observed_sources.append(
            {
                "path_class": path_class,
                "name": name,
                "sha256": digest,
                "canonical_target": target,
                "target_type": "regular",
                "owner_class": "root",
                "group_class": "root",
                "mode": mode,
                "device": 1,
                "inode": len(observed_sources) + 1,
                "runner_writable": False,
                "contains_nopasswd_directive": bool(markers),
                "runner_nopasswd_markers": markers,
            }
        )

    accepted = {
        "os_id": "ubuntu",
        "os_version_id": "24.04",
        "architecture": "x86_64",
        "expected_principal": "runner",
        "required_runner_groups": [
            "adm",
            "users",
            "docker",
            "systemd-journal",
            "runner",
        ],
        "trusted_executables": [
            {
                "path": path,
                "canonical_target": path,
                "mode": command_metadata(path)["mode"],
            }
            for path in SCHEMA4_REQUIRED_PATHS
        ],
        "permission_ancestor_directories": [
            {
                "path": path,
                "canonical_target": path,
                "mode": "0750" if path == "/etc/sudoers.d" else "0755",
                "runner_searchable": path != "/etc/sudoers.d",
            }
            for path in SCHEMA4_ANCESTOR_DIRECTORIES
        ],
        "resolver": {
            "resolv_conf_path": "/etc/resolv.conf",
            "canonical_target": SCHEMA4_REVIEWED_RESOLVER_TARGET,
            "target_uid": 991,
            "target_mode": "0644",
        },
        "sudo_policy_sources": accepted_sources,
        "container_units": [
            {
                "name": name,
                **SCHEMA4_REVIEWED_UNIT_STATES[name],
            }
            for name in SCHEMA4_FIXED_UNITS
            if name not in SCHEMA2_EVIDENCE_ONLY_UNITS
        ],
        "container_sockets": [
            {
                "path": path,
                "present": True,
                "kind": "socket",
                "mode": "0660",
                "owner": "root",
                "group": "docker" if path != "/run/containerd/containerd.sock" else "root",
            }
            for path in SCHEMA4_FIXED_SOCKETS
        ],
        "required_docker_running_workload_count": 0,
        "local_control_inventory": local_control_inventory,
    }
    observation = {
        "schema_version": 4,
        "observation": "hosted_runner_fingerprint_candidate",
        "status": "observation_only_no_protection",
        "protected_target": "github_hosted_ubuntu_24_04_x86_64",
        "host": {
            "os_id": "ubuntu",
            "os_version_id": "24.04",
            "architecture": "x86_64",
            "runner_principal": "runner",
            "runner_groups": ["adm", "docker", "runner", "systemd-journal", "users"],
        },
        "required_paths": [command_metadata(path) for path in SCHEMA4_REQUIRED_PATHS],
        "permission_ancestor_directories": [
            {
                **{
                    **metadata(path, "directory"),
                    "mode": "0750" if path == "/etc/sudoers.d" else "0755",
                },
                "runner_searchable": path != "/etc/sudoers.d",
                "synthetic_create_delete_probe": "denied",
            }
            for path in SCHEMA4_ANCESTOR_DIRECTORIES
        ],
        "resolver": {
            "status": "observed",
            "is_symlink": True,
            "path": "/etc/resolv.conf",
            "canonical_target": SCHEMA4_REVIEWED_RESOLVER_TARGET,
            "target_type": "regular",
            "target_uid": 991,
            "target_mode": "0644",
        },
        "sudo": {
            "noninteractive_root_observation_succeeded": True,
            "policy_source_hashes": observed_sources,
            "policy_sources_truncated": False,
            "grant_source_review_required": True,
        },
        "systemd": {
            "units": [
                {
                    "name": name,
                    **SCHEMA4_REVIEWED_UNIT_STATES[name],
                }
                for name in SCHEMA4_FIXED_UNITS
            ],
            "azure_platform_agent": {
                "name": "walinuxagent.service",
                "status": "observed",
                "load_state": "loaded",
                "active_state": "active",
                "sub_state": "running",
                "unit_file_state": "enabled",
                "configured_user_class": "root_or_default",
                "control_group": "/azure.slice/walinuxagent.service",
                "main_pid": 100,
                "processes_truncated": False,
                "processes": [
                    {
                        "pid": 100,
                        "owner_class": "root",
                        "start_time_ticks": 1000,
                        "executable_basename": "python3",
                        "executable_device": 1,
                        "executable_inode": 1,
                    }
                ],
                "process_status": "observed",
                "process_owner_class": "root",
                "process_start_time_ticks": 1000,
                "executable_basename": "python3",
                "executable_device": 1,
                "executable_inode": 1,
            },
        },
        "container_runtime": {
            "sockets": [
                {
                    "path": path,
                    "present": True,
                    "type": "socket",
                    "mode": "0660",
                    "owner": "root",
                    "group": "docker" if path != "/run/containerd/containerd.sock" else "root",
                }
                for path in SCHEMA4_FIXED_SOCKETS
            ],
            "docker_running_workload_count": 0,
        },
        "local_control_inventory": {
            "status": "stable",
            "stable": True,
            "attempts": 1,
            "interval_milliseconds": 50,
            "limits": observation_limits(),
            "snapshot": {
                "scan_status": "within_bounds",
                "bounds_exceeded": [],
                "unavailable_inputs": [],
                "malformed_row_count": 0,
                "unresolved_unix_listener_count": 0,
                "inaccessible_root_filesystem_listener_count": 14,
                "reachability_complete": True,
                "ownership_complete": True,
                "root_container_processes": clone(root_containers),
                "unix_listeners": [
                    {
                        **clone(listener),
                        "runner_reachable": True,
                        "ownership_complete": True,
                    }
                    for listener in unix_listeners
                ],
                "tcp_listeners": [
                    {**clone(listener), "ownership_complete": True}
                    for listener in tcp_listeners
                ],
            },
        },
        "next_step": "review_closed_host_invariants_before_any_enforcement_change",
    }
    support = {
        "schema_version": 1,
        "command": "check-support",
        "status": "success",
        "data": {
            "hosted_runner_fingerprint": {
                "schema_version": 2,
                "protected_target": "github_hosted_ubuntu_24_04_x86_64",
                "status": "accepted_reference_not_checked",
                "observation_method": "integration_read_only_observation",
                "accepted": accepted,
            }
        },
    }
    transitions = {
        "schema_version": 1,
        "transitions": [
            {
                "path_class": "drop_in",
                "name": "runner",
                "sha256": FIXTURE_TRANSITION_DIGEST,
            }
        ],
    }
    return observation, support, transitions


class ClassificationTests(unittest.TestCase):
    @staticmethod
    def observed_source(observation, name="runner"):
        return next(
            source
            for source in observation["sudo"]["policy_source_hashes"]
            if source["name"] == name
        )

    @staticmethod
    def accepted_source(support, name="runner"):
        return next(
            source
            for source in support["data"]["hosted_runner_fingerprint"]["accepted"][
                "sudo_policy_sources"
            ]
            if source["name"] == name
        )

    def test_runs_bundle_for_matching_host(self):
        observation, support, transitions = fixture()
        self.assertEqual(
            classify(observation, support, transitions),
            {"run_bundle": True, "classification": "bundle_compatible"},
        )

    def test_accepts_only_reviewed_source_known_transition(self):
        observation, support, transitions = fixture()
        self.observed_source(observation)["sha256"] = FIXTURE_TRANSITION_DIGEST
        self.assertEqual(
            classify(observation, support, transitions),
            {
                "run_bundle": False,
                "classification": "source_known_bundle_old_sudo_policy",
            },
        )

    def test_empty_transition_set_cannot_skip_activation(self):
        observation, support, transitions = fixture()
        self.observed_source(observation)["sha256"] = FIXTURE_TRANSITION_DIGEST
        transitions["transitions"] = []
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_rejects_unknown_digest_and_other_drift(self):
        observation, support, transitions = fixture()
        self.observed_source(observation)["sha256"] = FIXTURE_UNKNOWN_DIGEST
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)
        observation, support, transitions = fixture()
        observation["host"]["runner_groups"] = ["runner"]
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        socket = observation["container_runtime"]["sockets"][0]
        observation["container_runtime"]["sockets"][0] = {
            "path": socket["path"],
            "present": False,
        }
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_refreshed_bundle_runs_on_transition_digest(self):
        observation, support, transitions = fixture()
        self.observed_source(observation)["sha256"] = FIXTURE_TRANSITION_DIGEST
        self.accepted_source(support)["alternate_sha256"] = [
            FIXTURE_TRANSITION_DIGEST
        ]
        self.assertEqual(
            classify(observation, support, transitions)["classification"],
            "bundle_compatible",
        )

    def test_schema4_to_schema2_boundary_is_explicit_and_fails_closed(self):
        observation, support, transitions = fixture()
        observation["schema_version"] = 3
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        support["data"]["hosted_runner_fingerprint"]["schema_version"] = 1
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        observation.pop("local_control_inventory")
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        observation["required_paths"].append(
            {
                "path": "/usr/bin/unreviewed",
                "present": True,
                "canonical_target": "/usr/bin/unreviewed",
                "path_type": "regular",
                "target_type": "regular",
                "owner_class": "root",
                "runner_writable": False,
                "executable": True,
                "runner_executable": True,
            }
        )
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_schema4_comparison_validates_the_complete_observation(self):
        def remove_test_metadata(observation):
            test_path = next(
                item
                for item in observation["required_paths"]
                if item["path"] == "/usr/bin/test"
            )
            test_path.pop("canonical_target")

        mutations = {
            "protected target": lambda observation: observation.__setitem__(
                "protected_target", "wrong_target"
            ),
            "test metadata": remove_test_metadata,
            "permission ancestors": lambda observation: observation[
                "permission_ancestor_directories"
            ].pop(),
            "Azure agent": lambda observation: observation["systemd"].pop(
                "azure_platform_agent"
            ),
            "required next step": lambda observation: observation.pop("next_step"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                observation, support, transitions = fixture()
                mutate(observation)
                with self.assertRaises(ClassificationError):
                    classify(observation, support, transitions)

    def test_schema2_enforces_test_but_not_the_synthetic_probe_result(self):
        observation, support, transitions = fixture()
        test_index = next(
            index
            for index, item in enumerate(observation["required_paths"])
            if item["path"] == "/usr/bin/test"
        )
        observation["required_paths"][test_index] = {
            "path": "/usr/bin/test",
            "present": False,
            "executable": False,
            "runner_executable": False,
        }
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        observation["permission_ancestor_directories"][0][
            "synthetic_create_delete_probe"
        ] = "unavailable"
        self.assertEqual(classify(observation, support, transitions)["run_bundle"], True)

    def test_schema2_local_control_projection_matches_the_rust_boundary(self):
        observation, support, _ = fixture()
        inventory = support["data"]["hosted_runner_fingerprint"]["accepted"][
            "local_control_inventory"
        ]
        projected = {
            key: value
            for key, value in observation["local_control_inventory"]["snapshot"].items()
            if key != "inaccessible_root_filesystem_listener_count"
        }
        self.assertEqual(
            projected,
            expected_schema2_local_control_snapshot(inventory),
        )
        self.assertEqual(
            observation["local_control_inventory"]["snapshot"][
                "inaccessible_root_filesystem_listener_count"
            ],
            14,
        )

    def test_schema4_rejects_raw_unreviewed_public_strings(self):
        def set_sudo_source(observation):
            source = self.observed_source(observation)
            source["name"] = "private-project-policy"
            source["canonical_target"] = "/etc/sudoers.d/private-project-policy"

        mutations = {
            "OS identity": lambda observation: observation["host"].__setitem__(
                "os_id", "private-project-os"
            ),
            "runner principal": lambda observation: observation["host"].__setitem__(
                "runner_principal", "private-project-runner"
            ),
            "fixed canonical target": lambda observation: observation[
                "required_paths"
            ][0].__setitem__(
                "canonical_target", "/usr/bin/private-project-helper"
            ),
            "non-UTF-8 canonical target": lambda observation: observation[
                "required_paths"
            ][0].__setitem__("canonical_target", "/usr/bin/\udcff"),
            "resolver target": lambda observation: observation[
                "resolver"
            ].__setitem__("canonical_target", "/run/private-project/resolv.conf"),
            "runner group": lambda observation: observation["host"].__setitem__(
                "runner_groups", ["private-project-group"]
            ),
            "systemd state": lambda observation: observation["systemd"]["units"][
                0
            ].__setitem__("load_state", "private-project-state"),
            "sudo source": set_sudo_source,
            "socket owner": lambda observation: observation["container_runtime"][
                "sockets"
            ][0].__setitem__("owner", "private-project-account"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                observation, _, _ = fixture()
                mutate(observation)
                with self.assertRaises(ValueError):
                    validate_schema4_observation(observation)

    def test_schema4_public_drift_classifications_are_valid_but_incompatible(self):
        def set_sudo_source(observation):
            source = self.observed_source(observation)
            source["name"] = public_sudo_source_name("private-project-policy")
            source["canonical_target"] = UNREVIEWED_SUDO_SOURCE_TARGET

        mutations = {
            "OS identity": lambda observation: observation["host"].update(
                {
                    "os_id": UNREVIEWED_OS_ID,
                    "os_version_id": UNREVIEWED_OS_VERSION_ID,
                    "architecture": UNREVIEWED_ARCHITECTURE,
                }
            ),
            "runner principal": lambda observation: observation["host"].__setitem__(
                "runner_principal", UNREVIEWED_RUNNER_PRINCIPAL
            ),
            "fixed canonical target": lambda observation: observation[
                "required_paths"
            ][0].__setitem__("canonical_target", UNREVIEWED_METADATA_TARGET),
            "resolver target": lambda observation: observation[
                "resolver"
            ].__setitem__("canonical_target", UNREVIEWED_RESOLVER_TARGET),
            "runner group": lambda observation: observation["host"].__setitem__(
                "runner_groups",
                sorted([public_runner_group_name("private-project-group")]),
            ),
            "systemd state": lambda observation: observation["systemd"]["units"][
                0
            ].__setitem__("load_state", UNREVIEWED_UNIT_STATE),
            "sudo source": set_sudo_source,
            "socket owner": lambda observation: observation["container_runtime"][
                "sockets"
            ][0].__setitem__("owner", UNREVIEWED_SOCKET_OWNER),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                observation, support, transitions = fixture()
                mutate(observation)
                validate_schema4_observation(observation)
                with self.assertRaises(ClassificationError):
                    classify(observation, support, transitions)

    def test_schema2_rejects_local_control_inventory_drift(self):
        observation, support, transitions = fixture()
        observation["local_control_inventory"]["snapshot"]["tcp_listeners"] = [
            {
                "family": "ipv4",
                "bind_class": "loopback",
                "port": 8080,
                "owners": [
                    {
                        "uid": 0,
                        "executable_basename": "systemd",
                        "canonical_executable": "/usr/lib/systemd/systemd",
                        "unified_cgroup": "/init.scope",
                        "processes": 1,
                    }
                ],
                "ownership_complete": True,
                "instances": 1,
            }
        ]
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_schema2_requires_stable_complete_local_control_inventory(self):
        def unavailable(inventory):
            inventory["status"] = "unavailable"
            inventory["snapshot"].update(
                {
                    "scan_status": "unavailable",
                    "unavailable_inputs": [
                        "proc",
                        "socket_ownership",
                        "unix_reachability",
                    ],
                    "reachability_complete": False,
                    "ownership_complete": False,
                }
            )

        def unstable(inventory):
            inventory.update({"status": "unstable", "stable": False, "attempts": 3})

        def bounds_exceeded(inventory):
            inventory["status"] = "bounds_exceeded"
            inventory["snapshot"].update(
                {
                    "scan_status": "bounds_exceeded",
                    "bounds_exceeded": ["tcp_listeners"],
                }
            )

        for label, mutate in {
            "unavailable": unavailable,
            "unstable": unstable,
            "bounds exceeded": bounds_exceeded,
        }.items():
            with self.subTest(label=label):
                observation, support, transitions = fixture()
                mutate(observation["local_control_inventory"])
                validate_schema4_observation(observation)
                with self.assertRaises(ClassificationError):
                    classify(observation, support, transitions)

    def test_schema2_requires_complete_sudo_evidence(self):
        observation, support, transitions = fixture()
        observation["sudo"]["policy_sources_truncated"] = True
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        source = observation["sudo"]["policy_source_hashes"][0]
        for field in (
            "sha256",
            "contains_nopasswd_directive",
            "runner_nopasswd_markers",
        ):
            source.pop(field)
        source["status"] = "oversized"
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_schema4_validation_rejects_raw_or_contradictory_nested_evidence(self):
        def add_overbound_owner(observation):
            observation["local_control_inventory"]["snapshot"][
                "tcp_listeners"
            ] = [
                {
                    "family": "ipv4",
                    "bind_class": "loopback",
                    "port": 8080,
                    "owners": [
                        {
                            "uid": 0,
                            "executable_basename": "systemd",
                            "canonical_executable": "/usr/lib/systemd/systemd",
                            "unified_cgroup": "/init.scope",
                            "processes": observation_limits()["processes"] + 1,
                        }
                    ],
                    "ownership_complete": True,
                    "instances": 1,
                }
            ]

        mutations = {
            "raw listener identity": lambda observation: observation[
                "local_control_inventory"
            ]["snapshot"].__setitem__("_socket_inode", 42),
            "contradictory summary": lambda observation: observation[
                "local_control_inventory"
            ]["snapshot"].__setitem__("ownership_complete", False),
            "unknown sudo field": lambda observation: observation["sudo"].__setitem__(
                "raw_policy", "private"
            ),
            "unknown host field": lambda observation: observation["host"].__setitem__(
                "raw_identity", "private"
            ),
            "owner process count above bound": add_overbound_owner,
            "public counter above input bound": lambda observation: observation[
                "local_control_inventory"
            ]["snapshot"].__setitem__(
                "inaccessible_root_filesystem_listener_count",
                MAX_PROC_NET_TABLE_BYTES + 1,
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                observation, support, transitions = fixture()
                mutate(observation)
                with self.assertRaises(ClassificationError):
                    classify(observation, support, transitions)

    def test_schema4_validation_rejects_noncanonical_sudo_source_order(self):
        observation, _, _ = fixture()
        validate_schema4_observation(observation)
        observation["sudo"]["policy_source_hashes"].reverse()
        with self.assertRaises(ValueError):
            validate_schema4_observation(observation)

    def test_schema4_comparison_rejects_malformed_evidence(self):
        observation, support, transitions = fixture()
        observation["required_paths"].append(observation["required_paths"][0])
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        del observation["resolver"]["canonical_target"]
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_schema2_enforces_trusted_executable_metadata_and_access(self):
        def mutate(field, value):
            observation, support, transitions = fixture()
            executable = next(
                item
                for item in observation["required_paths"]
                if item["path"] == "/usr/bin/sudo"
            )
            executable[field] = value
            with self.assertRaises(ClassificationError):
                classify(observation, support, transitions)

        for field, value in {
            "canonical_target": UNREVIEWED_METADATA_TARGET,
            "path_type": "directory",
            "target_type": "directory",
            "owner_class": "other",
            "group_class": "other",
            "mode": "0755",
            "runner_writable": True,
            "executable": False,
            "runner_executable": False,
        }.items():
            with self.subTest(field=field):
                mutate(field, value)

        observation, support, transitions = fixture()
        executable = observation["required_paths"][0]
        executable.update({"device": 99, "inode": 100})
        self.assertTrue(classify(observation, support, transitions)["run_bundle"])

    def test_schema2_enforces_permission_ancestor_metadata_and_access(self):
        for field, value in {
            "canonical_target": UNREVIEWED_METADATA_TARGET,
            "path_type": "regular",
            "target_type": "regular",
            "owner_class": "other",
            "group_class": "other",
            "mode": "0700",
            "runner_writable": True,
            "runner_searchable": False,
        }.items():
            with self.subTest(field=field):
                observation, support, transitions = fixture()
                ancestor = next(
                    item
                    for item in observation["permission_ancestor_directories"]
                    if item["path"] == "/usr/bin"
                )
                ancestor[field] = value
                with self.assertRaises(ClassificationError):
                    classify(observation, support, transitions)

        observation, support, transitions = fixture()
        ancestor = observation["permission_ancestor_directories"][0]
        ancestor.update(
            {
                "device": 99,
                "inode": 100,
                "synthetic_create_delete_probe": "unavailable",
            }
        )
        self.assertTrue(classify(observation, support, transitions)["run_bundle"])

    def test_schema2_enforces_resolver_and_sudo_metadata(self):
        for field, value in {
            "is_symlink": False,
            "canonical_target": UNREVIEWED_RESOLVER_TARGET,
            "target_type": "unexpected_type",
            "target_mode": "0600",
            "target_uid": 992,
        }.items():
            with self.subTest(surface="resolver", field=field):
                observation, support, transitions = fixture()
                observation["resolver"][field] = value
                with self.assertRaises(ClassificationError):
                    classify(observation, support, transitions)

        for field, value in {
            "target_type": "other",
            "owner_class": "other",
            "group_class": "other",
            "mode": "0440",
            "runner_writable": True,
            "runner_nopasswd_markers": [],
        }.items():
            with self.subTest(surface="sudo", field=field):
                observation, support, transitions = fixture()
                self.observed_source(observation)[field] = value
                with self.assertRaises(ClassificationError):
                    classify(observation, support, transitions)

        observation, support, transitions = fixture()
        self.observed_source(observation).update({"device": 99, "inode": 100})
        self.assertTrue(classify(observation, support, transitions)["run_bundle"])

    def test_schema2_enforces_units_sockets_and_workload_count(self):
        observation, support, transitions = fixture()
        observation["systemd"]["units"][0]["load_state"] = UNREVIEWED_UNIT_STATE
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        observation["container_runtime"]["sockets"][0][
            "owner"
        ] = UNREVIEWED_SOCKET_OWNER
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        observation["container_runtime"]["docker_running_workload_count"] = 1
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_schema4_azure_identity_remains_validated_observation_evidence(self):
        observation, support, transitions = fixture()
        azure_unit = next(
            unit
            for unit in observation["systemd"]["units"]
            if unit["name"] == "walinuxagent.service"
        )
        azure_unit["load_state"] = UNREVIEWED_UNIT_STATE
        agent = observation["systemd"]["azure_platform_agent"]
        agent["executable_device"] = 99
        agent["processes"][0]["executable_device"] = 99
        validate_schema4_observation(observation)
        self.assertTrue(classify(observation, support, transitions)["run_bundle"])

    def test_schema2_rejects_each_local_control_inventory_class_of_drift(self):
        mutations = {
            "container multiplicity": lambda snapshot: snapshot[
                "root_container_processes"
            ][0].__setitem__("instances", 2),
            "TCP endpoint": lambda snapshot: snapshot["tcp_listeners"][0].__setitem__(
                "port", 23
            ),
            "Unix identity": lambda snapshot: snapshot["unix_listeners"][0].__setitem__(
                "name_sha256", "0" * 64
            ),
            "owner multiplicity": lambda snapshot: snapshot["unix_listeners"][0][
                "owners"
            ][0].__setitem__("processes", 2),
            "pre-lockdown reduction": lambda snapshot: snapshot[
                "root_container_processes"
            ].pop(),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                observation, support, transitions = fixture()
                mutate(observation["local_control_inventory"]["snapshot"])
                validate_schema4_observation(observation)
                with self.assertRaises(ClassificationError):
                    classify(observation, support, transitions)

    def test_schema2_rejects_added_removed_and_unowned_local_control_endpoints(self):
        def add_endpoint(snapshot):
            listener = json.loads(json.dumps(snapshot["unix_listeners"][-1]))
            listener["name_sha256"] = "f" * 64
            snapshot["unix_listeners"].append(listener)

        def remove_endpoint(snapshot):
            snapshot["unix_listeners"].pop()

        def make_endpoint_unowned(snapshot):
            snapshot["unix_listeners"][0]["owners"] = []
            snapshot["unix_listeners"][0]["ownership_complete"] = False
            snapshot["ownership_complete"] = False

        for label, mutate in {
            "added": add_endpoint,
            "removed": remove_endpoint,
            "unowned": make_endpoint_unowned,
        }.items():
            with self.subTest(label=label):
                observation, support, transitions = fixture()
                mutate(observation["local_control_inventory"]["snapshot"])
                with self.assertRaises(ClassificationError):
                    classify(observation, support, transitions)

    def test_schema2_ignores_only_bounded_inaccessible_listener_count(self):
        for count in (0, 15):
            with self.subTest(count=count):
                observation, support, transitions = fixture()
                inventory = observation["local_control_inventory"]
                inventory["attempts"] = 2
                inventory["snapshot"][
                    "inaccessible_root_filesystem_listener_count"
                ] = count
                validate_schema4_observation(observation)
                self.assertTrue(classify(observation, support, transitions)["run_bundle"])

    def test_schema2_validates_the_bundled_local_control_hash_contract(self):
        observation, support, transitions = fixture()
        inventory = support["data"]["hosted_runner_fingerprint"]["accepted"][
            "local_control_inventory"
        ]
        inventory["unix_name_hash_schema"] = "fence-unix-name-v2"
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        inventory = support["data"]["hosted_runner_fingerprint"]["accepted"][
            "local_control_inventory"
        ]
        inventory[
            "standard_lockdown_removable_unix_listener_name_sha256"
        ] = inventory["unix_listeners"][-1]["name_sha256"]
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_schema2_validates_bundle_and_transition_shapes(self):
        observation, support, transitions = fixture()
        accepted = support["data"]["hosted_runner_fingerprint"]["accepted"]
        accepted["executable_paths"] = []
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        self.accepted_source(support, "sudoers")["alternate_sha256"].append(
            "not-a-digest"
        )
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        transitions["transitions"][0]["extra"] = True
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        transitions["transitions"][0]["name"] = "unknown"
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_all_digest_mismatches_must_have_exact_transitions(self):
        observation, support, transitions = fixture()
        self.observed_source(observation)["sha256"] = FIXTURE_TRANSITION_DIGEST
        self.observed_source(observation, "sudoers")["sha256"] = "7" * 64
        transitions["transitions"].append(
            {
                "path_class": "main_policy",
                "name": "sudoers",
                "sha256": "7" * 64,
            }
        )
        self.assertFalse(classify(observation, support, transitions)["run_bundle"])

        transitions["transitions"].pop()
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_transition_cannot_mask_non_digest_drift(self):
        observation, support, transitions = fixture()
        self.observed_source(observation)["sha256"] = FIXTURE_TRANSITION_DIGEST
        observation["required_paths"][0]["mode"] = "0700"
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)


def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def main(arguments):
    if arguments == ["--self-test"]:
        program = unittest.main(argv=[sys.argv[0]], exit=False)
        return 0 if program.result.wasSuccessful() else 1
    if len(arguments) != 4:
        raise SystemExit(
            "usage: action_bundle_host.py <observation> <bundle-support> <transitions> <github-output>"
        )
    observation_path, support_path, transitions_path, output_path = arguments
    try:
        result = classify(
            load_json(observation_path),
            load_json(support_path),
            load_json(transitions_path),
        )
    except (ClassificationError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise SystemExit(f"Action bundle host classification failed: {error}") from error
    with pathlib.Path(output_path).open("a", encoding="utf-8") as output:
        output.write(f"run_bundle={'true' if result['run_bundle'] else 'false'}\n")
        output.write(f"classification={result['classification']}\n")
    if result["run_bundle"]:
        print("bundled Action host fingerprint is compatible")
    else:
        print("bundled Action activation skipped: source-known host fingerprint postdates bundle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
