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
    UNREVIEWED_EXECUTABLE_PATH,
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


SCHEMA4_OBSERVATION_ONLY_EXECUTABLE_PATHS = {"/usr/bin/test"}
FIXTURE_ACCEPTED_DIGEST = "0" * 64
FIXTURE_TRANSITION_DIGEST = "1" * 64
FIXTURE_UNKNOWN_DIGEST = "2" * 64


def require(condition, message):
    if not condition:
        raise ClassificationError(message)


def index_by(items, *keys):
    indexed = {}
    for item in items:
        key = tuple(item.get(name) for name in keys)
        require(None not in key, "fingerprint item omitted a required identity field")
        require(key not in indexed, "fingerprint item identity was duplicated")
        indexed[key] = item
    return indexed


def accepted_digests(source):
    return {source["sha256"], *source.get("alternate_sha256", [])}


def project_fields(item, fields):
    return {
        field: list(item[field]) if isinstance(item[field], list) else item[field]
        for field in fields
        if field in item
    }


def project_schema4_observation_to_schema1(observation, accepted):
    try:
        validate_schema4_observation(observation)
    except ValueError as error:
        raise ClassificationError(
            f"host schema 4 observation is invalid: {error}"
        ) from error
    inventory = observation["local_control_inventory"]
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
    require(
        inventory["status"] == "stable",
        "host local control observation is unavailable",
    )
    require(
        inventory["stable"] is True,
        "host local control observation is unstable",
    )
    require(
        inventory["snapshot"]["scan_status"] == "within_bounds"
        and inventory["snapshot"]["reachability_complete"] is True
        and inventory["snapshot"]["ownership_complete"] is True,
        "host local control observation is incomplete",
    )

    required_paths = index_by(observation["required_paths"], "path")
    accepted_paths = set(accepted["executable_paths"])
    require(
        set(required_paths)
        == {(path,) for path in accepted_paths | SCHEMA4_OBSERVATION_ONLY_EXECUTABLE_PATHS},
        "schema 4 executable observation set cannot be projected to schema 1",
    )
    accepted_units = {unit["name"] for unit in accepted["container_units"]}
    return {
        "schema_version": 1,
        "status": observation["status"],
        "host": project_fields(
            observation["host"],
            (
                "os_id",
                "os_version_id",
                "architecture",
                "runner_principal",
                "runner_groups",
            ),
        ),
        "required_paths": [
            project_fields(
                required_paths[(path,)],
                (
                    "path",
                    "present",
                    "canonical_target",
                    "path_type",
                    "target_type",
                    "owner_class",
                    "runner_writable",
                    "executable",
                    "runner_executable",
                ),
            )
            for path in accepted["executable_paths"]
        ],
        "resolver": project_fields(
            observation["resolver"],
            (
                "status",
                "path",
                "is_symlink",
                "canonical_target",
                "target_type",
                "target_mode",
                "target_uid",
            ),
        ),
        "sudo": {
            "policy_source_hashes": [
                project_fields(
                    source,
                    (
                        "path_class",
                        "name",
                        "sha256",
                        "target_type",
                        "owner_class",
                        "group_class",
                        "runner_writable",
                        "runner_nopasswd_markers",
                    ),
                )
                for source in observation["sudo"]["policy_source_hashes"]
            ]
        },
        "systemd": {
            "units": [
                project_fields(
                    unit,
                    ("name", "load_state", "active_state", "unit_file_state"),
                )
                for unit in observation["systemd"]["units"]
                if unit["name"] in accepted_units
            ]
        },
        "container_runtime": {
            "sockets": [
                project_fields(
                    socket,
                    ("path", "present", "type", "mode", "owner", "group"),
                )
                for socket in observation["container_runtime"]["sockets"]
            ],
            "docker_running_workload_count": observation["container_runtime"][
                "docker_running_workload_count"
            ],
        },
    }


def compare_fixed_fingerprint(observation, accepted):
    require(observation.get("schema_version") == 1, "host projection schema mismatch")
    require(
        observation.get("status") == "observation_only_no_protection",
        "host observation status mismatch",
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
    require(
        set(required_paths) == {(path,) for path in accepted["executable_paths"]},
        "fixed executable path set drifted",
    )
    for path in accepted["executable_paths"]:
        item = required_paths[(path,)]
        require(item["present"] is True, "fixed executable is absent")
        require(item["canonical_target"] == path, "fixed executable target drifted")
        require(item["path_type"] == "regular", "fixed executable path type drifted")
        require(item["target_type"] == "regular", "fixed executable target type drifted")
        require(item["owner_class"] == "root", "fixed executable owner drifted")
        require(item["runner_writable"] is False, "fixed executable became runner writable")
        require(item["executable"] is True, "fixed executable lost execute permission")
        require(
            item["runner_executable"] is True,
            "fixed executable is unavailable to the runner",
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
        require(observed["target_type"] == "regular", "sudo policy type drifted")
        require(observed["owner_class"] == "root", "sudo policy owner drifted")
        require(observed["group_class"] == "root", "sudo policy group drifted")
        require(observed["runner_writable"] is False, "sudo policy became runner writable")
        require(
            observed["runner_nopasswd_markers"]
            == source["runner_nopasswd_markers"],
            "sudo policy marker classification drifted",
        )
        if observed["sha256"] not in accepted_digests(source):
            digest_mismatches.append((*key, observed["sha256"]))

    observed_units = index_by(observation["systemd"]["units"], "name")
    for unit in accepted["container_units"]:
        key = (unit["name"],)
        require(key in observed_units, "fixed container unit is absent")
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
    return digest_mismatches


def classify(observation, support, transitions):
    require(support.get("schema_version") == 1, "bundle support schema mismatch")
    require(support.get("command") == "check-support", "bundle support command mismatch")
    require(support.get("status") == "success", "bundle support command failed")
    fingerprint = support["data"]["hosted_runner_fingerprint"]
    require(fingerprint["schema_version"] == 1, "bundle fingerprint schema mismatch")
    require(
        fingerprint["status"] == "accepted_reference_not_checked",
        "bundle fingerprint status mismatch",
    )
    require(transitions.get("schema_version") == 1, "transition schema mismatch")
    transition_index = index_by(
        transitions.get("transitions", []), "path_class", "name", "sha256"
    )
    projected = project_schema4_observation_to_schema1(
        observation, fingerprint["accepted"]
    )
    mismatches = compare_fixed_fingerprint(projected, fingerprint["accepted"])
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
    accepted_paths = [
        path for path in SCHEMA4_REQUIRED_PATHS if path != "/usr/bin/test"
    ]

    def metadata(path, target_type="regular"):
        return {
            "path": path,
            "present": True,
            "canonical_target": path,
            "path_type": target_type,
            "target_type": target_type,
            "owner_class": "root",
            "group_class": "root",
            "mode": "0755",
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

    accepted = {
        "os_id": "ubuntu",
        "os_version_id": "24.04",
        "architecture": "x86_64",
        "expected_principal": "runner",
        "required_runner_groups": ["runner", "docker"],
        "executable_paths": accepted_paths,
        "resolver": {
            "resolv_conf_path": "/etc/resolv.conf",
            "canonical_target": SCHEMA4_REVIEWED_RESOLVER_TARGET,
            "target_uid": 991,
            "target_mode": "0644",
        },
        "sudo_policy_sources": [
            {
                "path_class": "drop_in",
                "name": "runner",
                "sha256": FIXTURE_ACCEPTED_DIGEST,
                "alternate_sha256": [],
                "runner_nopasswd_markers": ["principal"],
            }
        ],
        "container_units": [
            {
                "name": "docker.service",
                "load_state": "loaded",
                "active_state": "active",
                "unit_file_state": "enabled",
            }
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
            "runner_groups": ["docker", "runner"],
        },
        "required_paths": [command_metadata(path) for path in SCHEMA4_REQUIRED_PATHS],
        "permission_ancestor_directories": [
            {
                **metadata(path, "directory"),
                "runner_searchable": True,
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
            "policy_source_hashes": [
                {
                    "path_class": "drop_in",
                    "name": "runner",
                    "sha256": FIXTURE_ACCEPTED_DIGEST,
                    "canonical_target": "/etc/sudoers.d/runner",
                    "target_type": "regular",
                    "owner_class": "root",
                    "group_class": "root",
                    "mode": "0440",
                    "device": 1,
                    "inode": 1,
                    "runner_writable": False,
                    "contains_nopasswd_directive": True,
                    "runner_nopasswd_markers": ["principal"],
                }
            ],
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
                "inaccessible_root_filesystem_listener_count": 0,
                "reachability_complete": True,
                "ownership_complete": True,
                "root_container_processes": [],
                "unix_listeners": [],
                "tcp_listeners": [],
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
                "schema_version": 1,
                "status": "accepted_reference_not_checked",
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
    def test_runs_bundle_for_matching_host(self):
        observation, support, transitions = fixture()
        self.assertEqual(
            classify(observation, support, transitions),
            {"run_bundle": True, "classification": "bundle_compatible"},
        )

    def test_accepts_only_reviewed_source_known_transition(self):
        observation, support, transitions = fixture()
        observation["sudo"]["policy_source_hashes"][0][
            "sha256"
        ] = FIXTURE_TRANSITION_DIGEST
        self.assertEqual(
            classify(observation, support, transitions),
            {
                "run_bundle": False,
                "classification": "source_known_bundle_old_sudo_policy",
            },
        )

    def test_rejects_unknown_digest_and_other_drift(self):
        observation, support, transitions = fixture()
        observation["sudo"]["policy_source_hashes"][0][
            "sha256"
        ] = FIXTURE_UNKNOWN_DIGEST
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
        observation["sudo"]["policy_source_hashes"][0][
            "sha256"
        ] = FIXTURE_TRANSITION_DIGEST
        support["data"]["hosted_runner_fingerprint"]["accepted"][
            "sudo_policy_sources"
        ][0]["alternate_sha256"] = [FIXTURE_TRANSITION_DIGEST]
        self.assertEqual(
            classify(observation, support, transitions)["classification"],
            "bundle_compatible",
        )

    def test_schema4_projection_is_explicit_and_fails_closed(self):
        observation, support, transitions = fixture()
        observation["schema_version"] = 3
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

    def test_schema4_projection_validates_all_required_new_evidence(self):
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

    def test_schema4_valid_observation_only_values_do_not_change_schema1_decision(self):
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
        observation["permission_ancestor_directories"][0][
            "synthetic_create_delete_probe"
        ] = "unavailable"
        self.assertEqual(
            classify(observation, support, transitions)["classification"],
            "bundle_compatible",
        )

    def test_schema4_projection_has_exact_schema1_shape(self):
        observation, support, _ = fixture()
        accepted = support["data"]["hosted_runner_fingerprint"]["accepted"]
        projected = project_schema4_observation_to_schema1(observation, accepted)
        self.assertEqual(
            set(projected),
            {
                "schema_version",
                "status",
                "host",
                "required_paths",
                "resolver",
                "sudo",
                "systemd",
                "container_runtime",
            },
        )
        self.assertEqual(
            set(projected["host"]),
            {
                "os_id",
                "os_version_id",
                "architecture",
                "runner_principal",
                "runner_groups",
            },
        )
        self.assertTrue(
            all(
                set(item)
                == {
                    "path",
                    "present",
                    "canonical_target",
                    "path_type",
                    "target_type",
                    "owner_class",
                    "runner_writable",
                    "executable",
                    "runner_executable",
                }
                for item in projected["required_paths"]
            )
        )
        self.assertEqual(
            set(projected["resolver"]),
            {
                "status",
                "path",
                "is_symlink",
                "canonical_target",
                "target_type",
                "target_mode",
                "target_uid",
            },
        )
        self.assertEqual(set(projected["sudo"]), {"policy_source_hashes"})
        self.assertTrue(
            all(
                set(source)
                == {
                    "path_class",
                    "name",
                    "sha256",
                    "target_type",
                    "owner_class",
                    "group_class",
                    "runner_writable",
                    "runner_nopasswd_markers",
                }
                for source in projected["sudo"]["policy_source_hashes"]
            )
        )
        self.assertEqual(set(projected["systemd"]), {"units"})
        self.assertEqual(
            {unit["name"] for unit in projected["systemd"]["units"]},
            {unit["name"] for unit in accepted["container_units"]},
        )
        self.assertNotIn("azure_platform_agent", projected["systemd"])
        self.assertEqual(
            set(projected["container_runtime"]),
            {"sockets", "docker_running_workload_count"},
        )
        self.assertTrue(
            all(
                set(socket)
                == {"path", "present", "type", "mode", "owner", "group"}
                for socket in projected["container_runtime"]["sockets"]
            )
        )

    def test_schema4_rejects_raw_unreviewed_public_strings(self):
        def set_sudo_source(observation):
            source = observation["sudo"]["policy_source_hashes"][0]
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
            source = observation["sudo"]["policy_source_hashes"][0]
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

    def test_schema4_local_inventory_is_observation_only_for_schema1_bundle(self):
        observation, support, transitions = fixture()
        observation["local_control_inventory"]["snapshot"]["tcp_listeners"] = [
            {
                "family": "ipv4",
                "bind_class": "loopback",
                "port": 8080,
                "owners": [
                    {
                        "uid": 0,
                        "executable_basename": "exampled",
                        "canonical_executable": UNREVIEWED_EXECUTABLE_PATH,
                        "unified_cgroup": "/init.scope",
                        "processes": 1,
                    }
                ],
                "ownership_complete": True,
                "instances": 1,
            }
        ]
        self.assertEqual(
            classify(observation, support, transitions)["classification"],
            "bundle_compatible",
        )

    def test_schema4_projection_rejects_unavailable_new_evidence(self):
        observation, support, transitions = fixture()
        inventory = observation["local_control_inventory"]
        inventory["status"] = "unavailable"
        inventory["snapshot"]["scan_status"] = "unavailable"
        inventory["snapshot"]["unavailable_inputs"] = [
            "proc",
            "socket_ownership",
            "unix_reachability",
        ]
        inventory["snapshot"]["reachability_complete"] = False
        inventory["snapshot"]["ownership_complete"] = False
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_schema4_projection_requires_complete_untruncated_evidence(self):
        mutations = {
            "unstable inventory": lambda observation: observation[
                "local_control_inventory"
            ].update({"status": "unstable", "stable": False, "attempts": 3}),
            "bounded inventory": lambda observation: (
                observation["local_control_inventory"].update(
                    {"status": "bounds_exceeded"}
                ),
                observation["local_control_inventory"]["snapshot"].update(
                    {
                        "scan_status": "bounds_exceeded",
                        "bounds_exceeded": ["tcp_listeners"],
                    }
                ),
            ),
            "truncated sudo sources": lambda observation: observation["sudo"].update(
                {"policy_sources_truncated": True}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                observation, support, transitions = fixture()
                mutate(observation)
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

    def test_schema4_projection_rejects_raw_or_contradictory_nested_evidence(self):
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
                            "executable_basename": "exampled",
                            "canonical_executable": UNREVIEWED_EXECUTABLE_PATH,
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

    def test_schema4_projection_rejects_malformed_legacy_evidence(self):
        observation, support, transitions = fixture()
        observation["required_paths"].append(observation["required_paths"][0])
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

        observation, support, transitions = fixture()
        del observation["resolver"]["canonical_target"]
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
