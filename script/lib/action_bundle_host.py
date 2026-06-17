#!/usr/bin/env python3

import json
import pathlib
import sys
import unittest


class ClassificationError(ValueError):
    pass


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


def compare_fixed_fingerprint(observation, accepted):
    require(observation.get("schema_version") == 3, "host observation schema mismatch")
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
            (
                observed["present"],
                observed["type"],
                observed["mode"],
                observed["owner"],
                observed["group"],
            )
            == (
                socket["present"],
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
    mismatches = compare_fixed_fingerprint(observation, fingerprint["accepted"])
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
    accepted = {
        "os_id": "ubuntu",
        "os_version_id": "24.04",
        "architecture": "x86_64",
        "expected_principal": "runner",
        "required_runner_groups": ["runner", "docker"],
        "executable_paths": ["/usr/bin/tool"],
        "resolver": {
            "resolv_conf_path": "/etc/resolv.conf",
            "canonical_target": "/run/resolver",
            "target_uid": 991,
            "target_mode": "0644",
        },
        "sudo_policy_sources": [
            {
                "path_class": "drop_in",
                "name": "runner",
                "sha256": "old",
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
                "path": "/run/docker.sock",
                "present": True,
                "kind": "socket",
                "mode": "0660",
                "owner": "root",
                "group": "docker",
            }
        ],
        "required_docker_running_workload_count": 0,
    }
    observation = {
        "schema_version": 3,
        "status": "observation_only_no_protection",
        "host": {
            "os_id": "ubuntu",
            "os_version_id": "24.04",
            "architecture": "x86_64",
            "runner_principal": "runner",
            "runner_groups": ["docker", "runner"],
        },
        "required_paths": [
            {
                "path": "/usr/bin/tool",
                "present": True,
                "canonical_target": "/usr/bin/tool",
                "path_type": "regular",
                "target_type": "regular",
                "owner_class": "root",
                "runner_writable": False,
                "executable": True,
                "runner_executable": True,
            }
        ],
        "resolver": {
            "status": "observed",
            "is_symlink": True,
            "path": "/etc/resolv.conf",
            "canonical_target": "/run/resolver",
            "target_type": "regular",
            "target_uid": 991,
            "target_mode": "0644",
        },
        "sudo": {
            "policy_source_hashes": [
                {
                    "path_class": "drop_in",
                    "name": "runner",
                    "sha256": "old",
                    "target_type": "regular",
                    "owner_class": "root",
                    "group_class": "root",
                    "runner_writable": False,
                    "runner_nopasswd_markers": ["principal"],
                }
            ]
        },
        "systemd": {
            "units": [
                {
                    "name": "docker.service",
                    "load_state": "loaded",
                    "active_state": "active",
                    "unit_file_state": "enabled",
                }
            ]
        },
        "container_runtime": {
            "sockets": [
                {
                    "path": "/run/docker.sock",
                    "present": True,
                    "type": "socket",
                    "mode": "0660",
                    "owner": "root",
                    "group": "docker",
                }
            ],
            "docker_running_workload_count": 0,
        },
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
            {"path_class": "drop_in", "name": "runner", "sha256": "new"}
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
        observation["sudo"]["policy_source_hashes"][0]["sha256"] = "new"
        self.assertEqual(
            classify(observation, support, transitions),
            {
                "run_bundle": False,
                "classification": "source_known_bundle_old_sudo_policy",
            },
        )

    def test_rejects_unknown_digest_and_other_drift(self):
        observation, support, transitions = fixture()
        observation["sudo"]["policy_source_hashes"][0]["sha256"] = "unknown"
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)
        observation, support, transitions = fixture()
        observation["host"]["runner_groups"] = ["runner"]
        with self.assertRaises(ClassificationError):
            classify(observation, support, transitions)

    def test_refreshed_bundle_runs_on_transition_digest(self):
        observation, support, transitions = fixture()
        observation["sudo"]["policy_source_hashes"][0]["sha256"] = "new"
        support["data"]["hosted_runner_fingerprint"]["accepted"][
            "sudo_policy_sources"
        ][0]["alternate_sha256"] = ["new"]
        self.assertEqual(
            classify(observation, support, transitions)["classification"],
            "bundle_compatible",
        )


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
