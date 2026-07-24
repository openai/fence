#!/usr/bin/env python3

import copy
import datetime
import sys
import unittest


MAX_PROTECTED_SECONDS = 180
ACTION_ZERO_INPUT_BURST_JOB = "action zero-input standard"
ACTION_ZERO_INPUT_BURST_ACTIVATION = "activate bundled Fence agent with strict defaults"
ACTION_ZERO_INPUT_BURST_DESTINATIONS = ("192.0.2.1", "192.0.2.2")
EXPECTED_FINALIZATION_STEPS = {
    "integration": {
        "protected finalization quiet-1": "run quiet packaged trusted-launcher block",
        "protected finalization quiet-2": "run quiet packaged trusted-launcher block",
        "protected finalization quiet-3": "run quiet packaged trusted-launcher block",
        "protected standard-opt-out required": "run packaged trusted-launcher block",
    },
    "action": {
        "action finalization quiet-1": "activate bundled Fence agent without post-ready warming",
        "action finalization quiet-2": "activate bundled Fence agent without post-ready warming",
        "action finalization quiet-3": "activate bundled Fence agent without post-ready warming",
    },
}


def _timestamp(value, description):
    if not isinstance(value, str) or not value:
        raise ValueError(f"protected finalization {description} timestamp was invalid")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(
            f"protected finalization {description} timestamp was invalid"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"protected finalization {description} timestamp was invalid")
    return parsed


def _successful_step(step, job_name, description):
    if step.get("status") != "completed" or step.get("conclusion") != "success":
        raise ValueError(
            f"protected finalization {description} did not complete successfully: "
            f"{job_name}"
        )
    started = _timestamp(step.get("started_at"), f"{description} start for {job_name}")
    completed = _timestamp(
        step.get("completed_at"), f"{description} completion for {job_name}"
    )
    if completed < started:
        raise ValueError(
            f"protected finalization {description} timestamps were out of order: "
            f"{job_name}"
        )
    return started, completed


def validate_finalization_jobs(document, job_set):
    if not isinstance(job_set, str) or job_set not in EXPECTED_FINALIZATION_STEPS:
        raise ValueError("protected finalization job set was invalid")
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), list):
        raise ValueError("protected finalization job metadata was invalid")

    expected = EXPECTED_FINALIZATION_STEPS[job_set]
    jobs = {}

    for job in document["jobs"]:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            raise ValueError("protected finalization job metadata was invalid")
        observed_name = job["name"]
        matches = [
            name
            for name in expected
            if observed_name == name or observed_name.endswith(f" / {name}")
        ]
        if not matches:
            continue
        if len(matches) != 1:
            raise ValueError(
                f"protected finalization job name was ambiguous: {observed_name}"
            )

        name = matches[0]
        if observed_name != name:
            prefix = observed_name[: -(len(name) + 3)]
            if (
                not prefix
                or len(prefix) > 128
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in prefix)
            ):
                raise ValueError(
                    "protected finalization reusable-workflow prefix was invalid: "
                    f"{observed_name}"
                )
        if name in jobs:
            raise ValueError(f"protected finalization job was duplicated: {name}")
        jobs[name] = job

    missing = sorted(set(expected) - set(jobs))
    if missing:
        raise ValueError(
            f"protected finalization jobs were not observable: {', '.join(missing)}"
        )

    for name, job in jobs.items():
        job_id = job.get("id")
        if not isinstance(job_id, int) or isinstance(job_id, bool) or job_id <= 0:
            raise ValueError(f"protected finalization job identifier was invalid: {name}")
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            raise ValueError(
                f"protected finalization job did not complete successfully: {name}"
            )

        started = _timestamp(job.get("started_at"), f"job start for {name}")
        completed = _timestamp(job.get("completed_at"), f"job completion for {name}")
        steps = job.get("steps")
        if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
            raise ValueError(f"protected finalization job steps were invalid: {name}")

        activation_name = expected[name]
        activations = [step for step in steps if step.get("name") == activation_name]
        if len(activations) != 1:
            raise ValueError(
                f"protected finalization activation step was missing or duplicated: {name}"
            )
        activated, activation_completed = _successful_step(
            activations[0], name, "activation step"
        )
        if not started <= activated <= activation_completed <= completed:
            raise ValueError(
                f"protected finalization job and activation timestamps were out of order: "
                f"{name}"
            )
        if (completed - activated).total_seconds() > MAX_PROTECTED_SECONDS:
            raise ValueError(f"protected finalization exceeded 180 seconds: {name}")

        post_steps = [
            step for step in steps if step.get("name") == f"Post {activation_name}"
        ]
        if job_set == "action" and not post_steps:
            raise ValueError(f"protected finalization post hook was missing: {name}")
        if len(post_steps) > 1:
            raise ValueError(f"protected finalization post hook was duplicated: {name}")
        if post_steps:
            post_started, post_completed = _successful_step(
                post_steps[0], name, "post hook"
            )
            if not activation_completed <= post_started <= post_completed <= completed:
                raise ValueError(
                    f"protected finalization post-hook timestamps were out of order: {name}"
                )

    return jobs


def validate_action_zero_input_burst_job(document):
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), list):
        raise ValueError("blocked-burst job metadata was invalid")

    matching = []
    for job in document["jobs"]:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            raise ValueError("blocked-burst job metadata was invalid")
        observed_name = job["name"]
        if observed_name != ACTION_ZERO_INPUT_BURST_JOB and not observed_name.endswith(
            f" / {ACTION_ZERO_INPUT_BURST_JOB}"
        ):
            continue
        if observed_name != ACTION_ZERO_INPUT_BURST_JOB:
            prefix = observed_name[: -(len(ACTION_ZERO_INPUT_BURST_JOB) + 3)]
            if (
                not prefix
                or len(prefix) > 128
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in prefix)
            ):
                raise ValueError("blocked-burst reusable-workflow prefix was invalid")
        matching.append(job)

    if len(matching) != 1:
        raise ValueError("blocked-burst job was missing or duplicated")
    job = matching[0]
    job_id = job.get("id")
    if not isinstance(job_id, int) or isinstance(job_id, bool) or job_id <= 0:
        raise ValueError("blocked-burst job identifier was invalid")
    if job.get("status") != "completed" or job.get("conclusion") != "success":
        raise ValueError("blocked-burst job did not complete successfully")
    started = _timestamp(job.get("started_at"), "blocked-burst job start")
    completed = _timestamp(job.get("completed_at"), "blocked-burst job completion")
    steps = job.get("steps")
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        raise ValueError("blocked-burst job steps were invalid")

    ordered_steps = []
    for name, description in (
        (ACTION_ZERO_INPUT_BURST_ACTIVATION, "blocked-burst activation"),
        ("verify zero-input Action lifecycle", "blocked-burst evidence"),
        (f"Post {ACTION_ZERO_INPUT_BURST_ACTIVATION}", "blocked-burst post hook"),
    ):
        matches = [step for step in steps if step.get("name") == name]
        if len(matches) != 1:
            raise ValueError(f"{description} was missing or duplicated")
        ordered_steps.append(_successful_step(matches[0], ACTION_ZERO_INPUT_BURST_JOB, description))

    (activated, activation_completed), (evidence_started, evidence_completed), (
        post_started,
        post_completed,
    ) = ordered_steps
    if not (
        started
        <= activated
        <= activation_completed
        <= evidence_started
        <= evidence_completed
        <= post_started
        <= post_completed
        <= completed
    ):
        raise ValueError("blocked-burst job and post-hook timestamps were out of order")
    return job


def validate_action_zero_input_burst_report(report):
    if not isinstance(report, dict) or report.get("mode") != "block" or report.get("result") != "warning":
        raise ValueError("blocked-burst report was not verified warning-mode block evidence")
    omissions = report.get("omissions")
    if (
        not isinstance(omissions, dict)
        or type(omissions.get("network_rows")) is not int
        or omissions["network_rows"] <= 0
        or omissions.get("byte_budget_exceeded") is not False
        or omissions.get("source_truncated") is not False
    ):
        raise ValueError("blocked-burst report did not disclose bounded network row omissions")
    warnings = report.get("warnings")
    if (
        not isinstance(warnings, dict)
        or type(warnings.get("critical_findings")) is not int
        or warnings["critical_findings"] != 0
        or warnings.get("github_artifact_uploads_enabled") is not False
    ):
        raise ValueError("blocked-burst report contained critical or artifact-enabled evidence")
    network = report.get("network")
    if not isinstance(network, list) or len(network) > 20:
        raise ValueError("blocked-burst report did not contain bounded network evidence")

    for destination in ACTION_ZERO_INPUT_BURST_DESTINATIONS:
        rows = [
            row
            for row in network
            if isinstance(row, dict)
            and row.get("destination_kind") == "ip"
            and row.get("destination") == destination
            and row.get("decision") == "blocked"
            and type(row.get("count")) is int
            and row["count"] > 0
        ]
        if len(rows) != 1:
            raise ValueError(f"blocked-burst destination was missing or duplicated: {destination}")
        activities = rows[0].get("activities")
        if (
            not isinstance(activities, list)
            or sum(
                isinstance(activity, dict)
                and activity.get("kind") == "connection_attempt"
                and activity.get("protocol") == "udp"
                and type(activity.get("port")) is int
                and activity["port"] == 443
                and type(activity.get("count")) is int
                and activity["count"] > 0
                for activity in activities
            )
            != 1
        ):
            raise ValueError(f"blocked-burst UDP evidence was invalid: {destination}")
    return report


class ProtectedFinalizationTests(unittest.TestCase):
    def document(self, job_set="integration", protected_seconds=45, setup_seconds=155):
        base = datetime.datetime(2026, 7, 23, tzinfo=datetime.timezone.utc)
        activated = base + datetime.timedelta(seconds=setup_seconds)
        completed = activated + datetime.timedelta(seconds=protected_seconds)
        activation_completed = activated + datetime.timedelta(
            seconds=min(20, protected_seconds)
        )

        def timestamp(value):
            return value.isoformat().replace("+00:00", "Z")

        jobs = []
        for job_id, (name, activation_name) in enumerate(
            EXPECTED_FINALIZATION_STEPS[job_set].items(), start=1
        ):
            activation = {
                "name": activation_name,
                "status": "completed",
                "conclusion": "success",
                "started_at": timestamp(activated),
                "completed_at": timestamp(activation_completed),
            }
            post = {
                "name": f"Post {activation_name}",
                "status": "completed",
                "conclusion": "success",
                "started_at": timestamp(activation_completed),
                "completed_at": timestamp(completed),
            }
            jobs.append(
                {
                    "id": job_id,
                    "name": name,
                    "status": "completed",
                    "conclusion": "success",
                    "started_at": timestamp(base),
                    "completed_at": timestamp(completed),
                    "steps": [activation, post],
                }
            )
        return {"jobs": jobs}

    def action_burst_document(self, prefix=""):
        document = self.document("action")
        job = copy.deepcopy(document["jobs"][0])
        job["id"] = 99
        job["name"] = (
            f"{prefix} / {ACTION_ZERO_INPUT_BURST_JOB}"
            if prefix
            else ACTION_ZERO_INPUT_BURST_JOB
        )
        activation = job["steps"][0]
        activation["name"] = ACTION_ZERO_INPUT_BURST_ACTIVATION
        post = job["steps"][1]
        post["name"] = f"Post {ACTION_ZERO_INPUT_BURST_ACTIVATION}"
        evidence = {
            "name": "verify zero-input Action lifecycle",
            "status": "completed",
            "conclusion": "success",
            "started_at": activation["completed_at"],
            "completed_at": activation["completed_at"],
        }
        job["steps"] = [activation, evidence, post]
        document["jobs"].append(job)
        return document

    def action_burst_report(self):
        return {
            "mode": "block",
            "result": "warning",
            "warnings": {
                "critical_findings": 0,
                "github_artifact_uploads_enabled": False,
            },
            "omissions": {
                "network_rows": 22,
                "byte_budget_exceeded": False,
                "source_truncated": False,
            },
            "network": [
                {
                    "destination_kind": "ip",
                    "destination": destination,
                    "decision": "blocked",
                    "count": 1,
                    "activities": [
                        {
                            "kind": "connection_attempt",
                            "protocol": "udp",
                            "port": 443,
                            "count": 1,
                        }
                    ],
                }
                for destination in ACTION_ZERO_INPUT_BURST_DESTINATIONS
            ],
        }

    def test_blocked_burst_job_preserves_exactly_three_quiet_replicas(self):
        for prefix in ("", "release verification"):
            with self.subTest(prefix=prefix):
                document = self.action_burst_document(prefix)
                job = validate_action_zero_input_burst_job(document)
                self.assertEqual(job["id"], 99)
                self.assertEqual(
                    set(validate_finalization_jobs(document, "action")),
                    set(EXPECTED_FINALIZATION_STEPS["action"]),
                )

    def test_missing_or_duplicated_blocked_burst_jobs_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            validate_action_zero_input_burst_job(self.document("action"))

        document = self.action_burst_document()
        duplicate = copy.deepcopy(document["jobs"][-1])
        duplicate["name"] = f"release / {ACTION_ZERO_INPUT_BURST_JOB}"
        document["jobs"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            validate_action_zero_input_burst_job(document)

        for prefix in ("x" * 129, "bad\nname", "bad\x7fname"):
            with self.subTest(prefix=repr(prefix)):
                with self.assertRaisesRegex(ValueError, "prefix was invalid"):
                    validate_action_zero_input_burst_job(self.action_burst_document(prefix))

    def test_blocked_burst_requires_exact_successful_activation_evidence_and_post(self):
        for index, expression in (
            (0, "activation"),
            (1, "evidence"),
            (2, "post hook"),
        ):
            for field, value in (("name", "unexpected"), ("status", "in_progress"), ("conclusion", "failure")):
                with self.subTest(index=index, field=field, value=value):
                    document = self.action_burst_document()
                    document["jobs"][-1]["steps"][index][field] = value
                    with self.assertRaisesRegex(ValueError, expression):
                        validate_action_zero_input_burst_job(document)

        for job_id in (None, 0, -1, True, "99"):
            with self.subTest(job_id=job_id):
                document = self.action_burst_document()
                document["jobs"][-1]["id"] = job_id
                with self.assertRaisesRegex(ValueError, "identifier was invalid"):
                    validate_action_zero_input_burst_job(document)

    def test_blocked_burst_job_rejects_invalid_or_reversed_timestamps(self):
        for index, field, value in (
            (0, "started_at", "invalid"),
            (1, "started_at", "2026-07-23T00:00:00"),
            (2, "completed_at", "2026-07-23T00:00:00Z"),
        ):
            with self.subTest(index=index, field=field):
                document = self.action_burst_document()
                document["jobs"][-1]["steps"][index][field] = value
                with self.assertRaisesRegex(ValueError, "timestamp|out of order"):
                    validate_action_zero_input_burst_job(document)

    def test_blocked_burst_report_requires_both_exact_final_udp_destinations(self):
        report = self.action_burst_report()
        self.assertIs(validate_action_zero_input_burst_report(report), report)

        invalid = []
        for field, value in (
            ("mode", "audit"),
            ("result", "healthy"),
        ):
            candidate = copy.deepcopy(report)
            candidate[field] = value
            invalid.append((candidate, "warning-mode block"))
        for field, value in (
            ("network_rows", 0),
            ("network_rows", True),
            ("byte_budget_exceeded", True),
            ("source_truncated", True),
        ):
            candidate = copy.deepcopy(report)
            candidate["omissions"][field] = value
            invalid.append((candidate, "row omissions"))
        for field, value in (("critical_findings", 1), ("github_artifact_uploads_enabled", True)):
            candidate = copy.deepcopy(report)
            candidate["warnings"][field] = value
            invalid.append((candidate, "critical or artifact"))
        for index in range(len(ACTION_ZERO_INPUT_BURST_DESTINATIONS)):
            candidate = copy.deepcopy(report)
            candidate["network"].pop(index)
            invalid.append((candidate, "destination was missing"))
        for field, value in (("kind", "dns_query"), ("protocol", "tcp"), ("port", 8443), ("count", 0)):
            candidate = copy.deepcopy(report)
            candidate["network"][0]["activities"][0][field] = value
            invalid.append((candidate, "UDP evidence"))

        for candidate, expression in invalid:
            with self.subTest(expression=expression, report=repr(candidate)):
                with self.assertRaisesRegex(ValueError, expression):
                    validate_action_zero_input_burst_report(candidate)

    def test_slow_setup_does_not_consume_the_protected_budget(self):
        for job_set in EXPECTED_FINALIZATION_STEPS:
            with self.subTest(job_set=job_set):
                document = self.document(job_set, setup_seconds=155)
                self.assertEqual(
                    set(validate_finalization_jobs(document, job_set)),
                    set(EXPECTED_FINALIZATION_STEPS[job_set]),
                )

    def test_180_seconds_pass_and_181_seconds_fail(self):
        for job_set in EXPECTED_FINALIZATION_STEPS:
            with self.subTest(job_set=job_set, seconds=180):
                validate_finalization_jobs(self.document(job_set, 180), job_set)
            with self.subTest(job_set=job_set, seconds=181):
                with self.assertRaisesRegex(ValueError, "exceeded 180 seconds"):
                    validate_finalization_jobs(self.document(job_set, 181), job_set)

    def test_all_exact_activation_mappings_are_required(self):
        for job_set, expected in EXPECTED_FINALIZATION_STEPS.items():
            for name in expected:
                with self.subTest(job_set=job_set, name=name):
                    document = self.document(job_set)
                    job = next(item for item in document["jobs"] if item["name"] == name)
                    job["steps"][0]["name"] += " renamed"
                    with self.assertRaisesRegex(ValueError, "activation step"):
                        validate_finalization_jobs(document, job_set)

    def test_reusable_workflow_prefixes_are_bounded(self):
        for job_set in EXPECTED_FINALIZATION_STEPS:
            with self.subTest(job_set=job_set):
                document = self.document(job_set)
                for job in document["jobs"]:
                    job["name"] = f"release verification / {job['name']}"
                self.assertEqual(
                    set(validate_finalization_jobs(document, job_set)),
                    set(EXPECTED_FINALIZATION_STEPS[job_set]),
                )
        for prefix in ("", "x" * 129, "bad\nname", "bad\x7fname"):
            with self.subTest(prefix=repr(prefix)):
                document = self.document()
                document["jobs"][0]["name"] = (
                    f"{prefix} / {document['jobs'][0]['name']}"
                )
                with self.assertRaisesRegex(ValueError, "prefix was invalid"):
                    validate_finalization_jobs(document, "integration")

    def test_missing_or_duplicate_jobs_fail_closed(self):
        document = self.document()
        document["jobs"].pop()
        with self.assertRaisesRegex(ValueError, "not observable"):
            validate_finalization_jobs(document, "integration")

        document = self.document()
        duplicate = copy.deepcopy(document["jobs"][0])
        duplicate["name"] = f"reusable / {duplicate['name']}"
        document["jobs"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "job was duplicated"):
            validate_finalization_jobs(document, "integration")

    def test_jobs_and_activation_steps_must_succeed(self):
        for field, value in (
            ("status", "queued"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("conclusion", "cancelled"),
            ("conclusion", "skipped"),
            ("conclusion", None),
        ):
            for target in ("job", "activation"):
                with self.subTest(target=target, field=field, value=value):
                    document = self.document()
                    record = document["jobs"][0]
                    if target == "activation":
                        record = record["steps"][0]
                    record[field] = value
                    with self.assertRaisesRegex(ValueError, "complete successfully"):
                        validate_finalization_jobs(document, "integration")

    def test_post_hooks_must_succeed_within_the_protected_window(self):
        for field, value in (
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("conclusion", "cancelled"),
            ("conclusion", "skipped"),
        ):
            with self.subTest(field=field, value=value):
                document = self.document("action")
                document["jobs"][0]["steps"][1][field] = value
                with self.assertRaisesRegex(ValueError, "post hook"):
                    validate_finalization_jobs(document, "action")

        document = self.document("action")
        post = document["jobs"][0]["steps"][1]
        post["completed_at"] = "2026-07-23T00:03:21Z"
        with self.assertRaisesRegex(ValueError, "post-hook timestamps"):
            validate_finalization_jobs(document, "action")

    def test_action_post_hook_is_required_and_integration_post_is_optional(self):
        document = self.document("action")
        document["jobs"][0]["steps"].pop(1)
        with self.assertRaisesRegex(ValueError, "post hook was missing"):
            validate_finalization_jobs(document, "action")

        document = self.document("integration")
        for job in document["jobs"]:
            job["steps"].pop(1)
        validate_finalization_jobs(document, "integration")

    def test_post_steps_cannot_be_mistaken_for_activation(self):
        document = self.document("action")
        document["jobs"][0]["steps"].pop(0)
        with self.assertRaisesRegex(ValueError, "activation step"):
            validate_finalization_jobs(document, "action")

        document = self.document("action")
        document["jobs"][0]["steps"].append(
            copy.deepcopy(document["jobs"][0]["steps"][0])
        )
        with self.assertRaisesRegex(ValueError, "activation step"):
            validate_finalization_jobs(document, "action")

        document = self.document("action")
        document["jobs"][0]["steps"].append(
            copy.deepcopy(document["jobs"][0]["steps"][1])
        )
        with self.assertRaisesRegex(ValueError, "post hook was duplicated"):
            validate_finalization_jobs(document, "action")

    def test_invalid_and_timezone_naive_timestamps_are_rejected(self):
        invalid_values = (
            None,
            "",
            "not-a-timestamp",
            "2026-07-23T00:00:00",
            "2026-07-23T00:00:00+25:00",
            123,
        )
        for target in ("job", "activation", "post"):
            for field in ("started_at", "completed_at"):
                for value in invalid_values:
                    with self.subTest(target=target, field=field, value=value):
                        document = self.document("action")
                        if target == "job":
                            record = document["jobs"][0]
                        elif target == "activation":
                            record = document["jobs"][0]["steps"][0]
                        else:
                            record = document["jobs"][0]["steps"][1]
                        record[field] = value
                        with self.assertRaisesRegex(ValueError, "timestamp was invalid"):
                            validate_finalization_jobs(document, "action")

    def test_reversed_timestamps_are_rejected(self):
        cases = (
            ("job", "started_at", "2026-07-23T00:03:00Z"),
            ("job", "completed_at", "2026-07-23T00:02:30Z"),
            ("activation", "started_at", "2026-07-23T00:04:00Z"),
            ("activation", "completed_at", "2026-07-23T00:02:00Z"),
            ("post", "started_at", "2026-07-23T00:02:00Z"),
            ("post", "completed_at", "2026-07-23T00:02:00Z"),
        )
        for target, field, value in cases:
            with self.subTest(target=target, field=field):
                document = self.document("action")
                if target == "job":
                    record = document["jobs"][0]
                elif target == "activation":
                    record = document["jobs"][0]["steps"][0]
                else:
                    record = document["jobs"][0]["steps"][1]
                record[field] = value
                with self.assertRaisesRegex(ValueError, "out of order"):
                    validate_finalization_jobs(document, "action")

    def test_invalid_metadata_and_job_identifiers_are_rejected(self):
        for document in (None, [], {}, {"jobs": None}, {"jobs": [None]}):
            with self.subTest(document=repr(document)):
                with self.assertRaisesRegex(ValueError, "metadata was invalid"):
                    validate_finalization_jobs(document, "integration")

        for job_id in (None, 0, -1, True, "1"):
            with self.subTest(job_id=job_id):
                document = self.document()
                document["jobs"][0]["id"] = job_id
                with self.assertRaisesRegex(ValueError, "identifier was invalid"):
                    validate_finalization_jobs(document, "integration")

        for steps in (None, {}, [None]):
            with self.subTest(steps=repr(steps)):
                document = self.document()
                document["jobs"][0]["steps"] = steps
                with self.assertRaisesRegex(ValueError, "steps were invalid"):
                    validate_finalization_jobs(document, "integration")

        for job_set in (None, "", "unknown", 1, []):
            with self.subTest(job_set=repr(job_set)):
                with self.assertRaisesRegex(ValueError, "job set was invalid"):
                    validate_finalization_jobs(self.document(), job_set)


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: protected_finalization.py --self-test")
    program = unittest.main(argv=[sys.argv[0]], exit=False)
    raise SystemExit(0 if program.result.wasSuccessful() else 1)
