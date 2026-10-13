#!/usr/bin/env python3

import copy
import datetime
import sys
import time
import unittest
import urllib.error
from unittest import mock

from dns_evidence import (
    MATERIALIZATION_REJECTION_REASONS,
    MAX_SAFE_INTEGER,
    validate_materialization_rejections,
)


MAX_PROTECTED_SECONDS = 180
MAX_JOB_COUNT = 100
METADATA_ATTEMPTS = 3
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
STRUCTURED_REPORT_FIELDS = {
    "schema_version", "mode", "result", "controls", "network", "warnings",
    "omissions", "suggested_allowlist",
}
PROTECTED_CONTROLS = {
    "network": "verified",
    "sudo": "disabled_verified",
    "containers": "disabled_verified",
    "protection_available": True,
    "readiness": "ready",
    "resident_health": "healthy",
}
QUIET_WARNINGS = {
    "critical_findings": 0,
    "critical_codes": [],
    "wildcard_rejections": 0,
    "wildcard_authorizations_truncated": False,
    "results_storage_attribution_failures": 0,
    "results_storage_authorizations_truncated": False,
    "github_artifact_uploads_enabled": False,
    "github_artifact_authorizations": 0,
}
QUIET_OMISSIONS = {
    "network_rows": 0,
    "hostname_recommendations": 0,
    "ip_recommendations": 0,
    "actor_entries": 0,
    "activity_entries": 0,
    "critical_codes": 0,
    "unparsed_findings": 0,
    "unparsed_finding_reasons": {
        "short_header": 0,
        "invalid_ipv4_header": 0,
        "ipv4_fragment": 0,
        "unsupported_ipv4_protocol": 0,
        "unsupported_ipv6_header": 0,
        "unknown_ip_version": 0,
        "invalid_port": 0,
        "unrecognized": 0,
    },
    "dns_evidence_missing": False,
    "source_truncated": False,
    "byte_budget_exceeded": False,
}


def _exact_fields(value, expected):
    return (
        isinstance(value, dict)
        and set(value) == set(expected)
        and all(
            type(value[key]) is type(item)
            and (_exact_fields(value[key], item) if isinstance(item, dict) else value[key] == item)
            for key, item in expected.items()
        )
    )


def validate_action_finalization_report(report, job_name):
    if job_name not in EXPECTED_FINALIZATION_STEPS["action"] and job_name != ACTION_ZERO_INPUT_BURST_JOB:
        raise ValueError("protected finalization report job was unknown")
    if not isinstance(report, dict) or set(report) != STRUCTURED_REPORT_FIELDS:
        raise ValueError("protected finalization structured report schema was invalid")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise ValueError("protected finalization structured report version was invalid")
    if report["mode"] != "block":
        raise ValueError("protected finalization structured report was not block evidence")
    if not _exact_fields(report["controls"], PROTECTED_CONTROLS):
        raise ValueError("protected finalization structured report controls were invalid")
    network = report["network"]
    if not isinstance(network, list) or len(network) > 20 or any(not isinstance(row, dict) for row in network):
        raise ValueError("protected finalization structured network evidence was invalid")
    warnings, omissions = report["warnings"], report["omissions"]
    if not isinstance(warnings, dict) or not isinstance(omissions, dict):
        raise ValueError("protected finalization structured report metadata was invalid")
    suggestions = report["suggested_allowlist"]
    if not isinstance(suggestions, list) or len(suggestions) > 20:
        raise ValueError("protected finalization structured allowlist suggestions were invalid")
    reasons = validate_materialization_rejections(warnings, public=True)
    if job_name == ACTION_ZERO_INPUT_BURST_JOB:
        return validate_action_zero_input_burst_report(report)

    total = warnings["materialization_rejections"]
    storage_rejections = warnings.get("results_storage_rejections")
    if type(storage_rejections) is not int or not 0 <= storage_rejections <= MAX_SAFE_INTEGER:
        raise ValueError("quiet finalization results-storage rejection count was invalid")
    expected_warnings = {
        **QUIET_WARNINGS,
        "materialization_rejections": total,
        "materialization_rejection_reasons": reasons,
        "results_storage_rejections": storage_rejections,
    }
    if not _exact_fields(warnings, expected_warnings):
        raise ValueError("quiet finalization report contained other warnings")
    if not _exact_fields(omissions, QUIET_OMISSIONS) or suggestions:
        raise ValueError("quiet finalization report omitted evidence or suggested an allowlist")
    if report["result"] != ("warning" if total else "healthy"):
        raise ValueError("quiet finalization report result did not match its DNS refusals")
    return report


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


class MetadataPending(ValueError):
    def __init__(self, message, *, unfinished_job=None):
        super().__init__(message)
        self.unfinished_job = unfinished_job


def _defer_metadata(error, pending):
    if pending is None:
        raise error
    pending.append(error)


def _ordered_step_times(job_started, job_completed, *intervals):
    times = [
        job_started,
        *(value for interval in intervals for value in interval if value is not None),
        job_completed,
    ]
    return all(previous <= current for previous, current in zip(times, times[1:]))


def _successful_step(step, job_name, description, job_started, job_completed, pending=None):
    if (
        step.get("status") in ("pending", "in_progress")
        and {"conclusion", "started_at", "completed_at"} <= step.keys()
        and step["conclusion"] is None
        and step["completed_at"] is None
    ):
        started = None
        if step["started_at"] is not None:
            started = _timestamp(step["started_at"], f"{description} start for {job_name}")
            if not job_started <= started <= job_completed:
                raise ValueError(f"protected finalization {description} start was outside the job: {job_name}")
        _defer_metadata(
            MetadataPending(
                f"protected finalization {description} metadata was unfinished: {job_name}",
                unfinished_job=job_name,
            ),
            pending,
        )
        return started, None
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


def _bounded_job_steps(job, started, completed, name, pending=None):
    # The required preflight locks mandatory workflow steps and the Action post hook.
    # Only absent/empty metadata may use this stricter, whole-job timing proof.
    steps = job.get("steps", [])
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        raise ValueError(f"protected finalization job steps were invalid: {name}")
    if not steps and (completed - started).total_seconds() > MAX_PROTECTED_SECONDS:
        _defer_metadata(
            MetadataPending(
                f"protected finalization activation step metadata was empty and job exceeded "
                f"{MAX_PROTECTED_SECONDS} seconds: {name}"
            ),
            pending,
        )
    return steps


def verified_finalization_jobs(fetch, job_set):
    unfinished_jobs = set()
    for attempt in range(METADATA_ATTEMPTS):
        try:
            document = fetch()
            pending = []
            jobs = validate_finalization_jobs(document, job_set, pending=pending)
            if job_set == "action":
                jobs[ACTION_ZERO_INPUT_BURST_JOB] = validate_action_zero_input_burst_job(document, pending=pending)
            unfinished_jobs.update(error.unfinished_job for error in pending if error.unfinished_job is not None)
            if pending:
                raise pending[0]
            for name in sorted(unfinished_jobs):
                if not jobs[name].get("steps"):
                    raise MetadataPending(f"protected finalization previously unfinished step metadata was absent: {name}")
            return jobs
        except urllib.error.HTTPError as error:
            if error.code not in {502, 503, 504}:
                raise
            if attempt == METADATA_ATTEMPTS - 1:
                raise ValueError(f"protected finalization metadata unavailable: HTTP {error.code}") from None
        except MetadataPending:
            if attempt == METADATA_ATTEMPTS - 1:
                raise
        time.sleep(5)


def validate_job_listing(document):
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("jobs"), list)
        or type(document.get("total_count")) is not int
        or not 0 <= document["total_count"] <= MAX_JOB_COUNT
        or document["total_count"] != len(document["jobs"])
    ):
        raise ValueError("protected finalization job listing was incomplete or exceeded its fixed bound")
    return document


def validate_finalization_jobs(document, job_set, *, pending=None):
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
        if completed < started:
            raise ValueError(f"protected finalization job timestamps were out of order: {name}")
        steps = _bounded_job_steps(job, started, completed, name, pending)
        if not steps:
            continue

        activation_name = expected[name]
        activations = [step for step in steps if step.get("name") == activation_name]
        if len(activations) != 1:
            raise ValueError(
                f"protected finalization activation step was missing or duplicated: {name}"
            )
        activation = _successful_step(
            activations[0], name, "activation step", started, completed, pending
        )
        if not _ordered_step_times(started, completed, activation):
            raise ValueError(
                f"protected finalization job and activation timestamps were out of order: "
                f"{name}"
            )
        if activation[0] is not None and (completed - activation[0]).total_seconds() > MAX_PROTECTED_SECONDS:
            raise ValueError(f"protected finalization exceeded 180 seconds: {name}")

        post_steps = [
            step for step in steps if step.get("name") == f"Post {activation_name}"
        ]
        if job_set == "action" and not post_steps:
            raise ValueError(f"protected finalization post hook was missing: {name}")
        if len(post_steps) > 1:
            raise ValueError(f"protected finalization post hook was duplicated: {name}")
        if post_steps:
            post = _successful_step(
                post_steps[0], name, "post hook", started, completed, pending
            )
            if not _ordered_step_times(started, completed, activation, post):
                raise ValueError(
                    f"protected finalization post-hook timestamps were out of order: {name}"
                )

    return jobs


def validate_action_zero_input_burst_job(document, *, pending=None):
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
    if completed < started:
        raise ValueError("blocked-burst job timestamps were out of order")
    steps = _bounded_job_steps(job, started, completed, ACTION_ZERO_INPUT_BURST_JOB, pending)
    if not steps:
        return job

    ordered_steps = []
    for name, description in (
        (ACTION_ZERO_INPUT_BURST_ACTIVATION, "blocked-burst activation"),
        ("verify zero-input Action lifecycle", "blocked-burst evidence"),
        (f"Post {ACTION_ZERO_INPUT_BURST_ACTIVATION}", "blocked-burst post hook"),
    ):
        matches = [step for step in steps if step.get("name") == name]
        if len(matches) != 1:
            raise ValueError(f"{description} was missing or duplicated")
        ordered_steps.append(
            _successful_step(matches[0], ACTION_ZERO_INPUT_BURST_JOB, description, started, completed, pending)
        )

    if not _ordered_step_times(started, completed, *ordered_steps):
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

    def action_burst_document(self, prefix="", *, setup_seconds=155, protected_seconds=45):
        document = self.document("action", protected_seconds, setup_seconds)
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

    @mock.patch("time.sleep")
    def test_transient_metadata_errors_retry_but_remain_bounded(self, sleep):
        for status in (502, 503, 504):
            with self.subTest(status=status):
                sleep.reset_mock()
                error = urllib.error.HTTPError("https://api.github.com/", status, "unavailable", {}, None)
                fetch = mock.Mock(side_effect=[error, self.document()])
                self.assertEqual(set(verified_finalization_jobs(fetch, "integration")),
                                 set(EXPECTED_FINALIZATION_STEPS["integration"]))
                self.assertEqual(fetch.call_count, 2)
                sleep.assert_called_once_with(5)

                sleep.reset_mock()
                fetch = mock.Mock(side_effect=error)
                with self.assertRaisesRegex(ValueError, f"metadata unavailable: HTTP {status}"):
                    verified_finalization_jobs(fetch, "integration")
                self.assertEqual(fetch.call_count, METADATA_ATTEMPTS)
                self.assertEqual(sleep.call_count, METADATA_ATTEMPTS - 1)

    @mock.patch("time.sleep")
    def test_unfinished_selected_steps_are_retried_within_the_metadata_budget(self, sleep):
        for job_set, document, job_index, step_index in (
            ("integration", self.document(), 0, 0),
            ("action", self.action_burst_document(), 0, 0),
            ("action", self.action_burst_document(), 0, 1),
            ("action", self.action_burst_document(), -1, 1),
        ):
            for status in ("pending", "in_progress"):
                with self.subTest(job_set=job_set, job_index=job_index, step_index=step_index, status=status):
                    sleep.reset_mock()
                    stale = copy.deepcopy(document)
                    step = stale["jobs"][job_index]["steps"][step_index]
                    step.update(status=status, conclusion=None, completed_at=None)
                    if status == "pending":
                        step["started_at"] = None
                    fetch = mock.Mock(side_effect=[stale, document])
                    self.assertEqual(len(verified_finalization_jobs(fetch, job_set)), len(document["jobs"]))
                    self.assertEqual(fetch.call_count, 2)
                    sleep.assert_called_once_with(5)

                    sleep.reset_mock()
                    fetch = mock.Mock(return_value=stale)
                    with self.assertRaisesRegex(MetadataPending, "metadata was unfinished"):
                        verified_finalization_jobs(fetch, job_set)
                    self.assertEqual(fetch.call_count, METADATA_ATTEMPTS)
                    self.assertEqual(sleep.call_count, METADATA_ATTEMPTS - 1)

    @mock.patch("time.sleep")
    def test_unfinished_step_cannot_disappear_into_the_whole_job_fallback(self, sleep):
        for job_index in (0, -1):
            with self.subTest(job_index=job_index):
                complete = self.action_burst_document(setup_seconds=0)
                complete["jobs"][1]["steps"] = []
                unfinished = copy.deepcopy(complete)
                unfinished["jobs"][job_index]["steps"][0].update(
                    status="pending", conclusion=None, started_at=None, completed_at=None
                )
                empty = copy.deepcopy(complete)
                empty["jobs"][job_index]["steps"] = []

                fetch = mock.Mock(side_effect=[unfinished, *[empty] * (METADATA_ATTEMPTS - 1)])
                with self.assertRaisesRegex(MetadataPending, "previously unfinished"):
                    verified_finalization_jobs(fetch, "action")
                self.assertEqual(fetch.call_count, METADATA_ATTEMPTS)

                fetch = mock.Mock(side_effect=[unfinished, empty, complete])
                self.assertEqual(len(verified_finalization_jobs(fetch, "action")), len(complete["jobs"]))
                self.assertEqual(fetch.call_count, 3)

                failed = copy.deepcopy(complete)
                failed["jobs"][job_index]["steps"][0]["conclusion"] = "failure"
                fetch = mock.Mock(side_effect=[unfinished, failed, complete])
                with self.assertRaises(ValueError) as failure:
                    verified_finalization_jobs(fetch, "action")
                self.assertNotIsInstance(failure.exception, MetadataPending)
                self.assertEqual(fetch.call_count, 2)

    @mock.patch("time.sleep")
    def test_invalid_evidence_takes_precedence_over_unfinished_metadata(self, sleep):
        for pending_job, invalid_job in ((0, 0), (0, 1), (0, -1), (-1, -1)):
            with self.subTest(pending_job=pending_job, invalid_job=invalid_job):
                document = self.action_burst_document(setup_seconds=0)
                document["jobs"][pending_job]["steps"][0].update(
                    status="in_progress", conclusion=None, completed_at=None
                )
                document["jobs"][invalid_job]["steps"][1]["conclusion"] = "failure"
                fetch = mock.Mock(return_value=document)
                with self.assertRaisesRegex(ValueError, "did not complete successfully") as failure:
                    verified_finalization_jobs(fetch, "action")
                self.assertNotIsInstance(failure.exception, MetadataPending)
                fetch.assert_called_once()
                sleep.assert_not_called()

    @mock.patch("time.sleep")
    def test_each_unfinished_job_must_supply_successful_step_records(self, sleep):
        complete = self.action_burst_document(setup_seconds=0)
        unfinished = copy.deepcopy(complete)
        for job in unfinished["jobs"][:2]:
            job["steps"][0].update(status="in_progress", conclusion=None, completed_at=None)
        incomplete = copy.deepcopy(complete)
        incomplete["jobs"][1]["steps"] = []
        fetch = mock.Mock(side_effect=[unfinished, *[incomplete] * (METADATA_ATTEMPTS - 1)])
        with self.assertRaisesRegex(MetadataPending, "previously unfinished"):
            verified_finalization_jobs(fetch, "action")
        self.assertEqual(fetch.call_count, METADATA_ATTEMPTS)

    def test_job_listing_is_complete_and_bounded(self):
        for count in (0, MAX_JOB_COUNT):
            document = {"total_count": count, "jobs": [{}] * count}
            self.assertIs(validate_job_listing(document), document)
        for document in (
            None,
            {},
            {"total_count": True, "jobs": [{}]},
            {"total_count": -1, "jobs": []},
            {"total_count": 1, "jobs": []},
            {"total_count": MAX_JOB_COUNT + 1, "jobs": [{}] * MAX_JOB_COUNT},
            {"total_count": MAX_JOB_COUNT + 1, "jobs": [{}] * (MAX_JOB_COUNT + 1)},
        ):
            with self.subTest(document=document), self.assertRaisesRegex(ValueError, "job listing was incomplete"):
                validate_job_listing(document)

    @mock.patch("time.sleep")
    def test_malformed_unfinished_step_metadata_is_not_retried(self, sleep):
        for changes in (
            {"conclusion": "failure"},
            {"conclusion": "cancelled"},
            {"conclusion": "skipped"},
            {"completed_at": "2026-07-23T00:00:30Z"},
            {"started_at": "invalid"},
            {"started_at": "2026-07-23T00:04:00Z"},
            {"status": "queued"},
            {"status": []},
        ):
            with self.subTest(changes=changes):
                document = self.document()
                step = document["jobs"][0]["steps"][0]
                step.update(status="in_progress", conclusion=None, completed_at=None)
                step.update(changes)
                fetch = mock.Mock(return_value=document)
                with self.assertRaises(ValueError) as failure:
                    verified_finalization_jobs(fetch, "integration")
                self.assertNotIsInstance(failure.exception, MetadataPending)
                fetch.assert_called_once()
                sleep.assert_not_called()

    @mock.patch("time.sleep")
    def test_empty_expected_steps_must_become_available_for_all_job_sets(self, sleep):
        for job_set, document in (
            ("integration", self.document()),
            ("action", self.action_burst_document()),
            ("action", self.action_burst_document("ubuntu-latest action acceptance")),
        ):
            for index in range(len(document["jobs"])):
                with self.subTest(job_set=job_set, name=document["jobs"][index]["name"]):
                    sleep.reset_mock()
                    pending = copy.deepcopy(document)
                    pending["jobs"][index]["steps"] = []
                    fetch = mock.Mock(side_effect=[pending, document])
                    result = verified_finalization_jobs(fetch, job_set)
                    self.assertEqual(len(result), len(document["jobs"]))
                    self.assertEqual(fetch.call_count, 2)
                    sleep.assert_called_once_with(5)

                    sleep.reset_mock()
                    fetch = mock.Mock(return_value=pending)
                    with self.assertRaisesRegex(MetadataPending, "step metadata was empty"):
                        verified_finalization_jobs(fetch, job_set)
                    self.assertEqual(fetch.call_count, METADATA_ATTEMPTS)
                    self.assertEqual(sleep.call_count, METADATA_ATTEMPTS - 1)

    @mock.patch("time.sleep")
    def test_missing_step_metadata_accepts_only_an_entire_job_within_budget(self, sleep):
        for job_set, document in (
            ("integration", self.document("integration", MAX_PROTECTED_SECONDS, 0)),
            ("action", self.action_burst_document(
                setup_seconds=0, protected_seconds=MAX_PROTECTED_SECONDS
            )),
            ("action", self.action_burst_document(
                "ubuntu-latest action acceptance", setup_seconds=0,
                protected_seconds=MAX_PROTECTED_SECONDS
            )),
        ):
            for shape in ("empty", "absent"):
                with self.subTest(job_set=job_set, shape=shape):
                    pending = copy.deepcopy(document)
                    for job in pending["jobs"]:
                        if shape == "empty":
                            job["steps"] = []
                        else:
                            del job["steps"]
                    fetch = mock.Mock(return_value=pending)
                    result = verified_finalization_jobs(fetch, job_set)
                    self.assertEqual({job["id"] for job in result.values()},
                                     {job["id"] for job in pending["jobs"]})
                    fetch.assert_called_once()
                    sleep.assert_not_called()

                    # The whole-job proof includes every post hook and the final second.
                    for index in range(len(pending["jobs"])):
                        sleep.reset_mock()
                        too_slow = copy.deepcopy(pending)
                        job = too_slow["jobs"][index]
                        completed = _timestamp(job["completed_at"], "test job")
                        job["completed_at"] = (completed + datetime.timedelta(seconds=1)).isoformat()
                        with self.subTest(name=job["name"]):
                            fetch = mock.Mock(return_value=too_slow)
                            with self.assertRaisesRegex(MetadataPending, "job exceeded 180 seconds"):
                                verified_finalization_jobs(fetch, job_set)
                            self.assertEqual(fetch.call_count, METADATA_ATTEMPTS)
                            self.assertEqual(sleep.call_count, METADATA_ATTEMPTS - 1)
                    sleep.reset_mock()

    @mock.patch("time.sleep")
    def test_short_jobs_cannot_use_fallback_to_hide_bad_evidence(self, sleep):
        cases = (
            ("id", None), ("id", True), ("id", "1"),
            ("status", "queued"), ("status", "in_progress"),
            ("conclusion", "failure"), ("conclusion", "cancelled"),
            ("conclusion", "skipped"), ("conclusion", None),
            ("started_at", None), ("started_at", "2026-07-23T00:00:00"),
            ("started_at", "2026-07-23T00:04:00Z"),
            ("completed_at", "invalid"), ("completed_at", "2026-07-23T00:00:00+25:00"),
            ("steps", None), ("steps", False), ("steps", ""), ("steps", {}),
            ("steps", [None]), ("steps", [{"name": "Post wrong"}]),
        )
        for job_set, document in (
            ("integration", self.document("integration", 45, 0)),
            ("action", self.action_burst_document(setup_seconds=0)),
        ):
            for index in range(len(document["jobs"])):
                for field, value in cases:
                    with self.subTest(job_set=job_set, index=index, field=field, value=value):
                        invalid = copy.deepcopy(document)
                        job = invalid["jobs"][index]
                        job["steps"] = []
                        job[field] = value
                        fetch = mock.Mock(return_value=invalid)
                        with self.assertRaises(ValueError) as failure:
                            verified_finalization_jobs(fetch, job_set)
                        self.assertNotIsInstance(failure.exception, MetadataPending)
                        fetch.assert_called_once()
                        sleep.assert_not_called()

    @mock.patch("time.sleep")
    def test_nonempty_steps_are_always_validated_even_for_short_jobs(self, sleep):
        for job_set, document in (
            ("integration", self.document("integration", 45, 0)),
            ("action", self.action_burst_document("release verification", setup_seconds=0)),
        ):
            for index, job in enumerate(document["jobs"]):
                for step_index in range(len(job["steps"])):
                    for field, value in (
                        ("name", "unexpected"), ("status", "in_progress"),
                        ("conclusion", "failure"), ("conclusion", "cancelled"),
                        ("conclusion", "skipped"), ("started_at", None),
                        ("completed_at", "2026-07-23T00:02:00Z"),
                    ):
                        # Integration has no required post hook, but any known one must be valid.
                        if job_set == "integration" and step_index == 1 and field == "name":
                            continue
                        with self.subTest(job_set=job_set, index=index, step_index=step_index, field=field):
                            invalid = copy.deepcopy(document)
                            invalid["jobs"][index]["steps"][step_index][field] = value
                            fetch = mock.Mock(return_value=invalid)
                            with self.assertRaises(ValueError):
                                verified_finalization_jobs(fetch, job_set)
                            fetch.assert_called_once()
                            sleep.assert_not_called()
                    with self.subTest(job_set=job_set, index=index, duplicate=step_index):
                        invalid = copy.deepcopy(document)
                        invalid["jobs"][index]["steps"].append(copy.deepcopy(job["steps"][step_index]))
                        fetch = mock.Mock(return_value=invalid)
                        with self.assertRaises(ValueError):
                            verified_finalization_jobs(fetch, job_set)
                        fetch.assert_called_once()
                        sleep.assert_not_called()

    @mock.patch("time.sleep")
    def test_finalization_never_retries_failed_or_invalid_evidence(self, sleep):
        for status in (401, 403, 404, 429, 500):
            fetch = mock.Mock(side_effect=urllib.error.HTTPError(
                "https://api.github.com/", status, "rejected", {}, None
            ))
            with self.subTest(status=status), self.assertRaises(urllib.error.HTTPError):
                verified_finalization_jobs(fetch, "action")
            fetch.assert_called_once()
            sleep.assert_not_called()

        cases = [
            ("conclusion", "failure"), ("status", "cancelled"),
            ("started_at", None), ("completed_at", "invalid"),
            ("steps", None), ("steps", [{"name": "Post wrong"}]),
        ]
        for index in (0, -1):
            for field, value in cases:
                with self.subTest(index=index, field=field, value=value):
                    document = self.action_burst_document()
                    document["jobs"][index][field] = value
                    fetch = mock.Mock(side_effect=[document, self.action_burst_document()])
                    with self.assertRaises(ValueError):
                        verified_finalization_jobs(fetch, "action")
                    fetch.assert_called_once()
                    sleep.assert_not_called()

        document = self.action_burst_document()
        document["jobs"][0]["steps"].append(copy.deepcopy(document["jobs"][0]["steps"][0]))
        fetch = mock.Mock(return_value=document)
        with self.assertRaisesRegex(ValueError, "missing or duplicated"):
            verified_finalization_jobs(fetch, "action")
        fetch.assert_called_once()
        sleep.assert_not_called()

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

    def action_quiet_report(self, **counts):
        reasons = dict.fromkeys(MATERIALIZATION_REJECTION_REASONS, 0)
        reasons.update(counts)
        total = sum(reasons.values())
        return {
            "schema_version": 1,
            "mode": "block",
            "result": "warning" if total else "healthy",
            "controls": copy.deepcopy(PROTECTED_CONTROLS),
            "network": [],
            "warnings": {
                **copy.deepcopy(QUIET_WARNINGS),
                "materialization_rejections": total,
                "materialization_rejection_reasons": reasons,
                "results_storage_rejections": 0,
            },
            "omissions": copy.deepcopy(QUIET_OMISSIONS),
            "suggested_allowlist": [],
        }

    def test_quiet_reports_allow_only_classified_noncritical_dns_refusals(self):
        for name in EXPECTED_FINALIZATION_STEPS["action"]:
            for reason in (None, *MATERIALIZATION_REJECTION_REASONS[:-1]):
                with self.subTest(name=name, reason=reason):
                    report = self.action_quiet_report(**({reason: 1} if reason else {}))
                    self.assertIs(validate_action_finalization_report(report, name), report)

    def test_quiet_reports_reject_other_warnings_omissions_and_lost_controls(self):
        name = next(iter(EXPECTED_FINALIZATION_STEPS["action"]))
        invalid = []
        for section, defaults in (
            ("warnings", QUIET_WARNINGS),
            ("omissions", QUIET_OMISSIONS),
            ("controls", PROTECTED_CONTROLS),
        ):
            for field, default in defaults.items():
                candidate = self.action_quiet_report(capacity=1)
                candidate[section][field] = (
                    not default if type(default) is bool
                    else 1 if type(default) is int
                    else ["unexpected"] if isinstance(default, list)
                    else "unexpected"
                )
                invalid.append(candidate)
            candidate = self.action_quiet_report(capacity=1)
            candidate[section]["unknown"] = 0
            invalid.append(candidate)
        for field, value in (
            ("schema_version", True),
            ("schema_version", 2),
            ("mode", "audit"),
            ("result", "critical"),
            ("result", "healthy"),
            ("network", [None]),
            ("network", [{}] * 21),
            ("suggested_allowlist", ["github.com"]),
        ):
            candidate = self.action_quiet_report(capacity=1)
            candidate[field] = value
            invalid.append(candidate)
        candidate = self.action_quiet_report()
        candidate["result"] = "warning"
        invalid.append(candidate)
        candidate = self.action_quiet_report(capacity=1)
        candidate["warnings"]["materialization_rejection_reasons"]["unknown"] = 0
        invalid.append(candidate)
        invalid.append(self.action_quiet_report(firewall_update_failed=1))
        for value in (-1, True, "1", MAX_SAFE_INTEGER + 1):
            candidate = self.action_quiet_report(capacity=1)
            candidate["warnings"]["results_storage_rejections"] = value
            invalid.append(candidate)
        for candidate in invalid:
            with self.subTest(report=repr(candidate)), self.assertRaises(ValueError):
                validate_action_finalization_report(candidate, name)
        with self.assertRaisesRegex(ValueError, "job was unknown"):
            validate_action_finalization_report(self.action_quiet_report(), "other job")

    def test_quiet_reports_reject_unparsed_reason_count_changes(self):
        for name in EXPECTED_FINALIZATION_STEPS["action"]:
            for field in QUIET_OMISSIONS["unparsed_finding_reasons"]:
                for value in (1, -1, True, False, "0", None, MAX_SAFE_INTEGER + 1):
                    report = self.action_quiet_report()
                    report["omissions"]["unparsed_finding_reasons"][field] = value
                    with self.subTest(name=name, field=field, value=value), self.assertRaisesRegex(
                        ValueError, "omitted evidence"
                    ):
                        validate_action_finalization_report(report, name)

                report = self.action_quiet_report()
                del report["omissions"]["unparsed_finding_reasons"][field]
                with self.subTest(name=name, missing=field), self.assertRaisesRegex(
                    ValueError, "omitted evidence"
                ):
                    validate_action_finalization_report(report, name)

            report = self.action_quiet_report()
            report["omissions"]["unparsed_finding_reasons"]["unexpected"] = 0
            with self.subTest(name=name, extra=True), self.assertRaisesRegex(
                ValueError, "omitted evidence"
            ):
                validate_action_finalization_report(report, name)

    def test_quiet_reports_allow_safe_results_storage_denials(self):
        name = next(iter(EXPECTED_FINALIZATION_STEPS["action"]))
        for counts in ({}, {"authorization_changed": 1}):
            report = self.action_quiet_report(**counts)
            report["warnings"]["results_storage_rejections"] = 3
            self.assertIs(validate_action_finalization_report(report, name), report)

    def test_full_blocked_burst_report_still_requires_burst_evidence(self):
        report = self.action_quiet_report()
        burst = self.action_burst_report()
        report["result"] = burst["result"]
        report["network"] = burst["network"]
        report["omissions"].update(burst["omissions"])
        self.assertIs(validate_action_finalization_report(report, ACTION_ZERO_INPUT_BURST_JOB), report)
        report["warnings"]["materialization_rejections"] = 1
        report["warnings"]["materialization_rejection_reasons"]["firewall_update_failed"] = 1
        with self.assertRaisesRegex(ValueError, "firewall update failed"):
            validate_action_finalization_report(report, ACTION_ZERO_INPUT_BURST_JOB)

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
