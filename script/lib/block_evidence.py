#!/usr/bin/env python3

import json
from pathlib import Path
import re
import socket
import sys
import time
import unittest
from unittest.mock import MagicMock, patch


WAIT_SECONDS = 10
POLL_SECONDS = 0.01
MAX_DIAGNOSTIC_DESTINATIONS = 8
DESTINATIONS = tuple(f"192.0.2.{index}" for index in range(10, 50))
FINAL_PROBES = (
    ("192.0.2.1", b"fence-action-final-block-probe"),
    ("192.0.2.2", b"fence-action-post-block-probe"),
)


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def valid_counter(value):
    return type(value) is int and 0 <= value <= (1 << 64) - 1


def counter_label(value):
    return str(value) if valid_counter(value) else "invalid"


def blocked_destinations(findings):
    return {
        finding["remote_address"]
        for finding in findings if isinstance(finding, dict)
        and finding.get("remote_address") in DESTINATIONS
        and finding.get("classification") == "rejected"
        and finding.get("protocol") == "udp"
        and finding.get("remote_port") == 443
    } if isinstance(findings, list) else set()


def assert_block_evidence_drains(report_path):
    require(sys.flags.optimize == 0, "Python optimization must be disabled")
    initial = json.loads(report_path.read_text(encoding="utf-8"))
    require(initial.get("mode") == "block", "bounded blocked-event evidence requires block mode")
    counters = initial.get("counters")
    require(isinstance(counters, dict), "bounded blocked-event evidence requires network counters")
    before_total = counters.get("total_violations")
    before_sampled = counters.get("sampled_violations")
    require(
        valid_counter(before_total) and valid_counter(before_sampled),
        "bounded blocked-event evidence requires valid initial counters",
    )
    before_ruleset_hash = initial.get("ruleset_hash")
    require(
        isinstance(before_ruleset_hash, str)
        and re.fullmatch(r"[0-9a-f]{64}", before_ruleset_hash) is not None,
        "bounded blocked-event evidence requires a valid initial firewall epoch",
    )

    for destination in DESTINATIONS:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.sendto(b"fence-action-block-probe", (destination, 443))
            except OSError:
                pass

    # The resident yields to DNS refresh and security checks between event batches.
    deadline = time.monotonic() + WAIT_SECONDS
    while True:
        current = json.loads(report_path.read_text(encoding="utf-8"))
        current_counters = current.get("counters")
        if not isinstance(current_counters, dict):
            current_counters = {}
        total = current_counters.get("total_violations")
        sampled = current_counters.get("sampled_violations")
        ruleset_hash = current.get("ruleset_hash")
        observed = blocked_destinations(current.get("findings"))
        missing = [item for item in DESTINATIONS if item not in observed]
        now = time.monotonic()
        if (
            now <= deadline
            and current.get("mode") == "block"
            and current.get("network_verification_status") == "verified"
            and current.get("critical_findings") == []
            and valid_counter(total) and valid_counter(sampled)
            and isinstance(ruleset_hash, str)
            and re.fullmatch(r"[0-9a-f]{64}", ruleset_hash) is not None
            and (ruleset_hash != before_ruleset_hash or total >= before_total + len(DESTINATIONS))
            and sampled >= before_sampled + len(DESTINATIONS)
            and not missing
        ):
            require(
                "fence-action-block-probe" not in json.dumps(current, sort_keys=True),
                "bounded blocked-event evidence retained packet payload",
            )
            break
        if now >= deadline:
            missing_label = ",".join(missing[:MAX_DIAGNOSTIC_DESTINATIONS]) or "none"
            if len(missing) > MAX_DIAGNOSTIC_DESTINATIONS:
                missing_label += f" (+{len(missing) - MAX_DIAGNOSTIC_DESTINATIONS} more)"
            raise SystemExit(
                f"blocked-event evidence incomplete after {WAIT_SECONDS}s: "
                f"matched={len(DESTINATIONS) - len(missing)}/{len(DESTINATIONS)}; "
                f"total={counter_label(before_total)}->{counter_label(total)}; "
                f"sampled={counter_label(before_sampled)}->{counter_label(sampled)}; "
                f"missing={missing_label}"
            )
        time.sleep(min(POLL_SECONDS, deadline - now))

    for destination, payload in FINAL_PROBES:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.sendto(payload, (destination, 443))
            except OSError:
                pass


class BlockEvidenceTests(unittest.TestCase):
    def evidence(self, count=None):
        count = len(DESTINATIONS) if count is None else count
        return {
            "mode": "block",
            "network_verification_status": "verified",
            "critical_findings": [],
            "ruleset_hash": "a" * 64,
            "counters": {"total_violations": count, "sampled_violations": count},
            "findings": [
                {"remote_address": item, "classification": "rejected", "protocol": "udp", "remote_port": 443}
                for item in DESTINATIONS[:count]
            ],
        }

    def run_probe(self, final, *, delay=0, initial=None, send_error=False):
        elapsed = 0.0
        reads = 0
        initial = self.evidence(0) if initial is None else initial

        def read_report(*args, **kwargs):
            nonlocal reads
            reads += 1
            report = initial if reads == 1 or elapsed < delay else final
            return json.dumps(report)

        def sleep(seconds):
            nonlocal elapsed
            elapsed = round(elapsed + seconds, 6)

        probe = MagicMock()
        if send_error:
            probe.sendto.side_effect = OSError("blocked fixture")
        with patch.object(Path, "read_text", side_effect=read_report), \
                patch.object(socket, "socket") as create_socket, \
                patch.object(time, "monotonic", side_effect=lambda: elapsed), \
                patch.object(time, "sleep", side_effect=sleep):
            create_socket.return_value.__enter__.return_value = probe
            try:
                assert_block_evidence_drains(Path("fixture-report.json"))
                error = None
            except SystemExit as failure:
                error = str(failure)
        return error, elapsed, probe.sendto.call_args_list

    def test_complete_evidence_returns_without_waiting(self):
        error, elapsed, sends = self.run_probe(self.evidence())
        self.assertIsNone(error)
        self.assertEqual(elapsed, 0)
        expected = [(b"fence-action-block-probe", (item, 443)) for item in DESTINATIONS]
        expected.extend((payload, (item, 443)) for item, payload in FINAL_PROBES)
        self.assertEqual([send.args for send in sends], expected)

    def test_delayed_complete_evidence_passes_without_resending(self):
        for delay in (WAIT_SECONDS / 2, WAIT_SECONDS - POLL_SECONDS, WAIT_SECONDS):
            with self.subTest(delay=delay):
                error, elapsed, sends = self.run_probe(self.evidence(), delay=delay, send_error=True)
                self.assertIsNone(error)
                self.assertEqual(elapsed, delay)
                self.assertEqual(len(sends), len(DESTINATIONS) + len(FINAL_PROBES))

    def test_evidence_after_deadline_fails(self):
        error, elapsed, sends = self.run_probe(self.evidence(), delay=WAIT_SECONDS + POLL_SECONDS)
        self.assertIn(f"matched=0/{len(DESTINATIONS)}", error)
        self.assertEqual(elapsed, WAIT_SECONDS)
        self.assertEqual(len(sends), len(DESTINATIONS))

    def test_missing_event_fails_even_with_complete_counters(self):
        report = self.evidence()
        report["findings"].pop()
        error, elapsed, sends = self.run_probe(report)
        self.assertIn(f"matched={len(DESTINATIONS) - 1}/{len(DESTINATIONS)}", error)
        self.assertIn(f"missing={DESTINATIONS[-1]}", error)
        self.assertEqual(elapsed, WAIT_SECONDS)
        self.assertEqual(len(sends), len(DESTINATIONS))

    def test_each_destination_needs_a_blocked_udp_443_event(self):
        for field, value in (("classification", "allowed"), ("protocol", "tcp"), ("remote_port", 80)):
            with self.subTest(field=field):
                report = self.evidence()
                report["findings"][-1][field] = value
                report["findings"].append(report["findings"][0])
                self.assertIn(f"matched={len(DESTINATIONS) - 1}/{len(DESTINATIONS)}", self.run_probe(report)[0])

    def test_invalid_evidence_never_passes(self):
        cases = [
            ("mode", "audit"), ("network_verification_status", "critical_drift"),
            ("critical_findings", ["fixture_critical"]), ("ruleset_hash", "invalid"),
            ("findings", None), ("counters", None),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                report = self.evidence()
                report[field] = value
                self.assertIsNotNone(self.run_probe(report)[0])
        for field in ("total_violations", "sampled_violations"):
            for value in (-1, True, str(len(DESTINATIONS)), None, len(DESTINATIONS) - 1, 1 << 64):
                with self.subTest(field=field, value=value):
                    report = self.evidence()
                    report["counters"][field] = value
                    self.assertIsNotNone(self.run_probe(report)[0])

    def test_counter_reset_requires_new_firewall_epoch(self):
        initial = self.evidence(0)
        baseline = len(DESTINATIONS) * 2
        initial["counters"] = {"total_violations": baseline, "sampled_violations": baseline}
        report = self.evidence()
        report["counters"]["sampled_violations"] = baseline + len(DESTINATIONS)
        self.assertIsNotNone(self.run_probe(report, initial=initial)[0])
        report["ruleset_hash"] = "b" * 64
        self.assertIsNone(self.run_probe(report, initial=initial)[0])
        report["counters"]["sampled_violations"] = len(DESTINATIONS)
        self.assertIsNotNone(self.run_probe(report, initial=initial)[0])

    def test_diagnostics_are_bounded_and_do_not_echo_report_text(self):
        report = self.evidence(0)
        untrusted = "\n::error::untrusted-report-text\x1b[31m" * 100
        report["counters"]["total_violations"] = untrusted
        report["counters"]["sampled_violations"] = 1 << 1000
        report["findings"] = [{"remote_address": untrusted, "message": untrusted}]
        error, _, _ = self.run_probe(report)
        self.assertIn("total=0->invalid; sampled=0->invalid", error)
        omitted = len(DESTINATIONS) - MAX_DIAGNOSTIC_DESTINATIONS
        if omitted > 0:
            self.assertIn(f"(+{omitted} more)", error)
        self.assertLess(len(error), 512)
        self.assertNotRegex(error, r"[\x00-\x1f\x7f]|::error::|untrusted-report-text")

    def test_payload_leak_and_invalid_baseline_fail(self):
        report = self.evidence()
        report["message"] = "fence-action-block-probe"
        self.assertIn("retained packet payload", self.run_probe(report)[0])
        for field, value in (("mode", "audit"), ("counters", None), ("ruleset_hash", "invalid")):
            with self.subTest(field=field):
                initial = self.evidence(0)
                initial[field] = value
                error, elapsed, sends = self.run_probe(self.evidence(), initial=initial)
                self.assertIsNotNone(error)
                self.assertEqual((elapsed, len(sends)), (0, 0))


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: block_evidence.py --self-test")
    unittest.main(argv=[sys.argv[0]])
