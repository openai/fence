#!/usr/bin/env python3

import copy
import json
import sys
import time
import unittest
from unittest.mock import Mock, patch


MATERIALIZATION_REJECTION_REASONS = (
    "invalid_response",
    "authorization_changed",
    "capacity",
    "queue_unavailable",
    "firewall_update_failed",
)
MAX_U64 = (1 << 64) - 1
MAX_SAFE_INTEGER = (1 << 53) - 1
AUDIT_PROBE_WAIT_SECONDS = 10


def validate_materialization_rejections(document, *, public=False):
    total_field = "materialization_rejections" if public else "materialization_request_rejections"
    maximum = MAX_SAFE_INTEGER if public else MAX_U64
    if not isinstance(document, dict):
        raise ValueError("DNS materialization evidence was missing")
    total = document.get(total_field)
    reasons = document.get("materialization_rejection_reasons")
    if type(total) is not int or not 0 <= total <= maximum:
        raise ValueError("DNS materialization rejection count was invalid")
    if not isinstance(reasons, dict) or set(reasons) != set(MATERIALIZATION_REJECTION_REASONS):
        raise ValueError("DNS materialization rejection reasons were missing or unknown")
    if any(type(count) is not int or not 0 <= count <= maximum for count in reasons.values()):
        raise ValueError("DNS materialization rejection reason count was invalid")
    reason_total = sum(reasons.values())
    if total != (reason_total if public else min(MAX_U64, reason_total)):
        raise ValueError("DNS materialization rejection reasons did not match the total")
    if reasons["firewall_update_failed"]:
        raise ValueError("DNS firewall update failed")
    return reasons


def wait_for_audit_probe_evidence(report_path, dns_path):
    """Wait for the hosted audit probes and resident re-verification; never resend a probe."""
    deadline = time.monotonic() + AUDIT_PROBE_WAIT_SECONDS
    while True:
        report, dns = (json.loads(path.read_text(encoding="utf-8")) for path in (report_path, dns_path))
        attempts = {
            (item["remote_address"], item["protocol"], item["rule_class"])
            for item in report["findings"]
            if item["classification"] == "would_block" and item["remote_port"] == 443
        }
        missing = []
        for hostname, classification, rule in (
            ("github.com", "platform_profile", "matches_recent_hostname_policy"),
            ("www.google.com", "outside_policy", "undeclared_new_egress"),
        ):
            if not any(
                (address, "tcp", rule) in attempts
                for item in dns["observations"]
                if item["hostname"] == hostname and item["policy_classification"] == classification
                for address in item["resolved_addresses"]
            ):
                missing.append(hostname)
        if ("192.0.2.10", "udp", "undeclared_new_egress") not in attempts:
            missing.append("direct-IP probe")
        health = [doc["resident_health"] for doc in (report, dns)]
        if any(item["status"] != "healthy" for item in health):
            raise SystemExit("resident unhealthy while waiting for audit probe evidence")
        if any(item["verification_sequence"] < 2 for item in health):
            missing.append("resident re-verification")

        remaining = deadline - time.monotonic()
        if not missing and remaining >= 0:
            return report, dns  # The caller validates these exact snapshots.
        if remaining <= 0:
            raise SystemExit(f"audit probe evidence deadline reached: {', '.join(missing) or 'late evidence'}")
        time.sleep(min(0.25, remaining))


class DnsEvidenceTests(unittest.TestCase):
    def evidence(self, *, public=False, **counts):
        reasons = dict.fromkeys(MATERIALIZATION_REJECTION_REASONS, 0)
        reasons.update(counts)
        field = "materialization_rejections" if public else "materialization_request_rejections"
        return {
            field: sum(reasons.values()),
            "materialization_rejection_reasons": reasons,
        }

    def test_classified_noncritical_refusals_are_accepted(self):
        for public in (False, True):
            for reason in MATERIALIZATION_REJECTION_REASONS[:-1]:
                with self.subTest(public=public, reason=reason):
                    evidence = self.evidence(public=public, **{reason: 2})
                    self.assertEqual(validate_materialization_rejections(evidence, public=public)[reason], 2)
            validate_materialization_rejections(self.evidence(public=public), public=public)

    def test_firewall_failure_is_fatal(self):
        for public in (False, True):
            with self.subTest(public=public), self.assertRaisesRegex(ValueError, "firewall update failed"):
                validate_materialization_rejections(
                    self.evidence(public=public, firewall_update_failed=1), public=public
                )

    def test_missing_unknown_or_invalid_reason_fields_fail(self):
        for public in (False, True):
            valid = self.evidence(public=public, capacity=1)
            field = "materialization_rejections" if public else "materialization_request_rejections"
            invalid = [None, {}, {field: 1}]
            for count in (-1, True, "1", 1.5, None, MAX_U64 + 1):
                candidate = copy.deepcopy(valid)
                candidate[field] = count
                invalid.append(candidate)
                candidate = copy.deepcopy(valid)
                candidate["materialization_rejection_reasons"]["capacity"] = count
                invalid.append(candidate)
            for mutation in ("missing", "unknown", "mismatch"):
                candidate = copy.deepcopy(valid)
                reasons = candidate["materialization_rejection_reasons"]
                if mutation == "missing":
                    del reasons["invalid_response"]
                elif mutation == "unknown":
                    reasons["unexpected"] = 0
                else:
                    candidate[field] = 2
                invalid.append(candidate)
            for candidate in invalid:
                with self.subTest(public=public, candidate=candidate), self.assertRaises(ValueError):
                    validate_materialization_rejections(candidate, public=public)

    def test_raw_counts_saturate_but_public_counts_must_be_exact(self):
        raw = self.evidence(invalid_response=MAX_U64, capacity=1)
        raw["materialization_request_rejections"] = MAX_U64
        validate_materialization_rejections(raw)
        for counts in (
            {"capacity": MAX_SAFE_INTEGER + 1},
            {"capacity": MAX_SAFE_INTEGER, "invalid_response": 1},
        ):
            with self.subTest(counts=counts), self.assertRaises(ValueError):
                validate_materialization_rejections(self.evidence(public=True, **counts), public=True)


class AuditProbeEvidenceTests(unittest.TestCase):
    def setUp(self):
        health = {"status": "healthy", "verification_sequence": 2}
        self.report = {"resident_health": health, "findings": []}
        self.dns = {"resident_health": health, "observations": []}
        for address, hostname, dns_class, protocol, rule in (
            ("192.0.2.1", "github.com", "platform_profile", "tcp", "matches_recent_hostname_policy"),
            ("192.0.2.2", "www.google.com", "outside_policy", "tcp", "undeclared_new_egress"),
            ("192.0.2.10", None, None, "udp", "undeclared_new_egress"),
        ):
            self.report["findings"].append(dict(
                remote_address=address, remote_port=443, protocol=protocol, rule_class=rule, classification="would_block"
            ))
            if hostname:
                self.dns["observations"].append(dict(
                    hostname=hostname, policy_classification=dns_class, resolved_addresses=[address]
                ))

    def wait(self, elapsed, *reports):
        report_path, dns_path = Mock(), Mock()
        report_path.read_text.side_effect = [json.dumps(doc) for doc in (reports or (self.report,))]
        dns_path.read_text.return_value = json.dumps(self.dns)
        with patch.object(time, "monotonic", side_effect=(0, *elapsed)), patch.object(time, "sleep"):
            return wait_for_audit_probe_evidence(report_path, dns_path)

    def test_accepts_complete_or_delayed_samples_without_waiting_past_deadline(self):
        expected = (self.report, self.dns)
        self.assertEqual(self.wait([0]), expected)
        self.assertEqual(self.wait([0, AUDIT_PROBE_WAIT_SECONDS], self.report | {"findings": []}, self.report), expected)
        with self.assertRaisesRegex(SystemExit, "late evidence"):
            self.wait([AUDIT_PROBE_WAIT_SECONDS + 1])

    def test_requires_each_exact_sample_and_resident_reverification(self):
        for i, label in enumerate(("github.com", "www.google.com", "direct-IP probe")):
            with self.subTest(label=label), self.assertRaisesRegex(SystemExit, label):
                wrong_rule = copy.deepcopy(self.report)
                wrong_rule["findings"][i]["rule_class"] = "other"
                self.wait([AUDIT_PROBE_WAIT_SECONDS], wrong_rule)
        self.dns["observations"][0]["resolved_addresses"] = ["192.0.2.2"]
        self.dns["resident_health"]["verification_sequence"] = 1
        with self.assertRaisesRegex(SystemExit, "github.com, resident re-verification"):
            self.wait([AUDIT_PROBE_WAIT_SECONDS])
        self.dns["resident_health"]["status"] = "critical"
        with self.assertRaisesRegex(SystemExit, "resident unhealthy"):
            self.wait([])


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: dns_evidence.py --self-test")
    unittest.main(argv=[sys.argv[0]])
