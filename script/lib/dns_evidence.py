#!/usr/bin/env python3

import copy
import sys
import unittest


MATERIALIZATION_REJECTION_REASONS = (
    "invalid_response",
    "authorization_changed",
    "capacity",
    "queue_unavailable",
    "firewall_update_failed",
)
MAX_U64 = (1 << 64) - 1
MAX_SAFE_INTEGER = (1 << 53) - 1


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


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: dns_evidence.py --self-test")
    unittest.main(argv=[sys.argv[0]])
