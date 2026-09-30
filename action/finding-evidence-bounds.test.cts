"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { validateFindingEvidenceBounds } = require("./post.cts");

function evidence(retained, sampled, truncated) {
  return {
    findings: Array.from({ length: retained }, () => ({})),
    findings_truncated: truncated,
    counters: {
      total_violations: sampled,
      sampled_violations: sampled,
    },
  };
}

test("accepts resident finding evidence at producer boundaries", () => {
  assert.equal(validateFindingEvidenceBounds(evidence(0, 0, false)).findings.length, 0);
  assert.equal(validateFindingEvidenceBounds(evidence(1, 1, false)).findings.length, 1);
  assert.equal(validateFindingEvidenceBounds(evidence(1024, 1024, false)).findings.length, 1024);
  assert.equal(validateFindingEvidenceBounds(evidence(1024, 1025, true)).findings.length, 1024);
});

test("rejects resident finding evidence the producer cannot emit", () => {
  for (const invalid of [
    { ...evidence(0, 0, false), findings: "not-an-array" },
    evidence(1025, 1025, false),
    evidence(1023, 1024, true),
    evidence(1, 2, false),
    evidence(1024, 1024, true),
  ]) {
    assert.throws(
      () => validateFindingEvidenceBounds(invalid),
      /bounded network findings/,
    );
  }
});
