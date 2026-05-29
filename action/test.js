"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  runtimePaths,
  summaryLines,
  validateBundle,
  validateInlineConfig,
  validateReady,
  validateReport,
} = require("./lib");

const parsed = validateInlineConfig('{"schema_version":1,"mode":"block","invocation_id":"action-test","allowances":[]}');
assert.equal(parsed.invocationId, "action-test");
assert.throws(() => validateInlineConfig('{"invocation_id":"Action_Test"}'), /slug grammar/);
assert.throws(() => validateInlineConfig("[]"), /JSON object/);

assert.deepEqual(runtimePaths("action-test"), {
  directory: "/run/fence/action-test",
  config: "/run/fence/action-test/config.json",
  ready: "/run/fence/action-test/ready.json",
  report: "/run/fence/action-test/report.json",
  unit: "fence-action-test.service",
});
assert.throws(() => runtimePaths("../action-test"), /slug grammar/);

const report = {
  status: "protected_host_block",
  mode: "block",
  readiness_status: "ready",
  selected_platform_profile_id: "github_hosted_job_status_v1",
  network_verification_status: "verified",
  setup_status: "resident_protected",
  protection_available: true,
  sudo_status: "disabled_verified",
  container_status: "disabled_verified",
  policy_hash: "a".repeat(64),
  ruleset_hash: "b".repeat(64),
  critical_findings: [],
  critical_findings_truncated: false,
};
validateReport(report);
validateReady({
  status: "ready",
  selected_platform_profile_id: "github_hosted_job_status_v1",
  policy_hash: report.policy_hash,
  ruleset_hash: report.ruleset_hash,
  protection_available: true,
}, report);
assert.match(summaryLines(report).join("\n"), /critical findings \\| `0`/);
assert.throws(() => validateReport({ ...report, critical_findings: [{}] }), /critical resident findings/);
assert.throws(() => validateReport({ ...report, critical_findings_truncated: true }), /bounded critical findings/);
assert.throws(() => validateReport({ ...report, sudo_status: "preserved_verified" }), /inconsistent/);
assert.throws(() => validateReady({ status: "ready" }, report), /identity/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "fence-action-test-"));
try {
  const binary = path.join(temporary, "fence");
  const binaryLink = path.join(temporary, "fence-link");
  const wrongBinary = path.join(temporary, "wrong-fence");
  const manifest = path.join(temporary, "bundle.json");
  const manifestLink = path.join(temporary, "bundle-link.json");
  fs.writeFileSync(binary, "fence-test-binary", "utf8");
  fs.writeFileSync(wrongBinary, "wrong-fence-test-binary", "utf8");
  fs.chmodSync(binary, 0o755);
  fs.chmodSync(wrongBinary, 0o755);
  const digest = crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex");
  fs.writeFileSync(manifest, JSON.stringify({
    schema_version: 1,
    repository: "GrantBirki/fence",
    signer_workflow: "GrantBirki/fence/.github/workflows/release.yml",
    bundle_path: "action/bin/fence",
    artifact_sha256: digest,
    attestation_verified: true,
  }), "utf8");
  validateBundle(manifest, binary);
  fs.symlinkSync(binary, binaryLink);
  fs.symlinkSync(manifest, manifestLink);
  assert.throws(() => validateBundle(manifest, wrongBinary), /checksum/);
  assert.throws(() => validateBundle(manifest, binaryLink), /regular file/);
  assert.throws(() => validateBundle(manifestLink, binary), /regular file/);
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}

process.stdout.write("Fence Action wrapper unit checks passed.\n");
