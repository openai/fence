"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  defaultInlineConfig,
  runtimePaths,
  summaryLines,
  validateBundle,
  validateInlineConfig,
  validateReady,
  validateReport,
} = require("./lib.cts");
const { run } = require("./main.cts");

const report = {
  runtime_evidence_schema_version: 1,
  status: "protected_host_block",
  mode: "block",
  readiness_status: "ready",
  platform_profile_id: "github_hosted_workflow_bootstrap_v1",
  profile_realization_id: "github_hosted_workflow_bootstrap_dns_mediation_v1",
  network_verification_status: "verified",
  setup_status: "resident_protected",
  protection_available: true,
  sudo_status: "disabled_verified",
  container_status: "disabled_verified",
  policy_hash_schema_version: 3,
  policy_hash: "a".repeat(64),
  base_ruleset_hash: "b".repeat(64),
  ruleset_hash: "c".repeat(64),
  critical_findings: [],
  critical_findings_truncated: false,
};

function manifestFor(binary: string, overrides = {}): Record<string, unknown> {
  const digest = crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex");
  return {
    schema_version: 2,
    repository: "GrantBirki/fence",
    release_tag: "v0.1.0-alpha.3",
    release_channel: "prerelease",
    release_url: "https://github.com/GrantBirki/fence/releases/tag/v0.1.0-alpha.3",
    source_commit: "a".repeat(40),
    artifact_name: "fence_v0.1.0-alpha.3_linux-amd64",
    signer_workflow: "GrantBirki/fence/.github/workflows/release.yml",
    bundle_path: "action/bin/fence",
    artifact_sha256: digest,
    attestation_verified: true,
    ...overrides,
  };
}

test("validates explicit and zero-input inline configurations", () => {
  const parsed = validateInlineConfig('{"schema_version":1,"mode":"block","invocation_id":"action-test","allowlist":[]}');
  assert.equal(parsed.invocationId, "action-test");
  assert.equal(parsed.usingDefault, false);

  const defaultConfig = defaultInlineConfig({ GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" });
  assert.equal(
    defaultConfig,
    '{"schema_version":1,"mode":"block","invocation_id":"fence-12345-2","allowlist":[]}',
  );
  assert.deepEqual(validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }), {
    invocationId: "fence-12345-2",
    raw: defaultConfig,
    usingDefault: true,
  });
  assert.deepEqual(validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, "audit"), {
    invocationId: "fence-12345-2",
    raw: '{"schema_version":1,"mode":"audit","invocation_id":"fence-12345-2","allowlist":[]}',
    usingDefault: true,
  });
  assert.equal(
    defaultInlineConfig({ GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, "block"),
    defaultConfig,
  );
  assert.equal(
    defaultInlineConfig({ GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, "audit"),
    '{"schema_version":1,"mode":"audit","invocation_id":"fence-12345-2","allowlist":[]}',
  );
  assert.throws(
    () => validateInlineConfig(
      '{"schema_version":1,"mode":"block","invocation_id":"action-test","allowlist":[]}',
      {},
      "audit",
    ),
    /cannot be combined/,
  );
  assert.throws(
    () => validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, "observe"),
    /mode input/,
  );
  assert.throws(() => validateInlineConfig("", {}), /GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT/);
  assert.throws(() => validateInlineConfig('{"invocation_id":"Action_Test"}'), /slug grammar/);
  assert.throws(() => validateInlineConfig('{"invocation_id":"action--test"}'), /slug grammar/);
  assert.throws(() => validateInlineConfig("[]"), /JSON object/);
  assert.throws(
    () => validateInlineConfig(JSON.stringify({ invocation_id: "x", padding: "x".repeat(256 * 1024) })),
    /256 KiB/,
  );
});

test("derives only bounded fixed runtime paths", () => {
  assert.deepEqual(runtimePaths("action-test"), {
    directory: "/run/fence/action-test",
    config: "/run/fence/action-test/config.json",
    ready: "/run/fence/action-test/ready.json",
    report: "/run/fence/action-test/report.json",
    unit: "fence-action-test.service",
  });
  assert.throws(() => runtimePaths("../action-test"), /slug grammar/);
  assert.throws(() => runtimePaths("action--test"), /slug grammar/);
});

test("validates stable runtime evidence and sanitizes summaries", () => {
  validateReport(report);
  validateReady({
    runtime_evidence_schema_version: 1,
    status: "ready",
    platform_profile_id: "github_hosted_workflow_bootstrap_v1",
    profile_realization_id: "github_hosted_workflow_bootstrap_dns_mediation_v1",
    policy_hash_schema_version: report.policy_hash_schema_version,
    policy_hash: report.policy_hash,
    base_ruleset_hash: report.base_ruleset_hash,
    ruleset_hash: report.ruleset_hash,
    protection_available: true,
  }, report);
  assert.match(summaryLines(report).join("\n"), /critical findings \| `0`/);
  assert.doesNotMatch(summaryLines({ ...report, mode: "block\n| injected" }).join("\n"), /\n\| injected/);
  assert.throws(() => validateReport({ ...report, critical_findings: [{}] }), /critical resident findings/);
  assert.throws(
    () => validateReport({ ...report, network_verification_status: "critical_drift", critical_findings: [{}] }),
    /critical resident findings/,
  );
  assert.throws(() => validateReport({ ...report, network_verification_status: "critical_drift" }), /verified network state/);
  assert.throws(() => validateReport({ ...report, critical_findings_truncated: true }), /bounded critical findings/);
  assert.throws(() => validateReport({ ...report, sudo_status: "preserved_verified" }), /inconsistent/);
  assert.throws(() => validateReport({ ...report, runtime_evidence_schema_version: 0 }), /profile/);
  assert.throws(() => validateReady({ status: "ready" }, report), /identity/);
});

test("rejects the retired status-only profile identity", () => {
  assert.throws(
    () => validateReport({
      ...report,
      platform_profile_id: "github_hosted_job_status_v1",
      profile_realization_id: "github_hosted_job_status_dns_mediation_v1",
    }),
    /profile/,
  );
  assert.throws(
    () => validateReport({
      ...report,
      profile_realization_id: "github_hosted_job_status_dns_mediation_v1",
    }),
    /profile/,
  );
});

test("validates immutable attested bundle metadata and binary identity", () => {
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

    fs.writeFileSync(manifest, JSON.stringify(manifestFor(binary)), "utf8");
    validateBundle(manifest, binary);
    fs.writeFileSync(manifest, JSON.stringify(manifestFor(binary, {
      release_tag: "v0.1.0",
      release_channel: "stable",
      release_url: "https://github.com/GrantBirki/fence/releases/tag/v0.1.0",
      source_commit: "b".repeat(40),
      artifact_name: "fence_v0.1.0_linux-amd64",
    })), "utf8");
    validateBundle(manifest, binary);
    fs.writeFileSync(manifest, JSON.stringify(manifestFor(binary, {
      release_tag: "v0.1.0",
      release_channel: "prerelease",
      release_url: "https://github.com/GrantBirki/fence/releases/tag/v0.1.0",
      source_commit: "b".repeat(40),
      artifact_name: "fence_v0.1.0_linux-amd64",
    })), "utf8");
    assert.throws(() => validateBundle(manifest, binary), /contract/);
    fs.writeFileSync(manifest, JSON.stringify(manifestFor(binary, {
      release_tag: "v0.1.0",
      release_channel: "stable",
      release_url: "https://github.com/GrantBirki/fence/releases/tag/v0.1.0",
      source_commit: "b".repeat(40),
      artifact_name: "fence_v0.1.0_linux-amd64",
    })), "utf8");
    fs.symlinkSync(binary, binaryLink);
    fs.symlinkSync(manifest, manifestLink);
    assert.throws(() => validateBundle(manifest, wrongBinary), /checksum/);
    assert.throws(() => validateBundle(manifest, binaryLink), /regular file/);
    assert.throws(() => validateBundle(manifestLink, binary), /regular file/);
    fs.writeFileSync(manifest, "null", "utf8");
    assert.throws(() => validateBundle(manifest, binary), /contract/);
    fs.writeFileSync(manifest, "[]", "utf8");
    assert.throws(() => validateBundle(manifest, binary), /contract/);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test("bounds fixed privileged child command execution", () => {
  assert.throws(() => run("/bin/sleep", ["1"], undefined, false, 1), /ETIMEDOUT|timed out/i);
});
