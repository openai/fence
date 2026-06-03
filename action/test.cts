"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  allowlistYamlSnippet,
  correlateFindingsToDns,
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
    dnsReport: "/run/fence/action-test/dns-report.json",
    unit: "fence-action-test.service",
  });
  assert.throws(() => runtimePaths("../action-test"), /slug grammar/);
  assert.throws(() => runtimePaths("action--test"), /slug grammar/);
});

test("validates stable runtime evidence", () => {
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

test("renders a concise healthy block summary without raw evidence fields", () => {
  const summary = summaryLines(report).join("\n");
  assert.match(summary, /^### 🟢 Fence Summary/);
  assert.match(summary, /\*\*Network restrictions active\*\*/);
  assert.match(summary, /GitHub workflow support channel/);
  assert.equal(summary.match(/Fence Summary/g)?.length, 1);
  assert.doesNotMatch(summary, /Fence local evidence/);
  assert.doesNotMatch(summary, /critical findings/i);
  assert.doesNotMatch(summary, /platform profile/i);
  assert.doesNotMatch(summary, /readiness/i);
  assert.doesNotMatch(summary, /protected_host_block/);
  assert.doesNotMatch(summaryLines({ ...report, mode: "block\n| injected" }).join("\n"), /\n\| injected/);
});

test("renders degraded and critical summaries without a healthy signal", () => {
  const degraded = {
    ...report,
    status: "protected_host_block_degraded",
    readiness_status: "ready_degraded",
    setup_status: "resident_degraded",
    protection_available: false,
    container_status: "preserved_unsafe",
  };
  validateReport(degraded);
  const degradedSummary = summaryLines(degraded).join("\n");
  assert.match(degradedSummary, /^### Fence Summary/);
  assert.doesNotMatch(degradedSummary, /🟢/);
  assert.match(degradedSummary, /\*\*Limited assurance\*\*/);
  assert.match(degradedSummary, /Docker\/container access was preserved/);

  const critical = {
    ...report,
    network_verification_status: "critical_drift",
    critical_findings: [{
      timestamp: "unix-ms:1",
      code: "owned_nftables_state_missing",
      message: "Fence-owned network state changed after readiness.",
    }],
  };
  validateReport(critical, false);
  assert.throws(() => validateReport(critical, true), /critical resident findings/);
  const criticalSummary = summaryLines(critical).join("\n");
  assert.match(criticalSummary, /^### Fence Summary/);
  assert.doesNotMatch(criticalSummary, /🟢/);
  assert.match(criticalSummary, /\*\*Fence needs attention\*\*/);
  assert.match(criticalSummary, /`owned_nftables_state_missing`/);
  assert.match(criticalSummary, /Fence-owned network state changed after readiness/);
});

test("renders audit would-block findings with DNS-backed allowlist guidance", () => {
  const audit = {
    ...report,
    status: "protected_host_audit_observation",
    mode: "audit",
    readiness_status: "ready_observation_only",
    setup_status: "resident_observation_only",
    protection_available: false,
    sudo_status: "preserved_verified",
    container_status: "preserved_verified",
    findings: [
      {
        timestamp: "unix-ms:1",
        mode: "audit",
        classification: "would_block",
        family: "ipv4",
        protocol: "tcp",
        remote_address: "203.0.113.10",
        remote_port: 443,
        rule_class: "undeclared_new_egress",
        ignored_payload: "secret-payload-marker",
      },
      {
        timestamp: "unix-ms:2",
        mode: "audit",
        classification: "would_block",
        family: "ipv4",
        protocol: "tcp",
        remote_address: "203.0.113.10",
        remote_port: 443,
        rule_class: "undeclared_new_egress",
      },
      {
        timestamp: "unix-ms:3",
        mode: "audit",
        classification: "would_block",
        family: "ipv4",
        protocol: "udp",
        remote_address: "192.0.2.10",
        remote_port: 443,
        rule_class: "undeclared_new_egress",
      },
    ],
    findings_truncated: false,
  };
  const dnsEvidence = {
    observations: [{
      hostname: "www.google.com",
      query_type: "a",
      profile_classification: "audit_observed_without_authorization",
      occurrences: 1,
      resolved_addresses: ["203.0.113.10"],
      minimum_observed_ttl_seconds: 60,
      addresses_truncated: false,
    }],
    observations_truncated: false,
  };

  validateReport(audit);
  const correlation = correlateFindingsToDns(audit, dnsEvidence);
  assert.deepEqual(correlation.hostnameRows, [{
    destination: "www.google.com",
    destinationKind: "hostname",
    protocol: "tcp",
    port: 443,
    count: 2,
  }]);
  assert.deepEqual(correlation.ipRows, [{
    destination: "192.0.2.10",
    destinationKind: "ip",
    protocol: "udp",
    port: 443,
    count: 1,
  }]);

  const summary = summaryLines(audit, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟢 Fence Summary/);
  assert.match(summary, /\*\*Observing only\*\*/);
  assert.match(summary, /#### Would Be Blocked In Block Mode/);
  assert.match(summary, /\| `www.google.com` \| `tcp` \| `443` \| `2` \|/);
  assert.match(summary, /\| `192.0.2.10` \| `udp` \| `443` \| `1` \|/);
  assert.match(summary, /<summary>View allowlist example<\/summary>/);
  assert.match(summary, /```yaml/);
  assert.match(summary, /GrantBirki\/fence@<commit-sha>/);
  assert.match(summary, /"schema_version": 1/);
  assert.match(summary, /"mode": "block"/);
  assert.match(summary, /"allowlist": \[/);
  assert.match(summary, /"destination": "www.google.com"/);
  assert.doesNotMatch(summary, /@main/);
  assert.doesNotMatch(summary, /secret-payload-marker/);
});

test("renders audit IP-only and missing-DNS fallbacks safely", () => {
  const audit = {
    ...report,
    status: "protected_host_audit_observation",
    mode: "audit",
    readiness_status: "ready_observation_only",
    setup_status: "resident_observation_only",
    protection_available: false,
    sudo_status: "preserved_verified",
    container_status: "preserved_verified",
    findings: [
      {
        timestamp: "unix-ms:1",
        mode: "audit",
        classification: "would_block",
        family: "ipv4",
        protocol: "udp",
        remote_address: "192.0.2.10",
        remote_port: 443,
        rule_class: "undeclared_new_egress",
      },
      {
        timestamp: "unix-ms:2",
        mode: "audit",
        classification: "would_block",
        family: "ipv6",
        protocol: "unknown_or_unparsed",
        remote_address: null,
        remote_port: null,
        rule_class: "endpoint_unavailable_from_prefix",
      },
    ],
    findings_truncated: false,
  };
  const summary = summaryLines(audit).join("\n");
  assert.match(summary, /^### Fence Summary/);
  assert.doesNotMatch(summary, /🟢/);
  assert.match(summary, /DNS audit evidence was unavailable/);
  assert.match(summary, /Manual review required for IP-only findings/);
  assert.match(summary, /could not be mapped to an endpoint/);
  assert.doesNotMatch(summary, /View allowlist example/);
});

test("renders bounded allowlist YAML snippets", () => {
  const snippet = allowlistYamlSnippet([
    {
      destination: "api.example.com",
      destinationKind: "hostname",
      protocol: "tcp",
      port: 443,
      count: 5,
    },
  ]).join("\n");
  assert.match(snippet.trimStart(), /^<details>/);
  assert.match(snippet, /<summary>View allowlist example<\/summary>/);
  assert.match(snippet, /```yaml/);
  assert.match(snippet, /GrantBirki\/fence@<commit-sha>/);
  assert.match(snippet, /"schema_version": 1/);
  assert.match(snippet, /"invocation_id": "example-run"/);
  assert.match(snippet, /"allowlist": \[/);
  assert.match(snippet, /"destination": "api.example.com"/);
  assert.doesNotMatch(snippet, /@main/);
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
