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
  materializationWaitTimeouts,
  materializationWarningLines,
  runtimePaths,
  summaryLines,
  validateBundle,
  validateInlineConfig,
  validateReady,
  validateReport,
} = require("./lib.cts");
const actionLog = require("./log.cts");
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

function captureStdout(callback: () => void): string {
  const originalWrite = process.stdout.write;
  let output = "";
  process.stdout.write = ((chunk: unknown) => {
    output += String(chunk);
    return true;
  }) as typeof process.stdout.write;
  try {
    callback();
  } finally {
    process.stdout.write = originalWrite;
  }
  return output;
}

function captureStderr(callback: () => void): string {
  const originalWrite = process.stderr.write;
  let output = "";
  process.stderr.write = ((chunk: unknown) => {
    output += String(chunk);
    return true;
  }) as typeof process.stderr.write;
  try {
    callback();
  } finally {
    process.stderr.write = originalWrite;
  }
  return output;
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
  assert.equal(
    defaultInlineConfig({ GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, {
      invocationId: "custom-run",
      mode: "block",
      containerPolicy: "unsafe_preserve",
      platformProfile: "github_hosted_workflow_bootstrap_v1",
      disableBroadGithubDomains: "true",
      allowlist: [
        "# comments are ignored",
        "www.example.com",
        "api.example.com:8443",
        "tcp://upload.example.com:9443",
        "udp://dns.example.com:53",
        "hostname mirror.example.com tcp 443",
        "ip 192.0.2.10 tcp 443",
        "cidr 192.0.2.0/24 udp 123",
        "cidr 2001:db8::/64 tcp 443",
      ].join("\n"),
    }),
    JSON.stringify({
      schema_version: 1,
      mode: "block",
      invocation_id: "custom-run",
      allowlist: [
        { destination_type: "hostname", destination: "www.example.com", protocol: "tcp", port: 443 },
        { destination_type: "hostname", destination: "api.example.com", protocol: "tcp", port: 8443 },
        { destination_type: "hostname", destination: "upload.example.com", protocol: "tcp", port: 9443 },
        { destination_type: "hostname", destination: "dns.example.com", protocol: "udp", port: 53 },
        { destination_type: "hostname", destination: "mirror.example.com", protocol: "tcp", port: 443 },
        { destination_type: "ip", destination: "192.0.2.10", protocol: "tcp", port: 443 },
        { destination_type: "cidr", destination: "192.0.2.0/24", protocol: "udp", port: 123 },
        { destination_type: "cidr", destination: "2001:db8::/64", protocol: "tcp", port: 443 },
      ],
      container_policy: "unsafe_preserve",
      platform_profile: "github_hosted_workflow_bootstrap_v1",
      disable_broad_github_domains: true,
    }),
  );
  assert.equal(
    defaultInlineConfig({ GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, {
      disableBroadGithubDomains: "false",
    }),
    defaultConfig,
  );
  assert.throws(
    () => validateInlineConfig(
      '{"schema_version":1,"mode":"block","invocation_id":"action-test","allowlist":[]}',
      {},
      { mode: "audit" },
    ),
    /cannot be combined/,
  );
  for (const nativeInput of [
    { invocationId: "native-run" },
    { containerPolicy: "disable" },
    { platformProfile: "github_hosted_workflow_bootstrap_v1" },
    { disableBroadGithubDomains: "true" },
    { allowlist: "example.com" },
  ]) {
    assert.throws(
      () => validateInlineConfig(
        '{"schema_version":1,"mode":"block","invocation_id":"action-test","allowlist":[]}',
        {},
        nativeInput,
      ),
      /cannot be combined/,
    );
  }
  assert.throws(
    () => validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, "observe"),
    /mode input/,
  );
  assert.throws(
    () => validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, { mode: "audit", containerPolicy: "disable" }),
    /container_policy input cannot be used with audit mode/,
  );
  assert.throws(
    () => validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, { containerPolicy: "keep" }),
    /container_policy input/,
  );
  assert.throws(
    () => validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, { platformProfile: "none" }),
    /platform_profile input/,
  );
  assert.throws(
    () => validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, { disableBroadGithubDomains: "TRUE" }),
    /disable_broad_github_domains input/,
  );
  for (const allowlist of [
    "https://example.com:443",
    "example.com:notaport",
    "example.com:0",
    "192.0.2.10",
    "192.0.2.0/24",
    "hostname 192.0.2.10 tcp 443",
    "ip example.com tcp 443",
    "cidr 192.0.2.0/33 tcp 443",
    "hostname example.com icmp 443",
    "hostname example.com tcp 65536",
    "hostname example.com tcp 443 extra",
  ]) {
    assert.throws(
      () => validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, { allowlist }),
      /allowlist line 1/,
    );
  }
  assert.throws(() => validateInlineConfig("", {}), /GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT/);
  assert.throws(
    () => validateInlineConfig("", { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, { invocationId: "Action_Test" }),
    /invocation_id input/,
  );
  assert.throws(() => validateInlineConfig('{"invocation_id":"Action_Test"}'), /slug grammar/);
  assert.throws(() => validateInlineConfig('{"invocation_id":"action--test"}'), /slug grammar/);
  assert.throws(() => validateInlineConfig("[]"), /JSON object/);
  assert.throws(
    () => validateInlineConfig(JSON.stringify({ invocation_id: "x", padding: "x".repeat(256 * 1024) })),
    /256 KiB/,
  );
});

test("formats concise setup and ready logs without raw evidence fields", () => {
  const details = actionLog.configLogDetails(
    JSON.stringify({
      schema_version: 1,
      mode: "block",
      invocation_id: "fence-12345-1",
      allowlist: [
        { destination_type: "hostname", destination: "api.example.com", protocol: "tcp", port: 443 },
      ],
    }),
    true,
  );
  assert.equal(details.mode, "block");
  assert.equal(details.source, "native inputs");
  assert.equal(details.containerPolicy, "disable");
  assert.equal(details.platformProfile, "github_hosted_workflow_bootstrap_v1");
  assert.equal(details.disableBroadGithubDomains, false);
  assert.equal(details.allowlistCount, 1);
  assert.deepEqual(details.allowlistDestinations, ["hostname:api.example.com:tcp:443"]);

  const lines = actionLog.setupLines({ release_tag: "v0.1.6" }, details).join("\n");
  assert.match(lines, /🛡️ Fence v0\.1\.6/);
  assert.match(lines, /🔒 Mode: block/);
  assert.match(lines, /🌐 Policy: GitHub workflow traffic \+ 1 allowlist entry/);
  assert.doesNotMatch(lines, /policy_hash/);
  assert.doesNotMatch(lines, /runtime_evidence_schema_version/);

  assert.equal(
    actionLog.readyLine(report),
    "✅ Fence ready: network restrictions active; passwordless sudo and Docker/container access locked down",
  );
});

test("formats audit and degraded log wording accurately", () => {
  const auditDetails = actionLog.configLogDetails(
    '{"schema_version":1,"mode":"audit","invocation_id":"fence-12345-1","allowlist":[]}',
    true,
  );
  assert.equal(actionLog.setupLines({ release_tag: "v0.1.6" }, auditDetails).join("\n"), [
    "🛡️ Fence v0.1.6",
    "👀 Mode: audit",
    "🌐 Policy: observing GitHub workflow traffic + 0 allowlist entries",
  ].join("\n"));

  const auditReport = {
    ...report,
    status: "protected_host_audit_observation",
    mode: "audit",
    readiness_status: "ready_observation_only",
    setup_status: "resident_observation_only",
    protection_available: false,
    sudo_status: "preserved_verified",
    container_status: "preserved_verified",
  };
  assert.equal(
    actionLog.readyLine(auditReport),
    "✅ Fence ready: audit mode is observing traffic, not blocking it",
  );
  assert.equal(
    actionLog.postEvidenceLine(auditReport, 2),
    "👀 Audit observed 2 would-block destinations; see Fence Summary",
  );

  const degraded = {
    ...report,
    status: "protected_host_block_degraded",
    readiness_status: "ready_degraded",
    setup_status: "resident_degraded",
    protection_available: false,
    container_status: "preserved_unsafe",
  };
  assert.equal(
    actionLog.readyLine(degraded),
    "✅ Fence ready: network restrictions active; passwordless sudo locked down; Docker/container access preserved",
  );
  assert.equal(
    actionLog.postEvidenceLine(degraded, 0),
    "⚠️ Limited assurance: Docker/container access was preserved",
  );
});

test("emits colored logs, respects NO_COLOR, and gates debug output", () => {
  const colored = captureStdout(() => actionLog.success("✅ Fence evidence verified", {}));
  assert.match(colored, /\u001b\[32m✅ Fence evidence verified\u001b\[0m/);

  const plain = captureStdout(() => actionLog.success("✅ Fence evidence verified", { NO_COLOR: "1" }));
  assert.equal(plain, "✅ Fence evidence verified\n");

  assert.equal(captureStdout(() => actionLog.debug("hidden", {})), "");
  assert.match(
    captureStdout(() => actionLog.debug("visible", { RUNNER_DEBUG: "1" })),
    /^::debug::visible\n$/,
  );
  assert.match(
    captureStdout(() => actionLog.debug("visible", { ACTIONS_STEP_DEBUG: "true" })),
    /^::debug::visible\n$/,
  );
});

test("escapes workflow commands and bounds debug diagnostics", () => {
  assert.equal(actionLog.workflowEscape("line one\nline two\r100%"), "line one line two 100%25");

  const debug = captureStdout(() => actionLog.debugGroup(
    "Fence debug: setup",
    [
      "normal line",
      "::warning::injection",
      "x".repeat(5000),
    ],
    { RUNNER_DEBUG: "1" },
  ));
  assert.match(debug, /^::group::Fence debug: setup\n/);
  assert.match(debug, /normal line/);
  assert.match(debug, /_::warning::injection/);
  assert.match(debug, /\.\.\.\[truncated\]/);
  assert.match(debug, /::endgroup::\n$/);

  assert.equal(
    captureStdout(() => actionLog.debugGroup("Fence debug: setup", ["hidden"], {})),
    "",
  );
});

test("emits bounded warning and error workflow commands", () => {
  assert.equal(
    captureStdout(() => actionLog.warning("Fence warning\n100%")),
    "::warning::Fence warning 100%25\n",
  );
  assert.equal(
    captureStderr(() => actionLog.error("Fence setup failed\n100%")),
    "::error::Fence setup failed 100%25\n",
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
  assert.match(summary, /allowlist: \|/);
  assert.match(summary, /      www.google.com/);
  assert.doesNotMatch(summary, /invocation_id/);
  assert.doesNotMatch(summary, /config: >-/);
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

test("renders audit IP-only findings when DNS evidence excludes non-GitHub names", () => {
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
      },
    ],
    findings_truncated: false,
  };
  const dnsEvidence = {
    observations: [],
    observations_truncated: false,
    excluded_non_github_query_count: 2,
  };

  const summary = summaryLines(audit, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟢 Fence Summary/);
  assert.match(summary, /\| `203.0.113.10` \| `tcp` \| `443` \| `1` \|/);
  assert.match(summary, /Manual review required for IP-only findings/);
  assert.doesNotMatch(summary, /DNS audit evidence was unavailable/);
  assert.doesNotMatch(summary, /View allowlist example/);
});

test("renders DNS materialization timeout evidence as a non-critical warning", () => {
  const dnsEvidence = {
    observations: [],
    observations_truncated: false,
    materialization_wait_timeouts: 2,
  };
  assert.equal(materializationWaitTimeouts(dnsEvidence), 2);
  assert.equal(materializationWaitTimeouts({ materialization_wait_timeouts: -1 }), 0);
  assert.equal(materializationWaitTimeouts({ materialization_wait_timeouts: "2" }), 0);
  assert.match(
    materializationWarningLines(dnsEvidence).join("\n"),
    /withheld 2 DNS answer\(s\).*firewall access was still being verified/,
  );
  const summary = summaryLines(report, dnsEvidence).join("\n");
  assert.match(summary, /^### Fence Summary/);
  assert.doesNotMatch(summary, /🟢/);
  assert.match(summary, /Temporary DNS delays observed/);
  assert.doesNotMatch(summary, /critical issue/);
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
    {
      destination: "metrics.example.com",
      destinationKind: "hostname",
      protocol: "tcp",
      port: 8443,
      count: 2,
    },
    {
      destination: "dns.example.com",
      destinationKind: "hostname",
      protocol: "udp",
      port: 53,
      count: 1,
    },
  ]).join("\n");
  assert.match(snippet.trimStart(), /^<details>/);
  assert.match(snippet, /<summary>View allowlist example<\/summary>/);
  assert.match(snippet, /```yaml/);
  assert.match(snippet, /GrantBirki\/fence@<commit-sha>/);
  assert.match(snippet, /allowlist: \|/);
  assert.match(snippet, /      api.example.com/);
  assert.match(snippet, /      metrics.example.com:8443/);
  assert.match(snippet, /      hostname dns.example.com udp 53/);
  assert.doesNotMatch(snippet, /invocation_id/);
  assert.doesNotMatch(snippet, /config: >-/);
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
