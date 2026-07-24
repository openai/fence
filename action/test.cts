"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  ACTION_RUNTIME_FILES,
  MAX_STRUCTURED_REPORT_BYTES,
  actionMountRecordFromMountInfo,
  actionPathGuardIdentities,
  actionRuntimeDigest,
  actionRuntimeFileDigests,
  allowlistYamlSnippet,
  correlateFindingsToDns,
  defaultInlineConfig,
  findingAttributionDebugLines,
  launcherIntegrityDocument,
  materializationRequestRejections,
  materializationWarningLines,
  mountIdFromFdInfo,
  networkReportLines,
  nativeInputsFromEnvironment,
  registeredActionPathGuardPaths,
  runtimePaths,
  structuredReportLine,
  summaryLines,
  validateBundle,
  validatedActionRuntimeSnapshot,
  validateActionPathGuardMount,
  validateInlineConfig,
  validateLauncherIntegrity,
  validateProtectedActionRuntime,
  validateReadOnlyActionMount,
  validateDnsEvidence,
  validateReady,
  validateReport,
  validateResidentHealth,
  validateResidentUnitStatus,
} = require("./lib.cts");
const actionLog = require("./log.cts");
const { settleResidentReport } = require("./post.cts");
const {
  fenceErrorCodeFromJournal,
  residentServiceArgs,
  run,
  terminalServiceStatus,
} = require("./main.cts");

function residentHealth(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    status: "healthy",
    resident_pid: 4242,
    verification_sequence: 9,
    last_successful_verification_unix_milliseconds: Date.now() - 1_000,
    verification_interval_seconds: 5,
    workers: [
      { name: "docker_tcp_dns", status: "running" },
      { name: "docker_udp_dns", status: "running" },
      { name: "host_tcp_dns", status: "running" },
      { name: "host_udp_dns", status: "running" },
      { name: "process_attribution", status: "running" },
    ],
    ...overrides,
  };
}

const report = {
  runtime_evidence_schema_version: 5,
  status: "protected_host_block",
  mode: "block",
  allow_github_artifacts: false,
  readiness_status: "ready",
  platform_profile_id: "github_hosted_workflow_bootstrap_v5",
  profile_realization_id: "github_hosted_workflow_bootstrap_dns_provenance_v5",
  network_verification_status: "verified",
  setup_status: "resident_protected",
  protection_available: true,
  sudo_status: "disabled_verified",
  container_status: "disabled_verified",
  policy_hash_schema_version: 9,
  policy_hash: "a".repeat(64),
  base_ruleset_hash: "b".repeat(64),
  ruleset_hash: "c".repeat(64),
  critical_findings: [],
  critical_findings_truncated: false,
  resident_health: residentHealth(),
};

const githubArtifactCompatibilityLimitations = [
  "github_artifact_compatibility_explicitly_enabled",
  "runner_owned_workflow_processes_can_authorize_bounded_results_storage",
  "github_artifact_uploads_remain_an_intentional_data_egress_channel",
];

function dnsEvidenceFor(
  currentReport: any = report,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    runtime_evidence_schema_version: 5,
    status: currentReport.status,
    mode: currentReport.mode,
    allow_github_artifacts: currentReport.allow_github_artifacts,
    platform_profile_id: currentReport.platform_profile_id,
    profile_realization_id: currentReport.profile_realization_id,
    protection_available: currentReport.protection_available,
    routing_status: "active",
    host_dns_routing: "direct_client_to_root_resident_mediator",
    docker_dns_routing: "local_root_resident_mediator",
    answer_attribution_status: "bounded_reportable_hostname_answers_only",
    proxy_policy_status: currentReport.mode === "audit"
      ? "audit_forwards_while_simulating_name_authorization"
      : "block_forwards_exact_roots_bounded_user_wildcard_names_actions_suffix_names_githubapp_suffix_names_results_storage_and_bounded_cname_descendants",
    hostname_policy: {
      exact: [],
      user_wildcards: [],
      allow_dynamic_githubapp_suffix: true,
      allow_github_artifacts: currentReport.allow_github_artifacts,
    },
    observations: [],
    observations_truncated: false,
    bounded_user_wildcard_authorizations: [],
    bounded_user_wildcard_authorizations_truncated: false,
    user_wildcard_request_rejections: 0,
    runner_authorized_results_storage: [],
    runner_authorized_results_storage_truncated: false,
    results_storage_authorization_count: 0,
    results_storage_attribution_failures: 0,
    results_storage_request_rejections: 0,
    resident_health: currentReport.resident_health,
    limitations: currentReport.allow_github_artifacts
      ? [...githubArtifactCompatibilityLimitations]
      : [],
    ...overrides,
  };
}

function githubArtifactReport(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    ...report,
    allow_github_artifacts: true,
    limitations: [...githubArtifactCompatibilityLimitations],
    ...overrides,
  };
}

function readinessFor(currentReport: any): Record<string, unknown> {
  return {
    runtime_evidence_schema_version: 5,
    status: currentReport.readiness_status,
    mode: currentReport.mode,
    allow_github_artifacts: currentReport.allow_github_artifacts,
    platform_profile_id: currentReport.platform_profile_id,
    profile_realization_id: currentReport.profile_realization_id,
    policy_hash_schema_version: currentReport.policy_hash_schema_version,
    policy_hash: currentReport.policy_hash,
    base_ruleset_hash: currentReport.base_ruleset_hash,
    ruleset_hash: currentReport.ruleset_hash,
    protection_available: currentReport.protection_available,
    resident_health: currentReport.resident_health,
    limitations: currentReport.allow_github_artifacts
      ? [...githubArtifactCompatibilityLimitations]
      : [],
  };
}

function manifestFor(binary: string, overrides = {}): Record<string, unknown> {
  const digest = crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex");
  return {
    schema_version: 4,
    repository: "openai/fence",
    release_tag: "v0.1.0-alpha.3",
    release_channel: "prerelease",
    release_url: "https://github.com/openai/fence/releases/tag/v0.1.0-alpha.3",
    source_commit: "a".repeat(40),
    source_ref: "refs/heads/main",
    artifact_name: "fence_v0.1.0-alpha.3_linux-amd64",
    signer_digest: "a".repeat(40),
    signer_workflow: "openai/fence/.github/workflows/release.yml",
    bundle_path: "action/bin/fence",
    artifact_sha256: digest,
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

function parsedStructuredNetworkReport(currentReport: any, dnsEvidence: any = undefined): any {
  const line = structuredReportLine(currentReport, dnsEvidence);
  assert.match(line, /^FENCE_REPORT_JSON=/);
  assert.ok(Buffer.byteLength(line, "utf8") <= MAX_STRUCTURED_REPORT_BYTES);
  assert.equal(captureStdout(() => actionLog.structuredRecord(line)), `${line}\n`);
  return JSON.parse(line.slice("FENCE_REPORT_JSON=".length));
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
      platformProfile: "github_hosted_workflow_bootstrap_v5",
      disableBroadGithubDomains: "true",
      allowlist: [
        "# comments are ignored",
        "www.example.com",
        "api.example.com:8443",
        "tcp://upload.example.com:9443",
        "udp://dns.example.com:53",
        "hostname mirror.example.com tcp 443",
        "*.Docker.IO",
        "tcp://*.docker.io:443",
        "*.Docker.IO:8443",
        "tcp://*.*.Docker.IO:443",
        "udp://*.*.Example.COM:53",
        "hostname *.Mirror.Example.COM tcp 443",
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
        { destination_type: "hostname", destination: "*.docker.io", protocol: "tcp", port: 443 },
        { destination_type: "hostname", destination: "*.docker.io", protocol: "tcp", port: 8443 },
        { destination_type: "hostname", destination: "*.*.docker.io", protocol: "tcp", port: 443 },
        { destination_type: "hostname", destination: "*.*.example.com", protocol: "udp", port: 53 },
        { destination_type: "hostname", destination: "*.mirror.example.com", protocol: "tcp", port: 443 },
        { destination_type: "ip", destination: "192.0.2.10", protocol: "tcp", port: 443 },
        { destination_type: "cidr", destination: "192.0.2.0/24", protocol: "udp", port: 123 },
        { destination_type: "cidr", destination: "2001:db8::/64", protocol: "tcp", port: 443 },
      ],
      container_policy: "unsafe_preserve",
      platform_profile: "github_hosted_workflow_bootstrap_v5",
      disable_broad_github_domains: true,
    }),
  );
  assert.equal(
    defaultInlineConfig({ GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" }, {
      disableBroadGithubDomains: "false",
    }),
    defaultConfig,
  );
  const rawWildcardConfig = '{"schema_version":1,"mode":"block","invocation_id":"raw-wildcard","allowlist":[{"destination_type":"hostname","destination":"*.*.docker.io","protocol":"udp","port":53}]}';
  assert.equal(validateInlineConfig(rawWildcardConfig).raw, rawWildcardConfig);
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
    { platformProfile: "github_hosted_workflow_bootstrap_v5" },
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
    "*",
    "*.com",
    "*.*.com",
    "*.*.*.docker.io",
    "foo*.docker.io",
    "docker.*.io",
    "*.foo.*.io",
    "*..docker.io",
    "*.-docker.io",
    "*.docker-.io",
    "*.docker.io.",
    "*.döcker.io",
    "*.127.0.0.1",
    "2130706433",
    "127.1",
    "0X7f000001",
    "0177.0.0.1",
    "tcp://*.docker.io:443/",
    "tcp://*.docker.io:443/path",
    "tcp://user@*.docker.io:443",
    "tcp://*.docker.io:443?query=1",
    "tcp://*.docker.io:443#fragment",
    "tcp://%65xample.com:443",
    "tcp://döcker.io:443",
    `*.${"a".repeat(64)}.example.com`,
    `*.${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.com`,
    "example.com:notaport",
    "example.com:0",
    "192.0.2.10",
    "192.0.2.0/24",
    "hostname 192.0.2.10 tcp 443",
    "ip example.com tcp 443",
    "cidr 192.0.2.0/33 tcp 443",
    "cidr 192.0.2.1/24 tcp 443",
    "cidr 192.0.2.1/0 tcp 443",
    "cidr 2001:db8::1/64 tcp 443",
    "cidr 2001:db8::1/0 tcp 443",
    "cidr fe80::%en0/64 tcp 443",
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

test("requires an explicit block-mode opt-in for bounded GitHub artifact uploads", () => {
  const environment = { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" };
  const strictConfig = defaultInlineConfig(environment);

  assert.equal(
    defaultInlineConfig(environment, { allowGithubArtifacts: "false" }),
    strictConfig,
  );
  assert.equal(
    defaultInlineConfig(environment, { allowGithubArtifacts: "  false  " }),
    strictConfig,
  );
  assert.deepEqual(
    JSON.parse(defaultInlineConfig(environment, { allowGithubArtifacts: "true" })),
    {
      schema_version: 1,
      mode: "block",
      invocation_id: "fence-12345-2",
      allowlist: [],
      allow_github_artifacts: true,
    },
  );
  assert.equal(
    nativeInputsFromEnvironment({ INPUT_ALLOW_GITHUB_ARTIFACTS: "true" })
      .allowGithubArtifacts,
    "true",
  );

  for (const value of ["TRUE", "False", "1", "yes", "enabled", true, 1]) {
    assert.throws(
      () => defaultInlineConfig(environment, { allowGithubArtifacts: value }),
      /allow_github_artifacts input must be (?:either true or false|a string)/,
    );
  }
  assert.throws(
    () => defaultInlineConfig(environment, {
      mode: "audit",
      allowGithubArtifacts: "true",
    }),
    /allow_github_artifacts input can only be used with block mode/,
  );

  const rawBlockConfig = JSON.stringify({
    schema_version: 1,
    mode: "block",
    invocation_id: "artifact-config",
    allowlist: [],
    allow_github_artifacts: true,
  });
  assert.equal(validateInlineConfig(rawBlockConfig).raw, rawBlockConfig);
  for (const value of ["true", "false"]) {
    assert.throws(
      () => validateInlineConfig(rawBlockConfig, {}, { allowGithubArtifacts: value }),
      /allow_github_artifacts input cannot be combined with config input/,
    );
  }
  assert.throws(
    () => validateInlineConfig(JSON.stringify({
      schema_version: 1,
      mode: "audit",
      invocation_id: "artifact-config",
      allowlist: [],
      allow_github_artifacts: true,
    })),
    /allow_github_artifacts can only be used with block mode/,
  );
  for (const value of ["true", 1, null]) {
    assert.throws(
      () => validateInlineConfig(JSON.stringify({
        schema_version: 1,
        mode: "block",
        invocation_id: "artifact-config",
        allowlist: [],
        allow_github_artifacts: value,
      })),
      /config allow_github_artifacts must be a boolean/,
    );
  }
});

test("normalizes canonical IPv4 and IPv6 allowlist networks", () => {
  for (const [input, expected] of [
    ["0.0.0.0/0", "0.0.0.0/0"],
    ["192.0.2.10/32", "192.0.2.10/32"],
    ["192.0.2.0/024", "192.0.2.0/24"],
    ["::/0", "::/0"],
    ["2001:0DB8:0000::/064", "2001:db8::/64"],
    ["2001:db8::1/128", "2001:db8::1/128"],
    ["::ffff:192.0.2.0/120", "::ffff:192.0.2.0/120"],
  ]) {
    const config = JSON.parse(defaultInlineConfig(
      { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" },
      { allowlist: `cidr ${input} tcp 443` },
    ));
    assert.equal(config.allowlist[0].destination, expected);
  }
});

test("limits native allowlists to 64 unique canonical destinations", () => {
  const environment = { GITHUB_RUN_ID: "12345", GITHUB_RUN_ATTEMPT: "2" };
  const hostnames = Array.from({ length: 65 }, (_, index) => `host-${index}.example.com`);
  const allowlistLength = (lines: string[]): number => JSON.parse(
    defaultInlineConfig(environment, { allowlist: lines.join("\n") }),
  ).allowlist.length;

  assert.equal(allowlistLength(hostnames.slice(0, 64)), 64);
  assert.throws(
    () => allowlistLength(hostnames),
    /allowlist line 65: allowlist input must contain no more than 64 unique entries/,
  );
  assert.equal(allowlistLength([...hostnames.slice(0, 64), hostnames[0]]), 64);
  assert.equal(allowlistLength([
    ...hostnames.slice(0, 63),
    "EXAMPLE.COM",
    "hostname example.com tcp 443",
  ]), 64);
  assert.equal(allowlistLength([
    ...hostnames.slice(0, 63),
    "cidr 192.0.2.0/024 tcp 443",
    "cidr 192.0.2.0/24 tcp 443",
  ]), 64);
  assert.equal(allowlistLength([
    ...hostnames.slice(0, 64),
    "# comments do not consume allowlist entries",
    "",
    "   ",
  ]), 64);
  assert.throws(
    () => allowlistLength([
      ...hostnames.slice(0, 63),
      "hostname protocols.example.com tcp 443",
      "hostname protocols.example.com udp 443",
    ]),
    /allowlist line 65: allowlist input must contain no more than 64 unique entries/,
  );
  assert.throws(
    () => allowlistLength([
      ...hostnames.slice(0, 63),
      "hostname ports.example.com tcp 443",
      "hostname ports.example.com tcp 8443",
    ]),
    /allowlist line 65: allowlist input must contain no more than 64 unique entries/,
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
  assert.equal(details.platformProfile, "github_hosted_workflow_bootstrap_v5");
  assert.equal(details.disableBroadGithubDomains, false);
  assert.equal(details.allowGithubArtifacts, false);
  assert.equal(details.allowlistCount, 1);
  assert.deepEqual(details.allowlistDestinations, ["hostname:api.example.com:tcp:443"]);

  const lines = actionLog.setupLines({ release_tag: "v0.1.6" }, details).join("\n");
  assert.match(lines, /🛡️ Fence v0\.1\.6/);
  assert.match(lines, /🔒 Mode: block/);
  assert.match(lines, /🌐 Policy: GitHub workflow traffic \+ 1 allowlist entry/);
  assert.doesNotMatch(lines, /GitHub artifact uploads/);
  assert.doesNotMatch(lines, /policy_hash/);
  assert.doesNotMatch(lines, /runtime_evidence_schema_version/);

  assert.equal(
    actionLog.readyLine(report),
    "✅ Fence ready: network restrictions active; passwordless sudo and Docker/container access locked down",
  );
});

test("discloses opted-in GitHub artifact egress in setup logs", () => {
  const details = actionLog.configLogDetails(
    JSON.stringify({
      schema_version: 1,
      mode: "block",
      invocation_id: "fence-12345-1",
      allowlist: [],
      allow_github_artifacts: true,
    }),
    true,
  );

  assert.equal(details.allowGithubArtifacts, true);
  const lines = actionLog.setupLines({ release_tag: "v0.8.9" }, details).join("\n");
  assert.match(lines, /🔒 Mode: block/);
  assert.match(lines, /⚠️ GitHub artifact uploads: enabled/);
  assert.match(lines, /artifacts can send data outside the job/);
  assert.doesNotMatch(lines, /sig=|token=|https:\/\//i);
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

test("writes canonical structured reports without the ordinary log truncation", () => {
  const record = {
    schema_version: 1,
    message: "🔒".repeat(700),
  };
  const line = `FENCE_REPORT_JSON=${JSON.stringify(record)}`;

  assert.ok(Buffer.byteLength(line, "utf8") > 2048);
  assert.ok(Buffer.byteLength(line, "utf8") <= MAX_STRUCTURED_REPORT_BYTES);
  const output = captureStdout(() => actionLog.structuredRecord(line));
  assert.equal(output, `${line}\n`);
  assert.deepEqual(JSON.parse(output.slice("FENCE_REPORT_JSON=".length)), record);
  assert.doesNotMatch(output, /\.\.\.\[truncated\]/);
});

test("accepts the exact structured-report byte limit and rejects a larger record", () => {
  const prefix = "FENCE_REPORT_JSON=";
  const empty = `${prefix}${JSON.stringify({ schema_version: 1, padding: "" })}`;
  const padding = "x".repeat(MAX_STRUCTURED_REPORT_BYTES - Buffer.byteLength(empty, "utf8"));
  const exact = `${prefix}${JSON.stringify({ schema_version: 1, padding })}`;

  assert.equal(Buffer.byteLength(exact, "utf8"), MAX_STRUCTURED_REPORT_BYTES);
  assert.equal(captureStdout(() => actionLog.structuredRecord(exact)), `${exact}\n`);

  const oversized = `${prefix}${JSON.stringify({ schema_version: 1, padding: `${padding}x` })}`;
  const output = captureStdout(() => {
    assert.throws(() => actionLog.structuredRecord(oversized), /16 KiB limit/);
  });
  assert.equal(output, "");
});

test("rejects malformed and injectable structured report records without emitting them", () => {
  const prefix = "FENCE_REPORT_JSON=";
  const valid = `${prefix}${JSON.stringify({ schema_version: 1 })}`;
  const invalidRecords: [unknown, RegExp][] = [
    [undefined, /must start with/],
    [null, /must start with/],
    [{ schema_version: 1 }, /must start with/],
    ["::warning::forged report", /must start with/],
    ["PREFIX_FENCE_REPORT_JSON={\"schema_version\":1}", /must start with/],
    [`${prefix}`, /valid JSON/],
    [`${prefix}{`, /valid JSON/],
    [`${prefix}null`, /canonical schema-version-1 JSON/],
    [`${prefix}[]`, /canonical schema-version-1 JSON/],
    [`${prefix}${JSON.stringify({ schema_version: 2 })}`, /canonical schema-version-1 JSON/],
    [`${prefix}{"schema_version":1,"schema_version":1}`, /canonical schema-version-1 JSON/],
    [`${prefix}{ "schema_version": 1 }`, /canonical schema-version-1 JSON/],
    [`${valid}\n::error::injected`, /single line without control characters/],
    [`${valid}\r::warning::injected`, /single line without control characters/],
    [`${valid}\u0000`, /single line without control characters/],
    [`${valid}\u001b`, /single line without control characters/],
    [`${valid}\u007f`, /single line without control characters/],
    [`${valid}\u0085`, /single line without control characters/],
    [`${valid}\u2028`, /single line without control characters/],
    [`${valid}\u2029`, /single line without control characters/],
  ];

  for (const [record, expectedError] of invalidRecords) {
    const output = captureStdout(() => {
      assert.throws(() => actionLog.structuredRecord(record), expectedError);
    });
    assert.equal(output, "");
  }
});

test("recognizes terminal service state and only bounded structured Fence error codes", () => {
  assert.equal(
    terminalServiceStatus([
      "LoadState=loaded",
      "ActiveState=failed",
      "SubState=failed",
      "Result=exit-code",
      "ExecMainCode=exited",
      "ExecMainStatus=1",
      "MainPID=0",
    ].join("\n")),
    "LoadState=loaded; ActiveState=failed; SubState=failed; Result=exit-code; ExecMainCode=exited; ExecMainStatus=1; MainPID=0",
  );
  assert.equal(
    terminalServiceStatus("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\n"),
    undefined,
  );
  assert.equal(
    terminalServiceStatus("LoadState=not-found\nActiveState=inactive\nSubState=dead\n"),
    "LoadState=not-found; ActiveState=inactive; SubState=dead",
  );

  const structuredFailure = JSON.stringify({
    schema_version: 1,
    command: "run",
    status: "error",
    fence_version: "0.6.2",
    error: {
      code: "invalid_platform_profile",
      message: "protected lifecycle setup failed",
    },
  });
  assert.equal(
    fenceErrorCodeFromJournal(`systemd service message\n${structuredFailure}\n`),
    "invalid_platform_profile",
  );
  for (const invalid of [
    JSON.stringify({ schema_version: 1, command: "run", status: "success", error: { code: "unsafe" } }),
    JSON.stringify({ schema_version: 1, command: "other", status: "error", error: { code: "unsafe" } }),
    JSON.stringify({ schema_version: 1, command: "run", status: "error", error: { code: "INVALID" } }),
    `{${"x".repeat(4096)}}`,
    "not JSON",
  ]) {
    assert.equal(fenceErrorCodeFromJournal(invalid), undefined);
  }
});

test("derives only bounded fixed runtime paths", () => {
  assert.deepEqual(runtimePaths("action-test"), {
    directory: "/run/fence/action-test",
    config: "/run/fence/action-test/config.json",
    ready: "/run/fence/action-test/ready.json",
    report: "/run/fence/action-test/report.json",
    dnsReport: "/run/fence/action-test/dns-report.json",
    unit: "fence-action-test.service",
    launcherDirectory: "/run/fence-launcher/action-test",
    launcherActionDirectory: "/run/fence-launcher/action-test/action",
    launcherIntegrity: "/run/fence-launcher/action-test/integrity.json",
  });
  assert.throws(() => runtimePaths("../action-test"), /slug grammar/);
  assert.throws(() => runtimePaths("action--test"), /slug grammar/);
});

test("launches only the protected root-owned agent copy", () => {
  const paths = runtimePaths("action-test");
  const args = residentServiceArgs(paths);
  assert.deepEqual(args, [
    "/usr/bin/systemd-run",
    "--quiet",
    "--property=Type=exec",
    "--unit",
    "fence-action-test.service",
    "/run/fence-launcher/action-test/action/bin/fence",
    "run",
    "--config",
    "/run/fence/action-test/config.json",
  ]);
  assert.equal(args.includes(path.join(__dirname, "bin", "fence")), false);
});

test("binds launcher integrity to the exact Action runtime file set", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "fence-action-runtime-"));
  try {
    fs.mkdirSync(path.join(temporary, "bin"));
    for (const relativePath of ACTION_RUNTIME_FILES) {
      const file = path.join(temporary, relativePath);
      fs.writeFileSync(file, `runtime:${relativePath}`, "utf8");
      fs.chmodSync(file, 0o644);
    }
    const files = actionRuntimeFileDigests(temporary);
    assert.equal(files.length, ACTION_RUNTIME_FILES.length);
    assert.match(actionRuntimeDigest(files), /^[0-9a-f]{64}$/);
    const pathGuards = [{
      path: "/opt/actions/fence",
      device: "1",
      inode: "2",
    }];
    const integrity = launcherIntegrityDocument(
      "action-test",
      "/opt/actions/fence/action",
      "/run/fence-launcher/action-test/action",
      files,
      pathGuards,
    );
    validateLauncherIntegrity(
      integrity,
      "action-test",
      "/opt/actions/fence/action",
      "/run/fence-launcher/action-test/action",
      files,
      pathGuards,
    );
    assert.throws(
      () => validateLauncherIntegrity(
        { ...integrity, runtime_digest: "0".repeat(64) },
        "action-test",
        "/opt/actions/fence/action",
        "/run/fence-launcher/action-test/action",
        files,
        pathGuards,
      ),
      /does not match/,
    );
    fs.writeFileSync(path.join(temporary, "post.cts"), "modified", "utf8");
    const modified = actionRuntimeFileDigests(temporary);
    assert.notEqual(actionRuntimeDigest(files), actionRuntimeDigest(modified));
    assert.throws(
      () => validateLauncherIntegrity(
        integrity,
        "action-test",
        "/opt/actions/fence/action",
        "/run/fence-launcher/action-test/action",
        modified,
        pathGuards,
      ),
      /does not match/,
    );
    assert.throws(
      () => validateLauncherIntegrity(
        integrity,
        "action-test",
        "/opt/actions/fence/action",
        "/run/fence-launcher/action-test/action",
        files,
        [{ ...pathGuards[0], inode: "3" }],
      ),
      /does not match/,
    );
    assert.throws(() => validateProtectedActionRuntime(temporary), /unsafe ownership or mode/);
    fs.renameSync(path.join(temporary, "bin"), path.join(temporary, "real-bin"));
    fs.symlinkSync(path.join(temporary, "real-bin"), path.join(temporary, "bin"));
    assert.throws(() => actionRuntimeFileDigests(temporary), /binary directory/);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test("rejects an Action runtime that changes while its bundle is validated", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "fence-action-snapshot-"));
  const originalReadFileSync = fs.readFileSync;
  try {
    fs.mkdirSync(path.join(temporary, "bin"));
    const binary = path.join(temporary, "bin", "fence");
    const manifest = path.join(temporary, "bundle-manifest.json");
    const post = path.join(temporary, "post.cts");
    for (const relativePath of ACTION_RUNTIME_FILES) {
      if (relativePath !== "bin/fence" && relativePath !== "bundle-manifest.json") {
        fs.writeFileSync(path.join(temporary, relativePath), `runtime:${relativePath}`, "utf8");
      }
    }
    fs.writeFileSync(binary, "fence-test-binary", "utf8");
    fs.writeFileSync(manifest, JSON.stringify(manifestFor(binary)), "utf8");

    const snapshot = validatedActionRuntimeSnapshot(temporary);
    assert.equal(snapshot.manifest.schema_version, 4);
    assert.equal(snapshot.files.length, ACTION_RUNTIME_FILES.length);

    let manifestReads = 0;
    fs.readFileSync = ((file: fs.PathOrFileDescriptor, ...args: any[]) => {
      if (String(file) === manifest && ++manifestReads === 2) {
        fs.writeFileSync(post, "changed-during-validation", "utf8");
      }
      return originalReadFileSync(file, ...args);
    }) as typeof fs.readFileSync;
    assert.throws(
      () => validatedActionRuntimeSnapshot(temporary),
      /changed while it was being validated/,
    );
  } finally {
    fs.readFileSync = originalReadFileSync;
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test("guards every renameable ancestor of the registered Action path", () => {
  const actionRoot = "/srv/runner/work/project/action";
  const renameable = new Set([
    "/srv/runner/work",
    "/srv/runner/work/project",
  ]);
  const guards = registeredActionPathGuardPaths(
    actionRoot,
    (candidate) => renameable.has(candidate),
  );
  assert.deepEqual(guards, [
    "/srv/runner/work",
    "/srv/runner/work/project",
  ]);
  assert.deepEqual(
    registeredActionPathGuardPaths(actionRoot, () => false),
    [],
  );
  assert.throws(
    () => registeredActionPathGuardPaths("relative/action", () => false),
    /normalized and absolute/,
  );
  const separatedRenameable = new Set([
    "/srv/runner/outer",
    "/srv/runner/outer/locked/project",
  ]);
  assert.deepEqual(
    registeredActionPathGuardPaths(
      "/srv/runner/outer/locked/project/action",
      (candidate) => separatedRenameable.has(candidate),
    ),
    [
      "/srv/runner/outer",
      "/srv/runner/outer/locked/project",
    ],
  );

  const temporary = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "fence-action-path-")));
  try {
    const stable = path.join(temporary, "stable");
    const outer = path.join(stable, "outer");
    const locked = path.join(outer, "locked");
    const project = path.join(locked, "project");
    const runtime = path.join(project, "action");
    fs.mkdirSync(runtime, { recursive: true });
    const identities = actionPathGuardIdentities(
      runtime,
      (candidate) => candidate === outer || candidate === project,
    );
    assert.deepEqual(identities.map((identity) => identity.path), [outer, project]);
    for (const identity of identities) {
      const metadata = fs.lstatSync(identity.path, { bigint: true });
      assert.equal(identity.device, metadata.dev.toString());
      assert.equal(identity.inode, metadata.ino.toString());
    }
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});

test("parses only one bounded active mount identity", () => {
  assert.equal(mountIdFromFdInfo("pos:\t0\nflags:\t0100000\nmnt_id:\t42\n"), "42");
  for (const fdInfo of [
    "",
    "mnt_id:\t0\n",
    "mnt_id:\t01\n",
    "mnt_id:\t1\nmnt_id:\t2\n",
    "x".repeat(4097),
  ]) {
    assert.throws(() => mountIdFromFdInfo(fdInfo), /active mount identity/);
  }
});

test("parses only the bounded active mount record", () => {
  const target = "/opt/actions/fence action";
  const mountInfo = "42 7 0:1 / /opt/actions/fence\\040action ro,nosuid,nodev shared:1 - ext4 /dev/root rw";
  assert.deepEqual(
    actionMountRecordFromMountInfo(mountInfo, target, "42"),
    { target, options: "ro,nosuid,nodev", id: "42" },
  );
  for (const invalid of [
    [mountInfo, target, "41"],
    [mountInfo, "/different", "42"],
    [mountInfo.replace("\\040", "\\777"), target, "42"],
    [mountInfo.replace(" - ", " "), target, "42"],
    [`${mountInfo}\n${mountInfo}`, target, "42"],
    ["x".repeat(16 * 1024 + 1), target, "42"],
  ]) {
    assert.throws(
      () => actionMountRecordFromMountInfo(invalid[0], invalid[1], invalid[2]),
      /active mount record/,
    );
  }
});

test("requires the active registered Action runtime mount to be read-only, nodev, and nosuid", () => {
  const target = "/opt/actions/fence/action";
  const mountId = "10";
  validateReadOnlyActionMount(JSON.stringify({
    filesystems: [{ target, options: "ro,nosuid,nodev,relatime", id: 10 }],
  }), target, mountId);
  const stacked = Array.from({ length: 24 }, (_, index) => ({
    target,
    options: index === 23 ? "ro,nosuid,nodev,relatime" : "rw,relatime",
    id: 10 + index,
  }));
  validateReadOnlyActionMount(JSON.stringify({ filesystems: stacked }), target, "33");

  for (const options of ["rw,nosuid,nodev", "ro,nodev", "ro,nosuid"]) {
    assert.throws(
      () => validateReadOnlyActionMount(JSON.stringify({
        filesystems: [{ target, options, id: 10 }],
      }), target, mountId),
      /missing/,
    );
  }
  for (const evidence of [
    { filesystems: [{ target: "/different", options: "ro,nosuid,nodev", id: 10 }] },
    { filesystems: [{ target, options: "ro,nosuid,nodev", id: 11 }] },
  ]) {
    assert.throws(
      () => validateReadOnlyActionMount(JSON.stringify(evidence), target, mountId),
      /does not match/,
    );
  }
  for (const filesystems of [
    [
      { target, options: "ro,nosuid,nodev", id: 10 },
      { target, options: "ro,nosuid,nodev", id: 10 },
    ],
    [{ target, options: "ro,nosuid,nodev", id: 10, parent: 1 }],
    [{ target, options: "ro,nosuid,nodev" }],
    [],
  ]) {
    assert.throws(
      () => validateReadOnlyActionMount(JSON.stringify({ filesystems }), target, mountId),
      /incomplete/,
    );
  }
  assert.throws(
    () => validateReadOnlyActionMount(JSON.stringify({
      filesystems: [
        { target, options: "ro,nosuid,nodev", id: 10 },
        { target, options: "rw,nosuid,nodev", id: 11 },
      ],
    }), target, "11"),
    /missing/,
  );
  assert.throws(
    () => validateReadOnlyActionMount(JSON.stringify({
      filesystems: [{ target, options: "ro,nosuid,nodev", id: 10 }],
    }), target, "01"),
    /incomplete/,
  );
  assert.throws(() => validateReadOnlyActionMount("not-json", target, mountId), /malformed/);
});

test("requires active registered Action path guards to remain exact writable mountpoints", () => {
  const target = "/srv/runner/work/project";
  const mountId = "10";
  validateActionPathGuardMount(JSON.stringify({
    filesystems: [{ target, options: "rw,nosuid,nodev,relatime", id: mountId }],
  }), target, mountId);
  validateActionPathGuardMount(JSON.stringify({
    filesystems: [
      { target, options: "ro,nosuid,nodev", id: 9 },
      { target, options: "rw,nosuid,nodev,relatime", id: 10 },
    ],
  }), target, mountId);
  for (const evidence of [
    { filesystems: [{ target, options: "ro,nosuid,nodev", id: 10 }] },
    { filesystems: [{ target, options: "rw,ro,nosuid,nodev", id: 10 }] },
    { filesystems: [{ target: "/different", options: "rw,nosuid,nodev", id: 10 }] },
    { filesystems: [{ target, options: "rw,nosuid,nodev", id: 11 }] },
    {
      filesystems: [
        { target, options: "rw,nosuid,nodev", id: 10 },
        { target, options: "rw,nosuid,nodev", id: 10 },
      ],
    },
    {
      filesystems: [
        { target, options: "rw,nosuid,nodev", id: 9 },
        { target, options: "ro,nosuid,nodev", id: 10 },
      ],
    },
    { filesystems: [{ target, options: "rw,nosuid,nodev", id: 10, parent: 1 }] },
    { filesystems: [{ target, options: "rw,nosuid,nodev" }] },
    { filesystems: [] },
  ]) {
    assert.throws(
      () => validateActionPathGuardMount(JSON.stringify(evidence), target, mountId),
      /guard mount/,
    );
  }
  assert.throws(
    () => validateActionPathGuardMount("not-json", target, mountId),
    /malformed/,
  );
});

test("settles queued network evidence in a fixed monotonic four-read window", () => {
  const initial = {
    ...report,
    counters: { total_violations: 0, sampled_violations: 0 },
  };
  const snapshots = Array.from({ length: 4 }, (_, index) => ({
    ...initial,
    counters: {
      total_violations: index + 1,
      sampled_violations: index + 1,
    },
  }));
  let elapsed = 0n;
  let reads = 0;
  const pauses: number[] = [];
  const serviceChecks: Array<[string, unknown]> = [];

  const settled = settleResidentReport(
    "/run/fence/action-test/report.json",
    "fence-action-test.service",
    initial,
    {
      now: () => elapsed,
      pause: (milliseconds: number) => {
        pauses.push(milliseconds);
        elapsed += BigInt(milliseconds) * 1_000_000n;
      },
      read: (file: string) => {
        assert.equal(file, "/run/fence/action-test/report.json");
        return snapshots[reads++];
      },
      verifyService: (unit: string, pid: unknown) => {
        serviceChecks.push([unit, pid]);
      },
    },
  );

  assert.equal(settled, snapshots[3]);
  assert.equal(reads, 4);
  assert.deepEqual(pauses, [40, 40, 40, 40]);
  assert.equal(elapsed, 160_000_000n);
  assert.deepEqual(serviceChecks, [
    ["fence-action-test.service", 4242],
    ["fence-action-test.service", 4242],
  ]);
});

test("settles bounded block, degraded-block, and audit evidence", () => {
  const variants = [
    report,
    {
      ...report,
      status: "protected_host_block_degraded",
      readiness_status: "ready_degraded",
      setup_status: "resident_degraded",
      protection_available: false,
      container_status: "preserved_unsafe",
    },
    {
      ...report,
      status: "protected_host_audit_observation",
      mode: "audit",
      readiness_status: "ready_observation_only",
      setup_status: "resident_observation_only",
      protection_available: false,
      sudo_status: "preserved_verified",
      container_status: "preserved_verified",
    },
  ];

  for (const variant of variants) {
    const initial = {
      ...variant,
      counters: { total_violations: 1, sampled_violations: 1 },
    };
    const latest = {
      ...initial,
      counters: { total_violations: 2, sampled_violations: 2 },
    };
    let elapsed = 0n;
    let reads = 0;
    let serviceChecks = 0;
    const settled = settleResidentReport("/run/fence/test/report.json", "fence-test.service", initial, {
      now: () => elapsed,
      pause: (milliseconds: number) => {
        elapsed += BigInt(milliseconds) * 1_000_000n;
      },
      read: () => {
        reads += 1;
        return latest;
      },
      verifyService: () => {
        serviceChecks += 1;
      },
    });

    assert.equal(settled, latest);
    assert.equal(reads, 4);
    assert.equal(serviceChecks, 2);
  }
});

test("rejects swapped or decreasing reports during bounded evidence settlement", () => {
  const initial = {
    ...report,
    counters: { total_violations: 4, sampled_violations: 3 },
  };
  const invalidSnapshots: Array<[any, RegExp]> = [
    [{ ...initial, policy_hash: "d".repeat(64) }, /identity changed/],
    [{ ...initial, resident_health: residentHealth({ resident_pid: 9000 }) }, /identity changed/],
    [{ ...initial, counters: { total_violations: 3, sampled_violations: 3 } }, /counters decreased/],
    [{ ...initial, counters: { total_violations: 4, sampled_violations: 2 } }, /counters decreased/],
    [{ ...initial, counters: { total_violations: -1, sampled_violations: 3 } }, /bounded network counters/],
    [{ ...initial, counters: { total_violations: 4, sampled_violations: "3" } }, /bounded network counters/],
    [{ ...initial, runtime_evidence_schema_version: 4 }, /reviewed hosted-runner profile/],
  ];

  for (const [snapshot, expected] of invalidSnapshots) {
    let elapsed = 0n;
    assert.throws(() => settleResidentReport(
      "/run/fence/test/report.json",
      "fence-test.service",
      initial,
      {
        now: () => elapsed,
        pause: (milliseconds: number) => {
          elapsed += BigInt(milliseconds) * 1_000_000n;
        },
        read: () => snapshot,
        verifyService: () => {},
      },
    ), expected);
  }
});

test("preserves a validated critical report during final evidence settlement", () => {
  const initial = {
    ...report,
    counters: { total_violations: 1, sampled_violations: 1 },
  };
  const critical = {
    ...initial,
    network_verification_status: "critical_drift",
    resident_health: residentHealth({ status: "critical" }),
    critical_findings: [{
      timestamp: "unix-ms:1",
      code: "dns_block_network_drift",
      message: "DNS-mediated owned nftables state drifted after readiness",
    }],
  };
  let elapsed = 0n;
  let reads = 0;
  let serviceChecks = 0;
  const settled = settleResidentReport("/run/fence/test/report.json", "fence-test.service", initial, {
    now: () => elapsed,
    pause: (milliseconds: number) => {
      elapsed += BigInt(milliseconds) * 1_000_000n;
    },
    read: () => {
      reads += 1;
      return critical;
    },
    verifyService: () => {
      serviceChecks += 1;
    },
  });

  assert.equal(settled, critical);
  assert.equal(reads, 1);
  assert.equal(serviceChecks, 2);
  assert.throws(() => validateReport(settled, true), /critical resident findings/);
});

test("does not delay or reread an already critical resident report", () => {
  const critical = {
    ...report,
    counters: { total_violations: 1, sampled_violations: 1 },
    network_verification_status: "critical_drift",
    resident_health: residentHealth({ status: "critical" }),
    critical_findings: [{
      timestamp: "unix-ms:1",
      code: "dns_block_network_drift",
      message: "DNS-mediated owned nftables state drifted after readiness",
    }],
  };
  let serviceChecks = 0;
  const settled = settleResidentReport("/run/fence/test/report.json", "fence-test.service", critical, {
    now: () => {
      throw new Error("critical evidence must not start a settlement clock");
    },
    pause: () => {
      throw new Error("critical evidence must not be delayed");
    },
    read: () => {
      throw new Error("critical evidence must not be reread");
    },
    verifyService: () => {
      serviceChecks += 1;
    },
  });

  assert.equal(settled, critical);
  assert.equal(serviceChecks, 1);
});

test("rejects malformed initial critical counters without delaying settlement", () => {
  const critical = {
    ...report,
    network_verification_status: "critical_drift",
    resident_health: residentHealth({ status: "critical" }),
    critical_findings: [{
      timestamp: "unix-ms:1",
      code: "dns_block_network_drift",
      message: "DNS-mediated owned nftables state drifted after readiness",
    }],
  };

  for (const counters of [
    undefined,
    null,
    [],
    { total_violations: -1, sampled_violations: 0 },
    { total_violations: Number.MAX_SAFE_INTEGER + 1, sampled_violations: 0 },
    { total_violations: 0, sampled_violations: "0" },
  ]) {
    let serviceChecks = 0;
    assert.throws(() => settleResidentReport(
      "/run/fence/test/report.json",
      "fence-test.service",
      { ...critical, counters },
      {
        now: () => {
          throw new Error("malformed critical evidence must not start a settlement clock");
        },
        pause: () => {
          throw new Error("malformed critical evidence must not be delayed");
        },
        read: () => {
          throw new Error("malformed critical evidence must not be reread");
        },
        verifyService: () => {
          serviceChecks += 1;
        },
      },
    ), /bounded network counters/);
    assert.equal(serviceChecks, 1);
  }
});

test("rejects malformed or decreasing newly critical counters before reporting", () => {
  const initial = {
    ...report,
    counters: { total_violations: 4, sampled_violations: 3 },
  };
  const critical = {
    ...initial,
    network_verification_status: "critical_drift",
    resident_health: residentHealth({ status: "critical" }),
    critical_findings: [{
      timestamp: "unix-ms:1",
      code: "dns_block_network_drift",
      message: "DNS-mediated owned nftables state drifted after readiness",
    }],
  };
  const invalidSnapshots: Array<[any, RegExp]> = [
    [{ ...critical, counters: undefined }, /bounded network counters/],
    [{ ...critical, counters: null }, /bounded network counters/],
    [{ ...critical, counters: { total_violations: -1, sampled_violations: 3 } }, /bounded network counters/],
    [{ ...critical, counters: { total_violations: 4, sampled_violations: "3" } }, /bounded network counters/],
    [{ ...critical, counters: { total_violations: 3, sampled_violations: 3 } }, /counters decreased/],
    [{ ...critical, counters: { total_violations: 4, sampled_violations: 2 } }, /counters decreased/],
  ];

  for (const [snapshot, expected] of invalidSnapshots) {
    let elapsed = 0n;
    let reads = 0;
    let serviceChecks = 0;
    assert.throws(() => settleResidentReport(
      "/run/fence/test/report.json",
      "fence-test.service",
      initial,
      {
        now: () => elapsed,
        pause: (milliseconds: number) => {
          elapsed += BigInt(milliseconds) * 1_000_000n;
        },
        read: () => {
          reads += 1;
          return snapshot;
        },
        verifyService: () => {
          serviceChecks += 1;
        },
      },
    ), expected);
    assert.equal(reads, 1);
    assert.equal(serviceChecks, 1);
  }
});

test("rejects malformed initial counters and an unverifiable final resident service", () => {
  for (const counters of [
    undefined,
    null,
    [],
    { total_violations: 0, sampled_violations: -1 },
    { total_violations: Number.MAX_SAFE_INTEGER + 1, sampled_violations: 0 },
  ]) {
    assert.throws(() => settleResidentReport(
      "/run/fence/test/report.json",
      "fence-test.service",
      { ...report, counters },
      { verifyService: () => {} },
    ), /bounded network counters/);
  }

  let checks = 0;
  let elapsed = 0n;
  const initial = {
    ...report,
    counters: { total_violations: 0, sampled_violations: 0 },
  };
  assert.throws(() => settleResidentReport(
    "/run/fence/test/report.json",
    "fence-test.service",
    initial,
    {
      now: () => elapsed,
      pause: (milliseconds: number) => {
        elapsed += BigInt(milliseconds) * 1_000_000n;
      },
      read: () => initial,
      verifyService: () => {
        checks += 1;
        if (checks === 2) {
          throw new Error("resident service changed");
        }
      },
    },
  ), /resident service changed/);
  assert.equal(checks, 2);
});

test("never exceeds the fixed evidence reread count when a monotonic clock stalls", () => {
  const initial = {
    ...report,
    counters: { total_violations: 0, sampled_violations: 0 },
  };
  let reads = 0;
  let pauses = 0;

  const settled = settleResidentReport("/run/fence/test/report.json", "fence-test.service", initial, {
    now: () => 0n,
    pause: () => {
      pauses += 1;
    },
    read: () => {
      reads += 1;
      return initial;
    },
    verifyService: () => {},
  });

  assert.equal(settled, initial);
  assert.equal(reads, 4);
  assert.equal(pauses, 4);
});

test("validates stable runtime evidence", () => {
  validateReport(report);
  const dnsEvidence = dnsEvidenceFor(report);
  validateDnsEvidence(dnsEvidence, report);
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
  validateReport(auditReport);
  validateDnsEvidence({
    ...dnsEvidence,
    status: auditReport.status,
    mode: auditReport.mode,
    protection_available: false,
    proxy_policy_status: "audit_forwards_while_simulating_name_authorization",
  }, auditReport);
  validateReady({
    runtime_evidence_schema_version: 5,
    status: "ready",
    allow_github_artifacts: false,
    platform_profile_id: "github_hosted_workflow_bootstrap_v5",
    profile_realization_id: "github_hosted_workflow_bootstrap_dns_provenance_v5",
    policy_hash_schema_version: report.policy_hash_schema_version,
    policy_hash: report.policy_hash,
    base_ruleset_hash: report.base_ruleset_hash,
    ruleset_hash: report.ruleset_hash,
    protection_available: true,
    resident_health: report.resident_health,
  }, report);
  validateReady({
    runtime_evidence_schema_version: 5,
    status: "ready",
    allow_github_artifacts: false,
    platform_profile_id: "github_hosted_workflow_bootstrap_v5",
    profile_realization_id: "github_hosted_workflow_bootstrap_dns_provenance_v5",
    policy_hash_schema_version: report.policy_hash_schema_version,
    policy_hash: report.policy_hash,
    base_ruleset_hash: report.base_ruleset_hash,
    ruleset_hash: "d".repeat(64),
    protection_available: true,
    resident_health: report.resident_health,
  }, report);
  assert.throws(() => validateReport({ ...report, critical_findings: [{}] }), /critical resident findings/);
  assert.throws(
    () => validateReport({ ...report, network_verification_status: "critical_drift", critical_findings: [{}] }),
    /critical resident findings/,
  );
  assert.throws(() => validateReport({ ...report, network_verification_status: "critical_drift" }), /verified network state/);
  assert.throws(() => validateReport({ ...report, critical_findings_truncated: true }), /bounded critical findings/);
  assert.throws(() => validateReport({ ...report, sudo_status: "preserved_verified" }), /inconsistent/);
  assert.throws(() => validateReport({ ...report, runtime_evidence_schema_version: 1 }), /profile/);
  assert.throws(() => validateReport({ ...report, policy_hash_schema_version: 3 }), /profile/);
  assert.throws(
    () => validateDnsEvidence({ ...dnsEvidence, runtime_evidence_schema_version: 1 }, report),
    /does not match/,
  );
  validateDnsEvidence({
    ...dnsEvidence,
    runner_authorized_results_storage: [{
      hostname: "productionresultssa17.blob.core.windows.net",
      authorization_origin: "pinned_runner_worker_dns",
    }],
    results_storage_authorization_count: 1,
  }, report);
  const wildcardPolicy = {
    exact: [],
    user_wildcards: [
      {
        pattern: "*.*.docker.io",
        suffix: "docker.io",
        prefix_labels: 2,
        transports: [{ protocol: "udp", port: 53 }],
      },
      {
        pattern: "*.docker.io",
        suffix: "docker.io",
        prefix_labels: 1,
        transports: [
          { protocol: "tcp", port: 443 },
          { protocol: "udp", port: 53 },
        ],
      },
    ],
    allow_dynamic_githubapp_suffix: true,
    allow_github_artifacts: false,
  };
  validateDnsEvidence({
    ...dnsEvidence,
    hostname_policy: wildcardPolicy,
    bounded_user_wildcard_authorizations: ["auth.docker.io", "registry-1.docker.io"],
    observations: [{
      hostname: "auth.docker.io",
      policy_classification: "user_wildcard_allowlist",
    }],
  }, report);
  validateDnsEvidence({
    ...dnsEvidence,
    hostname_policy: wildcardPolicy,
    bounded_user_wildcard_authorizations: Array.from(
      { length: 8 },
      (_, index) => `host-${index}.docker.io`,
    ),
    bounded_user_wildcard_authorizations_truncated: true,
    user_wildcard_request_rejections: 1,
  }, report);
  for (const invalidWildcardEvidence of [
    {
      bounded_user_wildcard_authorizations: ["registry-1.docker.io", "auth.docker.io"],
    },
    {
      bounded_user_wildcard_authorizations: ["auth.docker.io", "auth.docker.io"],
    },
    {
      bounded_user_wildcard_authorizations: ["*.docker.io"],
    },
    {
      bounded_user_wildcard_authorizations: Array.from(
        { length: 9 },
        (_, index) => `host-${index}.docker.io`,
      ),
    },
    {
      bounded_user_wildcard_authorizations_truncated: true,
      user_wildcard_request_rejections: 0,
    },
    {
      bounded_user_wildcard_authorizations_truncated: false,
      user_wildcard_request_rejections: 1,
    },
    {
      observations: [{
        hostname: "*.docker.io",
        policy_classification: "user_wildcard_allowlist",
      }],
    },
    {
      observations: [{
        hostname: "auth.docker.io",
        policy_classification: "unreviewed",
      }],
    },
  ]) {
    assert.throws(
      () => validateDnsEvidence({ ...dnsEvidence, ...invalidWildcardEvidence }, report),
      /DNS evidence/,
    );
  }
  assert.throws(
    () => validateDnsEvidence({
      ...dnsEvidence,
      hostname_policy: {
        ...wildcardPolicy,
        user_wildcards: [{
          pattern: "*.*.*.docker.io",
          suffix: "docker.io",
          prefix_labels: 3,
          transports: [{ protocol: "tcp", port: 443 }],
        }],
      },
    }, report),
    /wildcard policy/,
  );
  assert.throws(
    () => validateDnsEvidence({
      ...dnsEvidence,
      runner_authorized_results_storage: [{
        hostname: "example.blob.core.windows.net",
        authorization_origin: "pinned_runner_worker_dns",
      }],
      results_storage_authorization_count: 1,
    }, report),
    /invalid results-storage authorization/,
  );
  assert.throws(
    () => validateDnsEvidence({
      ...dnsEvidence,
      runner_authorized_results_storage: [{
        hostname: "productionresultssa17.blob.core.windows.net",
        authorization_origin: "workflow_dns",
      }],
      results_storage_authorization_count: 1,
    }, report),
    /invalid results-storage authorization/,
  );
  assert.throws(
    () => validateDnsEvidence({ ...dnsEvidence, results_storage_authorization_count: 1 }, report),
    /bounded runner provenance/,
  );
  assert.throws(
    () => validateDnsEvidence({
      ...dnsEvidence,
      resident_health: residentHealth({ resident_pid: 7 }),
    }, report),
    /resident process/,
  );
  assert.throws(
    () => validateReady({ status: "ready" }, report),
    /does not declare the GitHub artifact compatibility policy/,
  );
});

test("validates bounded GitHub artifact authorizations against the opted-in policy", () => {
  const artifactReport = githubArtifactReport();
  const authorizations = [
    {
      hostname: "productionresultssa10.blob.core.windows.net",
      authorization_origin: "opt_in_github_artifact_dns",
    },
    {
      hostname: "productionresultssa11.blob.core.windows.net",
      authorization_origin: "opt_in_github_artifact_dns",
    },
    {
      hostname: "productionresultssa12.blob.core.windows.net",
      authorization_origin: "pinned_runner_worker_dns",
    },
    {
      hostname: "productionresultssa13.blob.core.windows.net",
      authorization_origin: "pinned_runner_worker_dns",
    },
  ];
  const artifactDns = dnsEvidenceFor(artifactReport, {
    runner_authorized_results_storage: authorizations,
    results_storage_authorization_count: authorizations.length,
    observations: [
      {
        hostname: authorizations[0].hostname,
        policy_classification: "artifact_authorized_results_storage",
      },
      {
        hostname: authorizations[1].hostname,
        policy_classification: "artifact_authorized_results_storage_cname_derived",
      },
    ],
  });

  assert.equal(validateReport(artifactReport), artifactReport);
  const ready = readinessFor(artifactReport);
  assert.equal(validateReady(ready, artifactReport), ready);
  assert.equal(validateDnsEvidence(artifactDns, artifactReport), artifactDns);
  assert.throws(
    () => validateDnsEvidence(dnsEvidenceFor(artifactReport, {
      runner_authorized_results_storage: [
        ...authorizations,
        {
          hostname: "productionresultssa14.blob.core.windows.net",
          authorization_origin: "opt_in_github_artifact_dns",
        },
      ],
      results_storage_authorization_count: 5,
    }), artifactReport),
    /bounded runner provenance/,
  );
});

test("fails closed when GitHub artifact policy and resident evidence disagree", () => {
  const artifactReport = githubArtifactReport();
  const artifactDns = dnsEvidenceFor(artifactReport);
  const artifactReady = readinessFor(artifactReport);

  for (const invalidReport of [
    githubArtifactReport({ allow_github_artifacts: undefined }),
    githubArtifactReport({ allow_github_artifacts: "true" }),
    githubArtifactReport({ limitations: [] }),
    githubArtifactReport({ limitations: githubArtifactCompatibilityLimitations.slice(0, 2) }),
    githubArtifactReport({
      limitations: [
        ...githubArtifactCompatibilityLimitations,
        githubArtifactCompatibilityLimitations[0],
      ],
    }),
    {
      ...report,
      limitations: [...githubArtifactCompatibilityLimitations],
    },
  ]) {
    assert.throws(
      () => validateReport(invalidReport),
      /GitHub artifact (?:compatibility|data-egress) policy/,
    );
  }

  assert.throws(
    () => validateReport(githubArtifactReport({
      status: "protected_host_audit_observation",
      mode: "audit",
      readiness_status: "ready_observation_only",
      setup_status: "resident_observation_only",
      protection_available: false,
      sudo_status: "preserved_verified",
      container_status: "preserved_verified",
    })),
    /cannot enable GitHub artifact compatibility in audit mode/,
  );

  assert.throws(
    () => validateReady({
      ...artifactReady,
      allow_github_artifacts: false,
      limitations: [],
    }, artifactReport),
    /readiness identity/,
  );
  assert.throws(
    () => validateReady({ ...artifactReady, limitations: [] }, artifactReport),
    /does not disclose the GitHub artifact data-egress policy/,
  );

  assert.throws(
    () => validateDnsEvidence(dnsEvidenceFor(report), artifactReport),
    /does not match the resident report/,
  );
  assert.throws(
    () => validateDnsEvidence({ ...artifactDns, limitations: [] }, artifactReport),
    /does not disclose the GitHub artifact data-egress policy/,
  );
  assert.throws(
    () => validateDnsEvidence({
      ...artifactDns,
      hostname_policy: {
        ...(artifactDns.hostname_policy as Record<string, unknown>),
        allow_github_artifacts: false,
      },
    }, artifactReport),
    /bounded wildcard policy/,
  );
});

test("rejects artifact-origin storage access and classifications in strict mode", () => {
  const strictDns = dnsEvidenceFor(report);
  const unauthorizedAccount = {
    hostname: "productionresultssa10.blob.core.windows.net",
    authorization_origin: "opt_in_github_artifact_dns",
  };

  assert.throws(
    () => validateDnsEvidence({
      ...strictDns,
      runner_authorized_results_storage: [unauthorizedAccount],
      results_storage_authorization_count: 1,
    }, report),
    /invalid results-storage authorization/,
  );
  for (const classification of [
    "artifact_authorized_results_storage",
    "artifact_authorized_results_storage_cname_derived",
  ]) {
    assert.throws(
      () => validateDnsEvidence({
        ...strictDns,
        observations: [{
          hostname: unauthorizedAccount.hostname,
          policy_classification: classification,
        }],
      }, report),
      /invalid hostname observation/,
    );
  }
  for (const hostname of [
    "unrelated.blob.core.windows.net",
    "productionresultssa10.blob.core.windows.net.evil.example",
    "productionresultssa123456.blob.core.windows.net",
    "*.blob.core.windows.net",
  ]) {
    const artifactReport = githubArtifactReport();
    assert.throws(
      () => validateDnsEvidence(dnsEvidenceFor(artifactReport, {
        runner_authorized_results_storage: [{
          hostname,
          authorization_origin: "opt_in_github_artifact_dns",
        }],
        results_storage_authorization_count: 1,
      }), artifactReport),
      /invalid results-storage authorization/,
    );
  }
});

test("validates fresh resident worker and service identity evidence", () => {
  const now = 2_000_000;
  const health = {
    status: "healthy",
    resident_pid: 4242,
    verification_sequence: 9,
    last_successful_verification_unix_milliseconds: now - 5_000,
    verification_interval_seconds: 5,
    workers: [
      { name: "docker_tcp_dns", status: "running" },
      { name: "docker_udp_dns", status: "running" },
      { name: "host_tcp_dns", status: "running" },
      { name: "host_udp_dns", status: "running" },
      { name: "process_attribution", status: "running" },
    ],
  };
  validateResidentHealth(health, now);
  validateResidentHealth({ ...health, status: "critical" }, now, true);
  const failedWorkerHealth = {
    ...health,
    status: "critical",
    workers: health.workers.map((worker) =>
      worker.name === "process_attribution" ? { ...worker, status: "failed" } : worker
    ),
  };
  validateResidentHealth(failedWorkerHealth, now, true);
  assert.throws(() => validateResidentHealth(failedWorkerHealth, now), /invalid or unhealthy/);
  validateResidentUnitStatus("ActiveState=active\nSubState=running\nMainPID=4242\n", 4242);
  assert.throws(
    () => validateResidentHealth({ ...health, status: "critical" }, now),
    /invalid or unhealthy/,
  );
  assert.throws(
    () => validateResidentHealth({ ...health, last_successful_verification_unix_milliseconds: now - 20_001 }, now),
    /stale/,
  );
  assert.throws(
    () => validateResidentHealth({ ...health, last_successful_verification_unix_milliseconds: now + 5_001 }, now),
    /stale/,
  );
  assert.throws(
    () => validateResidentHealth({ ...health, workers: health.workers.slice(1) }, now),
    /worker set/,
  );
  assert.throws(
    () => validateResidentHealth({
      ...health,
      workers: health.workers.map((worker) =>
        worker.name === "host_udp_dns" ? { ...worker, status: "failed" } : worker
      ),
    }, now),
    /worker health/,
  );
  assert.throws(
    () => validateResidentHealth({
      ...health,
      workers: health.workers.filter((worker) => worker.name !== "process_attribution"),
    }, now),
    /worker set/,
  );
  assert.throws(
    () => validateResidentHealth({
      ...health,
      workers: health.workers.map((worker) =>
        worker.name === "process_attribution" ? { ...worker, status: "failed" } : worker
      ),
    }, now),
    /worker health/,
  );
  assert.throws(
    () => validateResidentUnitStatus("ActiveState=inactive\nSubState=dead\nMainPID=4242\n", 4242),
    /not active/,
  );
  assert.throws(
    () => validateResidentUnitStatus("ActiveState=active\nSubState=running\nMainPID=7\n", 4242),
    /not active/,
  );
  assert.throws(
    () => validateResidentUnitStatus("ActiveState=active\nSubState=running\n", 4242),
    /incomplete/,
  );
});

test("renders a canonical healthy structured network report from bounded evidence", () => {
  const currentReport = {
    ...report,
    findings: [
      {
        timestamp: "unix-ms:1",
        mode: "block",
        classification: "rejected",
        family: "ipv4",
        protocol: "tcp",
        remote_address: "192.0.2.44",
        remote_port: 443,
        rule_class: "undeclared_new_egress",
        local_attribution: {
          status: "attributed",
          actor_class: "runner",
          pid: 4242,
          executable_basename: "curl",
        },
      },
      {
        timestamp: "unix-ms:2",
        mode: "block",
        classification: "rejected",
        family: "ipv6",
        protocol: "udp",
        remote_address: "2001:db8::44",
        remote_port: 53,
        rule_class: "undeclared_new_egress",
      },
    ],
    findings_truncated: false,
  };
  const dnsEvidence = {
    observations: [
      {
        hostname: "github.com",
        query_type: "a",
        policy_classification: "platform_profile",
        occurrences: 2,
        resolved_addresses: ["192.0.2.1"],
      },
      {
        hostname: "blocked.example.com",
        query_type: "a",
        policy_classification: "outside_policy",
        occurrences: 1,
        resolved_addresses: ["192.0.2.44"],
      },
    ],
    observations_truncated: false,
    blocked_non_profile_query_count: 1,
  };

  const document = parsedStructuredNetworkReport(currentReport, dnsEvidence);
  assert.deepEqual(Object.keys(document), [
    "schema_version",
    "mode",
    "result",
    "controls",
    "network",
    "warnings",
    "omissions",
    "suggested_allowlist",
  ]);
  assert.equal(document.schema_version, 1);
  assert.equal(document.mode, "block");
  assert.equal(document.result, "healthy");
  assert.deepEqual(document.controls, {
    network: "verified",
    sudo: "disabled_verified",
    containers: "disabled_verified",
    protection_available: true,
    readiness: "ready",
    resident_health: "healthy",
  });

  const allowed = document.network.find((row: any) => row.destination === "github.com");
  assert.deepEqual(Object.keys(allowed), [
    "destination_kind",
    "destination",
    "decision",
    "activities",
    "actors",
    "count",
  ]);
  assert.equal(allowed.destination_kind, "hostname");
  assert.equal(allowed.decision, "allowed");
  assert.deepEqual(allowed.activities, [{ kind: "dns_query", query_type: "a", count: 2 }]);

  const blocked = document.network.find((row: any) => row.destination === "blocked.example.com");
  assert.equal(blocked.destination_kind, "hostname");
  assert.equal(blocked.decision, "blocked");
  assert.deepEqual(blocked.activities, [
    { kind: "dns_query", query_type: "a", count: 1 },
    { kind: "connection_attempt", protocol: "tcp", port: 443, count: 1 },
  ]);
  assert.deepEqual(blocked.actors, [{ label: "runner: curl (PID 4242)", count: 1 }]);

  const directIp = document.network.find((row: any) => row.destination === "2001:db8::44");
  assert.equal(directIp.destination_kind, "ip");
  assert.equal(directIp.decision, "blocked");
  assert.deepEqual(directIp.activities, [
    { kind: "connection_attempt", protocol: "udp", port: 53, count: 1 },
  ]);
  assert.deepEqual(document.suggested_allowlist, []);
  assert.equal(document.omissions.network_rows, 0);
  assert.equal(document.omissions.source_truncated, false);
  assert.equal(document.warnings.github_artifact_uploads_enabled, false);
  assert.equal(document.warnings.github_artifact_authorizations, 0);

  const humanReport = networkReportLines(currentReport, dnsEvidence).join("\n");
  assert.match(humanReport, /Fence network report: healthy/);
  assert.match(humanReport, /Decision \| Destination \| Activity \| Actor/);
  assert.match(humanReport, /github\.com/);
  assert.match(humanReport, /blocked\.example\.com/);
  assert.match(humanReport, /blocked \| blocked\.example\.com \| .* \| runner: curl \(PID 4242\)/);
  assert.match(humanReport, /2001:db8::44/);
  assert.doesNotMatch(humanReport, /intentional data-egress channel/);
});

test("reports GitHub artifact compatibility as intentionally reduced assurance", () => {
  const artifactReport = githubArtifactReport();
  const artifactHostname = "productionresultssa10.blob.core.windows.net";
  const pinnedHostname = "productionresultssa11.blob.core.windows.net";
  const authorizations = [
    { hostname: artifactHostname, authorization_origin: "opt_in_github_artifact_dns" },
    { hostname: pinnedHostname, authorization_origin: "pinned_runner_worker_dns" },
  ];
  const artifactDns = dnsEvidenceFor(artifactReport, {
    runner_authorized_results_storage: authorizations,
    results_storage_authorization_count: authorizations.length,
    observations: [{
      hostname: artifactHostname,
      query_type: "a",
      policy_classification: "artifact_authorized_results_storage",
      occurrences: 2,
      resolved_addresses: ["192.0.2.10"],
    }],
  });

  validateReport(artifactReport);
  validateDnsEvidence(artifactDns, artifactReport);
  const document = parsedStructuredNetworkReport(artifactReport, artifactDns);
  assert.equal(document.schema_version, 1);
  assert.equal(document.mode, "block");
  assert.equal(document.result, "warning");
  assert.equal(document.controls.protection_available, true);
  assert.equal(document.controls.network, "verified");
  assert.equal(document.controls.sudo, "disabled_verified");
  assert.equal(document.controls.containers, "disabled_verified");
  assert.equal(document.warnings.github_artifact_uploads_enabled, true);
  assert.equal(document.warnings.github_artifact_authorizations, 1);
  assert.equal(document.network.find((row: any) =>
    row.destination === artifactHostname
  ).decision, "allowed");

  const summary = summaryLines(artifactReport, artifactDns).join("\n");
  assert.match(summary, /^### 🟡 Fence Summary/);
  assert.doesNotMatch(summary, /^### 🟢 Fence Summary/m);
  assert.match(summary, /\| GitHub artifact uploads \| ⚠️ Enabled/);
  assert.match(summary, /intentional data-egress channel/);
  assert.match(summary, /1 of 4 storage accounts authorized/);
  assert.match(summary, /productionresultssa10\.blob\.core\.windows\.net/);

  const humanReport = networkReportLines(artifactReport, artifactDns).join("\n");
  assert.match(humanReport, /^Fence network report: warning/m);
  assert.match(humanReport, /GitHub artifact uploads: enabled; intentional data-egress channel/);
  assert.match(humanReport, /1 of 4 storage accounts authorized/);
  assert.match(humanReport, /allowed \| productionresultssa10\.blob\.core\.windows\.net/);
  assert.doesNotMatch(`${summary}\n${humanReport}`, /sig=|token=|https:\/\//i);

  const optedInWithoutUploads = parsedStructuredNetworkReport(
    artifactReport,
    dnsEvidenceFor(artifactReport),
  );
  assert.equal(optedInWithoutUploads.result, "warning");
  assert.equal(optedInWithoutUploads.warnings.github_artifact_uploads_enabled, true);
  assert.equal(optedInWithoutUploads.warnings.github_artifact_authorizations, 0);
  assert.match(
    summaryLines(artifactReport, dnsEvidenceFor(artifactReport)).join("\n"),
    /0 of 4 storage accounts authorized/,
  );
});

test("never reports artifact-only DNS classifications as allowed in strict mode", () => {
  for (const policyClassification of [
    "artifact_authorized_results_storage",
    "artifact_authorized_results_storage_cname_derived",
  ]) {
    const strictDocument = parsedStructuredNetworkReport(report, {
      observations: [{
        hostname: "productionresultssa10.blob.core.windows.net",
        query_type: "a",
        policy_classification: policyClassification,
        occurrences: 1,
        resolved_addresses: [],
      }],
      observations_truncated: false,
    });
    assert.equal(strictDocument.network[0].decision, "blocked");
  }
});

test("reports degraded and critical security states without claiming healthy protection", () => {
  const degraded = {
    ...report,
    status: "protected_host_block_degraded",
    readiness_status: "ready_degraded",
    setup_status: "resident_degraded",
    protection_available: false,
    container_status: "preserved_unsafe",
  };
  const degradedDocument = parsedStructuredNetworkReport(degraded, {
    observations: [],
    observations_truncated: false,
  });
  assert.equal(degradedDocument.mode, "block");
  assert.equal(degradedDocument.result, "warning");
  assert.equal(degradedDocument.controls.protection_available, false);
  assert.equal(degradedDocument.controls.containers, "preserved_unsafe");
  assert.match(networkReportLines(degraded).join("\n"), /Fence network report: warning/);

  const critical = {
    ...report,
    network_verification_status: "critical_drift",
    resident_health: residentHealth({ status: "critical" }),
    critical_findings: [{
      timestamp: "unix-ms:1",
      code: "owned_nftables_state_missing",
      message: "Fence-owned network state changed after readiness.",
    }],
  };
  const criticalDocument = parsedStructuredNetworkReport(critical, {
    observations: [],
    observations_truncated: false,
  });
  assert.equal(criticalDocument.result, "critical");
  assert.equal(criticalDocument.controls.network, "critical_drift");
  assert.equal(criticalDocument.controls.resident_health, "critical");
  assert.equal(criticalDocument.warnings.critical_findings, 1);
  assert.deepEqual(criticalDocument.warnings.critical_codes, ["owned_nftables_state_missing"]);
  assert.match(networkReportLines(critical).join("\n"), /Fence network report: critical/);
  assert.throws(() => validateReport(critical, true), /critical resident findings/);
});

test("reports source-produced sudo and container drift in every runtime mode", () => {
  const modes = [
    report,
    {
      ...report,
      status: "protected_host_block_degraded",
      readiness_status: "ready_degraded",
      setup_status: "resident_degraded",
      protection_available: false,
      container_status: "preserved_unsafe",
    },
    {
      ...report,
      status: "protected_host_audit_observation",
      mode: "audit",
      readiness_status: "ready_observation_only",
      setup_status: "resident_observation_only",
      protection_available: false,
      sudo_status: "preserved_verified",
      container_status: "preserved_verified",
    },
  ];

  for (const currentMode of modes) {
    for (const controls of [
      ["sudo_status"],
      ["container_status"],
      ["sudo_status", "container_status"],
    ]) {
      const critical = {
        ...currentMode,
        ...Object.fromEntries(controls.map((control) => [control, "critical_drift"])),
        resident_health: residentHealth({ status: "critical" }),
        critical_findings: controls.map((control, index) => ({
          timestamp: `unix-ms:${index + 1}`,
          code: `dns_${currentMode.mode === "audit" ? "audit" : "block"}_${
            control === "sudo_status" ? "sudo" : "container"
          }_drift`,
          message: "Resident control verification detected drift.",
        })),
      };

      assert.equal(validateReport(critical, false), critical);
      const document = parsedStructuredNetworkReport(critical, {
        observations: [],
        observations_truncated: false,
      });
      assert.equal(document.mode, currentMode.mode);
      assert.equal(document.result, "critical");
      assert.equal(document.controls.resident_health, "critical");
      assert.equal(
        document.controls.sudo,
        controls.includes("sudo_status") ? "critical_drift" : currentMode.sudo_status,
      );
      assert.equal(
        document.controls.containers,
        controls.includes("container_status") ? "critical_drift" : currentMode.container_status,
      );
      assert.equal(document.warnings.critical_findings, controls.length);
      assert.match(networkReportLines(critical).join("\n"), /Fence network report: critical/);
      assert.throws(() => validateReport(critical, true), /critical resident findings/);
    }
  }
});

test("reports bounded source-truncated critical findings and still fails closed", () => {
  const critical = {
    ...report,
    sudo_status: "critical_drift",
    resident_health: residentHealth({ status: "critical" }),
    critical_findings: Array.from({ length: 64 }, (_, index) => ({
      timestamp: `unix-ms:${index + 1}`,
      code: "dns_block_sudo_drift",
      message: "Resident sudo verification detected drift.",
    })),
    critical_findings_truncated: true,
  };

  assert.equal(validateReport(critical, false), critical);
  const document = parsedStructuredNetworkReport(critical, {
    observations: [],
    observations_truncated: false,
  });
  assert.equal(document.result, "critical");
  assert.equal(document.controls.sudo, "critical_drift");
  assert.equal(document.warnings.critical_findings, 64);
  assert.deepEqual(
    document.warnings.critical_codes,
    Array.from({ length: 5 }, () => "dns_block_sudo_drift"),
  );
  assert.equal(document.omissions.critical_codes, 59);
  assert.equal(document.omissions.source_truncated, true);
  assert.match(networkReportLines(critical).join("\n"), /truncated/i);
  assert.throws(() => validateReport(critical, true), /critical resident findings/);
});

test("rejects unbounded, inconsistent, and unsupported critical report evidence", () => {
  const finding = {
    timestamp: "unix-ms:1",
    code: "dns_block_sudo_drift",
    message: "Resident sudo verification detected drift.",
  };
  const critical = {
    ...report,
    resident_health: residentHealth({ status: "critical" }),
    critical_findings: [finding],
  };
  const audit = {
    ...critical,
    status: "protected_host_audit_observation",
    mode: "audit",
    readiness_status: "ready_observation_only",
    setup_status: "resident_observation_only",
    protection_available: false,
    sudo_status: "preserved_verified",
    container_status: "preserved_verified",
  };

  for (const invalid of [
    { ...report, sudo_status: "critical_drift" },
    { ...report, container_status: "critical_drift" },
    { ...report, resident_health: residentHealth({ status: "critical" }) },
    { ...critical, resident_health: residentHealth() },
    {
      ...critical,
      resident_health: residentHealth({
        status: "critical",
        last_successful_verification_unix_milliseconds: Date.now() - 20_001,
      }),
    },
    { ...critical, critical_findings_truncated: "true" },
    { ...critical, critical_findings_truncated: true },
    {
      ...critical,
      critical_findings: Array.from({ length: 63 }, () => finding),
      critical_findings_truncated: true,
    },
    {
      ...critical,
      critical_findings: Array.from({ length: 65 }, () => finding),
    },
    { ...critical, network_verification_status: "critical_invented" },
    { ...critical, sudo_status: "preserved_verified" },
    { ...critical, container_status: "preserved_verified" },
    { ...audit, network_verification_status: "critical_dynamic_update_failed" },
  ]) {
    assert.throws(() => validateReport(invalid, false));
    assert.throws(() => structuredReportLine(invalid));
  }

  for (const currentMode of [
    critical,
    {
      ...critical,
      status: "protected_host_block_degraded",
      readiness_status: "ready_degraded",
      setup_status: "resident_degraded",
      protection_available: false,
      container_status: "preserved_unsafe",
    },
  ]) {
    const dynamicUpdateFailure = {
      ...currentMode,
      network_verification_status: "critical_dynamic_update_failed",
    };
    assert.equal(validateReport(dynamicUpdateFailure, false), dynamicUpdateFailure);
    assert.equal(parsedStructuredNetworkReport(dynamicUpdateFailure).result, "critical");
    assert.throws(() => validateReport(dynamicUpdateFailure, true), /critical resident findings/);
  }
});

test("renders audit network decisions and hostname and direct-IP allowlist suggestions", () => {
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
      {
        timestamp: "unix-ms:2",
        mode: "audit",
        classification: "would_block",
        family: "ipv6",
        protocol: "udp",
        remote_address: "2001:db8::10",
        remote_port: 53,
        rule_class: "undeclared_new_egress",
      },
    ],
    findings_truncated: false,
  };
  const dnsEvidence = {
    observations: [{
      hostname: "api.example.com",
      query_type: "a",
      policy_classification: "outside_policy",
      occurrences: 1,
      resolved_addresses: ["203.0.113.10"],
    }],
    observations_truncated: false,
  };

  const document = parsedStructuredNetworkReport(audit, dnsEvidence);
  assert.equal(document.mode, "audit");
  assert.equal(document.controls.protection_available, false);
  assert.equal(document.controls.sudo, "preserved_verified");
  assert.equal(document.controls.containers, "preserved_verified");
  assert.equal(document.network.find((row: any) => row.destination === "api.example.com").decision, "would_block");
  assert.equal(document.network.find((row: any) => row.destination === "2001:db8::10").decision, "would_block");
  assert.deepEqual(document.suggested_allowlist, [
    "api.example.com",
    "ip 2001:db8::10 udp 53",
  ]);
  const humanReport = networkReportLines(audit, dnsEvidence).join("\n");
  assert.match(humanReport, /would.block/i);
  assert.match(humanReport, /api\.example\.com/);
  assert.match(humanReport, /2001:db8::10/);
});

test("retains both final denied burst destinations in one bounded warning report", () => {
  const destinations = [
    "192.0.2.1",
    "192.0.2.2",
    ...Array.from({ length: 40 }, (_, index) => `192.0.2.${index + 10}`),
  ];
  const burst = {
    ...report,
    counters: { total_violations: 42, sampled_violations: 42 },
    findings: destinations.map((destination, index) => ({
      timestamp: `unix-ms:${index + 1}`,
      mode: "block",
      classification: "rejected",
      family: "ipv4",
      protocol: "udp",
      remote_address: destination,
      remote_port: 443,
      rule_class: "undeclared_new_egress",
    })),
    findings_truncated: false,
  };
  const document = parsedStructuredNetworkReport(burst, dnsEvidenceFor(burst));

  assert.equal(document.mode, "block");
  assert.equal(document.result, "warning");
  assert.equal(document.network.length, 20);
  assert.equal(document.omissions.network_rows, 22);
  assert.equal(document.omissions.byte_budget_exceeded, false);
  assert.equal(document.omissions.source_truncated, false);
  assert.equal(document.warnings.critical_findings, 0);
  assert.equal(document.warnings.github_artifact_uploads_enabled, false);
  for (const destination of ["192.0.2.1", "192.0.2.2"]) {
    const rows = document.network.filter((row: any) => row.destination === destination);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].destination_kind, "ip");
    assert.equal(rows[0].decision, "blocked");
    assert.deepEqual(rows[0].activities, [{
      kind: "connection_attempt",
      protocol: "udp",
      port: 443,
      count: 1,
    }]);
  }
});

test("caps structured network rows and explicitly reports omitted evidence", () => {
  const dnsEvidence = {
    observations: Array.from({ length: 27 }, (_, index) => ({
      hostname: `host-${String(index).padStart(2, "0")}.example.com`,
      query_type: "a",
      policy_classification: "outside_policy",
      occurrences: 1,
      resolved_addresses: [],
    })),
    observations_truncated: true,
    blocked_non_profile_query_count: 27,
  };

  const document = parsedStructuredNetworkReport(report, dnsEvidence);
  assert.equal(document.network.length, 20);
  assert.equal(document.omissions.network_rows, 7);
  assert.equal(document.omissions.source_truncated, true);
  assert.ok(document.network.every((row: any) => row.decision === "blocked"));
  assert.match(networkReportLines(report, dnsEvidence).join("\n"), /omitt|truncat/i);
});

test("distinguishes typed DNS decisions and TCP and UDP connection attempts", () => {
  const currentReport = {
    ...report,
    findings: ["tcp", "udp"].map((protocol) => ({
      timestamp: "unix-ms:1",
      mode: "block",
      classification: "rejected",
      family: "ipv4",
      protocol,
      remote_address: "203.0.113.22",
      remote_port: 443,
      rule_class: "undeclared_new_egress",
    })),
    findings_truncated: false,
  };
  const dnsEvidence = {
    observations: [
      {
        hostname: "allowed.example.com",
        query_type: "a",
        policy_classification: "user_allowlist",
        occurrences: 2,
        resolved_addresses: ["192.0.2.20"],
      },
      {
        hostname: "allowed.example.com",
        query_type: "aaaa",
        policy_classification: "user_allowlist",
        occurrences: 1,
        resolved_addresses: ["2001:db8::20"],
      },
      {
        hostname: "allowed.example.com",
        query_type: "type_15",
        policy_classification: "user_allowlist",
        occurrences: 1,
        resolved_addresses: [],
      },
      {
        hostname: "blocked.example.com",
        query_type: "a",
        policy_classification: "outside_policy",
        occurrences: 1,
        resolved_addresses: ["203.0.113.22"],
      },
    ],
    observations_truncated: false,
    blocked_non_profile_query_count: 2,
  };

  const document = parsedStructuredNetworkReport(currentReport, dnsEvidence);
  const allowed = document.network.find((row: any) =>
    row.destination === "allowed.example.com" && row.decision === "allowed"
  );
  assert.deepEqual(allowed.activities, [
    { kind: "dns_query", query_type: "a", count: 2 },
    { kind: "dns_query", query_type: "aaaa", count: 1 },
  ]);

  const blockedType = document.network.find((row: any) =>
    row.destination === "allowed.example.com" && row.decision === "blocked"
  );
  assert.deepEqual(blockedType.activities, [
    { kind: "dns_query", query_type: "type_15", count: 1 },
  ]);

  const blocked = document.network.find((row: any) => row.destination === "blocked.example.com");
  assert.ok(blocked.activities.some((activity: any) =>
    activity.kind === "connection_attempt" && activity.protocol === "tcp" && activity.port === 443
  ));
  assert.ok(blocked.activities.some((activity: any) =>
    activity.kind === "connection_attempt" && activity.protocol === "udp" && activity.port === 443
  ));
});

test("reports bounded firewall, wildcard, and results-storage warning counters", () => {
  const dnsEvidence = {
    observations: [],
    observations_truncated: false,
    materialization_request_rejections: 2,
    user_wildcard_request_rejections: 3,
    bounded_user_wildcard_authorizations_truncated: true,
    results_storage_attribution_failures: 4,
    results_storage_request_rejections: 5,
    runner_authorized_results_storage_truncated: true,
  };

  const document = parsedStructuredNetworkReport(report, dnsEvidence);
  assert.equal(document.result, "warning");
  assert.equal(document.warnings.materialization_rejections, 2);
  assert.equal(document.warnings.wildcard_rejections, 3);
  assert.equal(document.warnings.wildcard_authorizations_truncated, true);
  assert.equal(document.warnings.results_storage_attribution_failures, 4);
  assert.equal(document.warnings.results_storage_rejections, 5);
  assert.equal(document.warnings.results_storage_authorizations_truncated, true);
  assert.equal(document.warnings.critical_findings, 0);
  assert.match(networkReportLines(report, dnsEvidence).join("\n"), /Fence network report: warning/);
});

test("preserves the fixed byte budget by pruning whole network rows explicitly", () => {
  const hostnames = Array.from({ length: 20 }, (_, index) =>
    `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.host-${index}.example.com`
  );
  const dnsEvidence = {
    observations: hostnames.map((hostname, index) => ({
      hostname,
      query_type: "a",
      policy_classification: "outside_policy",
      occurrences: 1,
      resolved_addresses: [`198.51.100.${index + 1}`],
    })),
    observations_truncated: false,
    blocked_non_profile_query_count: hostnames.length,
  };
  const currentReport = {
    ...report,
    findings: hostnames.flatMap((_, index) => Array.from({ length: 4 }, (_, actorIndex) => ({
      timestamp: "unix-ms:1",
      mode: "block",
      classification: "rejected",
      family: "ipv4",
      protocol: "tcp",
      remote_address: `198.51.100.${index + 1}`,
      remote_port: 443,
      rule_class: "undeclared_new_egress",
      local_attribution: {
        status: "attributed",
        actor_class: "runner",
        pid: 1000 + (index * 4) + actorIndex,
        executable_basename: `worker-${index}-${actorIndex}-${"x".repeat(108)}`,
      },
    }))),
    findings_truncated: false,
  };

  const line = structuredReportLine(currentReport, dnsEvidence);
  const document = parsedStructuredNetworkReport(currentReport, dnsEvidence);
  assert.ok(Buffer.byteLength(line, "utf8") <= MAX_STRUCTURED_REPORT_BYTES);
  assert.equal(document.result, "warning");
  assert.equal(document.omissions.byte_budget_exceeded, true);
  assert.ok(document.network.length < hostnames.length);
  assert.equal(document.omissions.network_rows, hostnames.length - document.network.length);
  assert.doesNotMatch(line, /\.\.\.\[truncated\]/);
  const humanReport = networkReportLines(currentReport, dnsEvidence).join("\n");
  assert.match(humanReport, /omitt/i);
  assert.match(humanReport, /truncat/i);
});

test("reports missing DNS evidence and unretained observations without inventing hostnames", () => {
  const audit = {
    ...report,
    status: "protected_host_audit_observation",
    mode: "audit",
    readiness_status: "ready_observation_only",
    setup_status: "resident_observation_only",
    protection_available: false,
    sudo_status: "preserved_verified",
    container_status: "preserved_verified",
    findings: [{
      timestamp: "unix-ms:1",
      mode: "audit",
      classification: "would_block",
      family: "ipv4",
      protocol: "udp",
      remote_address: "192.0.2.10",
      remote_port: 443,
      rule_class: "undeclared_new_egress",
    }],
    findings_truncated: false,
  };

  const missingDns = parsedStructuredNetworkReport(audit);
  assert.equal(missingDns.omissions.dns_evidence_missing, true);
  assert.equal(missingDns.network.find((row: any) => row.destination === "192.0.2.10").destination_kind, "ip");

  const unretained = parsedStructuredNetworkReport(audit, {
    observations: [],
    observations_truncated: false,
    excluded_unretained_query_count: 3,
  });
  const unretainedRow = unretained.network.find((row: any) => row.destination_kind === "unretained");
  assert.notEqual(unretainedRow, undefined);
  assert.equal(unretainedRow.destination, null);
  assert.equal(unretainedRow.decision, "would_block");
  assert.equal(unretainedRow.count, 3);
});

test("excludes payloads, command arguments, private paths, and unsafe actors from reports", () => {
  const marker = "sensitive-example-marker";
  const currentReport = {
    ...report,
    findings: [{
      timestamp: "unix-ms:1",
      mode: "block",
      classification: "rejected",
      family: "ipv4",
      protocol: "tcp",
      remote_address: "203.0.113.10",
      remote_port: 443,
      rule_class: "undeclared_new_egress",
      ignored_payload: marker,
      command_line: marker,
      local_attribution: {
        status: "attributed",
        actor_class: "runner",
        pid: 4242,
        executable_basename: "../../unsafe-executable",
        executable_path: `/example/private/${marker}`,
        command_line: marker,
        parent_executable_basenames: [marker],
      },
    }],
    findings_truncated: false,
  };
  const dnsEvidence = {
    observations: [{
      hostname: "example.com",
      query_type: "a",
      policy_classification: "outside_policy",
      occurrences: 1,
      resolved_addresses: ["203.0.113.10"],
      ignored_payload: marker,
    }],
    observations_truncated: false,
  };

  const line = structuredReportLine(currentReport, dnsEvidence);
  const humanReport = networkReportLines(currentReport, dnsEvidence).join("\n");
  assert.doesNotMatch(line, new RegExp(marker));
  assert.doesNotMatch(line, /unsafe-executable|example\/private|command_line|ignored_payload/);
  assert.doesNotMatch(humanReport, new RegExp(marker));
  assert.doesNotMatch(humanReport, /unsafe-executable|example\/private|command_line|ignored_payload/);
  assert.doesNotMatch(line, /[\r\n\u0000-\u001f\u007f]/);
  assert.ok(Buffer.byteLength(line, "utf8") <= MAX_STRUCTURED_REPORT_BYTES);
});

test("renders a concise healthy block results table without raw evidence fields", () => {
  const dnsEvidence = {
    observations: [
      {
        hostname: "github.com",
        query_type: "a",
        policy_classification: "platform_profile",
        occurrences: 2,
        resolved_addresses: ["192.0.2.1"],
      },
      {
        hostname: "api.github.com",
        query_type: "aaaa",
        policy_classification: "platform_profile",
        occurrences: 1,
        resolved_addresses: ["2001:db8::1"],
      },
      {
        hostname: "productionresultssa17.blob.core.windows.net",
        query_type: "a",
        policy_classification: "runner_authorized_results_storage",
        occurrences: 1,
        resolved_addresses: ["192.0.2.17"],
      },
      {
        hostname: "result-storage-cname.example.net",
        query_type: "aaaa",
        policy_classification: "runner_authorized_results_storage_cname_derived",
        occurrences: 1,
        resolved_addresses: ["2001:db8::17"],
      },
      {
        hostname: "auth.docker.io",
        query_type: "a",
        policy_classification: "user_wildcard_allowlist",
        occurrences: 1,
        resolved_addresses: ["192.0.2.18"],
      },
      {
        hostname: "codeload.github.com",
        query_type: "a",
        policy_classification: "outside_policy",
        occurrences: 1,
        resolved_addresses: [],
      },
      {
        hostname: "github.com",
        query_type: "type_15",
        policy_classification: "platform_profile",
        occurrences: 1,
        resolved_addresses: [],
      },
    ],
    observations_truncated: false,
    blocked_non_profile_query_count: 2,
  };
  const summary = summaryLines(report, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟢 Fence Summary/);
  assert.match(summary, /#### Controls/);
  assert.match(summary, /\| Mode \| 🔒 Block \|/);
  assert.match(summary, /\| Outbound network \| ✅ Restricted \|/);
  assert.match(summary, /\| Passwordless sudo \| ✅ Disabled \|/);
  assert.match(summary, /\| Docker\/container access \| ✅ Disabled \|/);
  assert.match(summary, /#### Network activity/);
  assert.match(summary, /\| `github.com` \| ✅ Allowed \| 2 A queries \|/);
  assert.match(summary, /\| `github.com` \| ⛔ Blocked \| 1 TYPE15 query \|/);
  assert.match(summary, /\| `api.github.com` \| ✅ Allowed \| 1 AAAA query \|/);
  assert.match(summary, /\| `productionresultssa17.blob.core.windows.net` \| ✅ Allowed \| 1 A query \|/);
  assert.match(summary, /\| `result-storage-cname.example.net` \| ✅ Allowed \| 1 AAAA query \|/);
  assert.match(summary, /\| `auth.docker.io` \| ✅ Allowed \| 1 A query \|/);
  assert.match(summary, /\| `codeload.github.com` \| ⛔ Blocked \| 1 A query \|/);
  assert.equal(summary.match(/Fence Summary/g)?.length, 1);
  assert.doesNotMatch(summary, /Fence local evidence/);
  assert.doesNotMatch(summary, /critical findings/i);
  assert.doesNotMatch(summary, /platform profile/i);
  assert.doesNotMatch(summary, /readiness/i);
  assert.doesNotMatch(summary, /protected_host_block/);
  assert.doesNotMatch(summary, /Fence limited outbound traffic/);
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
  assert.match(degradedSummary, /^### 🟡 Fence Summary/);
  assert.doesNotMatch(degradedSummary, /🟢/);
  assert.match(degradedSummary, /\| Passwordless sudo \| ✅ Disabled \|/);
  assert.match(degradedSummary, /\| Docker\/container access \| ⚠️ Available; limited assurance \|/);

  const critical = {
    ...report,
    network_verification_status: "critical_drift",
    resident_health: residentHealth({ status: "critical" }),
    critical_findings: [{
      timestamp: "unix-ms:1",
      code: "owned_nftables_state_missing",
      message: "Fence-owned network state changed after readiness.",
    }],
  };
  validateReport(critical, false);
  assert.throws(() => validateReport(critical, true), /critical resident findings/);
  const criticalSummary = summaryLines(critical).join("\n");
  assert.match(criticalSummary, /^### 🔴 Fence Summary/);
  assert.doesNotMatch(criticalSummary, /🟢/);
  assert.match(criticalSummary, /\| Outbound network \| ❌ Verification failed \|/);
  assert.match(criticalSummary, /#### Critical findings/);
  assert.match(criticalSummary, /\| ❌ Critical \|/);
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
      {
        timestamp: "unix-ms:4",
        mode: "audit",
        classification: "would_block",
        family: "ipv6",
        protocol: "tcp",
        remote_address: "2001:db8::10",
        remote_port: 8443,
        rule_class: "undeclared_new_egress",
      },
    ],
    findings_truncated: false,
  };
  const dnsEvidence = {
    observations: [
      {
        hostname: "www.google.com",
        query_type: "a",
        policy_classification: "outside_policy",
        occurrences: 1,
        resolved_addresses: ["203.0.113.10"],
        minimum_observed_ttl_seconds: 60,
        addresses_truncated: false,
      },
      {
        hostname: "api.github.com",
        query_type: "a",
        policy_classification: "platform_profile",
        occurrences: 1,
        resolved_addresses: ["203.0.113.10"],
        minimum_observed_ttl_seconds: 60,
        addresses_truncated: false,
      },
    ],
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
  assert.deepEqual(correlation.ipRows, [
    {
      destination: "192.0.2.10",
      destinationKind: "ip",
      protocol: "udp",
      port: 443,
      count: 1,
    },
    {
      destination: "2001:db8::10",
      destinationKind: "ip",
      protocol: "tcp",
      port: 8443,
      count: 1,
    },
  ]);

  const summary = summaryLines(audit, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟢 Fence Summary/);
  assert.match(summary, /\| Mode \| 👀 Audit \|/);
  assert.match(summary, /\| Outbound network \| ⚠️ Observing only \|/);
  assert.match(summary, /\| Passwordless sudo \| ➖ Available in audit mode \|/);
  assert.match(summary, /\| Docker\/container access \| ➖ Available in audit mode \|/);
  assert.match(summary, /#### Network activity/);
  assert.match(summary, /\| `www.google.com` \| ⚠️ Would block \| 1 A query, 2 TCP\/443 attempts \|/);
  assert.match(summary, /\| `192.0.2.10` \| ⚠️ Would block \| 1 UDP\/443 attempt \|/);
  assert.match(summary, /\| `2001:db8::10` \| ⚠️ Would block \| 1 TCP\/8443 attempt \|/);
  assert.match(summary, /<summary>View allowlist example<\/summary>/);
  assert.match(summary, /```yaml/);
  assert.match(summary, /openai\/fence@<commit-sha>/);
  assert.match(summary, /allowlist: \|/);
  assert.match(summary, /      www.google.com/);
  assert.match(summary, /      ip 192\.0\.2\.10 udp 443/);
  assert.match(summary, /      ip 2001:db8::10 tcp 8443/);
  assert.doesNotMatch(summary, /invocation_id/);
  assert.doesNotMatch(summary, /config: >-/);
  assert.doesNotMatch(summary, /@main/);
  assert.doesNotMatch(summary, /secret-payload-marker/);
});

test("renders only bounded approved local attribution beside network findings", () => {
  const audit = {
    ...report,
    status: "protected_host_audit_observation",
    mode: "audit",
    readiness_status: "ready_observation_only",
    setup_status: "resident_observation_only",
    protection_available: false,
    sudo_status: "preserved_verified",
    container_status: "preserved_verified",
    findings: [{
      timestamp: "unix-ms:1",
      mode: "audit",
      classification: "would_block",
      family: "ipv4",
      protocol: "tcp",
      remote_address: "203.0.113.10",
      remote_port: 443,
      rule_class: "undeclared_new_egress",
      local_attribution: {
        status: "attributed",
        actor_class: "runner",
        pid: 4242,
        executable_basename: "curl",
        parent_executable_basenames: ["bash", "node"],
        executable_path: "/private/operator/path",
        command_line: "secret-payload-marker",
      },
    }],
    findings_truncated: false,
  };
  const dnsEvidence = {
    observations: [{
      hostname: "example.com",
      query_type: "a",
      policy_classification: "outside_policy",
      occurrences: 1,
      resolved_addresses: ["203.0.113.10"],
    }],
    observations_truncated: false,
  };

  const summary = summaryLines(audit, dnsEvidence).join("\n");
  assert.match(summary, /\| Destination \| Result \| Activity \| Actor \|/);
  assert.match(
    summary,
    /\| `example.com` \| ⚠️ Would block \| 1 A query, 1 TCP\/443 attempt \| runner: curl \(PID 4242\) \|/,
  );
  assert.doesNotMatch(summary, /secret-payload-marker/);
  assert.doesNotMatch(summary, /private\/operator/);
  assert.doesNotMatch(summary, /\bbash\b/);
  assert.doesNotMatch(summary, /\bnode\b/);

  const debugLines = findingAttributionDebugLines(audit);
  assert.deepEqual(debugLines, [
    "finding_attribution_1=tcp/443 203.0.113.10 runner: curl (PID 4242)",
  ]);
  assert.doesNotMatch(debugLines.join("\n"), /secret-payload-marker/);
  assert.doesNotMatch(debugLines.join("\n"), /private\/operator/);
  assert.deepEqual(
    findingAttributionDebugLines({
      findings: [{
        ...audit.findings[0],
        local_attribution: {
          status: "attributed",
          actor_class: "runner",
          pid: 4242,
          executable_basename: "../../private-tool",
        },
      }],
    }),
    [],
  );
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
  assert.match(summary, /^### 🟡 Fence Summary/);
  assert.doesNotMatch(summary, /🟢/);
  assert.match(summary, /DNS evidence was unavailable; IP-level findings may require manual review/);
  assert.match(summary, /\| `192.0.2.10` \| ⚠️ Would block \| 1 UDP\/443 attempt \|/);
  assert.match(summary, /could not be mapped to an endpoint/);
  assert.match(summary, /View allowlist example/);
  assert.match(summary, /      ip 192\.0\.2\.10 udp 443/);
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
    excluded_unretained_query_count: 2,
  };

  const summary = summaryLines(audit, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟢 Fence Summary/);
  assert.match(summary, /\| `203.0.113.10` \| ⚠️ Would block \| 1 TCP\/443 attempt \|/);
  assert.doesNotMatch(summary, /DNS evidence was unavailable/);
  assert.match(summary, /View allowlist example/);
  assert.match(summary, /      ip 203\.0\.113\.10 tcp 443/);
});

test("renders DNS materialization request rejection evidence as a non-critical warning", () => {
  const dnsEvidence = {
    observations: [],
    observations_truncated: false,
    materialization_request_rejections: 2,
  };
  const structured = parsedStructuredNetworkReport(report, dnsEvidence);
  assert.equal(structured.result, "warning");
  assert.equal(structured.warnings.materialization_rejections, 2);
  assert.equal(structured.warnings.critical_findings, 0);
  assert.equal(materializationRequestRejections(dnsEvidence), 2);
  assert.equal(materializationRequestRejections({ materialization_request_rejections: -1 }), 0);
  assert.equal(materializationRequestRejections({ materialization_request_rejections: "2" }), 0);
  assert.match(
    materializationWarningLines(dnsEvidence).join("\n"),
    /DNS answers withheld while firewall updates were unavailable \| `2`/,
  );
  const summary = summaryLines(report, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟡 Fence Summary/);
  assert.doesNotMatch(summary, /🟢/);
  assert.match(summary, /#### Warnings/);
  assert.match(summary, /DNS answers withheld while firewall updates were unavailable/);
  assert.doesNotMatch(summary, /Critical findings/);
});

test("renders bounded results-storage provenance warnings without a healthy indicator", () => {
  const dnsEvidence = {
    observations: [],
    observations_truncated: false,
    materialization_request_rejections: 1,
    results_storage_attribution_failures: 2,
    results_storage_request_rejections: 3,
    runner_authorized_results_storage_truncated: true,
  };
  const summary = summaryLines(report, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟡 Fence Summary/);
  assert.doesNotMatch(summary, /🟢/);
  assert.equal((summary.match(/#### Warnings/g) || []).length, 1);
  assert.match(summary, /GitHub results-storage requests could not be attributed \| `2`/);
  assert.match(summary, /GitHub results-storage requests were rejected \| `3`/);
  assert.match(summary, /Additional results-storage accounts were denied/);
});

test("renders wildcard authorization budget exhaustion as a bounded warning", () => {
  const dnsEvidence = {
    observations: [],
    observations_truncated: false,
    bounded_user_wildcard_authorizations_truncated: true,
    user_wildcard_request_rejections: 3,
  };
  const summary = summaryLines(report, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟡 Fence Summary/);
  assert.doesNotMatch(summary, /🟢/);
  assert.match(summary, /User wildcard hostname authorization budget exhausted \| `3`/);
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
    {
      destination: "192.0.2.10",
      destinationKind: "ip",
      protocol: "tcp",
      port: 443,
      count: 1,
    },
    {
      destination: "2001:db8::10",
      destinationKind: "ip",
      protocol: "udp",
      port: 53,
      count: 1,
    },
  ]).join("\n");
  assert.match(snippet.trimStart(), /^<details>/);
  assert.match(snippet, /<summary>View allowlist example<\/summary>/);
  assert.match(snippet, /```yaml/);
  assert.match(snippet, /openai\/fence@<commit-sha>/);
  assert.match(snippet, /allowlist: \|/);
  assert.match(snippet, /      api.example.com/);
  assert.match(snippet, /      metrics.example.com:8443/);
  assert.match(snippet, /      hostname dns.example.com udp 53/);
  assert.match(snippet, /      ip 192\.0\.2\.10 tcp 443/);
  assert.match(snippet, /      ip 2001:db8::10 udp 53/);
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

test("validates generated release bundle metadata and binary identity", () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "fence-action-test-"));
  try {
    const binary = path.join(temporary, "fence");
    const binaryLink = path.join(temporary, "fence-link");
    const wrongBinary = path.join(temporary, "wrong-fence");
    const manifest = path.join(temporary, "bundle.json");
    const manifestLink = path.join(temporary, "bundle-link.json");
    fs.writeFileSync(binary, "fence-test-binary", "utf8");
    fs.writeFileSync(wrongBinary, "wrong-fence-test-binary", "utf8");
    fs.chmodSync(binary, 0o644);
    fs.chmodSync(wrongBinary, 0o644);

    const prereleaseManifest = manifestFor(binary);
    fs.writeFileSync(manifest, JSON.stringify(prereleaseManifest), "utf8");
    validateBundle(manifest, binary);
    const stableManifest = manifestFor(binary, {
      release_tag: "v0.1.0",
      release_channel: "stable",
      release_url: "https://github.com/openai/fence/releases/tag/v0.1.0",
      source_commit: "b".repeat(40),
      signer_digest: "b".repeat(40),
      artifact_name: "fence_v0.1.0_linux-amd64",
    });
    fs.writeFileSync(manifest, JSON.stringify(stableManifest), "utf8");
    validateBundle(manifest, binary);

    const missingRepository = { ...stableManifest };
    delete missingRepository.repository;
    const invalidReleaseIdentity = (version: string): Record<string, unknown> => ({
      ...stableManifest,
      release_tag: `v${version}`,
      release_channel: version.includes("-") ? "prerelease" : "stable",
      release_url: `https://github.com/openai/fence/releases/tag/v${version}`,
      artifact_name: `fence_v${version}_linux-amd64`,
    });
    const invalidManifests: Array<[string, Record<string, unknown>]> = [
      ["missing required field", missingRepository],
      ["unknown field", { ...stableManifest, action_commit: "c".repeat(40) }],
      ["retired self-reference", { ...stableManifest, release_tag_commit: "d".repeat(40) }],
      ["retired attestation assertion", { ...stableManifest, attestation_verified: true }],
      ["wrong schema", { ...stableManifest, schema_version: 3 }],
      ["wrong release channel", { ...stableManifest, release_channel: "prerelease" }],
      ["leading-zero major", invalidReleaseIdentity("01.2.3")],
      ["leading-zero minor", invalidReleaseIdentity("1.02.3")],
      ["leading-zero patch", invalidReleaseIdentity("1.2.03")],
      ["leading-zero numeric prerelease", invalidReleaseIdentity("1.2.3-01")],
      ["build metadata", invalidReleaseIdentity("1.2.3+build.1")],
      ["mismatched artifact version", { ...stableManifest, artifact_name: "fence_v9.9.9_linux-amd64" }],
      ["mismatched release URL", { ...stableManifest, release_url: "https://github.com/openai/fence/releases/tag/v9.9.9" }],
      ["malformed source commit", { ...stableManifest, source_commit: "B".repeat(40) }],
      ["wrong source ref", { ...stableManifest, source_ref: "refs/heads/topic" }],
      ["wrong signer digest", { ...stableManifest, signer_digest: "c".repeat(40) }],
      ["wrong signer workflow", { ...stableManifest, signer_workflow: "openai/fence/.github/workflows/other.yml" }],
      ["wrong bundle path", { ...stableManifest, bundle_path: "action/bin/other" }],
      ["malformed artifact digest", { ...stableManifest, artifact_sha256: "not-a-sha256" }],
    ];
    for (const [description, invalidManifest] of invalidManifests) {
      fs.writeFileSync(manifest, JSON.stringify(invalidManifest), "utf8");
      assert.throws(() => validateBundle(manifest, binary), /contract/, description);
    }

    fs.writeFileSync(manifest, JSON.stringify(stableManifest), "utf8");
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
