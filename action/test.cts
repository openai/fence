"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  ACTION_RUNTIME_FILES,
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
  registeredActionPathGuardPaths,
  runtimePaths,
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

function manifestFor(binary: string, overrides = {}): Record<string, unknown> {
  const digest = crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex");
  return {
    schema_version: 4,
    repository: "GrantBirki/fence",
    release_tag: "v0.1.0-alpha.3",
    release_channel: "prerelease",
    release_url: "https://github.com/GrantBirki/fence/releases/tag/v0.1.0-alpha.3",
    source_commit: "a".repeat(40),
    source_ref: "refs/heads/main",
    artifact_name: "fence_v0.1.0-alpha.3_linux-amd64",
    signer_digest: "a".repeat(40),
    signer_workflow: "GrantBirki/fence/.github/workflows/release.yml",
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
  assert.equal(details.platformProfile, "github_hosted_workflow_bootstrap_v5");
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

test("validates stable runtime evidence", () => {
  validateReport(report);
  const dnsEvidence = {
    runtime_evidence_schema_version: 5,
    status: report.status,
    mode: report.mode,
    platform_profile_id: report.platform_profile_id,
    profile_realization_id: report.profile_realization_id,
    protection_available: report.protection_available,
    routing_status: "active",
    host_dns_routing: "direct_client_to_root_resident_mediator",
    docker_dns_routing: "local_root_resident_mediator",
    answer_attribution_status: "bounded_reportable_hostname_answers_only",
    proxy_policy_status: "block_forwards_exact_roots_bounded_user_wildcard_names_actions_suffix_names_githubapp_suffix_names_results_storage_and_bounded_cname_descendants",
    hostname_policy: {
      exact: [],
      user_wildcards: [],
      allow_dynamic_githubapp_suffix: true,
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
    resident_health: report.resident_health,
  };
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
  assert.throws(() => validateReady({ status: "ready" }, report), /identity/);
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
  assert.deepEqual(correlation.ipRows, [{
    destination: "192.0.2.10",
    destinationKind: "ip",
    protocol: "udp",
    port: 443,
    count: 1,
  }]);

  const summary = summaryLines(audit, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟢 Fence Summary/);
  assert.match(summary, /\| Mode \| 👀 Audit \|/);
  assert.match(summary, /\| Outbound network \| ⚠️ Observing only \|/);
  assert.match(summary, /\| Passwordless sudo \| ➖ Available in audit mode \|/);
  assert.match(summary, /\| Docker\/container access \| ➖ Available in audit mode \|/);
  assert.match(summary, /#### Network activity/);
  assert.match(summary, /\| `www.google.com` \| ⚠️ Would block \| 1 A query, 2 TCP\/443 attempts \|/);
  assert.match(summary, /\| `192.0.2.10` \| ⚠️ Would block \| 1 UDP\/443 attempt \|/);
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
    excluded_unretained_query_count: 2,
  };

  const summary = summaryLines(audit, dnsEvidence).join("\n");
  assert.match(summary, /^### 🟢 Fence Summary/);
  assert.match(summary, /\| `203.0.113.10` \| ⚠️ Would block \| 1 TCP\/443 attempt \|/);
  assert.doesNotMatch(summary, /DNS evidence was unavailable/);
  assert.doesNotMatch(summary, /View allowlist example/);
});

test("renders DNS materialization request rejection evidence as a non-critical warning", () => {
  const dnsEvidence = {
    observations: [],
    observations_truncated: false,
    materialization_request_rejections: 2,
  };
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
      release_url: "https://github.com/GrantBirki/fence/releases/tag/v0.1.0",
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
      release_url: `https://github.com/GrantBirki/fence/releases/tag/v${version}`,
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
      ["mismatched release URL", { ...stableManifest, release_url: "https://github.com/GrantBirki/fence/releases/tag/v9.9.9" }],
      ["malformed source commit", { ...stableManifest, source_commit: "B".repeat(40) }],
      ["wrong source ref", { ...stableManifest, source_ref: "refs/heads/topic" }],
      ["wrong signer digest", { ...stableManifest, signer_digest: "c".repeat(40) }],
      ["wrong signer workflow", { ...stableManifest, signer_workflow: "GrantBirki/fence/.github/workflows/other.yml" }],
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
