"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

type Environment = Record<string, string | undefined>;
type RuntimePaths = {
  directory: string;
  config: string;
  ready: string;
  report: string;
  dnsReport: string;
  unit: string;
};
type InlineConfig = {
  invocationId: string;
  raw: string;
  usingDefault: boolean;
};
type DefaultMode = "block" | "audit";
type AuditFindingRow = {
  destination: string;
  destinationKind: "hostname" | "ip";
  protocol: string;
  port: number;
  count: number;
};
type AuditSummary = {
  dnsMissing: boolean;
  hostnameRows: AuditFindingRow[];
  ipRows: AuditFindingRow[];
  omittedHostnameRows: number;
  omittedIpRows: number;
  unparsedCount: number;
  sourceTruncated: boolean;
};

const MAX_CONFIG_BYTES = 256 * 1024;
const MAX_REPORT_BYTES = 4 * 1024 * 1024;
const MAX_AUDIT_HOSTNAME_ROWS = 10;
const MAX_AUDIT_IP_ROWS = 10;
const INVOCATION_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const DNS_HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PROFILE_REALIZATIONS = new Map([
  ["github_hosted_workflow_bootstrap_v1", "github_hosted_workflow_bootstrap_dns_mediation_v1"],
]);
const POLICY_HASH_SCHEMA_VERSION = 3;
const RUNTIME_EVIDENCE_SCHEMA_VERSION = 1;
const RELEASE_TAG = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const RUNTIME_ROOT = "/run/fence";
const REPORT_STATUSES = new Set([
  "protected_host_block",
  "protected_host_block_degraded",
  "protected_host_audit_observation",
]);
const READY_STATUSES = new Set(["ready", "ready_degraded", "ready_observation_only"]);

function fail(message: string): never {
  throw new Error(message);
}

function selectsReviewedProfile(profileId: unknown, realizationId: unknown): boolean {
  return typeof profileId === "string" &&
    typeof realizationId === "string" &&
    PROFILE_REALIZATIONS.get(profileId) === realizationId;
}

function normalizeDefaultMode(mode: unknown): DefaultMode {
  if (typeof mode !== "string" || mode.length === 0) {
    return "block";
  }
  if (mode === "block" || mode === "audit") {
    return mode;
  }
  fail("mode input must be either block or audit");
}

function defaultInlineConfig(environment: Environment, mode: unknown = undefined): string {
  const runId = environment.GITHUB_RUN_ID;
  const runAttempt = environment.GITHUB_RUN_ATTEMPT;
  if (!/^[0-9]+$/.test(runId || "") || !/^[0-9]+$/.test(runAttempt || "")) {
    fail("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT are required for the default config");
  }
  return JSON.stringify({
    schema_version: 1,
    mode: normalizeDefaultMode(mode),
    invocation_id: `fence-${runId}-${runAttempt}`,
    allowlist: [],
  });
}

function readJsonBounded(file: string, maximumBytes: number, description: string): any {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${description} is not a regular file`);
  }
  if (stat.size > maximumBytes) {
    fail(`${description} exceeds its size limit`);
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function validateInlineConfig(raw: unknown, environment: Environment = process.env, mode: unknown = undefined): InlineConfig {
  const usingDefault = typeof raw !== "string" || raw.length === 0;
  if (!usingDefault && typeof mode === "string" && mode.length > 0) {
    fail("mode input cannot be combined with config input");
  }
  const normalizedRaw = usingDefault ? defaultInlineConfig(environment, mode) : raw;
  if (Buffer.byteLength(normalizedRaw, "utf8") > MAX_CONFIG_BYTES) {
    fail("config input exceeds 256 KiB");
  }
  const parsed = JSON.parse(normalizedRaw);
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    fail("config input must be a JSON object");
  }
  const invocationId = parsed.invocation_id;
  if (
    typeof invocationId !== "string" ||
    invocationId.length < 1 ||
    invocationId.length > 64 ||
    !INVOCATION_ID.test(invocationId)
  ) {
    fail("config invocation_id must use the Fence lowercase slug grammar");
  }
  return { invocationId, raw: normalizedRaw, usingDefault };
}

function runtimePaths(invocationId: unknown): RuntimePaths {
  if (
    typeof invocationId !== "string" ||
    invocationId.length < 1 ||
    invocationId.length > 64 ||
    !INVOCATION_ID.test(invocationId)
  ) {
    fail("runtime invocation_id must use the Fence lowercase slug grammar");
  }
  const directory = path.join(RUNTIME_ROOT, invocationId);
  return {
    directory,
    config: path.join(directory, "config.json"),
    ready: path.join(directory, "ready.json"),
    report: path.join(directory, "report.json"),
    dnsReport: path.join(directory, "dns-report.json"),
    unit: `fence-${invocationId}.service`,
  };
}

function validateBundle(manifestPath: string, binaryPath: string): any {
  const manifest = readJsonBounded(manifestPath, 16 * 1024, "bundle manifest");
  const binaryStat = fs.lstatSync(binaryPath);
  if (!binaryStat.isFile() || binaryStat.isSymbolicLink() || (binaryStat.mode & 0o111) === 0) {
    fail("bundled Fence binary is not a regular file");
  }
  if (manifest === null || Array.isArray(manifest) || typeof manifest !== "object") {
    fail("bundle manifest does not match the reviewed Fence release contract");
  }
  const expectedReleaseChannel = manifest.release_tag && manifest.release_tag.includes("-")
    ? "prerelease"
    : "stable";
  const expectedKeys = [
    "artifact_name",
    "artifact_sha256",
    "attestation_verified",
    "bundle_path",
    "release_channel",
    "release_tag",
    "release_url",
    "repository",
    "schema_version",
    "signer_workflow",
    "source_commit",
  ];
  if (
    JSON.stringify(Object.keys(manifest).sort()) !== JSON.stringify(expectedKeys) ||
    manifest.schema_version !== 2 ||
    manifest.repository !== "GrantBirki/fence" ||
    !RELEASE_TAG.test(manifest.release_tag) ||
    manifest.release_channel !== expectedReleaseChannel ||
    manifest.release_url !== `https://github.com/GrantBirki/fence/releases/tag/${manifest.release_tag}` ||
    !/^[0-9a-f]{40}$/.test(manifest.source_commit) ||
    manifest.artifact_name !== `fence_${manifest.release_tag}_linux-amd64` ||
    !SHA256.test(manifest.artifact_sha256) ||
    manifest.signer_workflow !== "GrantBirki/fence/.github/workflows/release.yml" ||
    manifest.bundle_path !== "action/bin/fence" ||
    manifest.attestation_verified !== true
  ) {
    fail("bundle manifest does not match the reviewed Fence release contract");
  }
  const digest = crypto.createHash("sha256").update(fs.readFileSync(binaryPath)).digest("hex");
  if (digest !== manifest.artifact_sha256) {
    fail("bundled Fence binary checksum does not match its manifest");
  }
  return manifest;
}

function validateReport(report: any, failOnCritical = true): any {
  if (report === null || Array.isArray(report) || typeof report !== "object") {
    fail("Fence report must be a JSON object");
  }
  if (!REPORT_STATUSES.has(report.status)) {
    fail("Fence report has an unexpected status");
  }
  if (!READY_STATUSES.has(report.readiness_status)) {
    fail("Fence report does not contain a recognized readiness status");
  }
  const validIdentity =
    report.runtime_evidence_schema_version === RUNTIME_EVIDENCE_SCHEMA_VERSION &&
    selectsReviewedProfile(report.platform_profile_id, report.profile_realization_id) &&
    report.policy_hash_schema_version === POLICY_HASH_SCHEMA_VERSION &&
    SHA256.test(report.policy_hash) &&
    SHA256.test(report.base_ruleset_hash) &&
    SHA256.test(report.ruleset_hash);
  if (!validIdentity) {
    fail("Fence report does not select the reviewed hosted-runner profile");
  }
  if (!Array.isArray(report.critical_findings) || report.critical_findings_truncated !== false) {
    fail("Fence report does not contain bounded critical findings");
  }
  if (failOnCritical && report.critical_findings.length !== 0) {
    fail("Fence report contains critical resident findings");
  }
  if (report.network_verification_status !== "verified") {
    if (failOnCritical || report.critical_findings.length === 0) {
      fail("Fence report does not contain verified network state");
    }
  }
  const expected = {
    protected_host_block: {
      mode: "block",
      readiness: "ready",
      setup: "resident_protected",
      protection: true,
      sudo: "disabled_verified",
      containers: "disabled_verified",
    },
    protected_host_block_degraded: {
      mode: "block",
      readiness: "ready_degraded",
      setup: "resident_degraded",
      protection: false,
      sudo: "disabled_verified",
      containers: "preserved_unsafe",
    },
    protected_host_audit_observation: {
      mode: "audit",
      readiness: "ready_observation_only",
      setup: "resident_observation_only",
      protection: false,
      sudo: "preserved_verified",
      containers: "preserved_verified",
    },
  }[report.status];
  if (
    report.mode !== expected.mode ||
    report.readiness_status !== expected.readiness ||
    report.setup_status !== expected.setup ||
    report.protection_available !== expected.protection ||
    report.sudo_status !== expected.sudo ||
    report.container_status !== expected.containers
  ) {
    fail("Fence report mode and control status are inconsistent");
  }
  return report;
}

function validateReady(ready: any, report: any): any {
  if (ready === null || Array.isArray(ready) || typeof ready !== "object") {
    fail("Fence readiness must be a JSON object");
  }
  if (!READY_STATUSES.has(ready.status) || ready.status !== report.readiness_status) {
    fail("Fence readiness does not match the resident report");
  }
  const validIdentity =
    ready.runtime_evidence_schema_version === RUNTIME_EVIDENCE_SCHEMA_VERSION &&
    selectsReviewedProfile(ready.platform_profile_id, ready.profile_realization_id) &&
    ready.platform_profile_id === report.platform_profile_id &&
    ready.profile_realization_id === report.profile_realization_id &&
    ready.policy_hash_schema_version === report.policy_hash_schema_version &&
    ready.policy_hash === report.policy_hash &&
    ready.base_ruleset_hash === report.base_ruleset_hash &&
    ready.ruleset_hash === report.ruleset_hash &&
    ready.protection_available === report.protection_available;
  if (!validIdentity) {
    fail("Fence readiness identity does not match the resident report");
  }
  return ready;
}

function boundedScalar(value: unknown): string {
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
    return "unavailable";
  }
  return String(value).replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 96);
}

function boundedText(value: unknown, maximum = 192): string {
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
    return "unavailable";
  }
  return String(value)
    .replace(/[\r\n]+/g, " ")
    .replace(/\|/g, "\\|")
    .slice(0, maximum);
}

function markdownCode(value: unknown, maximum = 128): string {
  return `\`${boundedText(value, maximum).replace(/`/g, "_")}\``;
}

function isSafeHostname(value: unknown): value is string {
  return typeof value === "string" &&
    value === value.toLowerCase() &&
    !value.includes("*") &&
    !value.endsWith(".") &&
    DNS_HOSTNAME.test(value);
}

function isSupportedProtocol(value: unknown): value is string {
  return value === "tcp" || value === "udp";
}

function isValidPort(value: unknown): value is number {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function addRow(rows: Map<string, AuditFindingRow>, row: Omit<AuditFindingRow, "count">): void {
  const key = `${row.destinationKind}\0${row.destination}\0${row.protocol}\0${row.port}`;
  const existing = rows.get(key);
  if (existing) {
    existing.count += 1;
  } else {
    rows.set(key, { ...row, count: 1 });
  }
}

function sortedRows(rows: Iterable<AuditFindingRow>): AuditFindingRow[] {
  return Array.from(rows).sort((left, right) =>
    right.count - left.count ||
    left.destination.localeCompare(right.destination) ||
    left.protocol.localeCompare(right.protocol) ||
    left.port - right.port
  );
}

function dnsAddressHostnameMap(dnsEvidence: any): Map<string, Set<string>> {
  const addressMap = new Map<string, Set<string>>();
  if (dnsEvidence === undefined || dnsEvidence === null || !Array.isArray(dnsEvidence.observations)) {
    return addressMap;
  }
  for (const observation of dnsEvidence.observations) {
    if (observation === null || Array.isArray(observation) || typeof observation !== "object") {
      continue;
    }
    if (observation.query_type !== "a" && observation.query_type !== "aaaa") {
      continue;
    }
    const hostname = observation.hostname;
    if (!isSafeHostname(hostname) || !Array.isArray(observation.resolved_addresses)) {
      continue;
    }
    for (const address of observation.resolved_addresses) {
      if (typeof address !== "string" || net.isIP(address) === 0) {
        continue;
      }
      const hostnames = addressMap.get(address) || new Set<string>();
      hostnames.add(hostname);
      addressMap.set(address, hostnames);
    }
  }
  return addressMap;
}

function correlateFindingsToDns(report: any, dnsEvidence: any = undefined): AuditSummary {
  const hostnameRows = new Map<string, AuditFindingRow>();
  const ipRows = new Map<string, AuditFindingRow>();
  const addressMap = dnsAddressHostnameMap(dnsEvidence);
  let unparsedCount = 0;

  for (const finding of Array.isArray(report.findings) ? report.findings : []) {
    if (
      finding === null ||
      Array.isArray(finding) ||
      typeof finding !== "object" ||
      finding.classification !== "would_block"
    ) {
      continue;
    }
    if (
      typeof finding.remote_address !== "string" ||
      net.isIP(finding.remote_address) === 0 ||
      !isSupportedProtocol(finding.protocol) ||
      !isValidPort(finding.remote_port)
    ) {
      unparsedCount += 1;
      continue;
    }

    const hostnames = Array.from(addressMap.get(finding.remote_address) || []).sort();
    if (hostnames.length > 0) {
      for (const hostname of hostnames) {
        addRow(hostnameRows, {
          destination: hostname,
          destinationKind: "hostname",
          protocol: finding.protocol,
          port: finding.remote_port,
        });
      }
    } else {
      addRow(ipRows, {
        destination: finding.remote_address,
        destinationKind: "ip",
        protocol: finding.protocol,
        port: finding.remote_port,
      });
    }
  }

  const allHostnameRows = sortedRows(hostnameRows.values());
  const allIpRows = sortedRows(ipRows.values());
  return {
    dnsMissing: dnsEvidence === undefined || dnsEvidence === null,
    hostnameRows: allHostnameRows.slice(0, MAX_AUDIT_HOSTNAME_ROWS),
    ipRows: allIpRows.slice(0, MAX_AUDIT_IP_ROWS),
    omittedHostnameRows: Math.max(0, allHostnameRows.length - MAX_AUDIT_HOSTNAME_ROWS),
    omittedIpRows: Math.max(0, allIpRows.length - MAX_AUDIT_IP_ROWS),
    unparsedCount,
    sourceTruncated: report.findings_truncated === true ||
      Boolean(dnsEvidence && dnsEvidence.observations_truncated === true),
  };
}

function summaryHeading(summaryState: { healthy: boolean }): string {
  return summaryState.healthy ? "### 🟢 Fence Summary" : "### Fence Summary";
}

function summaryHasWarnings(report: any, auditSummary: AuditSummary): boolean {
  return (
    report.status === "protected_host_block_degraded" ||
    report.network_verification_status !== "verified" ||
    (Array.isArray(report.critical_findings) && report.critical_findings.length > 0) ||
    report.critical_findings_truncated === true ||
    report.findings_truncated === true ||
    auditSummary.sourceTruncated ||
    auditSummary.omittedHostnameRows > 0 ||
    auditSummary.omittedIpRows > 0 ||
    (report.mode === "audit" && auditSummary.dnsMissing)
  );
}

function criticalFindingLines(report: any): string[] {
  if (!Array.isArray(report.critical_findings) || report.critical_findings.length === 0) {
    return [];
  }
  const lines = [
    "",
    "| Finding | Detail |",
    "| --- | --- |",
  ];
  for (const finding of report.critical_findings.slice(0, 5)) {
    lines.push(`| ${markdownCode(finding && finding.code)} | ${boundedText(finding && finding.message)} |`);
  }
  if (report.critical_findings.length > 5) {
    lines.push(`| ${markdownCode("additional_findings_omitted")} | ${report.critical_findings.length - 5} more critical findings are available in the local report. |`);
  }
  return lines;
}

function modeStatusCard(report: any): string[] {
  if (
    report.network_verification_status !== "verified" ||
    (Array.isArray(report.critical_findings) && report.critical_findings.length > 0)
  ) {
    return [
      "**Fence needs attention**",
      "",
      "Fence detected a critical issue after startup and marked this job as failed.",
      ...criticalFindingLines(report),
    ];
  }

  if (report.status === "protected_host_block_degraded") {
    return [
      "**Limited assurance**",
      "",
      "Fence limited outbound traffic and locked down passwordless sudo, but Docker/container access was preserved. Container access can bypass the ordinary containment claim.",
    ];
  }

  if (report.mode === "audit") {
    return [
      "**Observing only**",
      "",
      "Fence did not block traffic in audit mode. The destinations below would need review before switching this workflow to block mode.",
    ];
  }

  return [
    "**Network restrictions active**",
    "",
    "Fence limited outbound traffic to the GitHub workflow support channel and your `allowlist`. Passwordless sudo and Docker/container access were locked down. Controls remain active until the runner is torn down.",
  ];
}

function allowlistYamlSnippet(rows: AuditFindingRow[]): string[] {
  if (rows.length === 0) {
    return [];
  }
  const allowlist = rows.map((row) => ({
    destination_type: "hostname",
    destination: row.destination,
    protocol: row.protocol,
    port: row.port,
  }));
  const config = JSON.stringify({
    schema_version: 1,
    mode: "block",
    invocation_id: "example-run",
    allowlist,
  }, null, 2);

  return [
    "",
    "<details>",
    "<summary>View allowlist example</summary>",
    "",
    "```yaml",
    "- uses: GrantBirki/fence@<commit-sha>",
    "  with:",
    "    config: >-",
    ...config.split("\n").map((line) => `      ${line}`),
    "```",
    "",
    "</details>",
  ];
}

function auditWouldBlockSummary(report: any, dnsEvidence: any = undefined, auditSummary: AuditSummary = correlateFindingsToDns(report, dnsEvidence)): string[] {
  if (report.mode !== "audit") {
    return [];
  }

  const rows = [...auditSummary.hostnameRows, ...auditSummary.ipRows];
  const lines = ["", "#### Would Be Blocked In Block Mode", ""];
  if (auditSummary.dnsMissing) {
    lines.push("DNS audit evidence was unavailable, so Fence could only report IP-level findings.", "");
  }
  if (rows.length === 0 && auditSummary.unparsedCount === 0) {
    lines.push("No would-block destinations were observed during this audit run.");
    return lines;
  }

  if (rows.length > 0) {
    lines.push("| Destination | Protocol | Port | Count |");
    lines.push("| --- | --- | ---: | ---: |");
    for (const row of rows) {
      lines.push(`| ${markdownCode(row.destination)} | ${markdownCode(row.protocol)} | ${markdownCode(row.port)} | ${markdownCode(row.count)} |`);
    }
    lines.push("");
  }
  if (auditSummary.ipRows.length > 0 && auditSummary.hostnameRows.length === 0) {
    lines.push("Manual review required for IP-only findings.");
    lines.push("");
  }
  if (auditSummary.unparsedCount > 0) {
    lines.push(`${auditSummary.unparsedCount} would-block finding(s) could not be mapped to an endpoint from the bounded packet prefix.`);
    lines.push("");
  }
  if (auditSummary.sourceTruncated || auditSummary.omittedHostnameRows > 0 || auditSummary.omittedIpRows > 0) {
    const omitted = auditSummary.omittedHostnameRows + auditSummary.omittedIpRows;
    lines.push(`Some audit evidence was truncated or omitted from this summary. Review the local report for full bounded evidence${omitted > 0 ? `; ${omitted} grouped row(s) were omitted here` : ""}.`);
  }
  lines.push(...allowlistYamlSnippet(auditSummary.hostnameRows));
  return lines;
}

function summaryLines(report: any, dnsEvidence: any = undefined): string[] {
  const auditSummary = correlateFindingsToDns(report, dnsEvidence);
  const summaryState = { healthy: !summaryHasWarnings(report, auditSummary) };
  return [
    summaryHeading(summaryState),
    "",
    ...modeStatusCard(report),
    ...auditWouldBlockSummary(report, dnsEvidence, auditSummary),
    "",
  ];
}

module.exports = {
  MAX_REPORT_BYTES,
  allowlistYamlSnippet,
  auditWouldBlockSummary,
  correlateFindingsToDns,
  defaultInlineConfig,
  modeStatusCard,
  readJsonBounded,
  runtimePaths,
  summaryHeading,
  summaryLines,
  validateBundle,
  validateInlineConfig,
  validateReady,
  validateReport,
};
