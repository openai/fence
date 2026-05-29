"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const MAX_CONFIG_BYTES = 256 * 1024;
const MAX_REPORT_BYTES = 4 * 1024 * 1024;
const INVOCATION_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const PROFILE_ID = "github_hosted_job_status_v1";
const RUNTIME_ROOT = "/run/fence";
const REPORT_STATUSES = new Set([
  "protected_host_block",
  "protected_host_block_degraded",
  "protected_host_audit_observation",
]);
const READY_STATUSES = new Set(["ready", "ready_degraded", "ready_observation_only"]);

function fail(message) {
  throw new Error(message);
}

function readJsonBounded(file, maximumBytes, description) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${description} is not a regular file`);
  }
  if (stat.size > maximumBytes) {
    fail(`${description} exceeds its size limit`);
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function validateInlineConfig(raw) {
  if (typeof raw !== "string" || raw.length === 0) {
    fail("config input is required");
  }
  if (Buffer.byteLength(raw, "utf8") > MAX_CONFIG_BYTES) {
    fail("config input exceeds 256 KiB");
  }
  const parsed = JSON.parse(raw);
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
  return { invocationId, raw };
}

function runtimePaths(invocationId) {
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
    unit: `fence-${invocationId}.service`,
  };
}

function validateBundle(manifestPath, binaryPath) {
  const manifest = readJsonBounded(manifestPath, 16 * 1024, "bundle manifest");
  const binaryStat = fs.lstatSync(binaryPath);
  if (!binaryStat.isFile() || binaryStat.isSymbolicLink() || (binaryStat.mode & 0o111) === 0) {
    fail("bundled Fence binary is not a regular file");
  }
  if (
    manifest.schema_version !== 1 ||
    manifest.repository !== "GrantBirki/fence" ||
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

function validateReport(report, failOnCritical = true) {
  if (report === null || Array.isArray(report) || typeof report !== "object") {
    fail("Fence report must be a JSON object");
  }
  if (!REPORT_STATUSES.has(report.status)) {
    fail("Fence report has an unexpected status");
  }
  if (!READY_STATUSES.has(report.readiness_status)) {
    fail("Fence report does not contain a recognized readiness status");
  }
  if (report.selected_platform_profile_id !== PROFILE_ID) {
    fail("Fence report does not select the reviewed hosted-runner profile");
  }
  if (report.network_verification_status !== "verified") {
    fail("Fence report does not contain verified network state");
  }
  if (!Array.isArray(report.critical_findings) || report.critical_findings_truncated !== false) {
    fail("Fence report does not contain bounded critical findings");
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
  if (failOnCritical && report.critical_findings.length !== 0) {
    fail("Fence report contains critical resident findings");
  }
  return report;
}

function validateReady(ready, report) {
  if (ready === null || Array.isArray(ready) || typeof ready !== "object") {
    fail("Fence readiness must be a JSON object");
  }
  if (!READY_STATUSES.has(ready.status) || ready.status !== report.readiness_status) {
    fail("Fence readiness does not match the resident report");
  }
  if (
    ready.selected_platform_profile_id !== PROFILE_ID ||
    ready.policy_hash !== report.policy_hash ||
    ready.ruleset_hash !== report.ruleset_hash ||
    ready.protection_available !== report.protection_available
  ) {
    fail("Fence readiness identity does not match the resident report");
  }
  return ready;
}

function boundedScalar(value) {
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
    return "unavailable";
  }
  return String(value).replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 96);
}

function summaryLines(report) {
  return [
    "### Fence local evidence",
    "",
    "| Field | Value |",
    "| --- | --- |",
    `| status | \`${boundedScalar(report.status)}\` |`,
    `| mode | \`${boundedScalar(report.mode)}\` |`,
    `| readiness | \`${boundedScalar(report.readiness_status)}\` |`,
    `| network verification | \`${boundedScalar(report.network_verification_status)}\` |`,
    `| sudo | \`${boundedScalar(report.sudo_status)}\` |`,
    `| containers | \`${boundedScalar(report.container_status)}\` |`,
    `| platform profile | \`${boundedScalar(report.selected_platform_profile_id)}\` |`,
    `| critical findings | \`${report.critical_findings.length}\` |`,
    "",
    "Fence remains resident until ephemeral runner teardown. This summary does not restore access.",
    "",
  ];
}

module.exports = {
  MAX_REPORT_BYTES,
  readJsonBounded,
  runtimePaths,
  summaryLines,
  validateBundle,
  validateInlineConfig,
  validateReady,
  validateReport,
};
