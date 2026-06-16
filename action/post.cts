"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const log = require("./log.cts");
const {
  actionPathGuardIdentities,
  actionRuntimeFileDigests,
  correlateFindingsToDns,
  findingAttributionDebugLines,
  materializationRequestRejections,
  materializationEvidenceCounter,
  MAX_REPORT_BYTES,
  readJsonBounded,
  readLauncherIntegrity,
  runtimePaths,
  summaryLines,
  validateBundle,
  validateActionPathGuardMount,
  validateLauncherIntegrity,
  validateProtectedActionRuntime,
  validateReadOnlyActionMount,
  validateDnsEvidence,
  validateReport,
  validateResidentUnitStatus,
} = require("./lib.cts");

const ACTION_ROOT = __dirname;
const BINARY = path.join(ACTION_ROOT, "bin", "fence");
const MANIFEST = path.join(ACTION_ROOT, "bundle-manifest.json");
const CHILD_ENV = {
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
  PATH: "/usr/bin:/usr/sbin:/bin:/sbin",
};

function emitError(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  log.error(`Fence post-job evidence failed: ${message}`);
}

function validateResidentService(unit: string, expectedPid: unknown): void {
  const result = spawnSync(
    "/usr/bin/systemctl",
    [
      "show",
      unit,
      "--no-pager",
      "--property=ActiveState",
      "--property=SubState",
      "--property=MainPID",
    ],
    {
      encoding: "utf8",
      env: CHILD_ENV,
      killSignal: "SIGKILL",
      maxBuffer: 16 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 2 * 1000,
    },
  );
  if (result.error || result.status !== 0 || String(result.stderr || "").length !== 0) {
    throw new Error("Fence resident service status could not be verified");
  }
  validateResidentUnitStatus(String(result.stdout || ""), expectedPid);
}

function validateProtectedActionMount(actionRoot: string): void {
  const raw = captureMountEvidence(actionRoot, "Fence protected Action mount could not be verified");
  validateReadOnlyActionMount(raw, actionRoot);
}

function captureMountEvidence(target: string, failureMessage: string): string {
  const result = spawnSync(
    "/usr/bin/findmnt",
    ["--json", "--uniq", "--mountpoint", target, "--output", "TARGET,OPTIONS"],
    {
      encoding: "utf8",
      env: CHILD_ENV,
      killSignal: "SIGKILL",
      maxBuffer: 16 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 2 * 1000,
    },
  );
  if (result.error || result.status !== 0 || String(result.stderr || "").length !== 0) {
    throw new Error(failureMessage);
  }
  return String(result.stdout || "");
}

function validateRegisteredActionPathGuards(actionRoot: string): ReturnType<typeof actionPathGuardIdentities> {
  const guards = actionPathGuardIdentities(actionRoot);
  for (const guard of guards) {
    const raw = captureMountEvidence(
      guard.path,
      "Fence registered Action path guard could not be verified",
    );
    validateActionPathGuardMount(raw, guard.path);
  }
  return guards;
}

function main(): void {
  log.info("📋 Validating Fence evidence");
  const invocationId = process.env.STATE_invocation_id;
  const reportPath = process.env.STATE_report_path;
  const dnsReportPath = process.env.STATE_dns_report_path;
  const launcherIntegrityPath = process.env.STATE_launcher_integrity_path;
  const paths = invocationId ? runtimePaths(invocationId) : undefined;
  if (!invocationId || !paths || paths.report !== reportPath) {
    throw new Error("Fence post-job report path is missing or invalid");
  }
  if (dnsReportPath && paths.dnsReport !== dnsReportPath) {
    throw new Error("Fence post-job DNS report path is invalid");
  }
  if (paths.launcherIntegrity !== launcherIntegrityPath) {
    throw new Error("Fence post-job launcher integrity path is missing or invalid");
  }
  validateProtectedActionMount(ACTION_ROOT);
  validateProtectedActionRuntime(ACTION_ROOT);
  const actionFiles = actionRuntimeFileDigests(ACTION_ROOT);
  const pathGuards = validateRegisteredActionPathGuards(ACTION_ROOT);
  validateLauncherIntegrity(
    readLauncherIntegrity(launcherIntegrityPath),
    invocationId,
    ACTION_ROOT,
    paths.launcherActionDirectory,
    actionFiles,
    pathGuards,
  );
  validateBundle(MANIFEST, BINARY);
  const report = validateReport(
    readJsonBounded(reportPath, MAX_REPORT_BYTES, "Fence report"),
    false,
  );
  validateResidentService(paths.unit, report.resident_health.resident_pid);
  let dnsEvidence;
  const effectiveDnsReportPath = dnsReportPath || paths.dnsReport;
  if (fs.existsSync(effectiveDnsReportPath)) {
    dnsEvidence = validateDnsEvidence(
      readJsonBounded(effectiveDnsReportPath, MAX_REPORT_BYTES, "Fence DNS report"),
      report,
    );
  } else if (report.mode === "block") {
    throw new Error("Fence block-mode DNS evidence is missing");
  }
  const auditSummary = correlateFindingsToDns(report, dnsEvidence);
  const dnsMaterializationRequestRejections = materializationRequestRejections(dnsEvidence);
  const resultsStorageAuthorizationCount = materializationEvidenceCounter(
    dnsEvidence,
    "results_storage_authorization_count",
  );
  const resultsStorageAttributionFailures = materializationEvidenceCounter(
    dnsEvidence,
    "results_storage_attribution_failures",
  );
  const resultsStorageRequestRejections = materializationEvidenceCounter(
    dnsEvidence,
    "results_storage_request_rejections",
  );
  log.debugGroup("Fence debug: post-job evidence", [
    `report_path=${reportPath}`,
    `dns_report_path=${effectiveDnsReportPath}`,
    `dns_report_present=${dnsEvidence !== undefined}`,
    `protected_action_runtime=verified`,
    `mode=${report.mode}`,
    `status=${report.status}`,
    `readiness=${report.readiness_status}`,
    `network_verification=${report.network_verification_status}`,
    `sudo=${report.sudo_status}`,
    `containers=${report.container_status}`,
    `critical_findings=${Array.isArray(report.critical_findings) ? report.critical_findings.length : "unknown"}`,
    `hostname_would_block_rows=${auditSummary.hostnameRows.length}`,
    `ip_would_block_rows=${auditSummary.ipRows.length}`,
    `unparsed_would_block_findings=${auditSummary.unparsedCount}`,
    `source_truncated=${auditSummary.sourceTruncated}`,
    `materialization_batch_count=${materializationEvidenceCounter(dnsEvidence, "materialization_batch_count")}`,
    `materialization_request_rejections=${dnsMaterializationRequestRejections}`,
    `materialization_update_max_milliseconds=${materializationEvidenceCounter(dnsEvidence, "materialization_update_max_milliseconds")}`,
    `upstream_request_failures=${materializationEvidenceCounter(dnsEvidence, "upstream_request_failures")}`,
    `results_storage_authorizations=${resultsStorageAuthorizationCount}`,
    `results_storage_attribution_failures=${resultsStorageAttributionFailures}`,
    `results_storage_request_rejections=${resultsStorageRequestRejections}`,
    `results_storage_authorizations_truncated=${dnsEvidence?.runner_authorized_results_storage_truncated === true}`,
    `resident_verification_sequence=${report.resident_health?.verification_sequence ?? "not_available"}`,
    `resident_last_verified_unix_milliseconds=${report.resident_health?.last_successful_verification_unix_milliseconds ?? "not_available"}`,
    ...findingAttributionDebugLines(report),
  ]);
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summaryLines(report, dnsEvidence).join("\n"), {
      encoding: "utf8",
    });
  }
  if (Array.isArray(report.critical_findings) && report.critical_findings.length > 0) {
    log.warning(`Fence detected ${report.critical_findings.length} critical resident finding(s); failing this job`);
  }
  if (dnsMaterializationRequestRejections > 0) {
    log.warning(
      `Fence withheld ${dnsMaterializationRequestRejections} DNS answer(s) because firewall update work could not be accepted`,
    );
  }
  if (resultsStorageAttributionFailures > 0 || resultsStorageRequestRejections > 0) {
    log.warning(
      `Fence rejected ${resultsStorageRequestRejections} GitHub results-storage request(s); ${resultsStorageAttributionFailures} could not be attributed`,
    );
  }
  validateReport(report, true);
  const auditDestinationCount = auditSummary.hostnameRows.length + auditSummary.ipRows.length;
  const evidenceLine = log.postEvidenceLine(report, auditDestinationCount);
  if (evidenceLine) {
    log.info(evidenceLine);
  }
  log.success("✅ Fence evidence verified");
  log.info("🧷 Fence remains active until the runner is torn down");
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    emitError(error);
    process.exitCode = 1;
  }
}

module.exports = { main };
