"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const log = require("./log.cts");
const {
  activeActionMountEvidence,
  actionPathGuardIdentities,
  actionRuntimeFileDigests,
  correlateFindingsToDns,
  findingAttributionDebugLines,
  materializationRejectionReasons,
  materializationRequestRejections,
  materializationEvidenceCounter,
  materializationWarning,
  MAX_REPORT_BYTES,
  networkReportLines,
  readJsonBounded,
  readLauncherIntegrity,
  resultsStorageWarnings,
  runtimePaths,
  structuredReportLine,
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
const EVIDENCE_SETTLE_INTERVAL_MILLISECONDS = 40;
const EVIDENCE_SETTLE_MAX_READS = 4;
const EVIDENCE_SETTLE_TIMEOUT_NANOSECONDS = 160_000_000n;
const CHILD_ENV = {
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
  PATH: "/usr/bin:/usr/sbin:/bin:/sbin",
};

// Failure output is a projection of rejected evidence, never a verified report.
// Keep codes closed so malformed evidence cannot turn diagnostics into a data dump.
const FAILURE_CRITICAL_CODES = new Set([
  "attribution_request_channel_disconnected",
  "attribution_result_channel_failed",
  "dns_audit_container_drift",
  "dns_audit_counter_read_failed",
  "dns_audit_evidence_persistence_failed",
  "dns_audit_evidence_write_failed",
  "dns_audit_network_drift",
  "dns_audit_nflog_failure",
  "dns_audit_report_write_failed",
  "dns_audit_routing_drift",
  "dns_audit_sudo_drift",
  "dns_audit_worker_unhealthy",
  "dns_block_container_drift",
  "dns_block_counter_read_failed",
  "dns_block_dynamic_update_failed",
  "dns_block_evidence_persistence_failed",
  "dns_block_evidence_write_failed",
  "dns_block_network_drift",
  "dns_block_nflog_failure",
  "dns_block_report_write_failed",
  "dns_block_root_refresh_failed",
  "dns_block_root_refresh_integrity_failed",
  "dns_block_routing_drift",
  "dns_block_sudo_drift",
  "dns_block_worker_unhealthy",
  "dns_tcp_client_panicked",
  "dns_tcp_client_spawn_failed",
  "dns_tcp_listener_failed",
  "dns_udp_listener_failed",
  "local_control_inventory_additive_drift",
  "local_control_inventory_bounds_exceeded",
  "local_control_inventory_incomplete",
  "local_control_inventory_unavailable",
  "local_control_inventory_unreviewed_reduction",
  "local_control_inventory_unstable",
  "resident_worker_channel_disconnected",
  "resident_worker_exited",
  "resident_worker_panicked",
  "runner_worker_identity_drift",
]);

type EvidenceSource = "resident" | "dns";

function postFailureDiagnostic(evidence: any, source: EvidenceSource, now = Date.now()): string {
  const health = evidence?.resident_health;
  const verifiedAt = health?.last_successful_verification_unix_milliseconds;
  const sequence = health?.verification_sequence;
  const age = Number.isSafeInteger(verifiedAt) && verifiedAt > 0 && Number.isSafeInteger(now)
    ? now - verifiedAt
    : null;
  const findings = Array.isArray(evidence?.critical_findings) && evidence.critical_findings.length <= 64
    ? evidence.critical_findings
    : null;
  return `Fence failure diagnostic (unverified): ${JSON.stringify({
    source,
    reported_resident_status: ["healthy", "critical", "starting"].includes(health?.status) ? health.status : "unavailable",
    verification_sequence: Number.isSafeInteger(sequence) && sequence >= 1 ? sequence : null,
    heartbeat_age_ms: Number.isSafeInteger(age) ? age : null,
    critical_findings: findings === null ? null : findings.length,
    critical_codes: findings === null ? [] : findings.slice(0, 5).map((finding: any) =>
      FAILURE_CRITICAL_CODES.has(finding?.code) ? finding.code : "unrecognized"),
    critical_codes_omitted: findings === null ? null : Math.max(0, findings.length - 5),
    critical_findings_truncated: typeof evidence?.critical_findings_truncated === "boolean"
      ? evidence.critical_findings_truncated : null,
  })}`;
}

function validatePostEvidence(evidence: any, source: EvidenceSource, validate: (value: any) => any): any {
  try {
    return validate(evidence);
  } catch (error) {
    try {
      log.info(postFailureDiagnostic(evidence, source));
    } catch {
      // Diagnostics must never replace the original validation failure.
    }
    throw error;
  }
}

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

type ResidentEvidenceSettleControls = {
  now?: () => bigint;
  pause?: (milliseconds: number) => void;
  read?: (reportPath: string) => any;
  verifyService?: (unit: string, expectedPid: unknown) => void;
};

function networkEvidenceCounters(report: any): { total: number; sampled: number } {
  const counters = report.counters;
  if (
    counters === null ||
    Array.isArray(counters) ||
    typeof counters !== "object" ||
    !Number.isSafeInteger(counters.total_violations) ||
    counters.total_violations < 0 ||
    !Number.isSafeInteger(counters.sampled_violations) ||
    counters.sampled_violations < 0
  ) {
    throw new Error("Fence resident report does not contain bounded network counters");
  }
  return {
    total: counters.total_violations,
    sampled: counters.sampled_violations,
  };
}

function settleResidentReport(
  reportPath: string,
  unit: string,
  initialReport: any,
  controls: ResidentEvidenceSettleControls = {},
): any {
  const now = controls.now || (() => process.hrtime.bigint());
  const pause = controls.pause || ((milliseconds: number) => {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
  });
  const read = controls.read || ((file: string) =>
    readJsonBounded(file, MAX_REPORT_BYTES, "Fence report"));
  const verifyService = controls.verifyService || validateResidentService;
  let report = validatePostEvidence(initialReport, "resident", (value: any) => validateReport(value, false));
  verifyService(unit, report.resident_health.resident_pid);
  let counters = networkEvidenceCounters(report);
  if (report.critical_findings.length > 0) {
    return report;
  }

  const started = now();
  const deadline = started + EVIDENCE_SETTLE_TIMEOUT_NANOSECONDS;
  const identityFields = [
    "runtime_evidence_schema_version",
    "status",
    "mode",
    "allow_github_artifacts",
    "readiness_status",
    "platform_profile_id",
    "profile_realization_id",
    "policy_hash_schema_version",
    "policy_hash",
    "base_ruleset_hash",
    "setup_status",
    "protection_available",
  ];

  for (let index = 0; index < EVIDENCE_SETTLE_MAX_READS; index += 1) {
    const remaining = deadline - now();
    if (remaining <= 0n) {
      break;
    }
    const remainingMilliseconds = Number((remaining + 999_999n) / 1_000_000n);
    pause(Math.min(EVIDENCE_SETTLE_INTERVAL_MILLISECONDS, remainingMilliseconds));
    const next = validatePostEvidence(read(reportPath), "resident", (value: any) => validateReport(value, false));
    if (
      identityFields.some((field) => next[field] !== initialReport[field]) ||
      next.resident_health.resident_pid !== initialReport.resident_health.resident_pid
    ) {
      throw new Error("Fence resident report identity changed during final evidence settlement");
    }
    const nextCounters = networkEvidenceCounters(next);
    if (
      nextCounters.sampled < counters.sampled ||
      (
        nextCounters.total < counters.total &&
        (
          next.mode !== "block" ||
          next.ruleset_hash === report.ruleset_hash
        )
      )
    ) {
      throw new Error("Fence resident network counters decreased during final evidence settlement");
    }
    if (next.critical_findings.length > 0) {
      verifyService(unit, next.resident_health.resident_pid);
      return next;
    }
    counters = nextCounters;
    report = next;
  }
  verifyService(unit, report.resident_health.resident_pid);
  return report;
}

function validateProtectedActionMount(actionRoot: string): void {
  const evidence = activeActionMountEvidence(actionRoot);
  validateReadOnlyActionMount(evidence.raw, actionRoot, evidence.mountId);
}

function validateRegisteredActionPathGuards(actionRoot: string): ReturnType<typeof actionPathGuardIdentities> {
  const guards = actionPathGuardIdentities(actionRoot);
  for (const guard of guards) {
    const evidence = activeActionMountEvidence(guard.path);
    validateActionPathGuardMount(evidence.raw, guard.path, evidence.mountId);
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
  const initialReport = readJsonBounded(reportPath, MAX_REPORT_BYTES, "Fence report");
  const report = settleResidentReport(reportPath, paths.unit, initialReport);
  let dnsEvidence;
  const effectiveDnsReportPath = dnsReportPath || paths.dnsReport;
  if (fs.existsSync(effectiveDnsReportPath)) {
    dnsEvidence = validatePostEvidence(
      readJsonBounded(effectiveDnsReportPath, MAX_REPORT_BYTES, "Fence DNS report"),
      "dns",
      (value: any) => validateDnsEvidence(value, report),
    );
  } else if (report.mode === "block") {
    throw new Error("Fence block-mode DNS evidence is missing");
  }
  const auditSummary = correlateFindingsToDns(report, dnsEvidence);
  const dnsMaterializationRequestRejections = materializationRequestRejections(dnsEvidence);
  const userWildcardRequestRejections = materializationEvidenceCounter(
    dnsEvidence,
    "user_wildcard_request_rejections",
  );
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
  const githubArtifactAuthorizationCount = Array.isArray(dnsEvidence?.runner_authorized_results_storage)
    ? dnsEvidence.runner_authorized_results_storage.filter((authorization: any) =>
      authorization.authorization_origin === "opt_in_github_artifact_dns"
    ).length
    : 0;
  log.debugGroup("Fence debug: post-job evidence", [
    `report_path=${reportPath}`,
    `dns_report_path=${effectiveDnsReportPath}`,
    `dns_report_present=${dnsEvidence !== undefined}`,
    `protected_action_runtime=verified`,
    `mode=${report.mode}`,
    `allow_github_artifacts=${report.allow_github_artifacts}`,
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
    `materialization_rejection_reasons=${JSON.stringify(materializationRejectionReasons(dnsEvidence))}`,
    `materialization_update_max_milliseconds=${materializationEvidenceCounter(dnsEvidence, "materialization_update_max_milliseconds")}`,
    `upstream_request_failures=${materializationEvidenceCounter(dnsEvidence, "upstream_request_failures")}`,
    `user_wildcard_authorizations=${Array.isArray(dnsEvidence?.bounded_user_wildcard_authorizations) ? dnsEvidence.bounded_user_wildcard_authorizations.length : "unknown"}`,
    `user_wildcard_authorizations_truncated=${dnsEvidence?.bounded_user_wildcard_authorizations_truncated === true}`,
    `user_wildcard_request_rejections=${userWildcardRequestRejections}`,
    `results_storage_authorizations=${resultsStorageAuthorizationCount}`,
    `github_artifact_authorizations=${githubArtifactAuthorizationCount}`,
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
  for (const line of networkReportLines(report, dnsEvidence)) {
    log.info(line);
  }
  log.structuredRecord(structuredReportLine(report, dnsEvidence));
  if (report.allow_github_artifacts) {
    log.warning(
      `Fence GitHub artifact compatibility permitted ${githubArtifactAuthorizationCount} of 4 storage accounts; artifact uploads are an intentional data-egress channel`,
    );
  }
  if (Array.isArray(report.critical_findings) && report.critical_findings.length > 0) {
    log.warning(`Fence detected ${report.critical_findings.length} critical resident finding(s); failing this job`);
  }
  const dnsWarning = materializationWarning(dnsEvidence);
  if (dnsWarning) {
    log.warning(dnsWarning);
  }
  if (userWildcardRequestRejections > 0) {
    log.warning(
      `Fence denied ${userWildcardRequestRejections} DNS request(s) after the user wildcard hostname authorization budget was exhausted`,
    );
  }
  for (const warning of resultsStorageWarnings(dnsEvidence)) {
    log.warning(warning);
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

module.exports = { main, postFailureDiagnostic, validatePostEvidence, settleResidentReport };
