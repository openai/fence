"use strict";

const fs = require("node:fs");
const path = require("node:path");
const log = require("./log.cts");
const {
  correlateFindingsToDns,
  materializationRequestRejections,
  materializationEvidenceCounter,
  MAX_REPORT_BYTES,
  readJsonBounded,
  runtimePaths,
  summaryLines,
  validateBundle,
  validateReport,
} = require("./lib.cts");

const ACTION_ROOT = __dirname;
const BINARY = path.join(ACTION_ROOT, "bin", "fence");
const MANIFEST = path.join(ACTION_ROOT, "bundle-manifest.json");

function emitError(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  log.error(`Fence post-job evidence failed: ${message}`);
}

function main(): void {
  log.info("📋 Validating Fence evidence");
  const invocationId = process.env.STATE_invocation_id;
  const reportPath = process.env.STATE_report_path;
  const dnsReportPath = process.env.STATE_dns_report_path;
  const paths = invocationId ? runtimePaths(invocationId) : undefined;
  if (!invocationId || !paths || paths.report !== reportPath) {
    throw new Error("Fence post-job report path is missing or invalid");
  }
  if (dnsReportPath && paths.dnsReport !== dnsReportPath) {
    throw new Error("Fence post-job DNS report path is invalid");
  }
  validateBundle(MANIFEST, BINARY);
  const report = validateReport(
    readJsonBounded(reportPath, MAX_REPORT_BYTES, "Fence report"),
    false,
  );
  let dnsEvidence;
  const effectiveDnsReportPath = dnsReportPath || paths.dnsReport;
  if (fs.existsSync(effectiveDnsReportPath)) {
    dnsEvidence = readJsonBounded(effectiveDnsReportPath, MAX_REPORT_BYTES, "Fence DNS report");
  }
  const auditSummary = correlateFindingsToDns(report, dnsEvidence);
  const dnsMaterializationRequestRejections = materializationRequestRejections(dnsEvidence);
  log.debugGroup("Fence debug: post-job evidence", [
    `report_path=${reportPath}`,
    `dns_report_path=${effectiveDnsReportPath}`,
    `dns_report_present=${dnsEvidence !== undefined}`,
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
