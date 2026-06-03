"use strict";

const fs = require("node:fs");
const path = require("node:path");
const {
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
  process.stderr.write(`::error::Fence post-job evidence failed: ${message.replace(/[\r\n%]/g, "_").slice(0, 512)}\n`);
}

function main(): void {
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
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summaryLines(report, dnsEvidence).join("\n"), {
      encoding: "utf8",
    });
  }
  validateReport(report, true);
  process.stdout.write("Fence post-job local evidence verified; resident controls remain active until runner teardown.\n");
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
