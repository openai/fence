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
} = require("./lib");

const ACTION_ROOT = __dirname;
const BINARY = path.join(ACTION_ROOT, "bin", "fence");
const MANIFEST = path.join(ACTION_ROOT, "bundle-manifest.json");

function emitError(error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`::error::Fence post-job evidence failed: ${message.replace(/[\r\n%]/g, "_").slice(0, 512)}\n`);
}

function main() {
  const invocationId = process.env.STATE_invocation_id;
  const reportPath = process.env.STATE_report_path;
  if (!invocationId || runtimePaths(invocationId).report !== reportPath) {
    throw new Error("Fence post-job report path is missing or invalid");
  }
  const manifest = validateBundle(MANIFEST, BINARY);
  const report = validateReport(
    readJsonBounded(reportPath, MAX_REPORT_BYTES, "Fence report"),
    true,
    manifest,
  );
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summaryLines(report).join("\n"), {
      encoding: "utf8",
    });
  }
  process.stdout.write("Fence post-job local evidence verified; resident controls remain active until runner teardown.\n");
}

try {
  main();
} catch (error) {
  emitError(error);
  process.exitCode = 1;
}
