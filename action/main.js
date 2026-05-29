"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  MAX_REPORT_BYTES,
  readJsonBounded,
  runtimePaths,
  summaryLines,
  validateBundle,
  validateInlineConfig,
  validateReady,
  validateReport,
} = require("./lib");

const ACTION_ROOT = __dirname;
const BINARY = path.join(ACTION_ROOT, "bin", "fence");
const MANIFEST = path.join(ACTION_ROOT, "bundle-manifest.json");
const READY_TIMEOUT_MS = 30 * 1000;
const POLL_INTERVAL_MS = 100;
const CHILD_ENV = {
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
  PATH: "/usr/bin:/usr/sbin:/bin:/sbin",
};

function emitError(error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`::error::Fence setup failed: ${message.replace(/[\r\n%]/g, "_").slice(0, 512)}\n`);
}

function run(executable, args, input = undefined, ignoreStdout = false) {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    env: CHILD_ENV,
    input,
    maxBuffer: 64 * 1024,
    stdio: ignoreStdout ? ["pipe", "ignore", "pipe"] : ["pipe", "pipe", "pipe"],
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const stderr = String(result.stderr || "").replace(/[\r\n%]/g, "_").slice(0, 512);
    throw new Error(`${path.basename(executable)} failed with exit ${result.status}: ${stderr}`);
  }
}

function sleep(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function assertRootDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o777) !== 0o755) {
    throw new Error(`unsafe root-owned runtime directory: ${directory}`);
  }
}

function appendState(name, value) {
  const state = process.env.GITHUB_STATE;
  if (!state) {
    throw new Error("GITHUB_STATE is required");
  }
  fs.appendFileSync(state, `${name}=${value}\n`, { encoding: "utf8" });
}

function appendSummary(report) {
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summaryLines(report).join("\n"), {
      encoding: "utf8",
    });
  }
}

function waitForReady(paths) {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (fs.existsSync(paths.ready) && fs.existsSync(paths.report)) {
      const report = validateReport(readJsonBounded(paths.report, MAX_REPORT_BYTES, "Fence report"));
      const ready = readJsonBounded(paths.ready, 64 * 1024, "Fence readiness");
      validateReady(ready, report);
      return report;
    }
    sleep(POLL_INTERVAL_MS);
  }
  throw new Error("Fence readiness was not emitted before the timeout");
}

function main() {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new Error("Fence Action supports only Linux x64");
  }
  validateBundle(MANIFEST, BINARY);
  const config = validateInlineConfig(process.env.INPUT_CONFIG);
  const paths = runtimePaths(config.invocationId);

  if (fs.existsSync(paths.directory)) {
    throw new Error("Fence runtime invocation directory already exists");
  }
  run("/usr/bin/sudo", ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", "/run/fence", paths.directory]);
  assertRootDirectory("/run/fence");
  assertRootDirectory(paths.directory);
  run("/usr/bin/sudo", ["/usr/bin/install", "-o", "root", "-g", "root", "-m", "0600", "/dev/null", paths.config]);
  run("/usr/bin/sudo", ["/usr/bin/tee", paths.config], config.raw, true);

  appendState("invocation_id", config.invocationId);
  appendState("report_path", paths.report);
  appendState("ready_path", paths.ready);
  run("/usr/bin/sudo", [
    "/usr/bin/systemd-run",
    "--quiet",
    "--collect",
    "--property=Type=exec",
    "--unit",
    paths.unit,
    BINARY,
    "run",
    "--config",
    paths.config,
  ]);
  const report = waitForReady(paths);
  appendSummary(report);
  process.stdout.write("Fence readiness verified; resident controls remain active until runner teardown.\n");
}

try {
  main();
} catch (error) {
  emitError(error);
  process.exitCode = 1;
}
