"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const log = require("./log.cts");
const {
  MAX_REPORT_BYTES,
  nativeInputsFromEnvironment,
  readJsonBounded,
  runtimePaths,
  validateBundle,
  validateInlineConfig,
  validateReady,
  validateReport,
} = require("./lib.cts");

const ACTION_ROOT = __dirname;
const BINARY = path.join(ACTION_ROOT, "bin", "fence");
const MANIFEST = path.join(ACTION_ROOT, "bundle-manifest.json");
const READY_TIMEOUT_MS = 30 * 1000;
const CHILD_TIMEOUT_MS = 10 * 1000;
const POLL_INTERVAL_MS = 100;
const CHILD_ENV = {
  LANG: "C.UTF-8",
  LC_ALL: "C.UTF-8",
  PATH: "/usr/bin:/usr/sbin:/bin:/sbin",
};

let diagnosticPaths: { unit: string } | undefined;
let serviceLaunchAttempted = false;

function emitError(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  log.error(`Fence setup failed: ${message}`);
  emitServiceDiagnostics(diagnosticPaths);
}

function run(
  executable: string,
  args: string[],
  input: string | undefined = undefined,
  ignoreStdout = false,
  timeout = CHILD_TIMEOUT_MS,
): void {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    env: CHILD_ENV,
    input,
    killSignal: "SIGKILL",
    maxBuffer: 64 * 1024,
    stdio: ignoreStdout ? ["pipe", "ignore", "pipe"] : ["pipe", "pipe", "pipe"],
    timeout,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const stderr = String(result.stderr || "").replace(/[\r\n%]/g, "_").slice(0, 512);
    throw new Error(`${path.basename(executable)} failed with exit ${result.status}: ${stderr}`);
  }
}

function capture(
  executable: string,
  args: string[],
  timeout = 2 * 1000,
): { status: number | null; stdout: string; stderr: string; error: string | undefined } {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    env: CHILD_ENV,
    killSignal: "SIGKILL",
    maxBuffer: 32 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    timeout,
  });
  return {
    status: result.status,
    stdout: String(result.stdout || ""),
    stderr: String(result.stderr || ""),
    error: result.error ? result.error.message : undefined,
  };
}

function compactServiceStatus(output: string): string {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .slice(0, 12)
    .join("; ");
}

function emitServiceDiagnostics(paths: { unit: string } | undefined): void {
  if (!paths || !serviceLaunchAttempted) {
    return;
  }
  const status = capture("/usr/bin/systemctl", [
    "show",
    paths.unit,
    "--no-pager",
    "--property=LoadState",
    "--property=ActiveState",
    "--property=SubState",
    "--property=Result",
    "--property=ExecMainCode",
    "--property=ExecMainStatus",
    "--property=MainPID",
  ]);
  const compactStatus = compactServiceStatus(`${status.stdout}\n${status.stderr}`);
  if (compactStatus.length > 0) {
    log.warning(`Fence service state for ${paths.unit}: ${compactStatus}`);
  }
  log.debugGroup("Fence debug: service status", [
    `unit=${paths.unit}`,
    `status=${status.status}`,
    `error=${status.error || "none"}`,
    ...`${status.stdout}\n${status.stderr}`.split(/\r?\n/).filter((line) => line.length > 0),
  ]);

  const journal = capture("/usr/bin/journalctl", [
    "--no-pager",
    "--unit",
    paths.unit,
    "--lines",
    "80",
    "--output",
    "short-monotonic",
  ]);
  log.debugGroup("Fence debug: service journal", [
    `unit=${paths.unit}`,
    `status=${journal.status}`,
    `error=${journal.error || "none"}`,
    ...`${journal.stdout}\n${journal.stderr}`.split(/\r?\n/).filter((line) => line.length > 0),
  ]);
}

function sleep(milliseconds: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function assertRootDirectory(directory: string): void {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o777) !== 0o755) {
    throw new Error(`unsafe root-owned runtime directory: ${directory}`);
  }
}

function appendState(name: string, value: string): void {
  const state = process.env.GITHUB_STATE;
  if (!state) {
    throw new Error("GITHUB_STATE is required");
  }
  fs.appendFileSync(state, `${name}=${value}\n`, { encoding: "utf8" });
}

function waitForReady(paths: { ready: string; report: string }): any {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  log.debugGroup("Fence debug: readiness", [
    `timeout_ms=${READY_TIMEOUT_MS}`,
    `poll_interval_ms=${POLL_INTERVAL_MS}`,
    `ready_path=${paths.ready}`,
    `report_path=${paths.report}`,
  ]);
  while (Date.now() < deadline) {
    if (fs.existsSync(paths.ready) && fs.existsSync(paths.report)) {
      const report = validateReport(
        readJsonBounded(paths.report, MAX_REPORT_BYTES, "Fence report"),
        true,
      );
      const ready = readJsonBounded(paths.ready, 64 * 1024, "Fence readiness");
      validateReady(ready, report);
      log.debugGroup("Fence debug: readiness verified", [
        `mode=${report.mode}`,
        `status=${report.status}`,
        `readiness=${report.readiness_status}`,
        `network_verification=${report.network_verification_status}`,
        `sudo=${report.sudo_status}`,
        `containers=${report.container_status}`,
        `critical_findings=${Array.isArray(report.critical_findings) ? report.critical_findings.length : "unknown"}`,
      ]);
      return report;
    }
    sleep(POLL_INTERVAL_MS);
  }
  throw new Error("Fence readiness was not emitted before the timeout");
}

function main(): void {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new Error("Fence Action supports only Linux x64");
  }
  const manifest = validateBundle(MANIFEST, BINARY);
  const config = validateInlineConfig(process.env.INPUT_CONFIG, process.env, nativeInputsFromEnvironment(process.env));
  const paths = runtimePaths(config.invocationId);
  diagnosticPaths = paths;
  const details = log.configLogDetails(config.raw, config.usingDefault);

  for (const line of log.setupLines(manifest, details)) {
    log.info(line);
  }
  log.debugGroup("Fence debug: setup inputs", [
    `mode=${details.mode}`,
    `invocation_id=${config.invocationId}`,
    `config_source=${details.source}`,
    `container_policy=${details.containerPolicy}`,
    `platform_profile=${details.platformProfile}`,
    `disable_broad_github_domains=${details.disableBroadGithubDomains}`,
    `allowlist_count=${details.allowlistCount}`,
    ...details.allowlistDestinations.map((entry: string) => `allowlist=${entry}`),
    `bundle_release=${manifest.release_tag}`,
    `bundle_source_commit=${manifest.source_commit}`,
    `platform=${process.platform}`,
    `arch=${process.arch}`,
    `runtime_directory=${paths.directory}`,
    `unit=${paths.unit}`,
  ]);

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
  appendState("dns_report_path", paths.dnsReport);
  appendState("ready_path", paths.ready);
  log.info("🚀 Starting resident service");
  const serviceArgs = [
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
  ];
  log.debugGroup("Fence debug: service launch", [
    `executable=/usr/bin/sudo`,
    `args=${serviceArgs.join(" ")}`,
    `child_timeout_ms=${CHILD_TIMEOUT_MS}`,
  ]);
  serviceLaunchAttempted = true;
  run("/usr/bin/sudo", serviceArgs);
  const report = waitForReady(paths);
  log.success(log.readyLine(report));
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    emitError(error);
    process.exitCode = 1;
  }
}

module.exports = { main, run };
