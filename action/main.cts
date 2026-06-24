"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const log = require("./log.cts");
const {
  ACTION_RUNTIME_FILES,
  MAX_REPORT_BYTES,
  activeActionMountEvidence,
  actionPathGuardIdentities,
  actionRuntimeDigest,
  actionRuntimeFileDigests,
  launcherIntegrityDocument,
  nativeInputsFromEnvironment,
  readJsonBounded,
  readLauncherIntegrity,
  runtimePaths,
  validateBundle,
  validateActionPathGuardMount,
  validateInlineConfig,
  validateLauncherIntegrity,
  validateProtectedActionRuntime,
  validateReadOnlyActionMount,
  validateReady,
  validateReport,
  validateResidentUnitStatus,
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
let serviceLaunchSucceeded = false;
let launcherPaths: ReturnType<typeof runtimePaths> | undefined;
let protectedActionPathGuards: string[] = [];
let protectedActionMounted = false;
let readinessObserved = false;
let runtimeDirectoryCreated = false;

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

function parseServiceProperties(output: string): Record<string, string> {
  const properties: Record<string, string> = {};
  for (const line of output.split(/\r?\n/)) {
    const separator = line.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const name = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (
      !new Set([
        "ActiveState",
        "ExecMainCode",
        "ExecMainStatus",
        "LoadState",
        "MainPID",
        "Result",
        "SubState",
      ]).has(name) ||
      name in properties ||
      value.length > 128 ||
      /[^A-Za-z0-9_.:-]/.test(value)
    ) {
      continue;
    }
    properties[name] = value;
  }
  return properties;
}

function terminalServiceStatus(output: string): string | undefined {
  const properties = parseServiceProperties(output);
  const terminal =
    properties.LoadState === "not-found" ||
    properties.ActiveState === "failed" ||
    (properties.ActiveState === "inactive" && properties.SubState === "dead");
  if (!terminal) {
    return undefined;
  }
  return [
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "MainPID",
  ]
    .filter((name) => name in properties)
    .map((name) => `${name}=${properties[name]}`)
    .join("; ");
}

function fenceErrorCodeFromJournal(output: string): string | undefined {
  for (const line of output.split(/\r?\n/).reverse()) {
    if (line.length === 0 || line.length > 4096) {
      continue;
    }
    try {
      const document = JSON.parse(line);
      const code = document?.error?.code;
      if (
        document?.schema_version === 1 &&
        document?.command === "run" &&
        document?.status === "error" &&
        typeof code === "string" &&
        /^[a-z][a-z0-9_]{0,63}$/.test(code)
      ) {
        return code;
      }
    } catch {
      // Unit journals also contain systemd messages; only exact Fence JSON is accepted.
    }
  }
  return undefined;
}

function captureServiceStatus(unit: string): ReturnType<typeof capture> {
  return capture("/usr/bin/systemctl", [
    "show",
    unit,
    "--no-pager",
    "--property=LoadState",
    "--property=ActiveState",
    "--property=SubState",
    "--property=Result",
    "--property=ExecMainCode",
    "--property=ExecMainStatus",
    "--property=MainPID",
  ]);
}

function emitServiceDiagnostics(paths: { unit: string } | undefined): void {
  if (!paths || !serviceLaunchAttempted) {
    return;
  }
  const status = captureServiceStatus(paths.unit);
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
    "20",
    "--output",
    "cat",
  ]);
  const errorCode = fenceErrorCodeFromJournal(journal.stdout);
  if (errorCode !== undefined) {
    log.warning(`Fence resident error code: ${errorCode}`);
  }
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

function pathEntryExists(entry: string): boolean {
  try {
    fs.lstatSync(entry);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function createOrValidateRootDirectory(directory: string): void {
  if (!pathEntryExists(directory)) {
    run("/usr/bin/sudo", [
      "/usr/bin/install",
      "-d",
      "-o",
      "root",
      "-g",
      "root",
      "-m",
      "0755",
      directory,
    ]);
  }
  assertRootDirectory(directory);
}

function installProtectedActionRuntime(
  invocationId: string,
  paths: ReturnType<typeof runtimePaths>,
): void {
  if (pathEntryExists(paths.launcherDirectory)) {
    throw new Error("Fence launcher invocation directory already exists");
  }
  const sourceFiles = actionRuntimeFileDigests(ACTION_ROOT);
  createOrValidateRootDirectory("/run/fence-launcher");
  run("/usr/bin/sudo", [
    "/usr/bin/install",
    "-d",
    "-o",
    "root",
    "-g",
    "root",
    "-m",
    "0755",
    paths.launcherDirectory,
    paths.launcherActionDirectory,
    path.join(paths.launcherActionDirectory, "bin"),
  ]);
  assertRootDirectory(paths.launcherDirectory);
  for (const relativePath of ACTION_RUNTIME_FILES) {
    const mode = relativePath === "bin/fence" ? "0555" : "0444";
    run("/usr/bin/sudo", [
      "/usr/bin/install",
      "-o",
      "root",
      "-g",
      "root",
      "-m",
      mode,
      path.join(ACTION_ROOT, relativePath),
      path.join(paths.launcherActionDirectory, relativePath),
    ]);
  }
  run("/usr/bin/sudo", [
    "/usr/bin/chmod",
    "0555",
    paths.launcherActionDirectory,
    path.join(paths.launcherActionDirectory, "bin"),
  ]);
  validateProtectedActionRuntime(paths.launcherActionDirectory);
  const protectedFiles = actionRuntimeFileDigests(paths.launcherActionDirectory);
  if (actionRuntimeDigest(sourceFiles) !== actionRuntimeDigest(protectedFiles)) {
    throw new Error("Fence protected Action copy does not match the registered runtime");
  }
  const pathGuards = actionPathGuardIdentities(ACTION_ROOT);
  const integrity = launcherIntegrityDocument(
    invocationId,
    ACTION_ROOT,
    paths.launcherActionDirectory,
    protectedFiles,
    pathGuards,
  );
  run("/usr/bin/sudo", [
    "/usr/bin/install",
    "-o",
    "root",
    "-g",
    "root",
    "-m",
    "0600",
    "/dev/null",
    paths.launcherIntegrity,
  ]);
  run("/usr/bin/sudo", ["/usr/bin/tee", paths.launcherIntegrity], JSON.stringify(integrity), true);
  run("/usr/bin/sudo", ["/usr/bin/chmod", "0444", paths.launcherIntegrity]);
  validateLauncherIntegrity(
    readLauncherIntegrity(paths.launcherIntegrity),
    invocationId,
    ACTION_ROOT,
    paths.launcherActionDirectory,
    protectedFiles,
    pathGuards,
  );

  for (const guard of pathGuards) {
    run("/usr/bin/sudo", [
      "/usr/bin/mount",
      "--bind",
      guard.path,
      guard.path,
    ]);
    protectedActionPathGuards.push(guard.path);
    const evidence = activeActionMountEvidence(guard.path);
    validateActionPathGuardMount(evidence.raw, guard.path, evidence.mountId);
  }

  run("/usr/bin/sudo", [
    "/usr/bin/mount",
    "--bind",
    paths.launcherActionDirectory,
    ACTION_ROOT,
  ]);
  protectedActionMounted = true;
  run("/usr/bin/sudo", [
    "/usr/bin/mount",
    "-o",
    "remount,bind,ro,nodev,nosuid",
    paths.launcherActionDirectory,
    ACTION_ROOT,
  ]);
  const actionMount = activeActionMountEvidence(ACTION_ROOT);
  validateReadOnlyActionMount(actionMount.raw, ACTION_ROOT, actionMount.mountId);
  validateProtectedActionRuntime(ACTION_ROOT);
  const mountedFiles = actionRuntimeFileDigests(ACTION_ROOT);
  const mountedPathGuards = actionPathGuardIdentities(ACTION_ROOT);
  validateLauncherIntegrity(
    readLauncherIntegrity(paths.launcherIntegrity),
    invocationId,
    ACTION_ROOT,
    paths.launcherActionDirectory,
    mountedFiles,
    mountedPathGuards,
  );
  for (const guard of mountedPathGuards) {
    const evidence = activeActionMountEvidence(guard.path);
    validateActionPathGuardMount(evidence.raw, guard.path, evidence.mountId);
  }
  validateBundle(MANIFEST, BINARY);
  log.debugGroup("Fence debug: protected Action runtime", [
    `registered_runtime=verified`,
    `protected_copy=verified`,
    `path_guard_count=${mountedPathGuards.length}`,
    `runtime_digest=${actionRuntimeDigest(mountedFiles)}`,
    `mount_options=ro,nodev,nosuid`,
  ]);
}

function serviceRemainsActive(paths: ReturnType<typeof runtimePaths>): boolean {
  if (!serviceLaunchSucceeded) {
    return false;
  }
  const status = capture("/usr/bin/systemctl", [
    "show",
    paths.unit,
    "--no-pager",
    "--property=ActiveState",
  ]);
  if (status.error || status.status !== 0) {
    return true;
  }
  const state = status.stdout.trim();
  return state !== "ActiveState=inactive" && state !== "ActiveState=failed";
}

function cleanupLauncherBeforeReadiness(): void {
  if (!launcherPaths || readinessObserved || !pathEntryExists(launcherPaths.launcherDirectory)) {
    return;
  }
  if (serviceRemainsActive(launcherPaths)) {
    log.warning("Fence left the protected Action runtime mounted because the resident service is still active");
    return;
  }
  try {
    if (protectedActionMounted) {
      run("/usr/bin/sudo", ["/usr/bin/umount", ACTION_ROOT]);
      protectedActionMounted = false;
    }
    for (const guard of [...protectedActionPathGuards].reverse()) {
      run("/usr/bin/sudo", ["/usr/bin/umount", guard]);
    }
    protectedActionPathGuards = [];
    if (runtimeDirectoryCreated && pathEntryExists(launcherPaths.directory)) {
      run("/usr/bin/sudo", [
        "/usr/bin/rm",
        "--recursive",
        "--force",
        "--one-file-system",
        launcherPaths.directory,
      ]);
      runtimeDirectoryCreated = false;
    }
    run("/usr/bin/sudo", [
      "/usr/bin/rm",
      "--recursive",
      "--force",
      "--one-file-system",
      launcherPaths.launcherDirectory,
    ]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log.warning(`Fence could not remove provisional launcher state: ${message}`);
  }
}

function appendState(name: string, value: string): void {
  const state = process.env.GITHUB_STATE;
  if (!state) {
    throw new Error("GITHUB_STATE is required");
  }
  fs.appendFileSync(state, `${name}=${value}\n`, { encoding: "utf8" });
}

function waitForReady(paths: { ready: string; report: string; unit: string }): any {
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
      const service = capture("/usr/bin/systemctl", [
        "show",
        paths.unit,
        "--no-pager",
        "--property=ActiveState",
        "--property=MainPID",
        "--property=SubState",
      ]);
      if (service.error || service.status !== 0) {
        throw new Error("Fence resident service status is unavailable after readiness");
      }
      validateResidentUnitStatus(service.stdout, report.resident_health.resident_pid);
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
    const service = captureServiceStatus(paths.unit);
    if (!service.error && service.status === 0) {
      const terminalStatus = terminalServiceStatus(service.stdout);
      if (terminalStatus !== undefined) {
        throw new Error(`Fence resident service exited before readiness: ${terminalStatus}`);
      }
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
  launcherPaths = paths;
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

  if (pathEntryExists(paths.directory)) {
    throw new Error("Fence runtime invocation directory already exists");
  }
  installProtectedActionRuntime(config.invocationId, paths);
  createOrValidateRootDirectory("/run/fence");
  run("/usr/bin/sudo", ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", paths.directory]);
  runtimeDirectoryCreated = true;
  assertRootDirectory(paths.directory);
  run("/usr/bin/sudo", ["/usr/bin/install", "-o", "root", "-g", "root", "-m", "0600", "/dev/null", paths.config]);
  run("/usr/bin/sudo", ["/usr/bin/tee", paths.config], config.raw, true);

  appendState("invocation_id", config.invocationId);
  appendState("report_path", paths.report);
  appendState("dns_report_path", paths.dnsReport);
  appendState("ready_path", paths.ready);
  appendState("launcher_integrity_path", paths.launcherIntegrity);
  log.info("🚀 Starting resident service");
  const serviceArgs = [
    "/usr/bin/systemd-run",
    "--quiet",
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
  serviceLaunchSucceeded = true;
  const report = waitForReady(paths);
  readinessObserved = true;
  log.success(log.readyLine(report));
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    emitError(error);
    cleanupLauncherBeforeReadiness();
    process.exitCode = 1;
  }
}

module.exports = { fenceErrorCodeFromJournal, main, run, terminalServiceStatus };
