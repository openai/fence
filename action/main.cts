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
  readReady,
  readLauncherIntegrity,
  runtimePaths,
  validateBundle,
  validatedActionRuntimeSnapshot,
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
const SERVICE_STATUS_PROPERTIES = new Map<string, RegExp>([
  ["LoadState", /^(?:loaded|not-found|masked|error|bad-setting)$/],
  ["ActiveState", /^(?:active|inactive|failed|activating|deactivating|reloading|maintenance)$/],
  ["SubState", /^(?:running|dead|failed|start|stop|auto-restart|exited)$/],
  ["Result", /^(?:success|exit-code|signal|core-dump|timeout|watchdog|resources|protocol|start-limit-hit|oom-kill)$/],
  ["ExecMainCode", /^(?:[0-9]{1,10}|exited|killed|dumped)$/],
  ["ExecMainStatus", /^[0-9]{1,10}$/],
  ["MainPID", /^[0-9]{1,10}$/],
]);

let diagnosticPaths: { unit: string } | undefined;
let serviceLaunchAttempted = false;
let launcherPaths: ReturnType<typeof runtimePaths> | undefined;
let protectedActionPathGuards: string[] = [];
let protectedActionMounted = false;
let readinessObserved = false;
let launcherHostClaimCreated = false;
let launcherMountUncertain = false;
let launcherDirectoryCreated = false;
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
): { status: number | null; stdout: string; error: boolean } {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    env: CHILD_ENV,
    killSignal: "SIGKILL",
    maxBuffer: 32 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
    timeout,
  });
  return {
    status: result.status,
    stdout: String(result.stdout || ""),
    error: Boolean(result.error),
  };
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
    if (name in properties || !SERVICE_STATUS_PROPERTIES.get(name)?.test(value)) {
      continue;
    }
    properties[name] = value;
  }
  return properties;
}

function formatServiceProperties(properties: Record<string, string>): string {
  return [...SERVICE_STATUS_PROPERTIES.keys()]
    .filter((name) => name in properties)
    .map((name) => `${name}=${properties[name]}`)
    .join("; ");
}

function terminalServiceStatus(output: string): string | undefined {
  const properties = parseServiceProperties(output);
  const terminal =
    (properties.ActiveState === "failed" && properties.SubState === "failed") ||
    (properties.ActiveState === "inactive" && properties.SubState === "dead");
  if (!terminal || properties.MainPID !== "0") {
    return undefined;
  }
  return formatServiceProperties(properties);
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

function localControlDiagnosticFromJournal(output: string): string | undefined {
  const unavailableReasons = new Set([
    "cgroup_identity", "ipv4_table", "ipv6_table", "malformed_rows", "proc", "proc_scan",
    "process_fd_readlink", "process_fd_scan", "process_identity", "process_identity_drift",
    "socket_ownership", "unix_reachability", "unix_table",
  ]);
  const boundReasons = new Set([
    "container_processes", "fds_per_process", "processes", "socket_owners",
    "tcp_listeners", "total_fds", "unix_listeners",
  ]);
  const validReasons = (values: unknown, allowed: Set<string>): values is string[] =>
    Array.isArray(values) && values.length <= allowed.size &&
    values.every((value) => typeof value === "string" && allowed.has(value)) &&
    new Set(values).size === values.length;
  for (const line of output.split(/\r?\n/).reverse()) {
    if (line.length === 0 || line.length > 4096) continue;
    try {
      const diagnostic = JSON.parse(line)?.fence_local_control;
      if (
        !diagnostic || !["unavailable", "unstable", "bounds_exceeded"].includes(diagnostic.status) ||
        !Number.isSafeInteger(diagnostic.attempts) || diagnostic.attempts < 1 ||
        !validReasons(diagnostic.unavailable_inputs, unavailableReasons) ||
        !validReasons(diagnostic.bounds_exceeded, boundReasons)
      ) continue;
      return `status=${diagnostic.status}; attempts=${diagnostic.attempts}; ` +
        `unavailable=${diagnostic.unavailable_inputs.join(",") || "none"}; ` +
        `bounds=${diagnostic.bounds_exceeded.join(",") || "none"}`;
    } catch {
      // Ignore other journal messages and never forward their contents.
    }
  }
  return undefined;
}

function lockdownCommandDiagnosticFromJournal(output: string): string | undefined {
  // Match only the native closed enums. Never render journal text or program arguments.
  const executables = new Set([
    "docker", "id", "mount", "nft", "stat", "sudo", "systemctl", "systemd_run",
    "test", "true", "umount", "visudo",
  ]);
  for (const line of output.split(/\r?\n/).reverse()) {
    if (line.length === 0 || line.length > 4096) continue;
    try {
      const d = JSON.parse(line)?.fence_lockdown_command;
      if (
        !d || !executables.has(d.executable) || !["root", "runner"].includes(d.principal) ||
        !["lockdown_command_timeout", "lockdown_command_output_too_large"].includes(d.code) ||
        !Number.isSafeInteger(d.timeout_ms) || d.timeout_ms < 0 || d.timeout_ms > 30_000
      ) continue;
      return `executable=${d.executable}; principal=${d.principal}; code=${d.code}; timeout_ms=${d.timeout_ms}`;
    } catch {
      // Ignore unrelated or malformed entries without forwarding them.
    }
  }
  return undefined;
}

function dnsStartupDiagnosticFromJournal(output: string): string | undefined {
  const reasons = new Map([
    ["address_in_use", "address already in use"],
    ["address_unavailable", "address unavailable"],
    ["permission_denied", "permission denied"],
    ["other", "other system error"],
  ]);
  for (const line of output.split(/\r?\n/).reverse()) {
    if (line.length === 0 || line.length > 4096) continue;
    try {
      const d = JSON.parse(line)?.fence_dns_startup;
      if (
        !d || !["host", "docker"].includes(d.listener) || !["udp", "tcp"].includes(d.protocol) ||
        !["bind", "configure"].includes(d.operation) || !reasons.has(d.reason)
      ) continue;
      return `${d.listener} ${d.protocol.toUpperCase()} ${d.operation}: ${reasons.get(d.reason)}`;
    } catch {
      // Never forward journal text or unknown fields.
    }
  }
  return undefined;
}

function resolverLayoutDiagnosticFromJournal(output: string): string | undefined {
  // Match the native ResolverLayoutFailure enum, never observed resolver or process details.
  const reasons = new Set([
    "link_unavailable", "link_not_symlink", "target_unavailable", "target_not_reviewed",
    "target_changed", "target_not_regular_file", "target_owner_not_reviewed",
    "target_permissions_unsafe", "target_writable_by_runner", "directory_unavailable",
    "directory_not_canonical", "directory_owner_not_reviewed", "directory_permissions_unsafe",
    "directory_writable_by_runner", "service_query_failed", "service_pid_unavailable",
    "service_process_unavailable", "service_owner_not_reviewed", "service_executable_unavailable",
    "service_executable_not_reviewed",
  ]);
  for (const line of output.split(/\r?\n/).reverse()) {
    if (line.length === 0 || line.length > 4096) continue;
    try {
      const reason = JSON.parse(line)?.fence_resolver_layout?.reason;
      if (reasons.has(reason)) return reason.replaceAll("_", " ");
    } catch {
      // Ignore unrelated journal messages and malformed diagnostics.
    }
  }
  return undefined;
}

function captureServiceStatus(unit: string): ReturnType<typeof capture> {
  return capture("/usr/bin/systemctl", [
    "show",
    unit,
    "--no-pager",
    ...[...SERVICE_STATUS_PROPERTIES.keys()].map((name) => `--property=${name}`),
  ]);
}

function emitServiceDiagnostics(paths: { unit: string } | undefined): void {
  if (!paths || !serviceLaunchAttempted) {
    return;
  }
  const status = captureServiceStatus(paths.unit);
  const journal = capture("/usr/bin/journalctl", [
    "--no-pager",
    "--unit",
    paths.unit,
    "--lines",
    "20",
    "--output",
    "cat",
  ]);
  emitCapturedServiceDiagnostics(paths.unit, status, journal);
}

function emitCapturedServiceDiagnostics(
  unit: string,
  status: ReturnType<typeof capture>,
  journal: ReturnType<typeof capture>,
): void {
  const serviceStatus = !status.error && status.status === 0
    ? formatServiceProperties(parseServiceProperties(status.stdout))
    : "";
  if (serviceStatus) log.warning(`Fence service state for ${unit}: ${serviceStatus}`);
  log.debugGroup("Fence debug: service diagnostics", [
    `service_status_exit=${status.status ?? "unavailable"}`,
    `journal_exit=${journal.status ?? "unavailable"}`,
  ]);
  if (journal.error || journal.status !== 0) return;
  const errorCode = fenceErrorCodeFromJournal(journal.stdout);
  if (errorCode !== undefined) {
    log.warning(`Fence resident error code: ${errorCode}`);
  }
  const localControlDiagnostic = localControlDiagnosticFromJournal(journal.stdout);
  if (localControlDiagnostic !== undefined) {
    log.warning(`Fence local control inspection: ${localControlDiagnostic}`);
  }
  const lockdownDiagnostic = lockdownCommandDiagnosticFromJournal(journal.stdout);
  if (lockdownDiagnostic !== undefined) {
    log.warning(`Fence host command: ${lockdownDiagnostic}`);
  }
  if (errorCode === "dns_proxy_bind_failed") {
    const dnsDiagnostic = dnsStartupDiagnosticFromJournal(journal.stdout);
    if (dnsDiagnostic !== undefined) {
      log.warning(`Fence DNS startup: ${dnsDiagnostic}`);
    }
  }
  if (errorCode === "unsupported_resolver_layout") {
    const resolverDiagnostic = resolverLayoutDiagnosticFromJournal(journal.stdout);
    if (resolverDiagnostic !== undefined) {
      log.warning(`Fence host resolver: ${resolverDiagnostic}`);
    }
  }
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

// Only a successful exclusive mkdir grants this launcher permission to remove the leaf.
function createInvocationDirectory(directory: string): void {
  run("/usr/bin/sudo", ["/usr/bin/mkdir", "--mode=0755", "--", directory]);
}

function bindLauncherMount(source: string, target: string): void {
  // A failed mount command may have taken effect. Never release the host claim on that ambiguity.
  launcherMountUncertain = true;
  run("/usr/bin/sudo", ["/usr/bin/mount", "--bind", source, target]);
  launcherMountUncertain = false;
}

function installProtectedActionRuntime(
  invocationId: string,
  paths: ReturnType<typeof runtimePaths>,
  sourceFiles: ReturnType<typeof actionRuntimeFileDigests>,
  sourceManifest: any,
): void {
  createOrValidateRootDirectory(path.dirname(paths.launcherHostClaim));
  if (pathEntryExists(paths.launcherHostClaim)) {
    throw new Error("Fence already owns this runner; run Fence only once per job");
  }
  // Action, guard, and resolver mounts are host-wide, not isolated by invocation ID.
  createInvocationDirectory(paths.launcherHostClaim);
  launcherHostClaimCreated = true;
  if (pathEntryExists(paths.directory) || pathEntryExists(paths.launcherDirectory)) {
    throw new Error("Fence invocation directory already exists");
  }
  createInvocationDirectory(paths.launcherDirectory);
  launcherDirectoryCreated = true;
  assertRootDirectory(paths.launcherDirectory);
  run("/usr/bin/sudo", [
    "/usr/bin/install",
    "-d",
    "-o",
    "root",
    "-g",
    "root",
    "-m",
    "0755",
    path.join(paths.launcherActionDirectory, "bin"),
  ]);
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
  const protectedManifest = validateBundle(
    path.join(paths.launcherActionDirectory, "bundle-manifest.json"),
    path.join(paths.launcherActionDirectory, "bin", "fence"),
  );
  if (JSON.stringify(protectedManifest) !== JSON.stringify(sourceManifest)) {
    throw new Error("Fence protected Action manifest does not match the validated source runtime");
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
    bindLauncherMount(guard.path, guard.path);
    protectedActionPathGuards.push(guard.path);
    const evidence = activeActionMountEvidence(guard.path);
    validateActionPathGuardMount(evidence.raw, guard.path, evidence.mountId);
  }

  bindLauncherMount(paths.launcherActionDirectory, ACTION_ROOT);
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

function residentServiceArgs(paths: ReturnType<typeof runtimePaths>): string[] {
  return [
    "/usr/bin/systemd-run",
    "--quiet",
    "--property=Type=exec",
    "--unit",
    paths.unit,
    path.join(paths.launcherActionDirectory, "bin", "fence"),
    "run",
    "--config",
    paths.config,
  ];
}

function provisionalCleanupPreservationReason(
  status: ReturnType<typeof capture>,
  inspect: (name: "ready.json" | "dns-routing-owned") => { uid: number; mode: number; isFile(): boolean } | undefined,
): string | undefined {
  // A timed-out systemd-run may still have launched the resident. Establish that
  // it stopped *before* looking for its marker, so readiness cannot race cleanup.
  if (status.error || status.status !== 0 || !terminalServiceStatus(status.stdout)) {
    return "the resident may still be running";
  }
  try {
    const marker = inspect("ready.json");
    if (marker !== undefined) {
      return marker.isFile() && marker.uid === 0 && (marker.mode & 0o7777) === 0o644
        ? "the resident created its root-owned readiness marker"
        : "readiness could not be safely determined";
    }
    // Root removes this marker only after host, Docker DNS, and any prior control rollback succeed.
    return inspect("dns-routing-owned") === undefined ? undefined : "provisional DNS or host-control rollback may be incomplete";
  } catch {
    // Only definite absence in the root-owned invocation directory permits removal.
    return "readiness and provisional DNS rollback could not be safely determined";
  }
}

function cleanupLauncherBeforeReadiness(): void {
  const paths = launcherPaths;
  if (!paths || !launcherHostClaimCreated || readinessObserved) {
    return;
  }
  if (launcherMountUncertain) {
    log.warning("Fence kept its host claim because a mount outcome is uncertain; runner teardown will remove it");
    return;
  }
  try {
    if (serviceLaunchAttempted) {
      const reason = provisionalCleanupPreservationReason(
        captureServiceStatus(paths.unit),
        (name) => fs.lstatSync(path.join(paths.directory, name), { throwIfNoEntry: false }),
      );
      if (reason) {
        log.warning(`Fence kept its runtime state because ${reason}; runner teardown will remove it`);
        return;
      }
    }
    if (protectedActionMounted) {
      run("/usr/bin/sudo", ["/usr/bin/umount", ACTION_ROOT]);
      protectedActionMounted = false;
    }
    for (const guard of [...protectedActionPathGuards].reverse()) {
      run("/usr/bin/sudo", ["/usr/bin/umount", guard]);
    }
    protectedActionPathGuards = [];
    if (runtimeDirectoryCreated) {
      run("/usr/bin/sudo", [
        "/usr/bin/rm",
        "--recursive",
        "--force",
        "--one-file-system",
        paths.directory,
      ]);
      runtimeDirectoryCreated = false;
    }
    if (launcherDirectoryCreated) {
      run("/usr/bin/sudo", [
        "/usr/bin/rm",
        "--recursive",
        "--force",
        "--one-file-system",
        paths.launcherDirectory,
      ]);
      launcherDirectoryCreated = false;
    }
    // Last operation: no other launch can acquire the host while this cleanup is running.
    run("/usr/bin/sudo", ["/usr/bin/rmdir", "--", paths.launcherHostClaim]);
    launcherHostClaimCreated = false;
  } catch {
    log.warning("Fence could not remove its provisional launcher state; runner teardown will remove it");
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
      const ready = readReady(paths.ready);
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
  const sourceRuntime = validatedActionRuntimeSnapshot(ACTION_ROOT);
  const manifest = sourceRuntime.manifest;
  const config = validateInlineConfig(process.env.INPUT_CONFIG, process.env, nativeInputsFromEnvironment(process.env));
  const paths = runtimePaths(config.invocationId);
  diagnosticPaths = paths;
  launcherPaths = paths;
  const details = log.configLogDetails(config.raw, config.usingDefault);

  for (const line of log.setupLines(manifest, details)) {
    log.info(line);
  }
  if (details.allowGithubArtifacts) {
    log.warning("Fence GitHub artifact compatibility is enabled; artifact uploads are an intentional data-egress channel");
  }
  log.debugGroup("Fence debug: setup inputs", [
    `mode=${details.mode}`,
    `invocation_id=${config.invocationId}`,
    `config_source=${details.source}`,
    `container_policy=${details.containerPolicy}`,
    `platform_profile=${details.platformProfile}`,
    `disable_broad_github_domains=${details.disableBroadGithubDomains}`,
    `allow_github_artifacts=${details.allowGithubArtifacts}`,
    `allowlist_count=${details.allowlistCount}`,
    ...details.allowlistDestinations.map((entry: string) => `allowlist=${entry}`),
    `bundle_release=${manifest.release_tag}`,
    `bundle_source_commit=${manifest.source_commit}`,
    `platform=${process.platform}`,
    `arch=${process.arch}`,
    `runtime_directory=${paths.directory}`,
    `unit=${paths.unit}`,
  ]);

  installProtectedActionRuntime(
    config.invocationId,
    paths,
    sourceRuntime.files,
    manifest,
  );
  createOrValidateRootDirectory("/run/fence");
  createInvocationDirectory(paths.directory);
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
  const protectedBinary = path.join(paths.launcherActionDirectory, "bin", "fence");
  const serviceArgs = residentServiceArgs(paths);
  log.debugGroup("Fence debug: service launch", [
    `executable=/usr/bin/sudo`,
    `protected_binary=${protectedBinary}`,
    `args=${serviceArgs.join(" ")}`,
    `child_timeout_ms=${CHILD_TIMEOUT_MS}`,
  ]);
  serviceLaunchAttempted = true;
  run("/usr/bin/sudo", serviceArgs);
  const report = waitForReady(paths);
  readinessObserved = true;
  log.ready(report);
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

module.exports = { dnsStartupDiagnosticFromJournal, emitCapturedServiceDiagnostics, fenceErrorCodeFromJournal, localControlDiagnosticFromJournal, lockdownCommandDiagnosticFromJournal, main, provisionalCleanupPreservationReason, residentServiceArgs, resolverLayoutDiagnosticFromJournal, run, terminalServiceStatus };
