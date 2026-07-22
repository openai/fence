"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");

type Environment = Record<string, string | undefined>;
type RuntimePaths = {
  directory: string;
  config: string;
  ready: string;
  report: string;
  dnsReport: string;
  unit: string;
  launcherDirectory: string;
  launcherActionDirectory: string;
  launcherIntegrity: string;
};
type ActionRuntimeFileDigest = {
  path: string;
  sha256: string;
};
type ActionPathGuard = {
  path: string;
  device: string;
  inode: string;
};
type InlineConfig = {
  invocationId: string;
  raw: string;
  usingDefault: boolean;
};
type NativeConfigInputs = {
  mode?: unknown;
  invocationId?: unknown;
  containerPolicy?: unknown;
  platformProfile?: unknown;
  disableBroadGithubDomains?: unknown;
  allowlist?: unknown;
};
type DefaultMode = "block" | "audit";
type AllowlistEntry = {
  destination_type: "hostname" | "ip" | "cidr";
  destination: string;
  protocol: "tcp" | "udp";
  port: number;
};
type AuditFindingRow = {
  destination: string;
  destinationKind: "hostname" | "ip";
  protocol: string;
  port: number;
  count: number;
};
type AuditSummary = {
  dnsMissing: boolean;
  hostnameRows: AuditFindingRow[];
  ipRows: AuditFindingRow[];
  omittedHostnameRows: number;
  omittedIpRows: number;
  unparsedCount: number;
  sourceTruncated: boolean;
};
type NetworkDecision = "allowed" | "blocked" | "would_block";
type NetworkActivityRow = {
  destination: string;
  decision: NetworkDecision;
  activities: Map<string, number>;
  actors: Map<string, number>;
  totalCount: number;
};
type NetworkActivitySummary = {
  rows: NetworkActivityRow[];
  omittedRows: number;
};

const MAX_CONFIG_BYTES = 256 * 1024;
const MAX_REPORT_BYTES = 4 * 1024 * 1024;
const MAX_AUDIT_HOSTNAME_ROWS = 10;
const MAX_AUDIT_IP_ROWS = 10;
const MAX_NETWORK_ACTIVITY_ROWS = 20;
const ALLOWED_DNS_CLASSIFICATIONS = new Set([
  "dynamic_platform",
  "platform_and_user_allowlist",
  "platform_cname_derived",
  "platform_profile",
  "runner_authorized_results_storage",
  "runner_authorized_results_storage_cname_derived",
  "user_allowlist",
  "user_cname_derived",
  "user_wildcard_allowlist",
]);
const DNS_CLASSIFICATIONS = new Set([...ALLOWED_DNS_CLASSIFICATIONS, "outside_policy"]);
const OUTSIDE_POLICY_DNS_CLASSIFICATIONS = new Set(["outside_policy"]);
const FORWARDED_DNS_QUERY_TYPES = new Set(["a", "aaaa"]);
const INVOCATION_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const DNS_HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const RESULTS_STORAGE_HOSTNAME = /^productionresultssa[0-9]{1,5}\.blob\.core\.windows\.net$/;
const MAX_ALLOWLIST_ENTRIES = 64;
const MAX_RESULTS_STORAGE_AUTHORIZATIONS = 4;
const MAX_USER_WILDCARD_AUTHORIZATIONS = 8;
const MAX_USER_WILDCARD_PREFIX_LABELS = 2;
const REVIEWED_PLATFORM_PROFILE = "github_hosted_workflow_bootstrap_v5";
const PROFILE_REALIZATIONS = new Map([
  [REVIEWED_PLATFORM_PROFILE, "github_hosted_workflow_bootstrap_dns_provenance_v5"],
]);
const POLICY_HASH_SCHEMA_VERSION = 9;
const RUNTIME_EVIDENCE_SCHEMA_VERSION = 5;
const RESIDENT_EVIDENCE_MAX_AGE_MILLISECONDS = 20 * 1000;
const RESIDENT_EVIDENCE_MAX_FUTURE_SKEW_MILLISECONDS = 5 * 1000;
const RESIDENT_VERIFICATION_INTERVAL_SECONDS = 5;
const REQUIRED_RESIDENT_WORKERS = [
  "docker_tcp_dns",
  "docker_udp_dns",
  "host_tcp_dns",
  "host_udp_dns",
  "process_attribution",
];
const RELEASE_TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)))*)?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const RUNTIME_ROOT = "/run/fence";
const LAUNCHER_RUNTIME_ROOT = "/run/fence-launcher";
const ACTION_RUNTIME_FILES = [
  "bin/fence",
  "bundle-manifest.json",
  "lib.cts",
  "log.cts",
  "main.cts",
  "post.cts",
] as const;
const MAX_ACTION_RUNTIME_FILE_BYTES = 64 * 1024 * 1024;
const MAX_ACTION_PATH_GUARDS = 16;
const MAX_ACTION_PATH_ANCESTORS = 64;
const MAX_ACTION_MOUNTINFO_BYTES = 4 * 1024 * 1024;
const MAX_ACTION_MOUNTINFO_RECORD_BYTES = 16 * 1024;
const REPORT_STATUSES = new Set([
  "protected_host_block",
  "protected_host_block_degraded",
  "protected_host_audit_observation",
]);
const READY_STATUSES = new Set(["ready", "ready_degraded", "ready_observation_only"]);

function fail(message: string): never {
  throw new Error(message);
}

function selectsReviewedProfile(profileId: unknown, realizationId: unknown): boolean {
  return typeof profileId === "string" &&
    typeof realizationId === "string" &&
    PROFILE_REALIZATIONS.get(profileId) === realizationId;
}

function normalizeDefaultMode(mode: unknown): DefaultMode {
  if (typeof mode !== "string" || mode.length === 0) {
    return "block";
  }
  if (mode === "block" || mode === "audit") {
    return mode;
  }
  fail("mode input must be either block or audit");
}

function normalizeOptionalInput(value: unknown, name: string, maximumBytes = 1024): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string") {
    fail(`${name} input must be a string`);
  }
  if (Buffer.byteLength(value, "utf8") > maximumBytes) {
    fail(`${name} input is too large`);
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

function normalizeBooleanInput(value: unknown, name: string): boolean {
  const normalized = normalizeOptionalInput(value, name);
  if (normalized === undefined || normalized === "false") {
    return false;
  }
  if (normalized === "true") {
    return true;
  }
  fail(`${name} input must be either true or false`);
}

function normalizeContainerPolicy(value: unknown, mode: DefaultMode): string | undefined {
  const normalized = normalizeOptionalInput(value, "container_policy");
  if (normalized === undefined) {
    return undefined;
  }
  if (mode === "audit") {
    fail("container_policy input cannot be used with audit mode");
  }
  if (normalized === "disable" || normalized === "unsafe_preserve") {
    return normalized;
  }
  fail("container_policy input must be either disable or unsafe_preserve");
}

function normalizePlatformProfile(value: unknown): string | undefined {
  const normalized = normalizeOptionalInput(value, "platform_profile");
  if (normalized === undefined) {
    return undefined;
  }
  if (normalized === REVIEWED_PLATFORM_PROFILE) {
    return normalized;
  }
  fail(`platform_profile input must be ${REVIEWED_PLATFORM_PROFILE}`);
}

function normalizeInvocationId(value: unknown, environment: Environment): string {
  const explicit = normalizeOptionalInput(value, "invocation_id");
  if (explicit !== undefined) {
    if (explicit.length > 64 || !INVOCATION_ID.test(explicit)) {
      fail("invocation_id input must use the Fence lowercase slug grammar");
    }
    return explicit;
  }
  const runId = environment.GITHUB_RUN_ID;
  const runAttempt = environment.GITHUB_RUN_ATTEMPT;
  if (!/^[0-9]+$/.test(runId || "") || !/^[0-9]+$/.test(runAttempt || "")) {
    fail("GITHUB_RUN_ID and GITHUB_RUN_ATTEMPT are required for the default config");
  }
  return `fence-${runId}-${runAttempt}`;
}

function normalizeProtocol(value: string): "tcp" | "udp" {
  if (value === "tcp" || value === "udp") {
    return value;
  }
  fail("allowlist protocol must be tcp or udp");
}

function normalizePort(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    fail("allowlist port must be an integer");
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    fail("allowlist port must be between 1 and 65535");
  }
  return port;
}

function isAscii(value: string): boolean {
  return /^[\x00-\x7f]*$/.test(value);
}

function isNumericIpv4Component(component: string): boolean {
  if (component.startsWith("0x")) {
    return component.length > 2 && /^[0-9a-f]+$/.test(component.slice(2));
  }
  return /^[0-9]+$/.test(component);
}

function resemblesNumericIpv4Address(value: string): boolean {
  const components = value.split(".");
  return components.length >= 1 &&
    components.length <= 4 &&
    components.every(isNumericIpv4Component);
}

function normalizeExactHostname(value: string): string | undefined {
  if (
    value.length < 1 ||
    value.length > 253 ||
    !isAscii(value) ||
    value.endsWith(".")
  ) {
    return undefined;
  }
  const normalized = value.toLowerCase();
  if (
    net.isIP(normalized) !== 0 ||
    resemblesNumericIpv4Address(normalized) ||
    !DNS_HOSTNAME.test(normalized)
  ) {
    return undefined;
  }
  return normalized;
}

function normalizeHostnameDestination(value: string): string | undefined {
  if (!value.includes("*")) {
    return normalizeExactHostname(value);
  }
  if (
    value.length < 1 ||
    value.length > 253 ||
    !isAscii(value) ||
    value.endsWith(".")
  ) {
    return undefined;
  }
  const labels = value.toLowerCase().split(".");
  let prefixLabels = 0;
  while (labels[prefixLabels] === "*") {
    prefixLabels += 1;
  }
  const suffixLabels = labels.slice(prefixLabels);
  if (
    prefixLabels < 1 ||
    prefixLabels > MAX_USER_WILDCARD_PREFIX_LABELS ||
    suffixLabels.length < 2 ||
    suffixLabels.some((label) => label.includes("*"))
  ) {
    return undefined;
  }
  const suffix = normalizeExactHostname(suffixLabels.join("."));
  return suffix === undefined ? undefined : `${"*.".repeat(prefixLabels)}${suffix}`;
}

function validateHostname(value: string): string {
  const destination = normalizeHostnameDestination(value);
  if (destination === undefined) {
    fail("allowlist hostname entries must be valid exact names or bounded wildcard patterns");
  }
  return destination;
}

function validateIp(value: string): string {
  if (net.isIP(value) === 0) {
    fail("allowlist ip entries must be valid literal IP addresses");
  }
  return value;
}

function validateCidr(value: string): string {
  const separator = value.lastIndexOf("/");
  if (separator <= 0 || separator === value.length - 1) {
    fail("allowlist cidr entries must include an address and prefix length");
  }
  const address = value.slice(0, separator);
  const prefix = value.slice(separator + 1);
  const family = net.isIP(address);
  if (family === 0 || !/^[0-9]+$/.test(prefix)) {
    fail("allowlist cidr entries must include a literal IP network and prefix length");
  }
  const prefixLength = Number(prefix);
  const maximum = family === 4 ? 32 : 128;
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > maximum) {
    fail(`allowlist cidr prefix length must be between 0 and ${maximum}`);
  }
  if (address.includes("%")) {
    fail("allowlist cidr entries must identify a canonical IP network");
  }

  const canonicalAddress = new net.SocketAddress({
    address,
    family: family === 4 ? "ipv4" : "ipv6",
  }).address;
  let addressParts: string[];
  if (family === 4) {
    addressParts = canonicalAddress.split(".");
  } else {
    let expandedAddress = canonicalAddress;
    const finalSeparator = expandedAddress.lastIndexOf(":");
    const finalComponent = expandedAddress.slice(finalSeparator + 1);
    if (finalComponent.includes(".")) {
      const octets = finalComponent.split(".").map(Number);
      const firstGroup = ((octets[0] << 8) | octets[1]).toString(16);
      const secondGroup = ((octets[2] << 8) | octets[3]).toString(16);
      expandedAddress = `${expandedAddress.slice(0, finalSeparator)}:${firstGroup}:${secondGroup}`;
    }
    const [head, tail = ""] = expandedAddress.split("::");
    const headGroups = head === "" ? [] : head.split(":");
    const tailGroups = tail === "" ? [] : tail.split(":");
    addressParts = [
      ...headGroups,
      ...Array(8 - headGroups.length - tailGroups.length).fill("0"),
      ...tailGroups,
    ];
  }
  const bitsPerPart = family === 4 ? 8n : 16n;
  const addressValue = addressParts.reduce(
    (result, part) => (result << bitsPerPart) + BigInt(family === 4 ? part : `0x${part}`),
    0n,
  );
  const hostBits = BigInt(maximum - prefixLength);
  if (((addressValue >> hostBits) << hostBits) !== addressValue) {
    fail("allowlist cidr entries must identify a canonical IP network without host bits");
  }
  return `${canonicalAddress}/${prefixLength}`;
}

function classifyDestination(value: string): "hostname" | "ip" | "cidr" {
  if (value.includes("/")) {
    return "cidr";
  }
  if (net.isIP(value) !== 0) {
    return "ip";
  }
  return "hostname";
}

function validateDestination(destinationType: "hostname" | "ip" | "cidr", destination: string): string {
  switch (destinationType) {
    case "hostname":
      return validateHostname(destination);
    case "ip":
      return validateIp(destination);
    case "cidr":
      return validateCidr(destination);
  }
}

function parseExplicitAllowlistLine(tokens: string[]): AllowlistEntry {
  if (tokens.length !== 4) {
    fail("allowlist explicit entries must use: hostname|ip|cidr destination tcp|udp port");
  }
  const destinationType = tokens[0];
  if (destinationType !== "hostname" && destinationType !== "ip" && destinationType !== "cidr") {
    fail("allowlist destination type must be hostname, ip, or cidr");
  }
  return {
    destination_type: destinationType,
    destination: validateDestination(destinationType, tokens[1]),
    protocol: normalizeProtocol(tokens[2]),
    port: normalizePort(tokens[3]),
  };
}

function parseUrlAllowlistLine(line: string): AllowlistEntry {
  if (!isAscii(line) || line.includes("%") || line.includes("@") || line.includes("?") || line.includes("#")) {
    fail("allowlist URL entries may contain only protocol, hostname, and port");
  }
  let parsed: URL;
  try {
    parsed = new URL(line);
  } catch {
    fail("allowlist URL entries must use tcp://hostname:port or udp://hostname:port");
  }
  const protocol = parsed.protocol.replace(/:$/, "");
  if (
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "" ||
    parsed.search ||
    parsed.hash ||
    parsed.port.length === 0
  ) {
    fail("allowlist URL entries may contain only protocol, hostname, and port");
  }
  return {
    destination_type: "hostname",
    destination: validateHostname(parsed.hostname),
    protocol: normalizeProtocol(protocol),
    port: normalizePort(parsed.port),
  };
}

function parseShortcutAllowlistLine(line: string): AllowlistEntry {
  if (line.includes("/")) {
    fail("allowlist cidr entries must use the explicit cidr destination protocol port form");
  }
  if (net.isIP(line) !== 0) {
    fail("allowlist ip entries must use the explicit ip destination protocol port form");
  }
  const colonIndex = line.lastIndexOf(":");
  const hasPort = colonIndex > 0 && line.indexOf(":") === colonIndex;
  const destination = hasPort ? line.slice(0, colonIndex) : line;
  const port = hasPort ? normalizePort(line.slice(colonIndex + 1)) : 443;
  return {
    destination_type: "hostname",
    destination: validateHostname(destination),
    protocol: "tcp",
    port,
  };
}

function parseAllowlistLine(line: string): AllowlistEntry {
  if (line.includes("://")) {
    return parseUrlAllowlistLine(line);
  }
  const tokens = line.split(/\s+/).filter(Boolean);
  if (tokens.length === 4) {
    return parseExplicitAllowlistLine(tokens);
  }
  if (tokens.length !== 1) {
    fail("allowlist entries must use a supported shorthand or explicit line form");
  }
  return parseShortcutAllowlistLine(tokens[0]);
}

function parseAllowlistInput(value: unknown): AllowlistEntry[] {
  const raw = normalizeOptionalInput(value, "allowlist", 64 * 1024);
  if (raw === undefined) {
    return [];
  }
  const entries: AllowlistEntry[] = [];
  const seen = new Set<string>();
  for (const [index, originalLine] of raw.split(/\r?\n/).entries()) {
    const line = originalLine.trim();
    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }
    try {
      const entry = parseAllowlistLine(line);
      const key = `${entry.destination_type}\0${entry.destination}\0${entry.protocol}\0${entry.port}`;
      if (!seen.has(key)) {
        seen.add(key);
        entries.push(entry);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      fail(`allowlist line ${index + 1}: ${message}`);
    }
  }
  if (entries.length > MAX_ALLOWLIST_ENTRIES) {
    fail(`allowlist input must contain no more than ${MAX_ALLOWLIST_ENTRIES} unique entries`);
  }
  return entries;
}

function normalizeNativeInputs(input: unknown): NativeConfigInputs {
  if (typeof input === "string" || input === undefined || input === null) {
    return { mode: input };
  }
  if (typeof input !== "object" || Array.isArray(input)) {
    fail("native Action inputs must be an object");
  }
  return input as NativeConfigInputs;
}

function nativeInputsFromEnvironment(environment: Environment): NativeConfigInputs {
  return {
    mode: environment.INPUT_MODE,
    invocationId: environment.INPUT_INVOCATION_ID,
    containerPolicy: environment.INPUT_CONTAINER_POLICY,
    platformProfile: environment.INPUT_PLATFORM_PROFILE,
    disableBroadGithubDomains: environment.INPUT_DISABLE_BROAD_GITHUB_DOMAINS,
    allowlist: environment.INPUT_ALLOWLIST,
  };
}

function defaultInlineConfig(environment: Environment, nativeInput: unknown = undefined): string {
  const inputs = normalizeNativeInputs(nativeInput);
  const mode = normalizeDefaultMode(normalizeOptionalInput(inputs.mode, "mode"));
  const document: Record<string, unknown> = {
    schema_version: 1,
    mode,
    invocation_id: normalizeInvocationId(inputs.invocationId, environment),
    allowlist: parseAllowlistInput(inputs.allowlist),
  };

  const containerPolicy = normalizeContainerPolicy(inputs.containerPolicy, mode);
  if (containerPolicy !== undefined) {
    document.container_policy = containerPolicy;
  }
  const platformProfile = normalizePlatformProfile(inputs.platformProfile);
  if (platformProfile !== undefined) {
    document.platform_profile = platformProfile;
  }
  if (normalizeBooleanInput(inputs.disableBroadGithubDomains, "disable_broad_github_domains")) {
    document.disable_broad_github_domains = true;
  }

  return JSON.stringify(document);
}

function readJsonBounded(file: string, maximumBytes: number, description: string): any {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${description} is not a regular file`);
  }
  if (stat.size > maximumBytes) {
    fail(`${description} exceeds its size limit`);
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function validateInlineConfig(raw: unknown, environment: Environment = process.env, nativeInput: unknown = undefined): InlineConfig {
  const inputs = normalizeNativeInputs(nativeInput);
  const usingDefault = typeof raw !== "string" || raw.length === 0;
  if (!usingDefault) {
    for (const [name, value] of [
      ["mode", inputs.mode],
      ["invocation_id", inputs.invocationId],
      ["container_policy", inputs.containerPolicy],
      ["platform_profile", inputs.platformProfile],
      ["disable_broad_github_domains", inputs.disableBroadGithubDomains],
      ["allowlist", inputs.allowlist],
    ] as [string, unknown][]) {
      if (normalizeOptionalInput(value, name) !== undefined) {
        fail(`${name} input cannot be combined with config input`);
      }
    }
  }
  const normalizedRaw = usingDefault ? defaultInlineConfig(environment, inputs) : raw;
  if (Buffer.byteLength(normalizedRaw, "utf8") > MAX_CONFIG_BYTES) {
    fail("config input exceeds 256 KiB");
  }
  const parsed = JSON.parse(normalizedRaw);
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
  return { invocationId, raw: normalizedRaw, usingDefault };
}

function runtimePaths(invocationId: unknown): RuntimePaths {
  if (
    typeof invocationId !== "string" ||
    invocationId.length < 1 ||
    invocationId.length > 64 ||
    !INVOCATION_ID.test(invocationId)
  ) {
    fail("runtime invocation_id must use the Fence lowercase slug grammar");
  }
  const directory = path.join(RUNTIME_ROOT, invocationId);
  const launcherDirectory = path.join(LAUNCHER_RUNTIME_ROOT, invocationId);
  return {
    directory,
    config: path.join(directory, "config.json"),
    ready: path.join(directory, "ready.json"),
    report: path.join(directory, "report.json"),
    dnsReport: path.join(directory, "dns-report.json"),
    unit: `fence-${invocationId}.service`,
    launcherDirectory,
    launcherActionDirectory: path.join(launcherDirectory, "action"),
    launcherIntegrity: path.join(launcherDirectory, "integrity.json"),
  };
}

function actionRuntimeFileDigests(actionRoot: string): ActionRuntimeFileDigest[] {
  const rootStat = fs.lstatSync(actionRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    fail("Fence Action runtime root is not a regular directory");
  }
  const binaryDirectoryStat = fs.lstatSync(path.join(actionRoot, "bin"));
  if (!binaryDirectoryStat.isDirectory() || binaryDirectoryStat.isSymbolicLink()) {
    fail("Fence Action binary directory is not a regular directory");
  }
  return ACTION_RUNTIME_FILES.map((relativePath) => {
    const file = path.join(actionRoot, relativePath);
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_ACTION_RUNTIME_FILE_BYTES) {
      fail(`Fence Action runtime file is unsafe: ${relativePath}`);
    }
    return {
      path: relativePath,
      sha256: crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
    };
  });
}

function actionRuntimeDigest(files: ActionRuntimeFileDigest[]): string {
  if (
    !Array.isArray(files) ||
    files.length !== ACTION_RUNTIME_FILES.length ||
    files.some((file, index) =>
      file === null ||
      typeof file !== "object" ||
      file.path !== ACTION_RUNTIME_FILES[index] ||
      !SHA256.test(file.sha256)
    )
  ) {
    fail("Fence Action runtime file digest set is invalid");
  }
  return crypto.createHash("sha256").update(JSON.stringify(files)).digest("hex");
}

function runnerCanRenamePath(candidate: string, parent: string): boolean {
  try {
    fs.accessSync(parent, fs.constants.W_OK | fs.constants.X_OK);
  } catch {
    return false;
  }
  const parentStat = fs.lstatSync(parent);
  const candidateStat = fs.lstatSync(candidate);
  const effectiveUser = typeof process.geteuid === "function"
    ? process.geteuid()
    : process.getuid();
  const sticky = (parentStat.mode & 0o1000) !== 0;
  return !sticky ||
    effectiveUser === 0 ||
    effectiveUser === parentStat.uid ||
    effectiveUser === candidateStat.uid;
}

function registeredActionPathGuardPaths(
  actionRoot: string,
  canRename: (candidate: string, parent: string) => boolean = runnerCanRenamePath,
): string[] {
  if (!path.isAbsolute(actionRoot) || path.normalize(actionRoot) !== actionRoot) {
    fail("Fence registered Action path must be normalized and absolute");
  }
  const deepestFirst: string[] = [];
  let candidate = path.dirname(actionRoot);
  let inspected = 0;
  while (candidate !== path.dirname(candidate)) {
    const parent = path.dirname(candidate);
    inspected += 1;
    if (inspected > MAX_ACTION_PATH_ANCESTORS) {
      fail("Fence registered Action path has too many ancestors");
    }
    if (canRename(candidate, parent)) {
      deepestFirst.push(candidate);
      if (deepestFirst.length > MAX_ACTION_PATH_GUARDS) {
        fail("Fence registered Action path has too many writable ancestors");
      }
    }
    candidate = parent;
  }
  return deepestFirst.reverse();
}

function validateActionPathGuardSet(guards: ActionPathGuard[], actionRoot: string): void {
  if (!Array.isArray(guards) || guards.length > MAX_ACTION_PATH_GUARDS) {
    fail("Fence registered Action path guard set is invalid");
  }
  let previous: string | undefined;
  for (const guard of guards) {
    if (
      guard === null ||
      typeof guard !== "object" ||
      Object.keys(guard).sort().join(",") !== "device,inode,path" ||
      !path.isAbsolute(guard.path) ||
      path.normalize(guard.path) !== guard.path ||
      !actionRoot.startsWith(`${guard.path}${path.sep}`) ||
      !/^[0-9]+$/.test(guard.device) ||
      !/^[0-9]+$/.test(guard.inode) ||
      (previous !== undefined && !guard.path.startsWith(`${previous}${path.sep}`))
    ) {
      fail("Fence registered Action path guard set is invalid");
    }
    previous = guard.path;
  }
}

function actionPathGuardIdentities(
  actionRoot: string,
  canRename: (candidate: string, parent: string) => boolean = runnerCanRenamePath,
): ActionPathGuard[] {
  const guards = registeredActionPathGuardPaths(actionRoot, canRename).map((guardPath) => {
    const stat = fs.lstatSync(guardPath, { bigint: true });
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      fs.realpathSync(guardPath) !== guardPath
    ) {
      fail("Fence registered Action path contains an unsafe ancestor");
    }
    return {
      path: guardPath,
      device: stat.dev.toString(),
      inode: stat.ino.toString(),
    };
  });
  validateActionPathGuardSet(guards, actionRoot);
  return guards;
}

function launcherIntegrityDocument(
  invocationId: string,
  actionRuntimePath: string,
  protectedCopyPath: string,
  files: ActionRuntimeFileDigest[],
  pathGuards: ActionPathGuard[],
): Record<string, unknown> {
  runtimePaths(invocationId);
  if (!path.isAbsolute(actionRuntimePath) || !path.isAbsolute(protectedCopyPath)) {
    fail("Fence Action integrity paths must be absolute");
  }
  validateActionPathGuardSet(pathGuards, actionRuntimePath);
  return {
    schema_version: 2,
    invocation_id: invocationId,
    action_runtime_path: actionRuntimePath,
    path_guards: pathGuards,
    protected_copy_path: protectedCopyPath,
    runtime_digest: actionRuntimeDigest(files),
    files,
  };
}

function validateLauncherIntegrity(
  integrity: any,
  invocationId: string,
  actionRuntimePath: string,
  protectedCopyPath: string,
  files: ActionRuntimeFileDigest[],
  pathGuards: ActionPathGuard[],
): void {
  if (integrity === null || Array.isArray(integrity) || typeof integrity !== "object") {
    fail("Fence Action launcher integrity evidence is invalid");
  }
  const expectedKeys = [
    "action_runtime_path",
    "files",
    "invocation_id",
    "path_guards",
    "protected_copy_path",
    "runtime_digest",
    "schema_version",
  ];
  if (
    JSON.stringify(Object.keys(integrity).sort()) !== JSON.stringify(expectedKeys) ||
    integrity.schema_version !== 2 ||
    integrity.invocation_id !== invocationId ||
    integrity.action_runtime_path !== actionRuntimePath ||
    integrity.protected_copy_path !== protectedCopyPath ||
    JSON.stringify(integrity.path_guards) !== JSON.stringify(pathGuards) ||
    integrity.runtime_digest !== actionRuntimeDigest(files) ||
    JSON.stringify(integrity.files) !== JSON.stringify(files)
  ) {
    fail("Fence Action launcher integrity evidence does not match the protected runtime");
  }
  validateActionPathGuardSet(pathGuards, actionRuntimePath);
}

function readLauncherIntegrity(file: string): any {
  const stat = fs.lstatSync(file);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.uid !== 0 ||
    (stat.mode & 0o777) !== 0o444 ||
    stat.size > 64 * 1024
  ) {
    fail("Fence Action launcher integrity file is unsafe");
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function validateProtectedActionRuntime(actionRoot: string): void {
  const expectedModes = new Map<string, number>([
    [".", 0o555],
    ["bin", 0o555],
    ["bin/fence", 0o555],
    ["bundle-manifest.json", 0o444],
    ["lib.cts", 0o444],
    ["log.cts", 0o444],
    ["main.cts", 0o444],
    ["post.cts", 0o444],
  ]);
  for (const [relativePath, expectedMode] of expectedModes) {
    const item = relativePath === "." ? actionRoot : path.join(actionRoot, relativePath);
    const stat = fs.lstatSync(item);
    const expectsDirectory = relativePath === "." || relativePath === "bin";
    if (
      stat.isSymbolicLink() ||
      stat.uid !== 0 ||
      (stat.mode & 0o777) !== expectedMode ||
      (expectsDirectory ? !stat.isDirectory() : !stat.isFile())
    ) {
      fail(`Fence protected Action runtime has unsafe ownership or mode: ${relativePath}`);
    }
  }
}

function validateReadOnlyActionMount(
  raw: unknown,
  expectedTarget: string,
  expectedMountId: string,
): void {
  const mount = effectiveActionMount(
    raw,
    expectedTarget,
    expectedMountId,
    "protected Action",
  );
  const options = new Set(mount.options.split(","));
  if (
    !options.has("ro") ||
    !options.has("nodev") ||
    !options.has("nosuid")
  ) {
    fail("Fence protected Action mount is missing required options");
  }
}

function mountIdentifier(value: unknown): string | undefined {
  const identifier = typeof value === "number" && Number.isSafeInteger(value)
    ? String(value)
    : value;
  if (
    typeof identifier !== "string" ||
    !/^[1-9][0-9]*$/.test(identifier)
  ) {
    return undefined;
  }
  return identifier;
}

function mountIdFromFdInfo(raw: unknown): string {
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > 4 * 1024) {
    fail("Fence active mount identity is unavailable");
  }
  const mountIds = raw
    .split("\n")
    .map((line) => /^mnt_id:\s+([1-9][0-9]*)\s*$/.exec(line)?.[1])
    .filter((mountId): mountId is string => mountId !== undefined);
  if (mountIds.length !== 1) {
    fail("Fence active mount identity is unavailable");
  }
  return mountIds[0];
}

function mountInfoRecordForId(mountId: string): string {
  const descriptor = fs.openSync(
    "/proc/self/mountinfo",
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  );
  try {
    const chunks: Buffer[] = [];
    const chunk = Buffer.alloc(16 * 1024);
    let totalBytes = 0;
    while (true) {
      const bytesRead = fs.readSync(descriptor, chunk, 0, chunk.length, null);
      if (bytesRead === 0) {
        break;
      }
      totalBytes += bytesRead;
      if (totalBytes > MAX_ACTION_MOUNTINFO_BYTES) {
        fail("Fence active mount table is unavailable");
      }
      chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
    }
    const matching = Buffer.concat(chunks, totalBytes)
      .toString("utf8")
      .split("\n")
      .filter((line) => line.startsWith(`${mountId} `));
    if (matching.length !== 1) {
      fail("Fence active mount table is unavailable");
    }
    return matching[0];
  } finally {
    fs.closeSync(descriptor);
  }
}

function decodeMountInfoPath(encoded: string): string {
  if (encoded.replace(/\\(?:011|012|040|134)/g, "").includes("\\")) {
    fail("Fence active mount record is malformed");
  }
  return encoded.replace(
    /\\(011|012|040|134)/g,
    (_escape, octal) => String.fromCharCode(Number.parseInt(octal, 8)),
  );
}

function actionMountRecordFromMountInfo(
  raw: unknown,
  expectedTarget: string,
  expectedMountId: string,
): { target: string; options: string; id: string } {
  if (
    typeof raw !== "string" ||
    Buffer.byteLength(raw, "utf8") > MAX_ACTION_MOUNTINFO_RECORD_BYTES ||
    raw.length === 0 ||
    raw.includes("\n") ||
    raw.includes("\r")
  ) {
    fail("Fence active mount record is unavailable");
  }
  const fields = raw.split(" ");
  const separator = fields.indexOf("-", 6);
  const mountId = mountIdentifier(fields[0]);
  if (
    mountId === undefined ||
    mountId !== expectedMountId ||
    !/^[0-9]+:[0-9]+$/.test(fields[2] || "") ||
    separator < 6 ||
    fields.length < separator + 4 ||
    !fields[5]
  ) {
    fail("Fence active mount record is malformed");
  }
  const target = decodeMountInfoPath(fields[4]);
  if (target !== expectedTarget) {
    fail("Fence active mount record does not match the registered runtime");
  }
  return { target, options: fields[5], id: mountId };
}

function activeActionMountEvidence(
  target: string,
): { raw: string; mountId: string } {
  if (!path.isAbsolute(target) || path.normalize(target) !== target) {
    fail("Fence active Action mount target is invalid");
  }
  let descriptor: number;
  try {
    descriptor = fs.openSync(
      target,
      fs.constants.O_RDONLY |
        fs.constants.O_DIRECTORY |
        fs.constants.O_NOFOLLOW,
    );
  } catch {
    fail("Fence active Action mount evidence is unavailable");
  }
  try {
    const mountId = mountIdFromFdInfo(
      fs.readFileSync(`/proc/self/fdinfo/${descriptor}`, "utf8"),
    );
    const record = actionMountRecordFromMountInfo(
      mountInfoRecordForId(mountId),
      target,
      mountId,
    );
    return {
      raw: JSON.stringify({ filesystems: [record] }),
      mountId,
    };
  } catch {
    fail("Fence active Action mount evidence is unavailable");
  } finally {
    fs.closeSync(descriptor);
  }
}

function effectiveActionMount(
  raw: unknown,
  expectedTarget: string,
  expectedMountId: string,
  description: string,
): { options: string } {
  if (mountIdentifier(expectedMountId) !== expectedMountId) {
    fail(`Fence ${description} mount evidence is incomplete`);
  }
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > 16 * 1024) {
    fail(`Fence ${description} mount evidence is unavailable`);
  }
  let document: any;
  try {
    document = JSON.parse(raw);
  } catch {
    fail(`Fence ${description} mount evidence is malformed`);
  }
  if (
    document === null ||
    Array.isArray(document) ||
    typeof document !== "object" ||
    !Array.isArray(document.filesystems) ||
    document.filesystems.length === 0
  ) {
    fail(`Fence ${description} mount evidence is incomplete`);
  }
  const mounts = document.filesystems.map((mount: any) => {
    const mountId = mountIdentifier(mount?.id);
    if (
      mount === null ||
      Array.isArray(mount) ||
      typeof mount !== "object" ||
      Object.keys(mount).sort().join(",") !== "id,options,target" ||
      typeof mount.options !== "string" ||
      mountId === undefined
    ) {
      fail(`Fence ${description} mount evidence is incomplete`);
    }
    if (mount.target !== expectedTarget) {
      fail(`Fence ${description} mount does not match the registered runtime`);
    }
    return { id: mountId, options: mount.options };
  });
  if (new Set(mounts.map((mount) => mount.id)).size !== mounts.length) {
    fail(`Fence ${description} mount evidence is incomplete`);
  }
  const activeMounts = mounts.filter((mount) => mount.id === expectedMountId);
  if (activeMounts.length !== 1) {
    fail(`Fence ${description} mount does not match the active runtime`);
  }
  return activeMounts[0];
}

function validateActionPathGuardMount(
  raw: unknown,
  expectedTarget: string,
  expectedMountId: string,
): void {
  const mount = effectiveActionMount(
    raw,
    expectedTarget,
    expectedMountId,
    "registered Action path guard",
  );
  const options = new Set(mount.options.split(","));
  if (!options.has("rw") || options.has("ro")) {
    fail("Fence registered Action path guard mount must remain writable");
  }
}

function validateBundle(manifestPath: string, binaryPath: string): any {
  const manifest = readJsonBounded(manifestPath, 16 * 1024, "bundle manifest");
  const binaryStat = fs.lstatSync(binaryPath);
  if (
    !binaryStat.isFile() ||
    binaryStat.isSymbolicLink() ||
    binaryStat.size === 0 ||
    binaryStat.size > MAX_ACTION_RUNTIME_FILE_BYTES
  ) {
    fail("bundled Fence binary is not a regular file");
  }
  if (manifest === null || Array.isArray(manifest) || typeof manifest !== "object") {
    fail("bundle manifest does not match the reviewed Fence release contract");
  }
  const expectedReleaseChannel = manifest.release_tag && manifest.release_tag.includes("-")
    ? "prerelease"
    : "stable";
  const expectedKeys = [
    "artifact_name",
    "artifact_sha256",
    "bundle_path",
    "release_channel",
    "release_tag",
    "release_url",
    "repository",
    "schema_version",
    "signer_digest",
    "signer_workflow",
    "source_commit",
    "source_ref",
  ];
  if (
    JSON.stringify(Object.keys(manifest).sort()) !== JSON.stringify(expectedKeys) ||
    manifest.schema_version !== 4 ||
    manifest.repository !== "openai/fence" ||
    !RELEASE_TAG.test(manifest.release_tag) ||
    manifest.release_channel !== expectedReleaseChannel ||
    manifest.release_url !== `https://github.com/openai/fence/releases/tag/${manifest.release_tag}` ||
    !/^[0-9a-f]{40}$/.test(manifest.source_commit) ||
    manifest.source_ref !== "refs/heads/main" ||
    manifest.artifact_name !== `fence_${manifest.release_tag}_linux-amd64` ||
    !SHA256.test(manifest.artifact_sha256) ||
    manifest.signer_digest !== manifest.source_commit ||
    manifest.signer_workflow !== "openai/fence/.github/workflows/release.yml" ||
    manifest.bundle_path !== "action/bin/fence"
  ) {
    fail("bundle manifest does not match the reviewed Fence release contract");
  }
  const digest = crypto.createHash("sha256").update(fs.readFileSync(binaryPath)).digest("hex");
  if (digest !== manifest.artifact_sha256) {
    fail("bundled Fence binary checksum does not match its manifest");
  }
  return manifest;
}

function validatedActionRuntimeSnapshot(
  actionRoot: string,
): { manifest: any; files: ActionRuntimeFileDigest[] } {
  const before = actionRuntimeFileDigests(actionRoot);
  const manifest = validateBundle(
    path.join(actionRoot, "bundle-manifest.json"),
    path.join(actionRoot, "bin", "fence"),
  );
  const after = actionRuntimeFileDigests(actionRoot);
  if (actionRuntimeDigest(before) !== actionRuntimeDigest(after)) {
    fail("Fence Action runtime changed while it was being validated");
  }
  return { manifest, files: after };
}

function validateReport(report: any, failOnCritical = true): any {
  if (report === null || Array.isArray(report) || typeof report !== "object") {
    fail("Fence report must be a JSON object");
  }
  if (!REPORT_STATUSES.has(report.status)) {
    fail("Fence report has an unexpected status");
  }
  if (!READY_STATUSES.has(report.readiness_status)) {
    fail("Fence report does not contain a recognized readiness status");
  }
  const validIdentity =
    report.runtime_evidence_schema_version === RUNTIME_EVIDENCE_SCHEMA_VERSION &&
    selectsReviewedProfile(report.platform_profile_id, report.profile_realization_id) &&
    report.policy_hash_schema_version === POLICY_HASH_SCHEMA_VERSION &&
    SHA256.test(report.policy_hash) &&
    SHA256.test(report.base_ruleset_hash) &&
    SHA256.test(report.ruleset_hash);
  if (!validIdentity) {
    fail("Fence report does not select the reviewed hosted-runner profile");
  }
  if (!Array.isArray(report.critical_findings) || report.critical_findings_truncated !== false) {
    fail("Fence report does not contain bounded critical findings");
  }
  if (failOnCritical && report.critical_findings.length !== 0) {
    fail("Fence report contains critical resident findings");
  }
  validateResidentHealth(report.resident_health, Date.now(), !failOnCritical);
  if (report.network_verification_status !== "verified") {
    if (failOnCritical || report.critical_findings.length === 0) {
      fail("Fence report does not contain verified network state");
    }
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
  return report;
}

function validateReady(ready: any, report: any): any {
  if (ready === null || Array.isArray(ready) || typeof ready !== "object") {
    fail("Fence readiness must be a JSON object");
  }
  if (!READY_STATUSES.has(ready.status) || ready.status !== report.readiness_status) {
    fail("Fence readiness does not match the resident report");
  }
  const validIdentity =
    ready.runtime_evidence_schema_version === RUNTIME_EVIDENCE_SCHEMA_VERSION &&
    selectsReviewedProfile(ready.platform_profile_id, ready.profile_realization_id) &&
    ready.platform_profile_id === report.platform_profile_id &&
    ready.profile_realization_id === report.profile_realization_id &&
    ready.policy_hash_schema_version === report.policy_hash_schema_version &&
    ready.policy_hash === report.policy_hash &&
    ready.base_ruleset_hash === report.base_ruleset_hash &&
    SHA256.test(ready.ruleset_hash) &&
    ready.protection_available === report.protection_available;
  if (!validIdentity) {
    fail("Fence readiness identity does not match the resident report");
  }
  const readyHealth = validateResidentHealth(ready.resident_health);
  if (readyHealth.resident_pid !== report.resident_health.resident_pid) {
    fail("Fence readiness resident process does not match the report");
  }
  return ready;
}

function validateDnsEvidence(dnsEvidence: any, report: any): any {
  if (dnsEvidence === null || Array.isArray(dnsEvidence) || typeof dnsEvidence !== "object") {
    fail("Fence DNS evidence must be a JSON object");
  }
  if (
    dnsEvidence.runtime_evidence_schema_version !== RUNTIME_EVIDENCE_SCHEMA_VERSION ||
    dnsEvidence.status !== report.status ||
    dnsEvidence.mode !== report.mode ||
    dnsEvidence.platform_profile_id !== report.platform_profile_id ||
    dnsEvidence.profile_realization_id !== report.profile_realization_id ||
    dnsEvidence.protection_available !== report.protection_available ||
    dnsEvidence.routing_status !== "active"
  ) {
    fail("Fence DNS evidence does not match the resident report");
  }
  const dnsHealth = validateResidentHealth(
    dnsEvidence.resident_health,
    Date.now(),
    report.resident_health.status === "critical",
  );
  if (dnsHealth.resident_pid !== report.resident_health.resident_pid) {
    fail("Fence DNS evidence resident process does not match the report");
  }
  validateDnsProvenanceEvidence(dnsEvidence);
  return dnsEvidence;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function validateUserWildcardPolicy(hostnamePolicy: any): void {
  if (
    hostnamePolicy === null ||
    Array.isArray(hostnamePolicy) ||
    typeof hostnamePolicy !== "object" ||
    !Array.isArray(hostnamePolicy.exact) ||
    !Array.isArray(hostnamePolicy.user_wildcards) ||
    typeof hostnamePolicy.allow_dynamic_githubapp_suffix !== "boolean" ||
    hostnamePolicy.user_wildcards.length > 64
  ) {
    fail("Fence DNS evidence does not contain bounded wildcard policy");
  }
  let previousPattern: string | undefined;
  for (const wildcard of hostnamePolicy.user_wildcards) {
    if (
      wildcard === null ||
      Array.isArray(wildcard) ||
      typeof wildcard !== "object" ||
      Object.keys(wildcard).sort().join(",") !== "pattern,prefix_labels,suffix,transports" ||
      typeof wildcard.pattern !== "string" ||
      normalizeHostnameDestination(wildcard.pattern) !== wildcard.pattern ||
      !wildcard.pattern.includes("*") ||
      !isSafeHostname(wildcard.suffix) ||
      !Number.isSafeInteger(wildcard.prefix_labels) ||
      wildcard.prefix_labels < 1 ||
      wildcard.prefix_labels > MAX_USER_WILDCARD_PREFIX_LABELS ||
      wildcard.pattern !== `${"*.".repeat(wildcard.prefix_labels)}${wildcard.suffix}` ||
      !Array.isArray(wildcard.transports) ||
      wildcard.transports.length < 1 ||
      wildcard.transports.length > 64 ||
      (previousPattern !== undefined && compareStrings(previousPattern, wildcard.pattern) >= 0)
    ) {
      fail("Fence DNS evidence contains invalid wildcard policy");
    }
    let previousTransport: string | undefined;
    for (const transport of wildcard.transports) {
      if (
        transport === null ||
        Array.isArray(transport) ||
        typeof transport !== "object" ||
        Object.keys(transport).sort().join(",") !== "port,protocol" ||
        !isSupportedProtocol(transport.protocol) ||
        !isValidPort(transport.port)
      ) {
        fail("Fence DNS evidence contains invalid wildcard transport policy");
      }
      const transportKey = `${transport.protocol === "tcp" ? "0" : "1"}:${String(transport.port).padStart(5, "0")}`;
      if (previousTransport !== undefined && compareStrings(previousTransport, transportKey) >= 0) {
        fail("Fence DNS evidence contains unsorted wildcard transport policy");
      }
      previousTransport = transportKey;
    }
    previousPattern = wildcard.pattern;
  }
}

function validateDnsProvenanceEvidence(dnsEvidence: any): void {
  const authorizations = dnsEvidence.runner_authorized_results_storage;
  const wildcardAuthorizations = dnsEvidence.bounded_user_wildcard_authorizations;
  const wildcardTruncated = dnsEvidence.bounded_user_wildcard_authorizations_truncated;
  const wildcardRejections = dnsEvidence.user_wildcard_request_rejections;
  if (
    dnsEvidence.host_dns_routing !== "direct_client_to_root_resident_mediator" ||
    dnsEvidence.docker_dns_routing !== "local_root_resident_mediator" ||
    dnsEvidence.answer_attribution_status !== "bounded_reportable_hostname_answers_only" ||
    !Array.isArray(authorizations) ||
    authorizations.length > MAX_RESULTS_STORAGE_AUTHORIZATIONS ||
    typeof dnsEvidence.runner_authorized_results_storage_truncated !== "boolean" ||
    !isNonnegativeSafeInteger(dnsEvidence.results_storage_authorization_count) ||
    !isNonnegativeSafeInteger(dnsEvidence.results_storage_attribution_failures) ||
    !isNonnegativeSafeInteger(dnsEvidence.results_storage_request_rejections) ||
    dnsEvidence.results_storage_authorization_count !== authorizations.length ||
    !Array.isArray(wildcardAuthorizations) ||
    wildcardAuthorizations.length > MAX_USER_WILDCARD_AUTHORIZATIONS ||
    typeof wildcardTruncated !== "boolean" ||
    !isNonnegativeSafeInteger(wildcardRejections) ||
    wildcardTruncated !== (wildcardRejections > 0) ||
    !Array.isArray(dnsEvidence.observations) ||
    typeof dnsEvidence.observations_truncated !== "boolean"
  ) {
    fail("Fence DNS evidence does not contain bounded runner provenance");
  }
  const expectedProxyPolicy = dnsEvidence.mode === "audit"
    ? "audit_forwards_while_simulating_name_authorization"
    : "block_forwards_exact_roots_bounded_user_wildcard_names_actions_suffix_names_githubapp_suffix_names_results_storage_and_bounded_cname_descendants";
  if (dnsEvidence.proxy_policy_status !== expectedProxyPolicy) {
    fail("Fence DNS evidence does not contain the reviewed proxy policy");
  }
  validateUserWildcardPolicy(dnsEvidence.hostname_policy);
  let previousWildcard: string | undefined;
  for (const hostname of wildcardAuthorizations) {
    if (
      !isSafeHostname(hostname) ||
      (previousWildcard !== undefined && compareStrings(previousWildcard, hostname) >= 0)
    ) {
      fail("Fence DNS evidence contains invalid wildcard authorization");
    }
    previousWildcard = hostname;
  }
  for (const observation of dnsEvidence.observations) {
    if (
      observation === null ||
      Array.isArray(observation) ||
      typeof observation !== "object" ||
      !isSafeHostname(observation.hostname) ||
      !DNS_CLASSIFICATIONS.has(observation.policy_classification)
    ) {
      fail("Fence DNS evidence contains invalid hostname observation");
    }
  }
  const seen = new Set<string>();
  for (const authorization of authorizations) {
    if (
      authorization === null ||
      Array.isArray(authorization) ||
      typeof authorization !== "object" ||
      Object.keys(authorization).sort().join(",") !== "authorization_origin,hostname" ||
      typeof authorization.hostname !== "string" ||
      !RESULTS_STORAGE_HOSTNAME.test(authorization.hostname) ||
      authorization.authorization_origin !== "pinned_runner_worker_dns" ||
      seen.has(authorization.hostname)
    ) {
      fail("Fence DNS evidence contains invalid results-storage authorization");
    }
    seen.add(authorization.hostname);
  }
}

function isNonnegativeSafeInteger(value: unknown): boolean {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function validateResidentHealth(
  health: any,
  nowMilliseconds = Date.now(),
  allowCritical = false,
): any {
  if (health === null || Array.isArray(health) || typeof health !== "object") {
    fail("Fence report does not contain resident health evidence");
  }
  const sequence = health.verification_sequence;
  const verifiedAt = health.last_successful_verification_unix_milliseconds;
  if (
    (health.status !== "healthy" && !(allowCritical && health.status === "critical")) ||
    !Number.isSafeInteger(health.resident_pid) ||
    health.resident_pid < 1 ||
    health.resident_pid > 0xffff_ffff ||
    !Number.isSafeInteger(sequence) ||
    sequence < 1 ||
    !Number.isSafeInteger(verifiedAt) ||
    verifiedAt < 1 ||
    health.verification_interval_seconds !== RESIDENT_VERIFICATION_INTERVAL_SECONDS
  ) {
    fail("Fence resident health evidence is invalid or unhealthy");
  }
  if (
    !Number.isSafeInteger(nowMilliseconds) ||
    verifiedAt > nowMilliseconds + RESIDENT_EVIDENCE_MAX_FUTURE_SKEW_MILLISECONDS ||
    nowMilliseconds - verifiedAt > RESIDENT_EVIDENCE_MAX_AGE_MILLISECONDS
  ) {
    fail("Fence resident health evidence is stale or has an invalid timestamp");
  }
  if (!Array.isArray(health.workers)) {
    fail("Fence resident worker health is missing");
  }
  const workers = health.workers.map((worker: any) => {
    const validStatus = worker && (
      worker.status === "running" ||
      (allowCritical && health.status === "critical" && worker.status === "failed")
    );
    if (
      worker === null ||
      Array.isArray(worker) ||
      typeof worker !== "object" ||
      typeof worker.name !== "string" ||
      !validStatus ||
      Object.keys(worker).sort().join(",") !== "name,status"
    ) {
      fail("Fence resident worker health is invalid");
    }
    return worker.name;
  });
  if (JSON.stringify(workers.sort()) !== JSON.stringify(REQUIRED_RESIDENT_WORKERS)) {
    fail("Fence resident worker set does not match the reviewed runtime");
  }
  return health;
}

function parseResidentUnitStatus(output: unknown): Record<string, string> {
  if (typeof output !== "string" || output.length > 16 * 1024) {
    fail("Fence resident service status is unavailable");
  }
  const status: Record<string, string> = {};
  for (const line of output.split(/\r?\n/)) {
    if (line.length === 0) continue;
    const separator = line.indexOf("=");
    if (separator < 1) {
      fail("Fence resident service status is malformed");
    }
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (!new Set(["ActiveState", "MainPID", "SubState"]).has(key) || key in status) {
      fail("Fence resident service status is malformed");
    }
    status[key] = value;
  }
  if (Object.keys(status).length !== 3) {
    fail("Fence resident service status is incomplete");
  }
  return status;
}

function validateResidentUnitStatus(output: unknown, expectedPid: unknown): void {
  const status = parseResidentUnitStatus(output);
  if (
    status.ActiveState !== "active" ||
    status.SubState !== "running" ||
    !Number.isSafeInteger(expectedPid) ||
    status.MainPID !== String(expectedPid)
  ) {
    fail("Fence resident service is not active with the expected main process");
  }
}

function boundedScalar(value: unknown): string {
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
    return "unavailable";
  }
  return String(value).replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 96);
}

function boundedText(value: unknown, maximum = 192): string {
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
    return "unavailable";
  }
  return String(value)
    .replace(/[\r\n]+/g, " ")
    .replace(/\|/g, "\\|")
    .slice(0, maximum);
}

function markdownCode(value: unknown, maximum = 128): string {
  return `\`${boundedText(value, maximum).replace(/`/g, "_")}\``;
}

function isSafeHostname(value: unknown): value is string {
  return typeof value === "string" &&
    normalizeExactHostname(value) === value;
}

function isSupportedProtocol(value: unknown): value is string {
  return value === "tcp" || value === "udp";
}

function isValidPort(value: unknown): value is number {
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

function addRow(rows: Map<string, AuditFindingRow>, row: Omit<AuditFindingRow, "count">): void {
  const key = `${row.destinationKind}\0${row.destination}\0${row.protocol}\0${row.port}`;
  const existing = rows.get(key);
  if (existing) {
    existing.count += 1;
  } else {
    rows.set(key, { ...row, count: 1 });
  }
}

function sortedRows(rows: Iterable<AuditFindingRow>): AuditFindingRow[] {
  return Array.from(rows).sort((left, right) =>
    right.count - left.count ||
    left.destination.localeCompare(right.destination) ||
    left.protocol.localeCompare(right.protocol) ||
    left.port - right.port
  );
}

function dnsAddressHostnameMap(
  dnsEvidence: any,
  classifications: Set<string> | undefined = undefined,
): Map<string, Set<string>> {
  const addressMap = new Map<string, Set<string>>();
  if (dnsEvidence === undefined || dnsEvidence === null || !Array.isArray(dnsEvidence.observations)) {
    return addressMap;
  }
  for (const observation of dnsEvidence.observations) {
    if (observation === null || Array.isArray(observation) || typeof observation !== "object") {
      continue;
    }
    if (observation.query_type !== "a" && observation.query_type !== "aaaa") {
      continue;
    }
    if (classifications !== undefined && !classifications.has(observation.policy_classification)) {
      continue;
    }
    const hostname = observation.hostname;
    if (!isSafeHostname(hostname) || !Array.isArray(observation.resolved_addresses)) {
      continue;
    }
    for (const address of observation.resolved_addresses) {
      if (typeof address !== "string" || net.isIP(address) === 0) {
        continue;
      }
      const hostnames = addressMap.get(address) || new Set<string>();
      hostnames.add(hostname);
      addressMap.set(address, hostnames);
    }
  }
  return addressMap;
}

function correlateFindingsToDns(report: any, dnsEvidence: any = undefined): AuditSummary {
  const hostnameRows = new Map<string, AuditFindingRow>();
  const ipRows = new Map<string, AuditFindingRow>();
  const addressMap = dnsAddressHostnameMap(dnsEvidence, OUTSIDE_POLICY_DNS_CLASSIFICATIONS);
  let unparsedCount = 0;

  for (const finding of Array.isArray(report.findings) ? report.findings : []) {
    if (
      finding === null ||
      Array.isArray(finding) ||
      typeof finding !== "object" ||
      finding.classification !== "would_block"
    ) {
      continue;
    }
    if (
      typeof finding.remote_address !== "string" ||
      net.isIP(finding.remote_address) === 0 ||
      !isSupportedProtocol(finding.protocol) ||
      !isValidPort(finding.remote_port)
    ) {
      unparsedCount += 1;
      continue;
    }

    const hostnames = Array.from(addressMap.get(finding.remote_address) || []).sort();
    if (hostnames.length > 0) {
      for (const hostname of hostnames) {
        addRow(hostnameRows, {
          destination: hostname,
          destinationKind: "hostname",
          protocol: finding.protocol,
          port: finding.remote_port,
        });
      }
    } else {
      addRow(ipRows, {
        destination: finding.remote_address,
        destinationKind: "ip",
        protocol: finding.protocol,
        port: finding.remote_port,
      });
    }
  }

  const allHostnameRows = sortedRows(hostnameRows.values());
  const allIpRows = sortedRows(ipRows.values());
  return {
    dnsMissing: dnsEvidence === undefined || dnsEvidence === null,
    hostnameRows: allHostnameRows.slice(0, MAX_AUDIT_HOSTNAME_ROWS),
    ipRows: allIpRows.slice(0, MAX_AUDIT_IP_ROWS),
    omittedHostnameRows: Math.max(0, allHostnameRows.length - MAX_AUDIT_HOSTNAME_ROWS),
    omittedIpRows: Math.max(0, allIpRows.length - MAX_AUDIT_IP_ROWS),
    unparsedCount,
    sourceTruncated: report.findings_truncated === true ||
      Boolean(dnsEvidence && dnsEvidence.observations_truncated === true),
  };
}

function summaryHeading(summaryState: { healthy: boolean; critical: boolean }): string {
  if (summaryState.critical) {
    return "### 🔴 Fence Summary";
  }
  return summaryState.healthy ? "### 🟢 Fence Summary" : "### 🟡 Fence Summary";
}

function summaryHasWarnings(report: any, auditSummary: AuditSummary, dnsEvidence: any): boolean {
  return (
    report.status === "protected_host_block_degraded" ||
    report.network_verification_status !== "verified" ||
    (Array.isArray(report.critical_findings) && report.critical_findings.length > 0) ||
    report.critical_findings_truncated === true ||
    report.findings_truncated === true ||
    auditSummary.sourceTruncated ||
    auditSummary.omittedHostnameRows > 0 ||
    auditSummary.omittedIpRows > 0 ||
    (report.mode === "audit" && auditSummary.dnsMissing) ||
    materializationRequestRejections(dnsEvidence) > 0 ||
    materializationEvidenceCounter(dnsEvidence, "user_wildcard_request_rejections") > 0 ||
    Boolean(dnsEvidence && dnsEvidence.bounded_user_wildcard_authorizations_truncated === true) ||
    resultsStorageEvidenceCounter(dnsEvidence, "results_storage_attribution_failures") > 0 ||
    resultsStorageEvidenceCounter(dnsEvidence, "results_storage_request_rejections") > 0 ||
    Boolean(dnsEvidence && dnsEvidence.runner_authorized_results_storage_truncated === true)
  );
}

function materializationEvidenceCounter(dnsEvidence: any, field: string): number {
  const value = dnsEvidence && dnsEvidence[field];
  return Number.isSafeInteger(value) && value > 0 ? value : 0;
}

function materializationRequestRejections(dnsEvidence: any): number {
  return materializationEvidenceCounter(dnsEvidence, "materialization_request_rejections");
}

function materializationWarningLines(dnsEvidence: any): string[] {
  return warningTableLines(materializationWarningRows(dnsEvidence));
}

function materializationWarningRows(dnsEvidence: any): string[] {
  const count = materializationRequestRejections(dnsEvidence);
  return count === 0 ? [] : [
    `| ⚠️ DNS answers withheld while firewall updates were unavailable | ${markdownCode(count)} |`,
  ];
}

function resultsStorageEvidenceCounter(dnsEvidence: any, field: string): number {
  const value = dnsEvidence && dnsEvidence[field];
  return Number.isSafeInteger(value) && value > 0 ? value : 0;
}

function resultsStorageWarningRows(dnsEvidence: any): string[] {
  const attributionFailures = resultsStorageEvidenceCounter(
    dnsEvidence,
    "results_storage_attribution_failures",
  );
  const requestRejections = resultsStorageEvidenceCounter(
    dnsEvidence,
    "results_storage_request_rejections",
  );
  const truncated = Boolean(
    dnsEvidence && dnsEvidence.runner_authorized_results_storage_truncated === true,
  );
  const rows = [];
  if (attributionFailures > 0) {
    rows.push(`| ⚠️ GitHub results-storage requests could not be attributed | ${markdownCode(attributionFailures)} |`);
  }
  if (requestRejections > 0) {
    rows.push(`| ⚠️ GitHub results-storage requests were rejected | ${markdownCode(requestRejections)} |`);
  }
  if (truncated) {
    rows.push("| ⚠️ Additional results-storage accounts were denied after the authorization limit | `1+` |");
  }
  return rows;
}

function userWildcardWarningRows(dnsEvidence: any): string[] {
  const requestRejections = materializationEvidenceCounter(
    dnsEvidence,
    "user_wildcard_request_rejections",
  );
  const truncated = Boolean(
    dnsEvidence && dnsEvidence.bounded_user_wildcard_authorizations_truncated === true,
  );
  return requestRejections > 0 || truncated
    ? [`| ⚠️ User wildcard hostname authorization budget exhausted | ${markdownCode(Math.max(1, requestRejections))} |`]
    : [];
}

function warningTableLines(rows: string[]): string[] {
  return rows.length === 0
    ? []
    : ["", "#### Warnings", "", "| Warning | Count |", "| --- | ---: |", ...rows];
}

function criticalFindingLines(report: any): string[] {
  if (!Array.isArray(report.critical_findings) || report.critical_findings.length === 0) {
    return [];
  }
  const lines = [
    "",
    "#### Critical findings",
    "",
    "| Result | Finding | Detail |",
    "| --- | --- | --- |",
  ];
  for (const finding of report.critical_findings.slice(0, 5)) {
    lines.push(`| ❌ Critical | ${markdownCode(finding && finding.code)} | ${boundedText(finding && finding.message)} |`);
  }
  if (report.critical_findings.length > 5) {
    lines.push(`| ❌ Critical | ${markdownCode("additional_findings_omitted")} | ${report.critical_findings.length - 5} more critical findings are available in the local report. |`);
  }
  return lines;
}

function controlsSummary(report: any): string[] {
  const network = report.network_verification_status !== "verified"
    ? "❌ Verification failed"
    : report.mode === "audit"
      ? "⚠️ Observing only"
      : "✅ Restricted";
  const sudo = report.sudo_status === "disabled_verified"
    ? "✅ Disabled"
    : report.sudo_status === "preserved_verified"
      ? "➖ Available in audit mode"
      : "❌ Unverified";
  const containers = report.container_status === "disabled_verified"
    ? "✅ Disabled"
    : report.container_status === "preserved_unsafe"
      ? "⚠️ Available; limited assurance"
      : report.container_status === "preserved_verified"
        ? "➖ Available in audit mode"
        : "❌ Unverified";
  return [
    "#### Controls",
    "",
    "| Control | Result |",
    "| --- | --- |",
    `| Mode | ${report.mode === "audit" ? "👀 Audit" : "🔒 Block"} |`,
    `| Outbound network | ${network} |`,
    `| Passwordless sudo | ${sudo} |`,
    `| Docker/container access | ${containers} |`,
  ];
}

function allowlistYamlSnippet(rows: AuditFindingRow[]): string[] {
  if (rows.length === 0) {
    return [];
  }
  const entries = rows.map((row) => {
    if (row.destinationKind === "ip") {
      return `ip ${row.destination} ${row.protocol} ${row.port}`;
    }
    if (row.protocol === "tcp" && row.port === 443) {
      return row.destination;
    }
    if (row.protocol === "tcp") {
      return `${row.destination}:${row.port}`;
    }
    return `hostname ${row.destination} ${row.protocol} ${row.port}`;
  });

  return [
    "",
    "<details>",
    "<summary>View allowlist example</summary>",
    "",
    "```yaml",
    "- uses: openai/fence@<commit-sha>",
    "  with:",
    "    allowlist: |",
    ...entries.map((line) => `      ${line}`),
    "```",
    "",
    "</details>",
  ];
}

function safePositiveInteger(value: unknown): number {
  return Number.isSafeInteger(value) && value > 0 ? Number(value) : 0;
}

function networkDecision(report: any, classification: unknown, queryType: unknown): NetworkDecision {
  const allowed = ALLOWED_DNS_CLASSIFICATIONS.has(classification) &&
    FORWARDED_DNS_QUERY_TYPES.has(queryType);
  if (allowed) {
    return "allowed";
  }
  return report.mode === "audit" ? "would_block" : "blocked";
}

function dnsQueryActivity(queryType: unknown): string {
  if (queryType === "a" || queryType === "aaaa") {
    return `${queryType.toUpperCase()} query`;
  }
  if (typeof queryType === "string" && /^type_[0-9]{1,5}$/.test(queryType)) {
    return `TYPE${queryType.slice(5)} query`;
  }
  return "DNS query";
}

function addNetworkActivity(
  rows: Map<string, NetworkActivityRow>,
  destination: string,
  decision: NetworkDecision,
  activity: string,
  count: number,
  actor: string | undefined = undefined,
): void {
  if (count === 0) {
    return;
  }
  const key = `${destination}\0${decision}`;
  const row = rows.get(key) || {
    destination,
    decision,
    activities: new Map<string, number>(),
    actors: new Map<string, number>(),
    totalCount: 0,
  };
  row.activities.set(activity, (row.activities.get(activity) || 0) + count);
  if (actor !== undefined) {
    row.actors.set(actor, (row.actors.get(actor) || 0) + count);
  }
  row.totalCount += count;
  rows.set(key, row);
}

function safeExecutableBasename(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9._+-]{1,128}$/.test(value);
}

function findingActorLabel(finding: any): string | undefined {
  if (
    finding === null ||
    Array.isArray(finding) ||
    typeof finding !== "object" ||
    finding.local_attribution === null ||
    Array.isArray(finding.local_attribution) ||
    typeof finding.local_attribution !== "object"
  ) {
    return undefined;
  }
  const attribution = finding.local_attribution;
  const fallbackLabels = new Map([
    ["ambiguous", "Ambiguous owner"],
    ["not_found", "Owner not found"],
    ["scan_limit_exceeded", "Attribution scan limit reached"],
    ["queue_full", "Attribution queue full"],
    ["worker_unavailable", "Attribution worker unavailable"],
  ]);
  if (fallbackLabels.has(attribution.status)) {
    return fallbackLabels.get(attribution.status);
  }
  if (
    attribution.status !== "attributed" ||
    !new Set(["runner", "root", "other", "unknown"]).has(attribution.actor_class) ||
    !Number.isSafeInteger(attribution.pid) ||
    attribution.pid < 1 ||
    attribution.pid > 0xffff_ffff ||
    !safeExecutableBasename(attribution.executable_basename)
  ) {
    return undefined;
  }
  return `${attribution.actor_class}: ${attribution.executable_basename} (PID ${attribution.pid})`;
}

function findingAttributionDebugLines(report: any): string[] {
  const lines: string[] = [];
  const findings = Array.isArray(report && report.findings) ? report.findings.slice(0, 1024) : [];
  for (const finding of findings) {
    const actor = findingActorLabel(finding);
    if (
      actor === undefined ||
      typeof finding.remote_address !== "string" ||
      net.isIP(finding.remote_address) === 0 ||
      !isSupportedProtocol(finding.protocol) ||
      !isValidPort(finding.remote_port)
    ) {
      continue;
    }
    if (lines.length === 10) {
      lines.push("additional_finding_attribution=omitted");
      break;
    }
    lines.push(
      `finding_attribution_${lines.length + 1}=${finding.protocol}/${finding.remote_port} ${finding.remote_address} ${actor}`,
    );
  }
  return lines;
}

function addConnectionFindingActivity(
  rows: Map<string, NetworkActivityRow>,
  report: any,
  dnsEvidence: any,
): void {
  const addressMap = dnsAddressHostnameMap(dnsEvidence);
  const findings = Array.isArray(report.findings) ? report.findings.slice(0, 1024) : [];
  for (const finding of findings) {
    if (
      finding === null ||
      Array.isArray(finding) ||
      typeof finding !== "object" ||
      typeof finding.remote_address !== "string" ||
      net.isIP(finding.remote_address) === 0 ||
      !isSupportedProtocol(finding.protocol) ||
      !isValidPort(finding.remote_port)
    ) {
      continue;
    }
    const decision = finding.classification === "rejected"
      ? "blocked"
      : finding.classification === "would_block"
        ? "would_block"
        : undefined;
    if (decision === undefined) {
      continue;
    }
    const hostnames = Array.from(addressMap.get(finding.remote_address) || []).sort();
    const destinations = hostnames.length > 0 ? hostnames : [finding.remote_address];
    const actor = findingActorLabel(finding);
    for (const destination of destinations) {
      addNetworkActivity(
        rows,
        destination,
        decision,
        `${finding.protocol.toUpperCase()}/${finding.remote_port} attempt`,
        1,
        actor,
      );
    }
  }
}

function networkActivityRows(
  report: any,
  dnsEvidence: any,
): NetworkActivitySummary {
  const rows = new Map<string, NetworkActivityRow>();
  let namedBlockedDnsQueries = 0;

  if (dnsEvidence && Array.isArray(dnsEvidence.observations)) {
    for (const observation of dnsEvidence.observations) {
      if (
        observation === null ||
        Array.isArray(observation) ||
        typeof observation !== "object" ||
        !isSafeHostname(observation.hostname)
      ) {
        continue;
      }
      const count = safePositiveInteger(observation.occurrences);
      const decision = networkDecision(
        report,
        observation.policy_classification,
        observation.query_type,
      );
      addNetworkActivity(rows, observation.hostname, decision, dnsQueryActivity(observation.query_type), count);
      if (decision === "blocked") {
        namedBlockedDnsQueries += count;
      }
    }
  }

  addConnectionFindingActivity(rows, report, dnsEvidence);

  if (report.mode === "audit") {
    addNetworkActivity(
      rows,
      "Other DNS names",
      "would_block",
      "DNS query (names not retained)",
      safePositiveInteger(dnsEvidence && dnsEvidence.excluded_unretained_query_count),
    );
  } else {
    const unnamedBlocked = Math.max(
      0,
      safePositiveInteger(dnsEvidence && dnsEvidence.blocked_non_profile_query_count) - namedBlockedDnsQueries,
    );
    addNetworkActivity(
      rows,
      "Other DNS names",
      "blocked",
      "DNS query (names not retained)",
      unnamedBlocked,
    );
  }

  const priority: Record<NetworkDecision, number> = {
    blocked: 0,
    would_block: 1,
    allowed: 2,
  };
  const sorted = Array.from(rows.values()).sort((left, right) =>
    priority[left.decision] - priority[right.decision] ||
    right.totalCount - left.totalCount ||
    left.destination.localeCompare(right.destination)
  );
  return {
    rows: sorted.slice(0, MAX_NETWORK_ACTIVITY_ROWS),
    omittedRows: Math.max(0, sorted.length - MAX_NETWORK_ACTIVITY_ROWS),
  };
}

function decisionLabel(decision: NetworkDecision): string {
  if (decision === "allowed") {
    return "✅ Allowed";
  }
  if (decision === "blocked") {
    return "⛔ Blocked";
  }
  return "⚠️ Would block";
}

function activityLabel(row: NetworkActivityRow): string {
  return Array.from(row.activities.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([activity, count]) => {
      if (activity === "DNS query") {
        return `${count} DNS ${count === 1 ? "query" : "queries"}`;
      }
      if (activity === "DNS query (names not retained)") {
        return `${count} DNS ${count === 1 ? "query" : "queries"} (names not retained)`;
      }
      if (activity.endsWith(" query")) {
        return `${count} ${activity.slice(0, -6)} ${count === 1 ? "query" : "queries"}`;
      }
      return `${count} ${activity}${count === 1 ? "" : "s"}`;
    })
    .join(", ");
}

function actorLabel(row: NetworkActivityRow): string {
  return Array.from(row.actors.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([actor, count]) => `${actor}${count === 1 ? "" : ` ×${count}`}`)
    .join(", ");
}

function networkActivitySummary(
  report: any,
  dnsEvidence: any = undefined,
  auditSummary: AuditSummary = correlateFindingsToDns(report, dnsEvidence),
): string[] {
  const activity = networkActivityRows(report, dnsEvidence);
  const lines = ["", "#### Network activity", ""];
  if (activity.rows.length === 0) {
    lines.push("_No reportable network activity was observed._");
    return lines;
  }

  const hasAttribution = activity.rows.some((row) => row.actors.size > 0);
  lines.push(hasAttribution
    ? "| Destination | Result | Activity | Actor |"
    : "| Destination | Result | Activity |");
  lines.push(hasAttribution ? "| --- | --- | ---: | --- |" : "| --- | --- | ---: |");
  for (const row of activity.rows) {
    const actor = row.actors.size > 0 ? boundedText(actorLabel(row)) : "➖";
    lines.push(hasAttribution
      ? `| ${markdownCode(row.destination)} | ${decisionLabel(row.decision)} | ${boundedText(activityLabel(row))} | ${actor} |`
      : `| ${markdownCode(row.destination)} | ${decisionLabel(row.decision)} | ${boundedText(activityLabel(row))} |`);
  }
  if (activity.omittedRows > 0) {
    lines.push(hasAttribution
      ? `| ${markdownCode("additional_destinations_omitted")} | ⚠️ Review local evidence | ${activity.omittedRows} more row(s) | ➖ |`
      : `| ${markdownCode("additional_destinations_omitted")} | ⚠️ Review local evidence | ${activity.omittedRows} more row(s) |`);
  }
  lines.push("");

  if (report.mode === "audit" && auditSummary.dnsMissing) {
    lines.push("⚠️ DNS evidence was unavailable; IP-level findings may require manual review.", "");
  }
  if (auditSummary.unparsedCount > 0) {
    lines.push(`⚠️ ${auditSummary.unparsedCount} would-block finding(s) could not be mapped to an endpoint.`);
    lines.push("");
  }
  if (auditSummary.sourceTruncated || auditSummary.omittedHostnameRows > 0 || auditSummary.omittedIpRows > 0) {
    const omitted = auditSummary.omittedHostnameRows + auditSummary.omittedIpRows;
    lines.push(`⚠️ Network evidence was truncated${omitted > 0 ? `; ${omitted} grouped row(s) were omitted` : ""}.`);
    lines.push("");
  }
  if (report.mode === "audit") {
    lines.push(...allowlistYamlSnippet([
      ...auditSummary.hostnameRows,
      ...auditSummary.ipRows,
    ]));
  }
  return lines;
}

function summaryLines(report: any, dnsEvidence: any = undefined): string[] {
  const auditSummary = correlateFindingsToDns(report, dnsEvidence);
  const critical = report.network_verification_status !== "verified" ||
    (Array.isArray(report.critical_findings) && report.critical_findings.length > 0);
  const summaryState = {
    healthy: !summaryHasWarnings(report, auditSummary, dnsEvidence),
    critical,
  };
  return [
    summaryHeading(summaryState),
    "",
    ...controlsSummary(report),
    ...criticalFindingLines(report),
    ...warningTableLines([
      ...materializationWarningRows(dnsEvidence),
      ...userWildcardWarningRows(dnsEvidence),
      ...resultsStorageWarningRows(dnsEvidence),
    ]),
    ...networkActivitySummary(report, dnsEvidence, auditSummary),
    "",
  ];
}

module.exports = {
  ACTION_RUNTIME_FILES,
  MAX_REPORT_BYTES,
  activeActionMountEvidence,
  actionMountRecordFromMountInfo,
  actionPathGuardIdentities,
  actionRuntimeDigest,
  actionRuntimeFileDigests,
  allowlistYamlSnippet,
  correlateFindingsToDns,
  findingAttributionDebugLines,
  controlsSummary,
  defaultInlineConfig,
  materializationRequestRejections,
  materializationEvidenceCounter,
  materializationWarningLines,
  mountIdFromFdInfo,
  networkActivitySummary,
  nativeInputsFromEnvironment,
  readJsonBounded,
  readLauncherIntegrity,
  launcherIntegrityDocument,
  registeredActionPathGuardPaths,
  runtimePaths,
  summaryHeading,
  summaryLines,
  validateBundle,
  validatedActionRuntimeSnapshot,
  validateInlineConfig,
  validateLauncherIntegrity,
  validateActionPathGuardMount,
  validateProtectedActionRuntime,
  validateReadOnlyActionMount,
  validateDnsEvidence,
  validateReady,
  validateReport,
  validateResidentHealth,
  validateResidentUnitStatus,
};
