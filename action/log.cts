"use strict";

const MAX_LOG_LINE_BYTES = 2048;
const MAX_DEBUG_LINE_BYTES = 4096;

type LogEnvironment = Record<string, string | undefined>;
type ColorName = "highlight" | "info" | "success" | "warning" | "error";
type ConfigLogDetails = {
  mode: string;
  source: string;
  containerPolicy: string;
  platformProfile: string;
  disableBroadGithubDomains: boolean;
  allowlistCount: number;
  allowlistDestinations: string[];
};

const COLORS: Record<ColorName, string> = {
  highlight: "\u001b[35m",
  info: "\u001b[34m",
  success: "\u001b[32m",
  warning: "\u001b[33m",
  error: "\u001b[31m",
};
const RESET = "\u001b[0m";

function truncateUtf8(value: string, maximumBytes: number): string {
  if (Buffer.byteLength(value, "utf8") <= maximumBytes) {
    return value;
  }
  let truncated = value;
  const marker = "...[truncated]";
  while (truncated.length > 0 && Buffer.byteLength(`${truncated}${marker}`, "utf8") > maximumBytes) {
    truncated = truncated.slice(0, -1);
  }
  return `${truncated}${marker}`;
}

function sanitizeLogText(value: unknown, maximumBytes = MAX_LOG_LINE_BYTES): string {
  const sanitized = String(value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "_")
    .replace(/[\r\n]+/g, " ");
  return truncateUtf8(sanitized.startsWith("::") ? `_${sanitized}` : sanitized, maximumBytes);
}

function workflowEscape(value: unknown): string {
  return sanitizeLogText(value, MAX_DEBUG_LINE_BYTES)
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

function colorize(value: string, color: ColorName, environment: LogEnvironment = process.env): string {
  if (environment.NO_COLOR !== undefined && environment.NO_COLOR !== "") {
    return value;
  }
  return `${COLORS[color]}${value}${RESET}`;
}

function debugEnabled(environment: LogEnvironment = process.env): boolean {
  return environment.RUNNER_DEBUG === "1" || environment.ACTIONS_STEP_DEBUG === "true";
}

function info(message: string): void {
  process.stdout.write(`${sanitizeLogText(message)}\n`);
}

function success(message: string, environment: LogEnvironment = process.env): void {
  process.stdout.write(`${colorize(sanitizeLogText(message), "success", environment)}\n`);
}

function warning(message: string): void {
  process.stdout.write(`::warning::${workflowEscape(message)}\n`);
}

function error(message: string): void {
  process.stderr.write(`::error::${workflowEscape(message)}\n`);
}

function debug(message: string, environment: LogEnvironment = process.env): void {
  if (!debugEnabled(environment)) {
    return;
  }
  process.stdout.write(`::debug::${workflowEscape(message)}\n`);
}

function debugGroup(title: string, lines: unknown[], environment: LogEnvironment = process.env): void {
  if (!debugEnabled(environment)) {
    return;
  }
  process.stdout.write(`::group::${workflowEscape(title)}\n`);
  for (const line of lines) {
    process.stdout.write(`${sanitizeLogText(line, MAX_DEBUG_LINE_BYTES)}\n`);
  }
  process.stdout.write("::endgroup::\n");
}

function formatAllowlistEntry(entry: any): string | undefined {
  if (entry === null || Array.isArray(entry) || typeof entry !== "object") {
    return undefined;
  }
  const destinationType = typeof entry.destination_type === "string" ? entry.destination_type : "unknown";
  const destination = typeof entry.destination === "string" ? entry.destination : "unknown";
  const protocol = typeof entry.protocol === "string" ? entry.protocol : "unknown";
  const port = typeof entry.port === "number" ? String(entry.port) : "unknown";
  return `${destinationType}:${destination}:${protocol}:${port}`;
}

function configLogDetails(rawConfig: string, usingDefault: boolean): ConfigLogDetails {
  const parsed = JSON.parse(rawConfig);
  const allowlist = Array.isArray(parsed.allowlist) ? parsed.allowlist : [];
  const mode = typeof parsed.mode === "string" ? parsed.mode : "unknown";
  return {
    mode,
    source: usingDefault ? "native inputs" : "raw config",
    containerPolicy: typeof parsed.container_policy === "string"
      ? parsed.container_policy
      : mode === "audit"
        ? "not used"
        : "disable",
    platformProfile: typeof parsed.platform_profile === "string"
      ? parsed.platform_profile
      : "github_hosted_workflow_bootstrap_v5",
    disableBroadGithubDomains: parsed.disable_broad_github_domains === true,
    allowlistCount: allowlist.length,
    allowlistDestinations: allowlist.map(formatAllowlistEntry).filter((value: unknown) => typeof value === "string"),
  };
}

function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return count === 1 ? singular : plural;
}

function setupLines(manifest: any, details: ConfigLogDetails): string[] {
  const version = typeof manifest.release_tag === "string" ? manifest.release_tag : "unknown";
  const modeIcon = details.mode === "audit" ? "👀" : "🔒";
  const policyPrefix = details.mode === "audit" ? "observing GitHub workflow traffic" : "GitHub workflow traffic";
  return [
    `🛡️ Fence ${version}`,
    `${modeIcon} Mode: ${details.mode}`,
    `🌐 Policy: ${policyPrefix} + ${details.allowlistCount} ${pluralize(details.allowlistCount, "allowlist entry", "allowlist entries")}`,
  ];
}

function readyLine(report: any): string {
  if (report.status === "protected_host_audit_observation") {
    return "✅ Fence ready: audit mode is observing traffic, not blocking it";
  }
  if (report.status === "protected_host_block_degraded") {
    return "✅ Fence ready: network restrictions active; passwordless sudo locked down; Docker/container access preserved";
  }
  return "✅ Fence ready: network restrictions active; passwordless sudo and Docker/container access locked down";
}

function postEvidenceLine(report: any, auditDestinationCount = 0): string | undefined {
  if (report.mode === "audit") {
    return `👀 Audit observed ${auditDestinationCount} would-block ${pluralize(auditDestinationCount, "destination")}; see Fence Summary`;
  }
  if (report.status === "protected_host_block_degraded") {
    return "⚠️ Limited assurance: Docker/container access was preserved";
  }
  return undefined;
}

module.exports = {
  colorize,
  configLogDetails,
  debug,
  debugEnabled,
  debugGroup,
  error,
  info,
  postEvidenceLine,
  readyLine,
  sanitizeLogText,
  setupLines,
  success,
  warning,
  workflowEscape,
};
