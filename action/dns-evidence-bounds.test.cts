"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { validateDnsEvidence } = require("./lib.cts");
const { validateDnsEvidenceBounds } = require("./post.cts");

function residentHealth() {
  return {
    status: "healthy",
    resident_pid: 4242,
    verification_sequence: 9,
    last_successful_verification_unix_milliseconds: Date.now() - 1_000,
    verification_interval_seconds: 5,
    workers: [
      { name: "docker_tcp_dns", status: "running" },
      { name: "docker_udp_dns", status: "running" },
      { name: "host_tcp_dns", status: "running" },
      { name: "host_udp_dns", status: "running" },
      { name: "process_attribution", status: "running" },
    ],
  };
}

function report() {
  return {
    status: "protected_host_block",
    mode: "block",
    allow_github_artifacts: false,
    platform_profile_id: "github_hosted_workflow_bootstrap_v5",
    profile_realization_id: "github_hosted_workflow_bootstrap_dns_provenance_v5",
    protection_available: true,
    container_status: "disabled_verified",
    resident_health: residentHealth(),
  };
}

function dnsEvidence(currentReport, overrides = {}) {
  return {
    runtime_evidence_schema_version: 5,
    status: currentReport.status,
    mode: currentReport.mode,
    allow_github_artifacts: currentReport.allow_github_artifacts,
    platform_profile_id: currentReport.platform_profile_id,
    profile_realization_id: currentReport.profile_realization_id,
    protection_available: currentReport.protection_available,
    resident_health: currentReport.resident_health,
    routing_status: "active",
    host_dns_routing: "direct_client_to_root_resident_mediator",
    docker_dns_routing: "local_root_resident_mediator",
    answer_attribution_status: "bounded_reportable_hostname_answers_only",
    proxy_policy_status: "block_forwards_exact_roots_bounded_user_wildcard_names_actions_suffix_names_githubapp_suffix_names_results_storage_and_bounded_cname_descendants",
    hostname_policy: {
      exact: [],
      user_wildcards: [],
      allow_dynamic_githubapp_suffix: true,
      allow_github_artifacts: false,
    },
    observations: [],
    observations_truncated: false,
    bounded_user_wildcard_authorizations: [],
    bounded_user_wildcard_authorizations_truncated: false,
    user_wildcard_request_rejections: 0,
    runner_authorized_results_storage: [],
    runner_authorized_results_storage_truncated: false,
    results_storage_authorization_count: 0,
    results_storage_attribution_failures: 0,
    results_storage_request_rejections: 0,
    limitations: [],
    ...overrides,
  };
}

function validateEvidence(evidence, currentReport) {
  return validateDnsEvidenceBounds(validateDnsEvidence(evidence, currentReport));
}

test("bounds retained DNS observations to the Rust evidence limit", () => {
  const currentReport = report();
  const observations = Array.from({ length: 256 }, (_, index) => ({
    hostname: `host-${index}.example.com`,
    policy_classification: "outside_policy",
  }));

  assert.doesNotThrow(() => validateEvidence(
    dnsEvidence(currentReport, { observations }),
    currentReport,
  ));
  assert.throws(
    () => validateEvidence(
      dnsEvidence(currentReport, {
        observations: [
          ...observations,
          { hostname: "host-256.example.com", policy_classification: "outside_policy" },
        ],
      }),
      currentReport,
    ),
    /retained DNS evidence bounds/,
  );
});

test("bounds retained addresses per DNS observation", () => {
  const currentReport = report();
  const addresses = Array.from({ length: 32 }, (_, index) => `192.0.2.${index + 1}`);

  assert.doesNotThrow(() => validateEvidence(
    dnsEvidence(currentReport, {
      observations: [{
        hostname: "api.example.com",
        policy_classification: "outside_policy",
        resolved_addresses: addresses,
      }],
    }),
    currentReport,
  ));
  assert.throws(
    () => validateEvidence(
      dnsEvidence(currentReport, {
        observations: [{
          hostname: "api.example.com",
          policy_classification: "outside_policy",
          resolved_addresses: [...addresses, "198.51.100.1"],
        }],
      }),
      currentReport,
    ),
    /retained DNS evidence bounds/,
  );
});
