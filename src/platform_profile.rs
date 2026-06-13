use serde::Serialize;

pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID: &str = "github_hosted_workflow_bootstrap_v2";
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_ACTIONS_SUFFIX_PATTERN: &str =
    "*.actions.githubusercontent.com";
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_RESULTS_STORAGE_PATTERN: &str =
    "productionresultssa<1-to-5-decimal-digits>.blob.core.windows.net";
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES: [&str; 1] =
    ["actions-results-receiver-production.githubapp.com"];
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_BROAD_GITHUB_HOSTNAMES: [&str; 4] = [
    "github.com",
    "api.github.com",
    "release-assets.githubusercontent.com",
    "hosted-compute-watchdog-prod-eus-01.githubapp.com",
];
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_CORE_ACTIONS_HOSTNAMES: [&str; 4] = [
    "vstoken.actions.githubusercontent.com",
    "pipelines.actions.githubusercontent.com",
    "payload.pipelines.actions.githubusercontent.com",
    "results-receiver.actions.githubusercontent.com",
];
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HOSTNAMES: [&str; 8] = [
    "github.com",
    "api.github.com",
    "release-assets.githubusercontent.com",
    "hosted-compute-watchdog-prod-eus-01.githubapp.com",
    "vstoken.actions.githubusercontent.com",
    "pipelines.actions.githubusercontent.com",
    "payload.pipelines.actions.githubusercontent.com",
    "results-receiver.actions.githubusercontent.com",
];
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_UPSTREAM_DNS: &str = "168.63.129.16:53";
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS: usize = 8;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS: usize = 2;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_RESULTS_STORAGE_AUTHORIZATIONS: usize = 4;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_AUTHORIZATIONS: usize = 32;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_DEPTH: u8 = 4;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_TTL_SECONDS: u32 = 300;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_REFRESH_INTERVAL_SECONDS: u64 = 5;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HTTPS_REFRESH_OVERLAP_SECONDS: u64 = 30;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsMediatedCompatibilityPlan {
    pub realization_status: &'static str,
    pub ruleset_preview_scope: &'static str,
    pub upstream_dns_policy: &'static str,
    pub upstream_dns: &'static str,
    pub bootstrap_hostnames: Vec<&'static str>,
    pub exact_compatibility_hostnames: Vec<&'static str>,
    pub bounded_actions_suffix_pattern: &'static str,
    pub max_dynamic_actions_suffix_authorizations: usize,
    pub max_dynamic_actions_suffix_prefix_labels: usize,
    pub runner_authorized_results_storage_pattern: &'static str,
    pub max_runner_authorized_results_storage_accounts: usize,
    pub results_storage_authorization_origin: &'static str,
    pub forwarded_query_types: Vec<&'static str>,
    pub max_derived_cname_authorizations: usize,
    pub max_derived_cname_depth: u8,
    pub max_observed_ttl_seconds: u32,
    pub bootstrap_refresh_interval_seconds: u64,
    pub https_rule_refresh_overlap_seconds: u64,
    pub https_materialization_protocol: &'static str,
    pub https_materialization_port: u16,
}

pub fn github_hosted_workflow_bootstrap_hostnames(
    disable_broad_github_domains: bool,
) -> Vec<&'static str> {
    if disable_broad_github_domains {
        GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_CORE_ACTIONS_HOSTNAMES.to_vec()
    } else {
        GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HOSTNAMES.to_vec()
    }
}

pub fn github_hosted_workflow_bootstrap_dns_mediation_plan(
    disable_broad_github_domains: bool,
) -> DnsMediatedCompatibilityPlan {
    DnsMediatedCompatibilityPlan {
        realization_status: "trusted_launcher_runtime_materialization_required",
        ruleset_preview_scope: "base_policy_before_dns_mediated_runtime_materialization",
        upstream_dns_policy: "root_resident_mediator_only_udp_53",
        upstream_dns: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_UPSTREAM_DNS,
        bootstrap_hostnames: github_hosted_workflow_bootstrap_hostnames(
            disable_broad_github_domains,
        ),
        exact_compatibility_hostnames:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES.to_vec(),
        bounded_actions_suffix_pattern: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_ACTIONS_SUFFIX_PATTERN,
        max_dynamic_actions_suffix_authorizations:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS,
        max_dynamic_actions_suffix_prefix_labels:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS,
        runner_authorized_results_storage_pattern:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_RESULTS_STORAGE_PATTERN,
        max_runner_authorized_results_storage_accounts:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_RESULTS_STORAGE_AUTHORIZATIONS,
        results_storage_authorization_origin: "pinned_runner_worker_dns",
        forwarded_query_types: vec!["a", "aaaa"],
        max_derived_cname_authorizations:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_AUTHORIZATIONS,
        max_derived_cname_depth: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_DEPTH,
        max_observed_ttl_seconds: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_TTL_SECONDS,
        bootstrap_refresh_interval_seconds:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_REFRESH_INTERVAL_SECONDS,
        https_rule_refresh_overlap_seconds:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HTTPS_REFRESH_OVERLAP_SECONDS,
        https_materialization_protocol: "tcp",
        https_materialization_port: 443,
    }
}

pub fn reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan(
    plan: &DnsMediatedCompatibilityPlan,
) -> bool {
    plan == &github_hosted_workflow_bootstrap_dns_mediation_plan(false)
        || plan == &github_hosted_workflow_bootstrap_dns_mediation_plan(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_bootstrap_profile_descriptor_is_bounded_and_versioned() {
        let profile = github_hosted_workflow_bootstrap_dns_mediation_plan(false);
        let opt_out = github_hosted_workflow_bootstrap_dns_mediation_plan(true);

        assert_eq!(
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
            "github_hosted_workflow_bootstrap_v2"
        );
        assert_eq!(
            profile.bootstrap_hostnames,
            [
                "github.com",
                "api.github.com",
                "release-assets.githubusercontent.com",
                "hosted-compute-watchdog-prod-eus-01.githubapp.com",
                "vstoken.actions.githubusercontent.com",
                "pipelines.actions.githubusercontent.com",
                "payload.pipelines.actions.githubusercontent.com",
                "results-receiver.actions.githubusercontent.com",
            ]
        );
        assert_eq!(profile.exact_compatibility_hostnames.len(), 1);
        assert_eq!(profile.max_dynamic_actions_suffix_authorizations, 8);
        assert_eq!(profile.max_dynamic_actions_suffix_prefix_labels, 2);
        assert_eq!(profile.max_runner_authorized_results_storage_accounts, 4);
        assert_eq!(
            profile.runner_authorized_results_storage_pattern,
            "productionresultssa<1-to-5-decimal-digits>.blob.core.windows.net"
        );
        assert_eq!(profile.forwarded_query_types, ["a", "aaaa"]);
        assert_eq!(profile.https_materialization_protocol, "tcp");
        assert_eq!(profile.https_materialization_port, 443);
        assert_eq!(
            opt_out.bootstrap_hostnames,
            [
                "vstoken.actions.githubusercontent.com",
                "pipelines.actions.githubusercontent.com",
                "payload.pipelines.actions.githubusercontent.com",
                "results-receiver.actions.githubusercontent.com",
            ]
        );
        assert!(reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan(&profile));
        assert!(reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan(&opt_out));
    }
}
