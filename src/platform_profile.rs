use serde::Serialize;

pub const GITHUB_HOSTED_JOB_STATUS_PROFILE_ID: &str = "github_hosted_job_status_v1";
pub const GITHUB_HOSTED_JOB_STATUS_ACTIONS_SUFFIX_PATTERN: &str = "*.actions.githubusercontent.com";
pub const GITHUB_HOSTED_JOB_STATUS_EXACT_COMPATIBILITY_HOSTNAMES: [&str; 1] =
    ["actions-results-receiver-production.githubapp.com"];
pub const GITHUB_HOSTED_JOB_STATUS_BOOTSTRAP_HOSTNAMES: [&str; 4] = [
    "vstoken.actions.githubusercontent.com",
    "pipelines.actions.githubusercontent.com",
    "payload.pipelines.actions.githubusercontent.com",
    "results-receiver.actions.githubusercontent.com",
];
pub const GITHUB_HOSTED_JOB_STATUS_UPSTREAM_DNS: &str = "168.63.129.16:53";
pub const GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS: usize = 8;
pub const GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS: usize = 2;
pub const GITHUB_HOSTED_JOB_STATUS_MAX_DERIVED_CNAME_AUTHORIZATIONS: usize = 32;
pub const GITHUB_HOSTED_JOB_STATUS_MAX_DERIVED_CNAME_DEPTH: u8 = 4;
pub const GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_TTL_SECONDS: u32 = 300;
pub const GITHUB_HOSTED_JOB_STATUS_REFRESH_INTERVAL_SECONDS: u64 = 5;
pub const GITHUB_HOSTED_JOB_STATUS_HTTPS_REFRESH_OVERLAP_SECONDS: u64 = 30;

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
    pub forwarded_query_types: Vec<&'static str>,
    pub max_derived_cname_authorizations: usize,
    pub max_derived_cname_depth: u8,
    pub max_observed_ttl_seconds: u32,
    pub bootstrap_refresh_interval_seconds: u64,
    pub https_rule_refresh_overlap_seconds: u64,
    pub https_materialization_protocol: &'static str,
    pub https_materialization_port: u16,
}

pub fn github_hosted_job_status_dns_mediation_plan() -> DnsMediatedCompatibilityPlan {
    DnsMediatedCompatibilityPlan {
        realization_status: "trusted_launcher_runtime_materialization_required",
        ruleset_preview_scope: "base_policy_before_dns_mediated_runtime_materialization",
        upstream_dns_policy: "root_resident_mediator_only_udp_53",
        upstream_dns: GITHUB_HOSTED_JOB_STATUS_UPSTREAM_DNS,
        bootstrap_hostnames: GITHUB_HOSTED_JOB_STATUS_BOOTSTRAP_HOSTNAMES.to_vec(),
        exact_compatibility_hostnames: GITHUB_HOSTED_JOB_STATUS_EXACT_COMPATIBILITY_HOSTNAMES
            .to_vec(),
        bounded_actions_suffix_pattern: GITHUB_HOSTED_JOB_STATUS_ACTIONS_SUFFIX_PATTERN,
        max_dynamic_actions_suffix_authorizations:
            GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_ACTIONS_SUFFIX_AUTHORIZATIONS,
        max_dynamic_actions_suffix_prefix_labels:
            GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_ACTIONS_SUFFIX_PREFIX_LABELS,
        forwarded_query_types: vec!["a", "aaaa"],
        max_derived_cname_authorizations: GITHUB_HOSTED_JOB_STATUS_MAX_DERIVED_CNAME_AUTHORIZATIONS,
        max_derived_cname_depth: GITHUB_HOSTED_JOB_STATUS_MAX_DERIVED_CNAME_DEPTH,
        max_observed_ttl_seconds: GITHUB_HOSTED_JOB_STATUS_MAX_DYNAMIC_TTL_SECONDS,
        bootstrap_refresh_interval_seconds: GITHUB_HOSTED_JOB_STATUS_REFRESH_INTERVAL_SECONDS,
        https_rule_refresh_overlap_seconds: GITHUB_HOSTED_JOB_STATUS_HTTPS_REFRESH_OVERLAP_SECONDS,
        https_materialization_protocol: "tcp",
        https_materialization_port: 443,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_status_profile_descriptor_is_bounded_and_versioned() {
        let profile = github_hosted_job_status_dns_mediation_plan();

        assert_eq!(
            GITHUB_HOSTED_JOB_STATUS_PROFILE_ID,
            "github_hosted_job_status_v1"
        );
        assert_eq!(profile.bootstrap_hostnames.len(), 4);
        assert_eq!(profile.exact_compatibility_hostnames.len(), 1);
        assert_eq!(profile.max_dynamic_actions_suffix_authorizations, 8);
        assert_eq!(profile.max_dynamic_actions_suffix_prefix_labels, 2);
        assert_eq!(profile.forwarded_query_types, ["a", "aaaa"]);
        assert_eq!(profile.https_materialization_protocol, "tcp");
        assert_eq!(profile.https_materialization_port, 443);
    }
}
