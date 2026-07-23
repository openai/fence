use serde::Serialize;

pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID: &str = "github_hosted_workflow_bootstrap_v5";
pub const AZURE_WIRESERVER_ADDRESS: &str = "168.63.129.16";
pub const AZURE_WIRESERVER_ROOT_UID: u32 = 0;
pub const AZURE_WIRESERVER_TCP_PORTS: [u16; 2] = [80, 32526];
pub const AZURE_INSTANCE_METADATA_ADDRESS: &str = "169.254.169.254";
pub const AZURE_INSTANCE_METADATA_TCP_PORT: u16 = 80;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_ACTIONS_SUFFIX_PATTERN: &str =
    "*.actions.githubusercontent.com";
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_GITHUBAPP_SUFFIX_PATTERN: &str = "*.githubapp.com";
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_RESULTS_STORAGE_PATTERN: &str =
    "productionresultssa<1-to-5-decimal-digits>.blob.core.windows.net";
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_TRUSTED_RESULTS_STORAGE_HOSTNAME: &str =
    "productionresultssa19.blob.core.windows.net";
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES: [&str; 2] = [
    "actions-results-receiver-production.githubapp.com",
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_TRUSTED_RESULTS_STORAGE_HOSTNAME,
];
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_BROAD_GITHUB_HOSTNAMES: [&str; 4] = [
    "github.com",
    "api.github.com",
    "release-assets.githubusercontent.com",
    "hosted-compute-watchdog-prod-eus-01.githubapp.com",
];
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_OPTIONAL_HOSTNAMES: [&str; 1] =
    ["hosted-compute-watchdog-prod-eus-01.githubapp.com"];
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
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_GITHUBAPP_SUFFIX_AUTHORIZATIONS: usize = 8;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_GITHUBAPP_SUFFIX_PREFIX_LABELS: usize = 1;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_RESULTS_STORAGE_AUTHORIZATIONS: usize = 4;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_AUTHORIZATIONS: usize = 32;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DERIVED_CNAME_DEPTH: u8 = 4;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_TTL_SECONDS: u32 = 300;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_REFRESH_INTERVAL_SECONDS: u64 = 5;
pub const GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HTTPS_REFRESH_OVERLAP_SECONDS: u64 = 30;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RootPlatformServicePermission {
    pub subject: &'static str,
    pub root_uid: u32,
    pub destination: &'static str,
    pub protocol: &'static str,
    pub port: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct SharedPlatformServicePermission {
    pub subject: &'static str,
    pub destination: &'static str,
    pub protocol: &'static str,
    pub port: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DnsMediatedCompatibilityPlan {
    pub realization_status: &'static str,
    pub ruleset_preview_scope: &'static str,
    pub upstream_dns_policy: &'static str,
    pub upstream_dns: &'static str,
    pub root_platform_service_permissions: Vec<RootPlatformServicePermission>,
    pub shared_platform_service_permissions: Vec<SharedPlatformServicePermission>,
    pub bootstrap_hostnames: Vec<&'static str>,
    pub exact_compatibility_hostnames: Vec<&'static str>,
    pub bounded_actions_suffix_pattern: &'static str,
    pub max_dynamic_actions_suffix_authorizations: usize,
    pub max_dynamic_actions_suffix_prefix_labels: usize,
    pub bounded_githubapp_suffix_pattern: Option<&'static str>,
    pub max_dynamic_githubapp_suffix_authorizations: usize,
    pub max_dynamic_githubapp_suffix_prefix_labels: usize,
    pub runner_authorized_results_storage_pattern: &'static str,
    pub max_runner_authorized_results_storage_accounts: usize,
    pub results_storage_authorization_origin: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_artifact_results_storage_authorization_origin: Option<&'static str>,
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

pub fn is_optional_github_hosted_workflow_bootstrap_hostname(hostname: &str) -> bool {
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_OPTIONAL_HOSTNAMES.contains(&hostname)
}

pub(crate) fn matches_results_storage_hostname(hostname: &str) -> bool {
    let Some(account) = hostname
        .strip_prefix("productionresultssa")
        .and_then(|value| value.strip_suffix(".blob.core.windows.net"))
    else {
        return false;
    };
    !account.is_empty() && account.len() <= 5 && account.bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn is_runner_authorized_results_storage_hostname(hostname: &str) -> bool {
    hostname != GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_TRUSTED_RESULTS_STORAGE_HOSTNAME
        && matches_results_storage_hostname(hostname)
}

pub fn github_hosted_workflow_bootstrap_dns_mediation_plan(
    disable_broad_github_domains: bool,
    allow_github_artifacts: bool,
) -> DnsMediatedCompatibilityPlan {
    DnsMediatedCompatibilityPlan {
        realization_status: "trusted_launcher_runtime_materialization_required",
        ruleset_preview_scope: "base_policy_before_dns_mediated_runtime_materialization",
        upstream_dns_policy: "root_resident_mediator_only_udp_53",
        upstream_dns: GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_UPSTREAM_DNS,
        root_platform_service_permissions: AZURE_WIRESERVER_TCP_PORTS
            .into_iter()
            .map(|port| RootPlatformServicePermission {
                subject: "root_uid",
                root_uid: AZURE_WIRESERVER_ROOT_UID,
                destination: AZURE_WIRESERVER_ADDRESS,
                protocol: "tcp",
                port,
            })
            .collect(),
        shared_platform_service_permissions: vec![SharedPlatformServicePermission {
            subject: "host_and_forwarded_traffic",
            destination: AZURE_INSTANCE_METADATA_ADDRESS,
            protocol: "tcp",
            port: AZURE_INSTANCE_METADATA_TCP_PORT,
        }],
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
        bounded_githubapp_suffix_pattern: (!disable_broad_github_domains)
            .then_some(GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_GITHUBAPP_SUFFIX_PATTERN),
        max_dynamic_githubapp_suffix_authorizations:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_GITHUBAPP_SUFFIX_AUTHORIZATIONS,
        max_dynamic_githubapp_suffix_prefix_labels:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_DYNAMIC_GITHUBAPP_SUFFIX_PREFIX_LABELS,
        runner_authorized_results_storage_pattern:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_RESULTS_STORAGE_PATTERN,
        max_runner_authorized_results_storage_accounts:
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_MAX_RESULTS_STORAGE_AUTHORIZATIONS,
        results_storage_authorization_origin: "pinned_runner_worker_dns",
        github_artifact_results_storage_authorization_origin: allow_github_artifacts
            .then_some("opt_in_github_artifact_dns"),
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
    [(false, false), (false, true), (true, false), (true, true)]
        .into_iter()
        .any(|(disable_broad_github_domains, allow_github_artifacts)| {
            plan == &github_hosted_workflow_bootstrap_dns_mediation_plan(
                disable_broad_github_domains,
                allow_github_artifacts,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_bootstrap_profile_descriptor_is_bounded_and_versioned() {
        let profile = github_hosted_workflow_bootstrap_dns_mediation_plan(false, false);
        let opt_out = github_hosted_workflow_bootstrap_dns_mediation_plan(true, false);
        let artifact_profile = github_hosted_workflow_bootstrap_dns_mediation_plan(false, true);
        let artifact_opt_out = github_hosted_workflow_bootstrap_dns_mediation_plan(true, true);

        assert_eq!(
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_PROFILE_ID,
            "github_hosted_workflow_bootstrap_v5"
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
        assert_eq!(
            profile.exact_compatibility_hostnames,
            [
                "actions-results-receiver-production.githubapp.com",
                "productionresultssa19.blob.core.windows.net",
            ]
        );
        assert_eq!(profile.max_dynamic_actions_suffix_authorizations, 8);
        assert_eq!(profile.max_dynamic_actions_suffix_prefix_labels, 2);
        assert_eq!(
            profile.bounded_githubapp_suffix_pattern,
            Some("*.githubapp.com")
        );
        assert_eq!(profile.max_dynamic_githubapp_suffix_authorizations, 8);
        assert_eq!(profile.max_dynamic_githubapp_suffix_prefix_labels, 1);
        assert_eq!(opt_out.bounded_githubapp_suffix_pattern, None);
        assert_eq!(profile.max_runner_authorized_results_storage_accounts, 4);
        assert_eq!(
            profile.runner_authorized_results_storage_pattern,
            "productionresultssa<1-to-5-decimal-digits>.blob.core.windows.net"
        );
        assert_eq!(
            profile.results_storage_authorization_origin,
            "pinned_runner_worker_dns"
        );
        assert_eq!(
            opt_out.results_storage_authorization_origin,
            "pinned_runner_worker_dns"
        );
        assert_eq!(
            artifact_profile.results_storage_authorization_origin,
            "pinned_runner_worker_dns"
        );
        assert_eq!(
            artifact_opt_out.results_storage_authorization_origin,
            "pinned_runner_worker_dns"
        );
        assert_eq!(
            profile.github_artifact_results_storage_authorization_origin,
            None
        );
        assert_eq!(
            opt_out.github_artifact_results_storage_authorization_origin,
            None
        );
        assert_eq!(
            artifact_profile.github_artifact_results_storage_authorization_origin,
            Some("opt_in_github_artifact_dns")
        );
        assert_eq!(
            artifact_opt_out.github_artifact_results_storage_authorization_origin,
            Some("opt_in_github_artifact_dns")
        );
        assert_eq!(
            artifact_profile.max_runner_authorized_results_storage_accounts,
            4
        );
        assert_eq!(
            artifact_opt_out.max_runner_authorized_results_storage_accounts,
            4
        );
        assert_eq!(
            artifact_profile.bounded_githubapp_suffix_pattern,
            Some("*.githubapp.com")
        );
        assert_eq!(artifact_opt_out.bounded_githubapp_suffix_pattern, None);
        assert_eq!(profile.forwarded_query_types, ["a", "aaaa"]);
        assert_eq!(profile.https_materialization_protocol, "tcp");
        assert_eq!(profile.https_materialization_port, 443);
        assert_eq!(profile.root_platform_service_permissions.len(), 2);
        assert_eq!(
            profile.root_platform_service_permissions,
            opt_out.root_platform_service_permissions
        );
        assert_eq!(
            profile.root_platform_service_permissions[0],
            RootPlatformServicePermission {
                subject: "root_uid",
                root_uid: 0,
                destination: "168.63.129.16",
                protocol: "tcp",
                port: 80,
            }
        );
        assert_eq!(profile.root_platform_service_permissions[1].port, 32526);
        assert_eq!(
            profile.shared_platform_service_permissions,
            opt_out.shared_platform_service_permissions
        );
        assert_eq!(
            profile.shared_platform_service_permissions,
            [SharedPlatformServicePermission {
                subject: "host_and_forwarded_traffic",
                destination: "169.254.169.254",
                protocol: "tcp",
                port: 80,
            }]
        );
        assert!(is_optional_github_hosted_workflow_bootstrap_hostname(
            "hosted-compute-watchdog-prod-eus-01.githubapp.com"
        ));
        assert!(!is_optional_github_hosted_workflow_bootstrap_hostname(
            "github.com"
        ));
        for hostname in [
            "productionresultssa0.blob.core.windows.net",
            "productionresultssa17.blob.core.windows.net",
            "productionresultssa99999.blob.core.windows.net",
        ] {
            assert!(matches_results_storage_hostname(hostname));
        }
        for hostname in [
            "productionresultssa.blob.core.windows.net",
            "productionresultssa100000.blob.core.windows.net",
            "productionresults-17.blob.core.windows.net",
            "productionresultssa17.example.com",
            "prefix.productionresultssa17.blob.core.windows.net",
        ] {
            assert!(!matches_results_storage_hostname(hostname));
        }
        assert!(!is_runner_authorized_results_storage_hostname(
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_TRUSTED_RESULTS_STORAGE_HOSTNAME
        ));
        assert!(is_runner_authorized_results_storage_hostname(
            "productionresultssa17.blob.core.windows.net"
        ));
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
        assert!(reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan(&artifact_profile));
        assert!(reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan(&artifact_opt_out));

        let mut unreviewed = artifact_profile;
        unreviewed.results_storage_authorization_origin = "workflow_dns";
        assert!(!reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan(&unreviewed));

        let mut unreviewed_artifact = artifact_opt_out;
        unreviewed_artifact.github_artifact_results_storage_authorization_origin =
            Some("workflow_dns");
        assert!(
            !reviewed_github_hosted_workflow_bootstrap_dns_mediation_plan(&unreviewed_artifact)
        );
    }
}
