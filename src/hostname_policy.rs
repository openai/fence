use crate::config::{DestinationType, NormalizedConfig, Protocol};
use crate::platform_profile::{
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES,
    GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HOSTNAMES, github_hosted_workflow_bootstrap_hostnames,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostnamePolicyOrigin {
    Platform,
    User,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct HostnameTransport {
    pub protocol: Protocol,
    pub port: u16,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExactHostnamePolicy {
    pub hostname: String,
    pub origins: Vec<HostnamePolicyOrigin>,
    pub transports: Vec<HostnameTransport>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RuntimeHostnamePolicy {
    pub exact: Vec<ExactHostnamePolicy>,
    pub allow_dynamic_githubapp_suffix: bool,
}

impl RuntimeHostnamePolicy {
    pub fn exact_entry(&self, hostname: &str) -> Option<&ExactHostnamePolicy> {
        self.exact
            .binary_search_by(|entry| entry.hostname.as_str().cmp(hostname))
            .ok()
            .map(|index| &self.exact[index])
    }

    pub fn platform_hostnames(&self) -> Vec<String> {
        GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_HOSTNAMES
            .iter()
            .chain(GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES.iter())
            .filter(|hostname| {
                self.exact_entry(hostname)
                    .is_some_and(|entry| entry.origins.contains(&HostnamePolicyOrigin::Platform))
            })
            .map(|hostname| (*hostname).to_owned())
            .collect()
    }
}

pub fn build_runtime_hostname_policy(config: &NormalizedConfig) -> RuntimeHostnamePolicy {
    let mut entries =
        BTreeMap::<String, (BTreeSet<HostnamePolicyOrigin>, BTreeSet<HostnameTransport>)>::new();

    for hostname in github_hosted_workflow_bootstrap_hostnames(config.disable_broad_github_domains)
        .into_iter()
        .chain(
            GITHUB_HOSTED_WORKFLOW_BOOTSTRAP_EXACT_COMPATIBILITY_HOSTNAMES
                .iter()
                .copied(),
        )
    {
        let (origins, transports) = entries.entry(hostname.to_owned()).or_default();
        origins.insert(HostnamePolicyOrigin::Platform);
        transports.insert(HostnameTransport {
            protocol: Protocol::Tcp,
            port: 443,
        });
    }

    for allowance in &config.requested_allowances {
        if allowance.destination_type != DestinationType::Hostname {
            continue;
        }
        let (origins, transports) = entries.entry(allowance.destination.clone()).or_default();
        origins.insert(HostnamePolicyOrigin::User);
        transports.insert(HostnameTransport {
            protocol: allowance.protocol,
            port: allowance.port,
        });
    }

    RuntimeHostnamePolicy {
        exact: entries
            .into_iter()
            .map(|(hostname, (origins, transports))| ExactHostnamePolicy {
                hostname,
                origins: origins.into_iter().collect(),
                transports: transports.into_iter().collect(),
            })
            .collect(),
        allow_dynamic_githubapp_suffix: !config.disable_broad_github_domains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_and_normalize;

    fn parse(json: &str) -> NormalizedConfig {
        parse_and_normalize(json.as_bytes()).unwrap()
    }

    #[test]
    fn merges_platform_and_user_hosts_without_losing_transports() {
        let policy = build_runtime_hostname_policy(&parse(
            r#"{"schema_version":1,"mode":"block","invocation_id":"merge","allowlist":[{"destination_type":"hostname","destination":"github.com","protocol":"udp","port":53},{"destination_type":"hostname","destination":"example.com","protocol":"tcp","port":8443},{"destination_type":"hostname","destination":"example.com","protocol":"udp","port":53}]}"#,
        ));

        let github = policy.exact_entry("github.com").unwrap();
        assert_eq!(
            github.origins,
            [HostnamePolicyOrigin::Platform, HostnamePolicyOrigin::User]
        );
        assert_eq!(
            github.transports,
            [
                HostnameTransport {
                    protocol: Protocol::Tcp,
                    port: 443,
                },
                HostnameTransport {
                    protocol: Protocol::Udp,
                    port: 53,
                },
            ]
        );

        let example = policy.exact_entry("example.com").unwrap();
        assert_eq!(example.origins, [HostnamePolicyOrigin::User]);
        assert_eq!(example.transports.len(), 2);
        assert!(
            policy
                .exact_entry("actions-results-receiver-production.githubapp.com")
                .is_some()
        );
        assert_eq!(
            policy.platform_hostnames(),
            [
                "github.com",
                "api.github.com",
                "release-assets.githubusercontent.com",
                "hosted-compute-watchdog-prod-eus-01.githubapp.com",
                "vstoken.actions.githubusercontent.com",
                "pipelines.actions.githubusercontent.com",
                "payload.pipelines.actions.githubusercontent.com",
                "results-receiver.actions.githubusercontent.com",
                "actions-results-receiver-production.githubapp.com",
                "productionresultssa19.blob.core.windows.net",
            ]
        );
        assert!(policy.allow_dynamic_githubapp_suffix);
    }

    #[test]
    fn broad_domain_opt_out_preserves_core_and_exact_compatibility_hosts() {
        let policy = build_runtime_hostname_policy(&parse(
            r#"{"schema_version":1,"mode":"block","invocation_id":"opt-out","disable_broad_github_domains":true,"allowlist":[]}"#,
        ));

        assert!(policy.exact_entry("github.com").is_none());
        assert!(
            policy
                .exact_entry("hosted-compute-watchdog-prod-eus-01.githubapp.com")
                .is_none()
        );
        assert!(
            policy
                .exact_entry("results-receiver.actions.githubusercontent.com")
                .is_some()
        );
        assert!(
            policy
                .exact_entry("actions-results-receiver-production.githubapp.com")
                .is_some()
        );
        assert_eq!(
            policy.platform_hostnames(),
            [
                "vstoken.actions.githubusercontent.com",
                "pipelines.actions.githubusercontent.com",
                "payload.pipelines.actions.githubusercontent.com",
                "results-receiver.actions.githubusercontent.com",
                "actions-results-receiver-production.githubapp.com",
                "productionresultssa19.blob.core.windows.net",
            ]
        );
        assert!(!policy.allow_dynamic_githubapp_suffix);
    }
}
