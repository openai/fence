use serde::Serialize;

pub const HOSTED_RUNNER_FINGERPRINT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct HostedRunnerFingerprintV1 {
    pub schema_version: u32,
    pub protected_target: &'static str,
    pub status: &'static str,
    pub observation_method: &'static str,
    pub accepted: Option<AcceptedHostedRunnerFactsV1>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct AcceptedHostedRunnerFactsV1 {
    pub expected_principal: &'static str,
    pub nft_binary_path: &'static str,
    pub systemd_run_path: &'static str,
    pub sudo_grant_source_classification: &'static str,
    pub container_activation_paths: Vec<&'static str>,
    pub container_socket_paths: Vec<&'static str>,
}

pub fn hosted_runner_fingerprint_requirement() -> HostedRunnerFingerprintV1 {
    HostedRunnerFingerprintV1 {
        schema_version: HOSTED_RUNNER_FINGERPRINT_SCHEMA_VERSION,
        protected_target: "github_hosted_ubuntu_24_04_x86_64",
        status: "observation_pending",
        observation_method: "integration_read_only_observation",
        accepted: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_stays_pending_until_hosted_evidence_is_reviewed() {
        let requirement = hosted_runner_fingerprint_requirement();

        assert_eq!(requirement.schema_version, 1);
        assert_eq!(
            requirement.protected_target,
            "github_hosted_ubuntu_24_04_x86_64"
        );
        assert_eq!(requirement.status, "observation_pending");
        assert!(requirement.accepted.is_none());
    }
}
