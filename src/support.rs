use crate::IMPLEMENTATION_PHASE;
use crate::hosted_runner::{HostedRunnerFingerprintV3, hosted_runner_fingerprint_requirement};
use serde::Serialize;
use std::path::Path;

const NFT_BINARY_PATH: &str = "/usr/sbin/nft";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostIdentity {
    pub os: String,
    pub architecture: String,
}

pub trait SupportProvider {
    fn host_identity(&self) -> HostIdentity;
    fn network_backend_observation(&self) -> NetworkBackendObservation;
}

#[derive(Debug, Default)]
pub struct SystemSupportProvider;

impl SupportProvider for SystemSupportProvider {
    fn host_identity(&self) -> HostIdentity {
        HostIdentity {
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
        }
    }

    fn network_backend_observation(&self) -> NetworkBackendObservation {
        NetworkBackendObservation {
            required: "native_nftables",
            nft_binary_expected_path: NFT_BINARY_PATH,
            nft_binary_present: Path::new(NFT_BINARY_PATH).is_file(),
            nft_version_observed: None,
            privileged_semantic_proof: "integration_test_required",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct NetworkBackendObservation {
    pub required: &'static str,
    pub nft_binary_expected_path: &'static str,
    pub nft_binary_present: bool,
    pub nft_version_observed: Option<String>,
    pub privileged_semantic_proof: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct SupportData {
    pub implementation_phase: &'static str,
    pub host_os: String,
    pub host_architecture: String,
    pub intended_protected_target_match: bool,
    pub protection_available: bool,
    pub reasons: Vec<&'static str>,
    pub deferred_capability_probes: Vec<&'static str>,
    pub network_backend: NetworkBackendObservation,
    pub hosted_runner_fingerprint: HostedRunnerFingerprintV3,
}

pub fn inspect_support(provider: &dyn SupportProvider) -> SupportData {
    let identity = provider.host_identity();
    SupportData {
        implementation_phase: IMPLEMENTATION_PHASE,
        intended_protected_target_match: identity.os == "linux"
            && identity.architecture == "x86_64",
        host_os: identity.os,
        host_architecture: identity.architecture,
        protection_available: false,
        reasons: vec![
            "protected_standard_block_requires_trusted_launcher",
            "hosted_runner_fingerprint_checked_during_activation",
            "activation_readiness_not_established_by_support_probe",
        ],
        deferred_capability_probes: vec![
            "trusted_transient_systemd_service_activation",
            "hosted_runner_fingerprint_activation_check",
            "standard_block_readiness",
        ],
        network_backend: provider.network_backend_observation(),
        hosted_runner_fingerprint: hosted_runner_fingerprint_requirement(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedProvider {
        os: &'static str,
        architecture: &'static str,
    }

    impl SupportProvider for FixedProvider {
        fn host_identity(&self) -> HostIdentity {
            HostIdentity {
                os: self.os.to_owned(),
                architecture: self.architecture.to_owned(),
            }
        }

        fn network_backend_observation(&self) -> NetworkBackendObservation {
            NetworkBackendObservation {
                required: "native_nftables",
                nft_binary_expected_path: NFT_BINARY_PATH,
                nft_binary_present: self.os == "linux",
                nft_version_observed: None,
                privileged_semantic_proof: "integration_test_required",
            }
        }
    }

    #[test]
    fn intended_target_still_reports_no_active_protection_from_read_only_probe() {
        let data = inspect_support(&FixedProvider {
            os: "linux",
            architecture: "x86_64",
        });

        assert!(data.intended_protected_target_match);
        assert!(!data.protection_available);
        assert_eq!(
            data.reasons,
            vec![
                "protected_standard_block_requires_trusted_launcher",
                "hosted_runner_fingerprint_checked_during_activation",
                "activation_readiness_not_established_by_support_probe"
            ]
        );
        assert!(data.network_backend.nft_binary_present);
        assert_eq!(
            data.hosted_runner_fingerprint.status,
            "accepted_reference_not_checked"
        );
    }

    #[test]
    fn unsupported_target_is_observed_without_claim() {
        let data = inspect_support(&FixedProvider {
            os: "macos",
            architecture: "aarch64",
        });

        assert!(!data.intended_protected_target_match);
        assert!(!data.protection_available);
        assert!(!data.network_backend.nft_binary_present);
    }

    #[test]
    fn system_provider_returns_runtime_identity() {
        let identity = SystemSupportProvider.host_identity();
        let backend = SystemSupportProvider.network_backend_observation();

        assert_eq!(identity.os, std::env::consts::OS);
        assert_eq!(identity.architecture, std::env::consts::ARCH);
        assert_eq!(backend.nft_binary_expected_path, NFT_BINARY_PATH);
        assert_eq!(
            backend.nft_binary_present,
            Path::new(NFT_BINARY_PATH).is_file()
        );
    }
}
