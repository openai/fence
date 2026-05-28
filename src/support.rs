use serde::Serialize;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HostIdentity {
    pub os: String,
    pub architecture: String,
}

pub trait SupportProvider {
    fn host_identity(&self) -> HostIdentity;
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
}

pub fn inspect_support(provider: &dyn SupportProvider) -> SupportData {
    let identity = provider.host_identity();
    SupportData {
        implementation_phase: "phase1",
        intended_protected_target_match: identity.os == "linux"
            && identity.architecture == "x86_64",
        host_os: identity.os,
        host_architecture: identity.architecture,
        protection_available: false,
        reasons: vec!["enforcement_not_implemented"],
        deferred_capability_probes: vec![
            "native_nftables",
            "transient_systemd_service",
            "sudo_lockdown",
            "container_lockdown",
        ],
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
    }

    #[test]
    fn intended_target_still_reports_no_protection_in_phase1() {
        let data = inspect_support(&FixedProvider {
            os: "linux",
            architecture: "x86_64",
        });

        assert!(data.intended_protected_target_match);
        assert!(!data.protection_available);
        assert_eq!(data.reasons, vec!["enforcement_not_implemented"]);
    }

    #[test]
    fn unsupported_target_is_observed_without_claim() {
        let data = inspect_support(&FixedProvider {
            os: "macos",
            architecture: "aarch64",
        });

        assert!(!data.intended_protected_target_match);
        assert!(!data.protection_available);
    }

    #[test]
    fn system_provider_returns_runtime_identity() {
        let identity = SystemSupportProvider.host_identity();

        assert_eq!(identity.os, std::env::consts::OS);
        assert_eq!(identity.architecture, std::env::consts::ARCH);
    }
}
