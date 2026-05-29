#![forbid(unsafe_code)]

pub mod cli;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod composed;
pub mod config;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod dns_mediator;
pub mod error;
pub mod findings;
pub mod hosted_runner;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod lifecycle;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod lockdown;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod nflog;
pub mod nft;
#[doc(hidden)]
pub mod nft_backend;
pub mod output;
pub mod plan;
pub mod platform_profile;
pub mod resolver;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod runtime;
pub mod support;

use serde::Serialize;

pub const IMPLEMENTATION_PHASE: &str = "phase3";

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VersionInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub build_version: &'static str,
    pub commit: &'static str,
    pub build_date: &'static str,
    pub implementation_phase: &'static str,
    pub protection_available: bool,
}

pub fn version_info() -> VersionInfo {
    VersionInfo {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        build_version: option_env!("BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
        commit: option_env!("BUILD_COMMIT").unwrap_or("unknown"),
        build_date: option_env!("BUILD_DATE").unwrap_or("unknown"),
        implementation_phase: IMPLEMENTATION_PHASE,
        protection_available: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_identifies_non_enforcing_phase() {
        let info = version_info();

        assert_eq!(info.name, env!("CARGO_PKG_NAME"));
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.implementation_phase, "phase3");
        assert!(!info.protection_available);
    }
}
