use crate::config::{parse_and_normalize, read_config_bounded};
use crate::error::ErrorDetail;
use crate::output::{CommandOutput, failure, success};
use crate::plan::build_plan;
use crate::resolver::{Resolver, SystemResolver};
use crate::support::{SupportProvider, SystemSupportProvider, inspect_support};
use crate::version_info;
use clap::{Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "fence",
    about = "Fence phase3 hosted-runner lifecycle design agent",
    disable_help_flag = true,
    disable_version_flag = true
)]
struct Cli {
    #[arg(long)]
    version: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    CheckSupport,
    RenderPlan {
        #[arg(long)]
        config: PathBuf,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
    },
}

pub fn execute_system<I, T>(args: I) -> CommandOutput
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    execute(
        args.into_iter().map(Into::into).collect(),
        &SystemResolver,
        &SystemSupportProvider,
    )
}

pub fn execute(
    args: Vec<OsString>,
    resolver: &dyn Resolver,
    support_provider: &dyn SupportProvider,
) -> CommandOutput {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(_) => {
            return failure(
                "cli",
                ErrorDetail::new(
                    "invalid_arguments",
                    "expected --version, check-support, render-plan --config, or run --config",
                ),
                2,
            );
        }
    };

    match (cli.version, cli.command) {
        (true, None) => success("version", version_info()),
        (true, Some(_)) => failure(
            "cli",
            ErrorDetail::new(
                "invalid_arguments",
                "--version cannot be combined with a command",
            ),
            2,
        ),
        (false, Some(Commands::CheckSupport)) => {
            success("check-support", inspect_support(support_provider))
        }
        (false, Some(Commands::RenderPlan { config })) => render_plan(&config, resolver),
        (false, Some(Commands::Run { config: _ })) => failure(
            "run",
            ErrorDetail::new(
                "enforcement_not_implemented",
                "run is unavailable until privileged enforcement is implemented",
            ),
            1,
        ),
        (false, None) => failure(
            "cli",
            ErrorDetail::new(
                "invalid_arguments",
                "expected --version, check-support, render-plan --config, or run --config",
            ),
            2,
        ),
    }
}

fn render_plan(config: &std::path::Path, resolver: &dyn Resolver) -> CommandOutput {
    let result = read_config_bounded(config)
        .and_then(|bytes| parse_and_normalize(&bytes))
        .and_then(|normalized| build_plan(normalized, resolver));
    match result {
        Ok(plan) => success("render-plan", plan),
        Err(error) => failure("render-plan", error, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::{Resolution, ResolveError};
    use crate::support::HostIdentity;
    use std::time::Duration;

    struct FailResolver;

    impl Resolver for FailResolver {
        fn resolve(&self, _hostname: &str, _timeout: Duration) -> Result<Resolution, ResolveError> {
            Err(ResolveError::Failed)
        }
    }

    struct LinuxProvider;

    impl SupportProvider for LinuxProvider {
        fn host_identity(&self) -> HostIdentity {
            HostIdentity {
                os: "linux".to_owned(),
                architecture: "x86_64".to_owned(),
            }
        }

        fn network_backend_observation(&self) -> crate::support::NetworkBackendObservation {
            crate::support::NetworkBackendObservation {
                required: "native_nftables",
                nft_binary_expected_path: "/usr/sbin/nft",
                nft_binary_present: true,
                nft_version_observed: None,
                privileged_semantic_proof: "integration_test_required",
            }
        }
    }

    fn execute_test(args: &[&str]) -> CommandOutput {
        execute(
            args.iter().map(OsString::from).collect(),
            &FailResolver,
            &LinuxProvider,
        )
    }

    #[test]
    fn version_and_support_return_successful_json() {
        let version = execute_test(&["fence", "--version"]);
        let support = execute_test(&["fence", "check-support"]);

        assert_eq!(version.exit_code, 0);
        assert!(version.json.contains("\"implementation_phase\":\"phase3\""));
        assert_eq!(support.exit_code, 0);
        assert!(support.json.contains("\"protection_available\":false"));
    }

    #[test]
    fn invalid_shape_and_run_fail_with_designated_codes() {
        let no_command = execute_test(&["fence"]);
        let invalid = execute_test(&["fence", "man"]);
        let mixed = execute_test(&["fence", "--version", "check-support"]);
        let run = execute_test(&["fence", "run", "--config", "/must/not/be/read"]);

        assert_eq!(no_command.exit_code, 2);
        assert_eq!(invalid.exit_code, 2);
        assert_eq!(mixed.exit_code, 2);
        assert_eq!(run.exit_code, 1);
        assert!(run.json.contains("enforcement_not_implemented"));
    }

    #[test]
    fn render_plan_reports_resolver_failure_as_json() {
        let root = std::path::Path::new("target/tmp/cli-unit-tests");
        std::fs::create_dir_all(root).unwrap();
        let config = root.join("resolution-failure.json");
        std::fs::write(
            &config,
            br#"{"schema_version":1,"mode":"block","invocation_id":"resolve-1","allowances":[{"destination_type":"hostname","destination":"example.com","protocol":"tcp","port":443}]}"#,
        )
        .unwrap();

        let output = execute_test(&["fence", "render-plan", "--config", config.to_str().unwrap()]);

        assert_eq!(output.exit_code, 1);
        assert!(output.json.contains("dns_resolution_failed"));
    }
}
