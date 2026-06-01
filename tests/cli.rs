use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fence"))
        .args(args)
        .output()
        .expect("failed to run fence binary")
}

fn success_json(args: &[&str]) -> Value {
    let output = run(args);
    assert!(
        output.status.success(),
        "command failed with status {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("stdout should contain JSON")
}

fn error_json(args: &[&str], exit_code: i32) -> Value {
    let output = run(args);
    assert_eq!(output.status.code(), Some(exit_code));
    assert!(output.stdout.is_empty());
    serde_json::from_slice(&output.stderr).expect("stderr should contain JSON")
}

fn config_file(name: &str, content: &[u8]) -> PathBuf {
    let directory = PathBuf::from("target/tmp/cli-tests");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn version_is_json_and_does_not_claim_protection() {
    let response = success_json(&["--version"]);

    assert_eq!(response["command"], "version");
    assert_eq!(response["status"], "success");
    assert_eq!(response["data"]["implementation_phase"], "v0");
    assert_eq!(response["data"]["protection_available"], false);
}

#[test]
fn support_is_read_only_and_not_protective() {
    let response = success_json(&["check-support"]);

    assert_eq!(response["command"], "check-support");
    assert_eq!(response["data"]["implementation_phase"], "v0");
    assert_eq!(response["data"]["protection_available"], false);
    assert_eq!(
        response["data"]["hosted_runner_fingerprint"]["status"],
        "accepted_reference_not_checked"
    );
    assert_eq!(
        response["data"]["hosted_runner_fingerprint"]["accepted"]["expected_principal"],
        "runner"
    );
    assert_eq!(
        response["data"]["reasons"][0],
        "protected_standard_block_requires_trusted_launcher"
    );
    assert_eq!(
        response["data"]["network_backend"]["nft_binary_expected_path"],
        "/usr/sbin/nft"
    );
}

#[test]
fn renders_deterministic_plan_without_creating_runtime_state() {
    let invocation_id = format!("cli-plan-{}", std::process::id());
    let runtime_path = PathBuf::from(format!("/run/fence/{invocation_id}"));
    let existed_before = runtime_path.exists();
    let path = config_file(
        "plan.json",
        format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"{invocation_id}","allowlist":[{{"destination_type":"ip","destination":"192.0.2.1","protocol":"tcp","port":443}},{{"destination_type":"cidr","destination":"2001:db8::/64","protocol":"udp","port":53}}]}}"#
        )
        .as_bytes(),
    );
    let path_arg = path.to_str().unwrap();
    let first = success_json(&["render-plan", "--config", path_arg]);
    let second = success_json(&["render-plan", "--config", path_arg]);

    assert_eq!(first, second);
    assert_eq!(first["data"]["application_status"], "not_applied");
    assert_eq!(first["data"]["verification_status"], "not_verified");
    assert_eq!(first["data"]["policy_hash_schema_version"], 3);
    assert_eq!(
        first["data"]["network_enforcement_preview"]["owned_table"]["name"],
        "fence_v0"
    );
    assert_eq!(
        first["data"]["network_enforcement_preview"]["nflog"]["group"],
        4242
    );
    assert!(first["data"]["ruleset_hash"].as_str().unwrap().len() == 64);
    assert_eq!(
        first["data"]["derived_runtime_paths"]["directory"],
        runtime_path.to_str().unwrap()
    );
    assert_eq!(runtime_path.exists(), existed_before);
}

#[test]
fn renders_default_bounded_workflow_bootstrap_profile_without_activation() {
    let invocation_id = format!("default-plan-{}", std::process::id());
    let runtime_path = PathBuf::from(format!("/run/fence/{invocation_id}"));
    let existed_before = runtime_path.exists();
    let path = config_file(
        "default-workflow-bootstrap-plan.json",
        format!(
            r#"{{"schema_version":1,"mode":"block","invocation_id":"{invocation_id}","allowlist":[]}}"#
        )
        .as_bytes(),
    );
    let response = success_json(&["render-plan", "--config", path.to_str().unwrap()]);
    let profile = &response["data"]["platform_profile"];
    let dns = &profile["dns_mediated_compatibility"];

    assert_eq!(response["data"]["policy_hash_schema_version"], 3);
    assert_eq!(profile["id"], "github_hosted_workflow_bootstrap_v1");
    assert_eq!(profile["selection_status"], "default_bounded_dns_mediated");
    assert_eq!(
        dns["realization_status"],
        "trusted_launcher_runtime_materialization_required"
    );
    assert_eq!(dns["max_dynamic_actions_suffix_authorizations"], 8);
    assert_eq!(dns["max_dynamic_actions_suffix_prefix_labels"], 2);
    assert_eq!(
        dns["forwarded_query_types"],
        serde_json::json!(["a", "aaaa"])
    );
    assert_eq!(dns["https_materialization_port"], 443);
    assert_eq!(runtime_path.exists(), existed_before);
}

#[test]
fn run_fails_closed_without_reading_config() {
    let response = error_json(&["run", "--config", "/not/a/real/config.json"], 1);

    assert_eq!(response["command"], "run");
    assert_eq!(
        response["error"]["code"],
        if cfg!(target_os = "linux") {
            "trusted_launcher_required"
        } else {
            "enforcement_not_implemented"
        }
    );
}

#[test]
fn invalid_and_oversized_configs_are_structured_errors() {
    let invalid = config_file(
        "invalid.json",
        br#"{"schema_version":1,"mode":"block","invocation_id":"bad","allowlist":[],"extra":true}"#,
    );
    let oversized = config_file(
        "oversized.json",
        &vec![b' '; fence::config::MAX_CONFIG_BYTES + 1],
    );
    let invalid_response = error_json(&["render-plan", "--config", invalid.to_str().unwrap()], 1);
    let oversized_response =
        error_json(&["render-plan", "--config", oversized.to_str().unwrap()], 1);

    assert_eq!(
        invalid_response["error"]["code"],
        "invalid_json_configuration"
    );
    assert_eq!(oversized_response["error"]["code"], "config_too_large");
}

#[test]
fn retired_platform_profiles_are_structured_errors() {
    for (name, profile) in [
        (
            "retired-job-status-profile.json",
            "github_hosted_job_status_v1",
        ),
        ("none-profile.json", "none"),
        (
            "broad-compatibility-profile.json",
            "github_hosted_https_udp_dns_candidate_v1",
        ),
    ] {
        let config = config_file(
            name,
            format!(
                r#"{{"schema_version":1,"mode":"block","invocation_id":"bad-profile","platform_profile":"{profile}","allowlist":[]}}"#
            )
            .as_bytes(),
        );
        let response = error_json(&["render-plan", "--config", config.to_str().unwrap()], 1);

        assert_eq!(response["error"]["code"], "invalid_platform_profile");
    }
}

#[test]
fn scaffold_and_malformed_commands_are_absent() {
    for arguments in [
        vec![],
        vec!["man"],
        vec!["completions", "bash"],
        vec!["add", "2", "3"],
        vec!["--help"],
    ] {
        let response = error_json(&arguments, 2);
        assert_eq!(response["error"]["code"], "invalid_arguments");
    }
}
