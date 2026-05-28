#![cfg(target_os = "linux")]

use fence::composed::run_host_block_candidate_test_service;
use fence::config::parse_and_normalize;
use fence::plan::build_plan;
use fence::resolver::SystemResolver;
use std::path::PathBuf;

#[test]
#[ignore = "executed as a transient service with host block policy on a disposable hosted runner"]
fn broad_compatibility_profile_host_block_candidate_worker() {
    if std::env::var_os("FENCE_PROFILE_CANDIDATE_WORKER").is_none() {
        return;
    }
    let invocation_id = std::env::var("FENCE_PROFILE_CANDIDATE_INVOCATION").unwrap();
    let config = format!(
        r#"{{"schema_version":1,"mode":"block","invocation_id":"{invocation_id}","platform_profile":"github_hosted_compatibility_candidate_v1","container_policy":"disable","allowances":[]}}"#
    );
    let plan = build_plan(
        parse_and_normalize(config.as_bytes()).unwrap(),
        &SystemResolver,
    )
    .unwrap();
    run_host_block_candidate_test_service(
        &std::env::var("FENCE_PROFILE_CANDIDATE_UNIT").unwrap(),
        &PathBuf::from(std::env::var_os("FENCE_PROFILE_CANDIDATE_ROOT").unwrap()),
        &plan,
    )
    .unwrap();
}
