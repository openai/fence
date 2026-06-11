#![cfg(target_os = "linux")]

use fence::config::parse_and_normalize;
use fence::dns_mediator::run_selected_profile_runtime_test_service;
use fence::plan::build_plan;
use fence::resolver::SystemResolver;
use std::path::PathBuf;

#[test]
#[ignore = "executed as a transient service with DNS-mediated host block policy on a disposable hosted runner"]
fn selected_profile_runtime_worker() {
    if std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_WORKER").is_none() {
        return;
    }
    let invocation_id = std::env::var("FENCE_SELECTED_PROFILE_RUNTIME_INVOCATION").unwrap();
    let config = format!(
        r#"{{"schema_version":1,"mode":"block","invocation_id":"{invocation_id}","container_policy":"disable","allowlist":[]}}"#
    );
    let plan = build_plan(
        parse_and_normalize(config.as_bytes()).unwrap(),
        &SystemResolver,
    )
    .unwrap();
    run_selected_profile_runtime_test_service(
        &std::env::var("FENCE_SELECTED_PROFILE_RUNTIME_UNIT").unwrap(),
        &PathBuf::from(std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_ROOT").unwrap()),
        &plan,
        std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_INJECT_WORKER_FAILURE").is_some(),
    )
    .unwrap();
}
