#![cfg(target_os = "linux")]

use fence::composed::run_host_block_candidate_test_service;
use fence::config::parse_and_normalize;
use fence::plan::build_plan;
use fence::resolver::{Resolution, ResolveError, Resolver};
use std::path::PathBuf;
use std::time::Duration;

struct NoResolver;

impl Resolver for NoResolver {
    fn resolve(&self, _hostname: &str, _timeout: Duration) -> Result<Resolution, ResolveError> {
        panic!("host block candidate policy contains no hostname allowances");
    }
}

#[test]
#[ignore = "executed as a host-blocking transient service only on a disposable hosted runner"]
fn strict_none_host_block_candidate_worker() {
    if std::env::var_os("FENCE_HOST_BLOCK_CANDIDATE_WORKER").is_none() {
        return;
    }
    let invocation_id = std::env::var("FENCE_HOST_BLOCK_CANDIDATE_INVOCATION").unwrap();
    let config = format!(
        r#"{{"schema_version":1,"mode":"block","invocation_id":"{invocation_id}","platform_profile":"none","container_policy":"disable","allowances":[]}}"#
    );
    let plan = build_plan(parse_and_normalize(config.as_bytes()).unwrap(), &NoResolver).unwrap();
    run_host_block_candidate_test_service(
        &std::env::var("FENCE_HOST_BLOCK_CANDIDATE_UNIT").unwrap(),
        &PathBuf::from(std::env::var_os("FENCE_HOST_BLOCK_CANDIDATE_ROOT").unwrap()),
        &plan,
    )
    .unwrap();
}
