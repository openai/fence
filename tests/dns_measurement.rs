#![cfg(target_os = "linux")]

use fence::config::parse_and_normalize;
use fence::dns_mediator::run_dns_mediation_audit_test_service;
use fence::plan::build_plan;
use fence::resolver::{Resolution, ResolveError, Resolver};
use std::path::PathBuf;
use std::time::Duration;

struct NoResolver;

impl Resolver for NoResolver {
    fn resolve(&self, _hostname: &str, _timeout: Duration) -> Result<Resolution, ResolveError> {
        panic!("DNS mediation audit policy contains no hostname allowances");
    }
}

#[test]
#[ignore = "executed as a transient service only on a disposable hosted runner"]
fn dns_mediation_audit_worker() {
    if std::env::var_os("FENCE_DNS_MEDIATION_WORKER").is_none() {
        return;
    }
    let invocation_id = std::env::var("FENCE_DNS_MEDIATION_INVOCATION").unwrap();
    let runtime_root = PathBuf::from(std::env::var_os("FENCE_DNS_MEDIATION_ROOT").unwrap());
    let unit = std::env::var("FENCE_DNS_MEDIATION_UNIT").unwrap();
    let config = format!(
        r#"{{"schema_version":1,"mode":"audit","invocation_id":"{invocation_id}","platform_profile":"none","allowances":[]}}"#
    );
    let plan = build_plan(parse_and_normalize(config.as_bytes()).unwrap(), &NoResolver).unwrap();
    run_dns_mediation_audit_test_service(&unit, &runtime_root, &plan).unwrap();
}
