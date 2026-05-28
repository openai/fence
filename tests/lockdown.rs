#![cfg(target_os = "linux")]

use fence::lockdown::{LockdownPosture, run_lockdown_test_service};
use std::path::PathBuf;

#[test]
#[ignore = "executed as a transient systemd service on a disposable hosted runner"]
fn lockdown_service_worker() {
    if std::env::var_os("FENCE_LOCKDOWN_WORKER").is_none() {
        return;
    }
    let scenario = std::env::var("FENCE_LOCKDOWN_SCENARIO").unwrap();
    let posture = match scenario.as_str() {
        "audit" => LockdownPosture::Audit,
        "unsafe-preserve" => LockdownPosture::UnsafePreserve,
        "standard" | "rollback" => LockdownPosture::StandardBlock,
        _ => panic!("invalid lockdown scenario"),
    };
    let result = run_lockdown_test_service(
        &std::env::var("FENCE_LOCKDOWN_UNIT").unwrap(),
        &PathBuf::from(std::env::var_os("FENCE_LOCKDOWN_ROOT").unwrap()),
        &std::env::var("FENCE_LOCKDOWN_INVOCATION").unwrap(),
        posture,
        scenario == "rollback",
    );
    if scenario == "rollback" {
        assert_eq!(
            result.unwrap_err().code,
            "injected_pre_ready_lockdown_failure"
        );
    } else {
        result.unwrap();
    }
}
