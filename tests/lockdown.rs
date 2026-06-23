#![cfg(target_os = "linux")]

use fence::lockdown::{
    LockdownPosture, run_lockdown_acl_rejection_test_service, run_lockdown_test_service,
};
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;

#[test]
#[ignore = "executed as a transient systemd service on a disposable hosted runner"]
fn lockdown_service_worker() {
    if std::env::var_os("FENCE_LOCKDOWN_WORKER").is_none() {
        return;
    }
    let scenario = std::env::var("FENCE_LOCKDOWN_SCENARIO").unwrap();
    if scenario == "acl-reject" {
        let error = run_lockdown_acl_rejection_test_service(
            &std::env::var("FENCE_LOCKDOWN_UNIT").unwrap(),
            &PathBuf::from(std::env::var_os("FENCE_LOCKDOWN_ACL_FIXTURE").unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code, "unsupported_host_fingerprint");
        return;
    }
    let _local_control_listener = (scenario == "local-control-reject")
        .then(|| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap());
    let posture = match scenario.as_str() {
        "audit" => LockdownPosture::Audit,
        "unsafe-preserve" => LockdownPosture::UnsafePreserve,
        "standard" | "rollback" | "local-control-reject" => LockdownPosture::StandardBlock,
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
    } else if scenario == "local-control-reject" {
        assert_eq!(
            result.unwrap_err().code,
            "local_control_inventory_unavailable"
        );
    } else {
        result.unwrap();
    }
}
