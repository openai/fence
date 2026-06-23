#![cfg(target_os = "linux")]

use fence::config::parse_and_normalize;
use fence::dns_mediator::run_selected_profile_runtime_test_service;
use fence::plan::build_plan;
use fence::resolver::SystemResolver;
use serde_json::Value;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
#[ignore = "executed as a transient service with DNS-mediated host block policy on a disposable hosted runner"]
fn selected_profile_runtime_worker() {
    if std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_WORKER").is_none() {
        return;
    }
    if std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_DRIFT_CHILD").is_some() {
        let report =
            PathBuf::from(std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_REPORT").unwrap());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let resident = fs::read(&report)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|report| {
                    report.get("setup_status").and_then(Value::as_str)
                        == Some("resident_selected_profile_runtime_test_only")
                        && report.get("readiness_status").and_then(Value::as_str)
                            == Some("selected_profile_runtime_ready_no_public_activation")
                });
            if resident {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "committed resident evidence was not emitted"
            );
            thread::sleep(Duration::from_millis(50));
        }
        let _listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        thread::sleep(Duration::from_secs(30));
        return;
    }
    let invocation_id = std::env::var("FENCE_SELECTED_PROFILE_RUNTIME_INVOCATION").unwrap();
    let runtime_root =
        PathBuf::from(std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_ROOT").unwrap());
    let _drift_child =
        std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_INJECT_LOCAL_CONTROL_DRIFT").map(|_| {
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "selected_profile_runtime_worker",
                    "--nocapture",
                ])
                .env("FENCE_SELECTED_PROFILE_RUNTIME_DRIFT_CHILD", "1")
                .env(
                    "FENCE_SELECTED_PROFILE_RUNTIME_REPORT",
                    runtime_root.join(&invocation_id).join("report.json"),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        });
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
        &runtime_root,
        &plan,
        std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_INJECT_WORKER_FAILURE").is_some(),
    )
    .unwrap();
}
