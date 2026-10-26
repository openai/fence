#![cfg(target_os = "linux")]

use fence::config::parse_and_normalize;
use fence::dns_mediator::run_selected_profile_runtime_test_service;
use fence::plan::build_plan;
use fence::resolver::SystemResolver;
use serde_json::Value;
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn wait_for_document(path: &Path, condition: impl Fn(&Value) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .is_some_and(|document| condition(&document))
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "resident evidence did not arrive"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "executed as a transient service with DNS-mediated host block policy on a disposable hosted runner"]
fn selected_profile_runtime_worker() {
    if std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_WORKER").is_none() {
        return;
    }
    let invocation_id = std::env::var("FENCE_SELECTED_PROFILE_RUNTIME_INVOCATION").unwrap();
    let runtime_root =
        PathBuf::from(std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_ROOT").unwrap());
    if std::env::var_os("FENCE_SELECTED_PROFILE_RUNTIME_DRIFT_CHILD").is_some() {
        let directory = runtime_root.join(&invocation_id);
        wait_for_document(&directory.join("ready.json"), |ready| {
            ready["status"] == "selected_profile_runtime_ready_no_public_activation"
                && ready["resident_health"]["status"] == "healthy"
        });
        let report_path = directory.join("report.json");
        let before: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
        assert_eq!(before["resident_health"]["status"], "healthy");
        assert!(before.get("first_failed_local_control_scan").is_none());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        wait_for_document(&report_path, |report| {
            report["resident_health"]["status"] == "critical"
                && report["first_failed_local_control_scan"].is_object()
        });
        drop(listener);
        fs::File::create_new(directory.join("test-listener-closed")).unwrap();
        return;
    }
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
