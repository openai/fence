use crate::config::MAX_REPORT_BYTES;
use crate::error::ErrorDetail;
use serde::Serialize;
use serde_json::Value;

const RESPONSE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
struct Envelope {
    schema_version: u32,
    command: String,
    status: &'static str,
    fence_version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorDetail>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CommandOutput {
    pub json: String,
    pub exit_code: i32,
    pub stderr: bool,
}

pub fn success(command: &str, data: impl Serialize) -> CommandOutput {
    success_value(
        command,
        serde_json::to_value(data).expect("typed response data must serialize"),
    )
}

fn success_value(command: &str, data: Value) -> CommandOutput {
    let envelope = Envelope {
        schema_version: RESPONSE_SCHEMA_VERSION,
        command: command.to_owned(),
        status: "success",
        fence_version: env!("CARGO_PKG_VERSION"),
        data: Some(data),
        error: None,
    };
    let json = serialize_envelope(&envelope);
    if json.len() > MAX_REPORT_BYTES {
        failure(
            command,
            ErrorDetail::new(
                "report_too_large",
                "serialized response exceeds the fixed report limit",
            ),
            1,
        )
    } else {
        CommandOutput {
            json,
            exit_code: 0,
            stderr: false,
        }
    }
}

pub fn failure(command: &str, error: ErrorDetail, exit_code: i32) -> CommandOutput {
    let envelope = Envelope {
        schema_version: RESPONSE_SCHEMA_VERSION,
        command: command.to_owned(),
        status: "error",
        fence_version: env!("CARGO_PKG_VERSION"),
        data: None,
        error: Some(error),
    };
    CommandOutput {
        json: serialize_envelope(&envelope),
        exit_code,
        stderr: true,
    }
}

fn serialize_envelope(envelope: &Envelope) -> String {
    serde_json::to_string(envelope).expect("typed response envelope must serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_success_and_structured_failure_envelopes() {
        let success_output = success("check-support", serde_json::json!({"supported": false}));
        let error_output = failure("run", ErrorDetail::new("unavailable", "not available"), 1);

        assert_eq!(success_output.exit_code, 0);
        assert!(!success_output.stderr);
        assert!(success_output.json.contains("\"status\":\"success\""));
        assert_eq!(error_output.exit_code, 1);
        assert!(error_output.stderr);
        assert!(error_output.json.contains("\"code\":\"unavailable\""));
    }

    #[test]
    fn bounds_success_output_before_emission() {
        let output = success("render-plan", "x".repeat(MAX_REPORT_BYTES));

        assert_eq!(output.exit_code, 1);
        assert!(output.stderr);
        assert!(output.json.contains("\"code\":\"report_too_large\""));
    }
}
