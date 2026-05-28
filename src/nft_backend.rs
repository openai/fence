use crate::config::MAX_REPORT_BYTES;
use crate::nft::{
    NFT_CLASSIFY_CHAIN, NFT_FAMILY, NFT_FORWARD_CHAIN, NFT_OUTPUT_CHAIN,
    NFT_SAMPLED_VIOLATIONS_COUNTER, NFT_TABLE, NFT_TOTAL_VIOLATIONS_COUNTER, NFT_VIOLATION_CHAIN,
    NetworkEvidence, OwnedChain, OwnedNftState, OwnedRule, VerificationFailure, verify_owned_state,
};
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const NFT_BINARY_PATH: &str = "/usr/sbin/nft";
pub const IP_BINARY_PATH: &str = "/usr/sbin/ip";
pub const COMMAND_OUTPUT_LIMIT_BYTES: usize = 1024 * 1024;
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BackendError {
    pub code: &'static str,
    pub message: String,
}

impl BackendError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<VerificationFailure> for BackendError {
    fn from(failure: VerificationFailure) -> Self {
        Self::new(failure.code, failure.message)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NftOperation {
    Preflight,
    ApplyProvisional,
    ReadOwnedState,
    ReadTotalViolationsCounter,
    DeleteOwnedState,
}

impl NftOperation {
    fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::Preflight => &["-c", "-f", "-"],
            Self::ApplyProvisional => &["-f", "-"],
            Self::ReadOwnedState => &["-j", "-n", "-y", "list", "table", NFT_FAMILY, NFT_TABLE],
            Self::ReadTotalViolationsCounter => &[
                "-j",
                "-n",
                "-y",
                "list",
                "counter",
                NFT_FAMILY,
                NFT_TABLE,
                NFT_TOTAL_VIOLATIONS_COUNTER,
            ],
            Self::DeleteOwnedState => &["delete", "table", NFT_FAMILY, NFT_TABLE],
        }
    }
}

pub trait NftExecutor {
    fn execute(&self, operation: NftOperation, input: &[u8]) -> Result<Vec<u8>, BackendError>;
}

#[derive(Debug, Clone)]
pub struct SystemNftExecutor {
    executable: PathBuf,
    prefix_arguments: Vec<String>,
}

impl SystemNftExecutor {
    pub fn host() -> Self {
        Self {
            executable: PathBuf::from(NFT_BINARY_PATH),
            prefix_arguments: Vec::new(),
        }
    }

    pub fn in_test_network_namespace(namespace: &str) -> Result<Self, BackendError> {
        validate_test_identifier(namespace)?;
        Ok(Self {
            executable: PathBuf::from(IP_BINARY_PATH),
            prefix_arguments: vec![
                "netns".to_owned(),
                "exec".to_owned(),
                namespace.to_owned(),
                NFT_BINARY_PATH.to_owned(),
            ],
        })
    }
}

impl NftExecutor for SystemNftExecutor {
    fn execute(&self, operation: NftOperation, input: &[u8]) -> Result<Vec<u8>, BackendError> {
        let arguments = self
            .prefix_arguments
            .iter()
            .map(String::as_str)
            .chain(operation.arguments().iter().copied())
            .collect::<Vec<_>>();
        run_process_bounded(
            &self.executable,
            &arguments,
            input,
            COMMAND_TIMEOUT,
            COMMAND_OUTPUT_LIMIT_BYTES,
        )
    }
}

pub struct NativeNftBackend<E: NftExecutor> {
    executor: E,
    created_table: bool,
}

impl<E: NftExecutor> NativeNftBackend<E> {
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            created_table: false,
        }
    }

    pub fn preflight(&self, program: &str) -> Result<(), BackendError> {
        self.executor
            .execute(NftOperation::Preflight, program.as_bytes())
            .map(|_| ())
    }

    pub fn apply_provisional(&mut self, program: &str) -> Result<(), BackendError> {
        self.executor
            .execute(NftOperation::ApplyProvisional, program.as_bytes())?;
        self.created_table = true;
        Ok(())
    }

    pub fn read_owned_state(&self) -> Result<OwnedNftState, BackendError> {
        let bytes = self.executor.execute(NftOperation::ReadOwnedState, &[])?;
        parse_owned_state(&bytes)
    }

    pub fn verify_owned_state(&self, expected: &OwnedNftState) -> Result<(), BackendError> {
        let observed = self.read_owned_state()?;
        verify_owned_state(expected, &observed).map_err(BackendError::from)
    }

    pub fn total_violation_packets(&self) -> Result<u64, BackendError> {
        let bytes = self
            .executor
            .execute(NftOperation::ReadTotalViolationsCounter, &[])?;
        parse_counter_packets(&bytes, NFT_TOTAL_VIOLATIONS_COUNTER)
    }

    pub fn rollback_pre_activation(&mut self) -> Result<bool, BackendError> {
        if !self.created_table {
            return Ok(false);
        }
        self.executor.execute(NftOperation::DeleteOwnedState, &[])?;
        self.created_table = false;
        Ok(true)
    }
}

#[derive(Debug)]
struct CapturedOutput {
    bytes: Vec<u8>,
    overflowed: bool,
}

fn run_process_bounded(
    executable: &Path,
    arguments: &[&str],
    input: &[u8],
    timeout: Duration,
    output_limit: usize,
) -> Result<Vec<u8>, BackendError> {
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        BackendError::new("nft_spawn_failed", bounded_message(&error.to_string()))
    })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| BackendError::new("nft_stdin_failed", "failed to open nft stdin"))?;
    stdin.write_all(input).map_err(|error| {
        BackendError::new("nft_stdin_failed", bounded_message(&error.to_string()))
    })?;
    drop(stdin);

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BackendError::new("nft_stdout_failed", "failed to capture nft stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BackendError::new("nft_stderr_failed", "failed to capture nft stderr"))?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, output_limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, output_limit));
    let deadline = Instant::now() + timeout;

    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            BackendError::new("nft_wait_failed", bounded_message(&error.to_string()))
        })? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(BackendError::new(
                "nft_command_timeout",
                "nft command exceeded its execution deadline",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| BackendError::new("nft_stdout_failed", "nft stdout reader failed"))?
        .map_err(|error| {
            BackendError::new("nft_stdout_failed", bounded_message(&error.to_string()))
        })?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| BackendError::new("nft_stderr_failed", "nft stderr reader failed"))?
        .map_err(|error| {
            BackendError::new("nft_stderr_failed", bounded_message(&error.to_string()))
        })?;
    if stdout.overflowed || stderr.overflowed {
        return Err(BackendError::new(
            "nft_output_too_large",
            "nft command output exceeded its fixed capture limit",
        ));
    }
    if !status.success() {
        return Err(BackendError::new(
            "nft_command_failed",
            bounded_message(&String::from_utf8_lossy(&stderr.bytes)),
        ));
    }
    Ok(stdout.bytes)
}

fn read_bounded(mut stream: impl Read, limit: usize) -> std::io::Result<CapturedOutput> {
    let mut bytes = Vec::new();
    let mut overflowed = false;
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let available = limit.saturating_sub(bytes.len());
        let retained = available.min(read);
        bytes.extend_from_slice(&chunk[..retained]);
        overflowed |= retained < read;
    }
    Ok(CapturedOutput { bytes, overflowed })
}

fn bounded_message(message: &str) -> String {
    const MAX_MESSAGE_BYTES: usize = 512;
    if message.len() <= MAX_MESSAGE_BYTES {
        return message.to_owned();
    }
    let mut end = MAX_MESSAGE_BYTES;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &message[..end])
}

fn parse_owned_state(bytes: &[u8]) -> Result<OwnedNftState, BackendError> {
    let document: Value = serde_json::from_slice(bytes)
        .map_err(|_| BackendError::new("invalid_nft_json", "nft returned invalid JSON output"))?;
    let items = document
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            BackendError::new("invalid_nft_json", "nft JSON is missing its object list")
        })?;
    let mut table_found = false;
    let mut chains = Vec::new();
    let mut counters = Vec::new();
    let mut rules = Vec::new();

    for item in items {
        let object = item.as_object().ok_or_else(|| {
            BackendError::new("unexpected_nft_state", "nft object is not structured")
        })?;
        if object.contains_key("metainfo") {
            continue;
        }
        if let Some(table) = object.get("table") {
            require_owned_table(table)?;
            table_found = true;
            continue;
        }
        if let Some(chain) = object.get("chain") {
            require_owned_object(chain)?;
            chains.push(parse_chain(chain)?);
            continue;
        }
        if let Some(counter) = object.get("counter") {
            require_owned_object(counter)?;
            counters.push(require_string(counter, "name")?.to_owned());
            continue;
        }
        if let Some(rule) = object.get("rule") {
            require_owned_object(rule)?;
            rules.push(parse_rule(rule)?);
            continue;
        }
        return Err(BackendError::new(
            "unexpected_nft_state",
            "owned nftables table contains an unexpected object",
        ));
    }

    if !table_found {
        return Err(BackendError::new(
            "unexpected_nft_state",
            "owned nftables table is absent from structured state",
        ));
    }
    chains.sort_by_key(chain_rank);
    counters.sort_by_key(|counter| counter_rank(counter));
    Ok(OwnedNftState {
        family: NFT_FAMILY.to_owned(),
        table: NFT_TABLE.to_owned(),
        chains,
        counters,
        rules,
    })
}

fn parse_counter_packets(bytes: &[u8], name: &str) -> Result<u64, BackendError> {
    let document: Value = serde_json::from_slice(bytes)
        .map_err(|_| BackendError::new("invalid_nft_json", "nft returned invalid JSON output"))?;
    let items = document
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            BackendError::new("invalid_nft_json", "nft JSON is missing its object list")
        })?;
    for item in items {
        let Some(counter) = item.get("counter") else {
            continue;
        };
        require_owned_object(counter)?;
        if require_string(counter, "name")? == name {
            return counter
                .get("packets")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    BackendError::new("unexpected_nft_state", "counter has no packet value")
                });
        }
    }
    Err(BackendError::new(
        "unexpected_nft_state",
        "requested owned counter is absent",
    ))
}

fn require_owned_table(value: &Value) -> Result<(), BackendError> {
    if require_string(value, "family")? != NFT_FAMILY || require_string(value, "name")? != NFT_TABLE
    {
        return Err(BackendError::new(
            "unexpected_nft_state",
            "nft JSON contains an unexpected table",
        ));
    }
    Ok(())
}

fn require_owned_object(value: &Value) -> Result<(), BackendError> {
    if require_string(value, "family")? != NFT_FAMILY
        || require_string(value, "table")? != NFT_TABLE
    {
        return Err(BackendError::new(
            "unexpected_nft_state",
            "nft JSON contains an object outside the owned table",
        ));
    }
    Ok(())
}

fn chain_rank(chain: &OwnedChain) -> u8 {
    let name = match chain {
        OwnedChain::Base { name, .. } | OwnedChain::Regular { name } => name.as_str(),
    };
    match name {
        NFT_OUTPUT_CHAIN => 0,
        NFT_FORWARD_CHAIN => 1,
        NFT_CLASSIFY_CHAIN => 2,
        NFT_VIOLATION_CHAIN => 3,
        _ => 4,
    }
}

fn counter_rank(counter: &str) -> u8 {
    match counter {
        NFT_SAMPLED_VIOLATIONS_COUNTER => 0,
        NFT_TOTAL_VIOLATIONS_COUNTER => 1,
        _ => 2,
    }
}

fn parse_chain(value: &Value) -> Result<OwnedChain, BackendError> {
    let name = require_string(value, "name")?.to_owned();
    match name.as_str() {
        NFT_OUTPUT_CHAIN | NFT_FORWARD_CHAIN => Ok(OwnedChain::Base {
            name,
            chain_type: require_string(value, "type")?.to_owned(),
            hook: require_string(value, "hook")?.to_owned(),
            priority: require_i64(value, "prio")?.try_into().map_err(|_| {
                BackendError::new("unexpected_nft_state", "nft chain priority is out of range")
            })?,
            policy: require_string(value, "policy")?.to_owned(),
        }),
        NFT_CLASSIFY_CHAIN | NFT_VIOLATION_CHAIN => Ok(OwnedChain::Regular { name }),
        _ => Err(BackendError::new(
            "unexpected_nft_state",
            "owned nftables table contains an unexpected chain",
        )),
    }
}

fn parse_rule(value: &Value) -> Result<OwnedRule, BackendError> {
    let chain = require_string(value, "chain")?.to_owned();
    let comment = require_string(value, "comment")?;
    let expressions = value.get("expr").and_then(Value::as_array).ok_or_else(|| {
        BackendError::new("unexpected_nft_state", "nft rule has no expression array")
    })?;
    match comment {
        "fence:loopback" if has_accept(expressions) && has_scalar(expressions, "lo") => {
            Ok(OwnedRule::Loopback { chain })
        }
        "fence:established"
            if has_accept(expressions) && has_established_related_state(expressions) =>
        {
            Ok(OwnedRule::EstablishedRelated { chain })
        }
        "fence:implicit_ipv6_control"
            if has_accept(expressions)
                && has_number(expressions, 255)
                && has_scalar(expressions, "nd-router-solicit")
                && has_scalar(expressions, "nd-neighbor-solicit")
                && has_scalar(expressions, "nd-neighbor-advert") =>
        {
            Ok(OwnedRule::ImplicitIpv6Control {
                chain,
                icmpv6_types: vec![
                    "router_solicitation".to_owned(),
                    "neighbor_solicitation".to_owned(),
                    "neighbor_advertisement".to_owned(),
                ],
                required_hop_limit: 255,
            })
        }
        "fence:classify" if has_jump(expressions, NFT_CLASSIFY_CHAIN) => {
            Ok(OwnedRule::ClassifyDispatch { chain })
        }
        "fence:allowance" if has_accept(expressions) => parse_allowance_rule(chain, expressions),
        "fence:violation" if has_jump(expressions, NFT_VIOLATION_CHAIN) => {
            Ok(OwnedRule::ViolationDispatch { chain })
        }
        "fence:sample_violation"
            if has_named_counter(expressions, NFT_SAMPLED_VIOLATIONS_COUNTER) =>
        {
            parse_sampled_rule(chain, expressions)
        }
        "fence:reject_violation"
            if has_named_counter(expressions, NFT_TOTAL_VIOLATIONS_COUNTER)
                && has_key(expressions, "reject") =>
        {
            Ok(OwnedRule::TerminalViolation {
                chain,
                verdict: "reject".to_owned(),
            })
        }
        "fence:accept_violation"
            if has_named_counter(expressions, NFT_TOTAL_VIOLATIONS_COUNTER)
                && has_accept(expressions) =>
        {
            Ok(OwnedRule::TerminalViolation {
                chain,
                verdict: "accept".to_owned(),
            })
        }
        _ => Err(BackendError::new(
            "unexpected_nft_state",
            bounded_message(&format!(
                "owned nftables table contains malformed rule class {comment}: {}",
                serde_json::to_string(expressions)
                    .unwrap_or_else(|_| "structured-expression-unavailable".to_owned())
            )),
        )),
    }
}

fn parse_allowance_rule(chain: String, expressions: &[Value]) -> Result<OwnedRule, BackendError> {
    let (address_family, destination) = extract_destination(expressions)?;
    let (protocol, port) = extract_transport(expressions)?;
    Ok(OwnedRule::Allowance {
        chain,
        address_family,
        destination,
        protocol,
        port,
    })
}

fn parse_sampled_rule(chain: String, expressions: &[Value]) -> Result<OwnedRule, BackendError> {
    let log = find_expression(expressions, "log").ok_or_else(|| {
        BackendError::new(
            "unexpected_nft_state",
            "owned logging rule omits its log expression",
        )
    })?;
    let prefix = log.get("prefix").and_then(Value::as_str).ok_or_else(|| {
        BackendError::new(
            "unexpected_nft_state",
            "owned logging rule omits its prefix",
        )
    })?;
    if !matches!(prefix, "fence-v0-block" | "fence-v0-audit") {
        return Err(BackendError::new(
            "unexpected_nft_state",
            "owned logging rule has an unexpected prefix",
        ));
    }
    let group = log.get("group").and_then(Value::as_u64);
    let snaplen = log.get("snaplen").and_then(Value::as_u64);
    let queue_threshold = log
        .get("qthreshold")
        .or_else(|| log.get("queue-threshold"))
        .and_then(Value::as_u64);
    let limit = find_expression(expressions, "limit").ok_or_else(|| {
        BackendError::new(
            "unexpected_nft_state",
            "owned logging rule omits its rate limit",
        )
    })?;
    let rate = limit.get("rate").and_then(Value::as_u64);
    let per = limit.get("per").and_then(Value::as_str);
    let burst = limit.get("burst").and_then(Value::as_u64);
    if group != Some(4242)
        || snaplen != Some(64)
        || queue_threshold != Some(1)
        || rate != Some(100)
        || per != Some("second")
        || burst != Some(100)
    {
        return Err(BackendError::new(
            "unexpected_nft_state",
            "owned logging rule does not match fixed NFLOG values",
        ));
    }
    Ok(OwnedRule::SampledViolation {
        chain,
        nflog_group: 4242,
        prefix: prefix.to_owned(),
        packet_prefix_bytes: 64,
        sample_rate_per_second: 100,
        sample_burst: 100,
    })
}

fn find_expression<'a>(expressions: &'a [Value], key: &str) -> Option<&'a Value> {
    expressions
        .iter()
        .find_map(|expression| expression.get(key))
}

fn has_named_counter(expressions: &[Value], name: &str) -> bool {
    let Some(counter) = find_expression(expressions, "counter") else {
        return false;
    };
    match counter {
        Value::String(value) => value == name,
        Value::Object(value) => value.get("name").and_then(Value::as_str) == Some(name),
        _ => false,
    }
}

fn extract_destination(expressions: &[Value]) -> Result<(String, String), BackendError> {
    for expression in expressions {
        let Some(matcher) = expression.get("match") else {
            continue;
        };
        let Some(left) = matcher.get("left").and_then(|left| left.get("payload")) else {
            continue;
        };
        let protocol = left.get("protocol").and_then(Value::as_str);
        let field = left.get("field").and_then(Value::as_str);
        if !matches!(
            (protocol, field),
            (Some("ip"), Some("daddr")) | (Some("ip6"), Some("daddr"))
        ) {
            continue;
        }
        let family = protocol.unwrap().to_owned();
        let right = matcher.get("right").ok_or_else(|| {
            BackendError::new("unexpected_nft_state", "allowance destination is absent")
        })?;
        if let Some(address) = right.as_str() {
            return Ok((family, address.to_owned()));
        }
        if let Some(prefix) = right.get("prefix") {
            let address = require_string(prefix, "addr")?;
            let length = require_i64(prefix, "len")?;
            return Ok((family, format!("{address}/{length}")));
        }
    }
    Err(BackendError::new(
        "unexpected_nft_state",
        "allowance rule does not contain a typed destination",
    ))
}

fn extract_transport(expressions: &[Value]) -> Result<(String, u16), BackendError> {
    for expression in expressions {
        let Some(matcher) = expression.get("match") else {
            continue;
        };
        let Some(left) = matcher.get("left").and_then(|left| left.get("payload")) else {
            continue;
        };
        let protocol = left.get("protocol").and_then(Value::as_str);
        let field = left.get("field").and_then(Value::as_str);
        if !matches!(
            (protocol, field),
            (Some("tcp"), Some("dport")) | (Some("udp"), Some("dport"))
        ) {
            continue;
        }
        let port = matcher
            .get("right")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(|| {
                BackendError::new(
                    "unexpected_nft_state",
                    "allowance transport port is invalid",
                )
            })?;
        return Ok((protocol.unwrap().to_owned(), port));
    }
    Err(BackendError::new(
        "unexpected_nft_state",
        "allowance rule does not contain a typed transport",
    ))
}

fn has_accept(expressions: &[Value]) -> bool {
    has_key(expressions, "accept")
}

fn has_established_related_state(expressions: &[Value]) -> bool {
    expressions.iter().any(|expression| {
        let Some(matcher) = expression.get("match") else {
            return false;
        };
        let is_ct_state = matcher
            .get("left")
            .and_then(|left| left.get("ct"))
            .and_then(|ct| ct.get("key"))
            .and_then(Value::as_str)
            == Some("state");
        let values = matcher
            .get("right")
            .and_then(Value::as_array)
            .map(|values| values.iter().filter_map(Value::as_u64).collect::<Vec<_>>());
        is_ct_state && values.as_deref() == Some(&[2, 4])
    })
}

fn has_jump(expressions: &[Value], target: &str) -> bool {
    expressions
        .iter()
        .any(|expression| expression.get("jump").and_then(Value::as_str) == Some(target))
}

fn has_key(expressions: &[Value], key: &str) -> bool {
    expressions
        .iter()
        .any(|expression| expression.get(key).is_some())
}

fn has_scalar(expressions: &[Value], expected: &str) -> bool {
    expressions
        .iter()
        .any(|expression| value_contains_scalar(expression, expected))
}

fn value_contains_scalar(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_scalar(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_scalar(value, expected)),
        _ => false,
    }
}

fn has_number(expressions: &[Value], expected: i64) -> bool {
    expressions
        .iter()
        .any(|expression| value_contains_number(expression, expected))
}

fn value_contains_number(value: &Value, expected: i64) -> bool {
    match value {
        Value::Number(value) => value.as_i64() == Some(expected),
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_number(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_number(value, expected)),
        _ => false,
    }
}

fn require_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, BackendError> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| {
        BackendError::new(
            "unexpected_nft_state",
            format!("nft object is missing {field}"),
        )
    })
}

fn require_i64(value: &Value, field: &str) -> Result<i64, BackendError> {
    value.get(field).and_then(Value::as_i64).ok_or_else(|| {
        BackendError::new(
            "unexpected_nft_state",
            format!("nft object is missing {field}"),
        )
    })
}

fn validate_test_identifier(identifier: &str) -> Result<(), BackendError> {
    let valid = !identifier.is_empty()
        && identifier.len() <= 64
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !identifier.starts_with('-')
        && !identifier.ends_with('-');
    if valid {
        Ok(())
    } else {
        Err(BackendError::new(
            "invalid_test_identifier",
            "test namespace and evidence identifiers must be bounded slugs",
        ))
    }
}

#[derive(Serialize)]
struct TestStateDocument<'a> {
    status: &'static str,
    owned_state: &'a OwnedNftState,
}

pub fn write_test_evidence(
    root: &Path,
    invocation_id: &str,
    evidence: &NetworkEvidence,
    owned_state: &OwnedNftState,
) -> Result<PathBuf, BackendError> {
    validate_test_identifier(invocation_id)?;
    fs::create_dir_all(root).map_err(|error| {
        BackendError::new("evidence_io_failed", bounded_message(&error.to_string()))
    })?;
    set_directory_mode(root, 0o700)?;
    let directory = root.join(invocation_id);
    fs::create_dir(&directory).map_err(|error| {
        BackendError::new("evidence_io_failed", bounded_message(&error.to_string()))
    })?;
    set_directory_mode(&directory, 0o700)?;
    let state = serde_json::to_vec(&TestStateDocument {
        status: "network_enforcement_test_only",
        owned_state,
    })
    .map_err(|_| {
        BackendError::new(
            "evidence_serialization_failed",
            "failed to serialize test state",
        )
    })?;
    let report = serde_json::to_vec(evidence).map_err(|_| {
        BackendError::new(
            "evidence_serialization_failed",
            "failed to serialize test report",
        )
    })?;
    if report.len() > MAX_REPORT_BYTES {
        return Err(BackendError::new(
            "evidence_report_too_large",
            "test evidence report exceeds the fixed report limit",
        ));
    }
    write_exclusive(&directory.join("state.json"), &state, 0o600)?;
    write_exclusive(&directory.join("report.json"), &report, 0o644)?;
    Ok(directory)
}

fn write_exclusive(path: &Path, bytes: &[u8], mode: u32) -> Result<(), BackendError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| {
            BackendError::new("evidence_io_failed", bounded_message(&error.to_string()))
        })?;
    file.write_all(bytes).map_err(|error| {
        BackendError::new("evidence_io_failed", bounded_message(&error.to_string()))
    })
}

fn set_directory_mode(path: &Path, mode: u32) -> Result<(), BackendError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
        BackendError::new("evidence_io_failed", bounded_message(&error.to_string()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DestinationType, Mode, Protocol};
    use crate::nft::{
        NETWORK_EVIDENCE_STATUS, expected_owned_state, unapplied_test_evidence_model,
    };
    use crate::plan::EffectiveAllowance;
    use serde_json::json;
    use std::cell::RefCell;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_DIRECTORY_INDEX: AtomicUsize = AtomicUsize::new(0);

    struct FakeExecutor {
        responses: RefCell<Vec<Result<Vec<u8>, BackendError>>>,
        operations: RefCell<Vec<NftOperation>>,
    }

    impl FakeExecutor {
        fn with_responses(responses: Vec<Result<Vec<u8>, BackendError>>) -> Self {
            Self {
                responses: RefCell::new(responses),
                operations: RefCell::new(Vec::new()),
            }
        }
    }

    impl NftExecutor for FakeExecutor {
        fn execute(&self, operation: NftOperation, _input: &[u8]) -> Result<Vec<u8>, BackendError> {
            self.operations.borrow_mut().push(operation);
            self.responses.borrow_mut().remove(0)
        }
    }

    fn allowances() -> Vec<EffectiveAllowance> {
        vec![
            EffectiveAllowance {
                destination_type: DestinationType::Ip,
                destination: "192.0.2.10".to_owned(),
                protocol: Protocol::Tcp,
                port: 443,
            },
            EffectiveAllowance {
                destination_type: DestinationType::Cidr,
                destination: "2001:db8::/64".to_owned(),
                protocol: Protocol::Udp,
                port: 53,
            },
        ]
    }

    fn object(kind: &str, value: Value) -> Value {
        json!({ kind: value })
    }

    fn rule(chain: &str, comment: &str, expressions: Value) -> Value {
        object(
            "rule",
            json!({
                "family": NFT_FAMILY,
                "table": NFT_TABLE,
                "chain": chain,
                "comment": comment,
                "expr": expressions
            }),
        )
    }

    fn active_state_json(mode: Mode) -> Vec<u8> {
        let (prefix, terminal_comment, terminal) = match mode {
            Mode::Block => (
                "fence-v0-block",
                "fence:reject_violation",
                json!({"reject": null}),
            ),
            Mode::Audit => (
                "fence-v0-audit",
                "fence:accept_violation",
                json!({"accept": null}),
            ),
        };
        let objects = vec![
            json!({"metainfo": {"json_schema_version": 1}}),
            object("table", json!({"family": NFT_FAMILY, "name": NFT_TABLE})),
            object(
                "chain",
                json!({"family": NFT_FAMILY, "table": NFT_TABLE, "name": NFT_CLASSIFY_CHAIN}),
            ),
            object(
                "chain",
                json!({"family": NFT_FAMILY, "table": NFT_TABLE, "name": NFT_OUTPUT_CHAIN, "type": "filter", "hook": "output", "prio": 10, "policy": "accept"}),
            ),
            object(
                "chain",
                json!({"family": NFT_FAMILY, "table": NFT_TABLE, "name": NFT_VIOLATION_CHAIN}),
            ),
            object(
                "chain",
                json!({"family": NFT_FAMILY, "table": NFT_TABLE, "name": NFT_FORWARD_CHAIN, "type": "filter", "hook": "forward", "prio": 10, "policy": "accept"}),
            ),
            object(
                "counter",
                json!({"family": NFT_FAMILY, "table": NFT_TABLE, "name": NFT_TOTAL_VIOLATIONS_COUNTER}),
            ),
            object(
                "counter",
                json!({"family": NFT_FAMILY, "table": NFT_TABLE, "name": NFT_SAMPLED_VIOLATIONS_COUNTER}),
            ),
            rule(
                NFT_OUTPUT_CHAIN,
                "fence:loopback",
                json!([{"match": {"left": {"meta": {"key": "oifname"}}, "op": "==", "right": "lo"}}, {"accept": null}]),
            ),
            rule(
                NFT_OUTPUT_CHAIN,
                "fence:established",
                json!([{"match": {"left": {"ct": {"key": "state"}}, "op": "in", "right": [2, 4]}}, {"accept": null}]),
            ),
            rule(
                NFT_OUTPUT_CHAIN,
                "fence:implicit_ipv6_control",
                json!([{"match": {"left": {"payload": {"protocol": "ip6", "field": "hoplimit"}}, "op": "==", "right": 255}}, {"match": {"left": {"payload": {"protocol": "icmpv6", "field": "type"}}, "op": "in", "right": ["nd-router-solicit", "nd-neighbor-solicit", "nd-neighbor-advert"]}}, {"accept": null}]),
            ),
            rule(
                NFT_OUTPUT_CHAIN,
                "fence:classify",
                json!([{"jump": NFT_CLASSIFY_CHAIN}]),
            ),
            rule(
                NFT_FORWARD_CHAIN,
                "fence:established",
                json!([{"match": {"left": {"ct": {"key": "state"}}, "op": "in", "right": [2, 4]}}, {"accept": null}]),
            ),
            rule(
                NFT_FORWARD_CHAIN,
                "fence:classify",
                json!([{"jump": NFT_CLASSIFY_CHAIN}]),
            ),
            rule(
                NFT_CLASSIFY_CHAIN,
                "fence:allowance",
                json!([{"match": {"left": {"payload": {"protocol": "ip", "field": "daddr"}}, "op": "==", "right": "192.0.2.10"}}, {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "op": "==", "right": 443}}, {"accept": null}]),
            ),
            rule(
                NFT_CLASSIFY_CHAIN,
                "fence:allowance",
                json!([{"match": {"left": {"payload": {"protocol": "ip6", "field": "daddr"}}, "op": "==", "right": {"prefix": {"addr": "2001:db8::", "len": 64}}}}, {"match": {"left": {"payload": {"protocol": "udp", "field": "dport"}}, "op": "==", "right": 53}}, {"accept": null}]),
            ),
            rule(
                NFT_CLASSIFY_CHAIN,
                "fence:violation",
                json!([{"jump": NFT_VIOLATION_CHAIN}]),
            ),
            rule(
                NFT_VIOLATION_CHAIN,
                "fence:sample_violation",
                json!([{"limit": {"rate": 100, "per": "second", "burst": 100}}, {"counter": {"name": NFT_SAMPLED_VIOLATIONS_COUNTER}}, {"log": {"group": 4242, "prefix": prefix, "snaplen": 64, "qthreshold": 1}}]),
            ),
            rule(
                NFT_VIOLATION_CHAIN,
                terminal_comment,
                json!([{"counter": {"name": NFT_TOTAL_VIOLATIONS_COUNTER}}, terminal]),
            ),
        ];
        serde_json::to_vec(&json!({"nftables": objects})).unwrap()
    }

    #[test]
    fn backend_preflights_applies_verifies_and_rolls_back_owned_state_only() {
        let executor = FakeExecutor::with_responses(vec![
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(active_state_json(Mode::Block)),
            Ok(Vec::new()),
        ]);
        let mut backend = NativeNftBackend::new(executor);

        assert!(!backend.rollback_pre_activation().unwrap());
        backend.preflight("program").unwrap();
        backend.apply_provisional("program").unwrap();
        backend
            .verify_owned_state(&expected_owned_state(Mode::Block, &allowances()))
            .unwrap();
        assert!(backend.rollback_pre_activation().unwrap());
        assert_eq!(
            *backend.executor.operations.borrow(),
            vec![
                NftOperation::Preflight,
                NftOperation::ApplyProvisional,
                NftOperation::ReadOwnedState,
                NftOperation::DeleteOwnedState
            ]
        );
    }

    #[test]
    fn backend_refuses_mismatched_or_failed_provisional_state() {
        let executor = FakeExecutor::with_responses(vec![Ok(active_state_json(Mode::Block))]);
        let backend = NativeNftBackend::new(executor);
        assert_eq!(
            backend
                .verify_owned_state(&expected_owned_state(Mode::Audit, &allowances()))
                .unwrap_err()
                .code,
            "owned_nft_state_mismatch"
        );

        let executor =
            FakeExecutor::with_responses(vec![Err(BackendError::new("apply_failed", "no table"))]);
        let mut backend = NativeNftBackend::new(executor);
        assert_eq!(
            backend.apply_provisional("invalid").unwrap_err().code,
            "apply_failed"
        );
        assert!(!backend.rollback_pre_activation().unwrap());
    }

    #[test]
    fn backend_reads_structured_total_violation_counter() {
        let counter = serde_json::to_vec(&json!({
            "nftables": [
                {"counter": {"family": NFT_FAMILY, "table": NFT_TABLE, "name": NFT_TOTAL_VIOLATIONS_COUNTER, "packets": 7, "bytes": 400}}
            ]
        }))
        .unwrap();
        let backend = NativeNftBackend::new(FakeExecutor::with_responses(vec![Ok(counter)]));

        assert_eq!(backend.total_violation_packets().unwrap(), 7);
        assert_eq!(
            *backend.executor.operations.borrow(),
            vec![NftOperation::ReadTotalViolationsCounter]
        );
    }

    #[test]
    fn parser_rejects_foreign_objects_and_malformed_rules() {
        let foreign = serde_json::to_vec(&json!({
            "nftables": [{"table": {"family": "inet", "name": "foreign"}}]
        }))
        .unwrap();
        assert_eq!(
            parse_owned_state(&foreign).unwrap_err().code,
            "unexpected_nft_state"
        );

        let malformed = serde_json::to_vec(&json!({
            "nftables": [
                {"table": {"family": NFT_FAMILY, "name": NFT_TABLE}},
                {"rule": {"family": NFT_FAMILY, "table": NFT_TABLE, "chain": NFT_VIOLATION_CHAIN, "comment": "fence:sample_violation", "expr": [{"counter": {"name": NFT_SAMPLED_VIOLATIONS_COUNTER}}, {"log": {"group": 1, "prefix": "fence-v0-block", "snaplen": 64, "qthreshold": 1}}, {"limit": {"rate": 100, "per": "second", "burst": 100}}]}}
            ]
        }))
        .unwrap();
        assert_eq!(
            parse_owned_state(&malformed).unwrap_err().code,
            "unexpected_nft_state"
        );
        assert_eq!(
            parse_owned_state(b"[]").unwrap_err().code,
            "invalid_nft_json"
        );
    }

    #[test]
    fn subprocess_runner_bounds_output_error_and_deadline() {
        let echoed = run_process_bounded(
            Path::new("/bin/cat"),
            &[],
            b"rules",
            Duration::from_secs(1),
            32,
        )
        .unwrap();
        assert_eq!(echoed, b"rules");

        let failed = run_process_bounded(
            Path::new("/bin/sh"),
            &["-c", "printf denied >&2; exit 3"],
            b"",
            Duration::from_secs(1),
            32,
        )
        .unwrap_err();
        assert_eq!(failed.code, "nft_command_failed");
        assert_eq!(failed.message, "denied");

        let overflow = run_process_bounded(
            Path::new("/bin/sh"),
            &["-c", "printf 123456789"],
            b"",
            Duration::from_secs(1),
            4,
        )
        .unwrap_err();
        assert_eq!(overflow.code, "nft_output_too_large");

        let timeout = run_process_bounded(
            Path::new("/bin/sleep"),
            &["1"],
            b"",
            Duration::from_millis(1),
            32,
        )
        .unwrap_err();
        assert_eq!(timeout.code, "nft_command_timeout");

        let missing = run_process_bounded(
            Path::new("/missing/fence-command"),
            &[],
            b"",
            Duration::from_secs(1),
            32,
        )
        .unwrap_err();
        assert_eq!(missing.code, "nft_spawn_failed");
        assert!(bounded_message(&"x".repeat(600)).ends_with("..."));
    }

    #[test]
    fn executor_selects_fixed_host_or_bounded_test_namespace_command() {
        let host = SystemNftExecutor::host();
        assert_eq!(host.executable, PathBuf::from(NFT_BINARY_PATH));
        assert!(host.prefix_arguments.is_empty());

        let namespace = SystemNftExecutor::in_test_network_namespace("proof-1").unwrap();
        assert_eq!(namespace.executable, PathBuf::from(IP_BINARY_PATH));
        assert_eq!(namespace.prefix_arguments[2], "proof-1");
        assert_eq!(
            SystemNftExecutor::in_test_network_namespace("../host")
                .unwrap_err()
                .code,
            "invalid_test_identifier"
        );
    }

    #[test]
    fn evidence_writer_creates_only_bounded_non_ready_files() {
        let index = TEST_DIRECTORY_INDEX.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!("target/tmp/nft-evidence-unit-{index}"));
        let _ = fs::remove_dir_all(&root);
        let evidence =
            unapplied_test_evidence_model(Mode::Audit, "policy".to_owned(), "ruleset".to_owned());
        assert_eq!(evidence.status, NETWORK_EVIDENCE_STATUS);

        let directory = write_test_evidence(
            &root,
            "proof-1",
            &evidence,
            &expected_owned_state(Mode::Audit, &[]),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(directory.join("state.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(directory.join("report.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert!(!directory.join("ready.json").exists());
        assert_eq!(
            write_test_evidence(
                &root,
                "proof-1",
                &evidence,
                &expected_owned_state(Mode::Audit, &[])
            )
            .unwrap_err()
            .code,
            "evidence_io_failed"
        );
        assert_eq!(
            write_test_evidence(
                &root,
                "../bad",
                &evidence,
                &expected_owned_state(Mode::Audit, &[])
            )
            .unwrap_err()
            .code,
            "invalid_test_identifier"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
