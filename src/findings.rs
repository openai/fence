use crate::attribution::{LocalProcessAttribution, SocketFamily, SocketProtocol, SocketTuple};
use crate::config::{MAX_FINDINGS, Mode};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(any(target_os = "linux", test))]
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PACKET_PREFIX_BYTES: usize = 64;
#[cfg(any(target_os = "linux", test))]
pub(crate) const MAX_CONNECTION_EVENTS_PER_BATCH: usize = 32;
#[cfg(any(target_os = "linux", test))]
pub(crate) const MAX_CONNECTION_EVENT_BATCH_DURATION: Duration = Duration::from_millis(20);
const RULE_CLASS_EGRESS: &str = "undeclared_new_egress";
const RULE_CLASS_UNAVAILABLE: &str = "endpoint_unavailable_from_prefix";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClassification {
    Rejected,
    WouldBlock,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnparsedReason {
    ShortHeader,
    InvalidIpv4Header,
    Ipv4Fragment,
    UnsupportedIpv4Protocol,
    UnsupportedIpv6Header,
    UnknownIpVersion,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConnectionFinding {
    pub timestamp: String,
    pub mode: Mode,
    pub classification: FindingClassification,
    pub family: String,
    pub protocol: String,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub rule_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_attribution: Option<LocalProcessAttribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unparsed_reason: Option<UnparsedReason>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ConnectionEvent {
    pub finding: ConnectionFinding,
    pub tuple: Option<SocketTuple>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ConnectionEventDrain {
    Exhausted,
    Pending,
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn drain_connection_events(
    first_timeout: Duration,
    receive: &mut dyn FnMut(Duration) -> Result<Option<ConnectionEvent>, ()>,
    record: &mut dyn FnMut(ConnectionEvent),
) -> Result<ConnectionEventDrain, ()> {
    let mut now = Instant::now;
    drain_connection_events_with_clock(first_timeout, receive, record, &mut now)
}

#[cfg(any(target_os = "linux", test))]
fn drain_connection_events_with_clock(
    first_timeout: Duration,
    receive: &mut dyn FnMut(Duration) -> Result<Option<ConnectionEvent>, ()>,
    record: &mut dyn FnMut(ConnectionEvent),
    now: &mut dyn FnMut() -> Instant,
) -> Result<ConnectionEventDrain, ()> {
    let started = now();
    for index in 0..MAX_CONNECTION_EVENTS_PER_BATCH {
        if index != 0
            && now().saturating_duration_since(started) >= MAX_CONNECTION_EVENT_BATCH_DURATION
        {
            return Ok(ConnectionEventDrain::Pending);
        }
        let timeout = if index == 0 {
            first_timeout
        } else {
            Duration::ZERO
        };
        match receive(timeout)? {
            Some(event) => record(event),
            None => return Ok(ConnectionEventDrain::Exhausted),
        }
    }
    Ok(ConnectionEventDrain::Pending)
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct FindingCollection {
    pub retained: Vec<ConnectionFinding>,
    pub sampled_total: u64,
    pub truncated: bool,
}

impl FindingCollection {
    pub fn empty() -> Self {
        Self {
            retained: Vec::new(),
            sampled_total: 0,
            truncated: false,
        }
    }

    pub fn record_prefix(&mut self, mode: Mode, timestamp: String, prefix: &[u8]) {
        self.record_finding(finding_from_prefix(mode, timestamp, prefix));
    }

    pub fn record_finding(&mut self, finding: ConnectionFinding) -> Option<usize> {
        self.sampled_total = self.sampled_total.saturating_add(1);
        if self.retained.len() == MAX_FINDINGS {
            self.truncated = true;
            return None;
        }
        let index = self.retained.len();
        self.retained.push(finding);
        Some(index)
    }

    pub fn record_attribution(&mut self, index: usize, attribution: LocalProcessAttribution) {
        if let Some(finding) = self.retained.get_mut(index) {
            finding.local_attribution = Some(attribution);
        }
    }
}

pub fn bounded_timestamp_now() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("unix-ms:{millis}")
}

pub fn finding_from_prefix(mode: Mode, timestamp: String, prefix: &[u8]) -> ConnectionFinding {
    connection_event_from_prefix(mode, timestamp, prefix).finding
}

pub(crate) fn connection_event_from_prefix(
    mode: Mode,
    timestamp: String,
    prefix: &[u8],
) -> ConnectionEvent {
    let prefix = &prefix[..prefix.len().min(PACKET_PREFIX_BYTES)];
    let classification = match mode {
        Mode::Block => FindingClassification::Rejected,
        Mode::Audit => FindingClassification::WouldBlock,
    };
    match prefix.first().map(|byte| byte >> 4) {
        Some(4) => ipv4_event(mode, classification, timestamp, prefix),
        Some(6) => ipv6_event(mode, classification, timestamp, prefix),
        None => unavailable_event(
            mode,
            classification,
            timestamp,
            "unknown_or_unparsed",
            UnparsedReason::ShortHeader,
        ),
        _ => unavailable_event(
            mode,
            classification,
            timestamp,
            "unknown_or_unparsed",
            UnparsedReason::UnknownIpVersion,
        ),
    }
}

fn ipv4_event(
    mode: Mode,
    classification: FindingClassification,
    timestamp: String,
    prefix: &[u8],
) -> ConnectionEvent {
    if prefix.len() < 20 {
        return unavailable_event(
            mode,
            classification,
            timestamp,
            "ipv4",
            UnparsedReason::ShortHeader,
        );
    }
    let header_length = usize::from(prefix[0] & 0x0f) * 4;
    let fragmented = (u16::from_be_bytes([prefix[6], prefix[7]]) & 0x3fff) != 0;
    if header_length < 20 {
        return unavailable_event(
            mode,
            classification,
            timestamp,
            "ipv4",
            UnparsedReason::InvalidIpv4Header,
        );
    }
    if fragmented {
        return unavailable_event(
            mode,
            classification,
            timestamp,
            "ipv4",
            UnparsedReason::Ipv4Fragment,
        );
    }
    let (protocol, socket_protocol) = match prefix[9] {
        6 => ("tcp", SocketProtocol::Tcp),
        17 => ("udp", SocketProtocol::Udp),
        _ => {
            return unavailable_event(
                mode,
                classification,
                timestamp,
                "ipv4",
                UnparsedReason::UnsupportedIpv4Protocol,
            );
        }
    };
    let Some(port_bytes) = prefix.get(header_length..header_length + 4) else {
        return unavailable_event(
            mode,
            classification,
            timestamp,
            "ipv4",
            UnparsedReason::ShortHeader,
        );
    };
    let local_address = Ipv4Addr::new(prefix[12], prefix[13], prefix[14], prefix[15]);
    let remote_address = Ipv4Addr::new(prefix[16], prefix[17], prefix[18], prefix[19]);
    endpoint_event(
        mode,
        classification,
        timestamp,
        "ipv4",
        protocol,
        socket_protocol,
        SocketFamily::Ipv4,
        IpAddr::V4(local_address),
        u16::from_be_bytes([port_bytes[0], port_bytes[1]]),
        remote_address.to_string(),
        IpAddr::V4(remote_address),
        u16::from_be_bytes([port_bytes[2], port_bytes[3]]),
    )
}

fn ipv6_event(
    mode: Mode,
    classification: FindingClassification,
    timestamp: String,
    prefix: &[u8],
) -> ConnectionEvent {
    if prefix.len() < 44 {
        return unavailable_event(
            mode,
            classification,
            timestamp,
            "ipv6",
            UnparsedReason::ShortHeader,
        );
    }
    let (protocol, socket_protocol) = match prefix[6] {
        6 => ("tcp", SocketProtocol::Tcp),
        17 => ("udp", SocketProtocol::Udp),
        _ => {
            return unavailable_event(
                mode,
                classification,
                timestamp,
                "ipv6",
                UnparsedReason::UnsupportedIpv6Header,
            );
        }
    };
    let source: [u8; 16] = prefix[8..24].try_into().expect("fixed checked IPv6 length");
    let destination: [u8; 16] = prefix[24..40]
        .try_into()
        .expect("fixed checked IPv6 length");
    let source_port = u16::from_be_bytes([prefix[40], prefix[41]]);
    let destination_port = u16::from_be_bytes([prefix[42], prefix[43]]);
    endpoint_event(
        mode,
        classification,
        timestamp,
        "ipv6",
        protocol,
        socket_protocol,
        SocketFamily::Ipv6,
        IpAddr::V6(Ipv6Addr::from(source)),
        source_port,
        Ipv6Addr::from(destination).to_string(),
        IpAddr::V6(Ipv6Addr::from(destination)),
        destination_port,
    )
}

#[allow(clippy::too_many_arguments)]
fn endpoint_event(
    mode: Mode,
    classification: FindingClassification,
    timestamp: String,
    family: &'static str,
    protocol: &'static str,
    socket_protocol: SocketProtocol,
    socket_family: SocketFamily,
    local_address: IpAddr,
    local_port: u16,
    remote_address: String,
    remote_ip: IpAddr,
    remote_port: u16,
) -> ConnectionEvent {
    ConnectionEvent {
        finding: ConnectionFinding {
            timestamp,
            mode,
            classification,
            family: family.to_owned(),
            protocol: protocol.to_owned(),
            remote_address: Some(remote_address),
            remote_port: Some(remote_port),
            rule_class: RULE_CLASS_EGRESS.to_owned(),
            local_attribution: None,
            unparsed_reason: None,
        },
        tuple: Some(SocketTuple {
            family: socket_family,
            protocol: socket_protocol,
            local_address,
            local_port,
            remote_address: remote_ip,
            remote_port,
        }),
    }
}

fn unavailable_event(
    mode: Mode,
    classification: FindingClassification,
    timestamp: String,
    family: &'static str,
    reason: UnparsedReason,
) -> ConnectionEvent {
    ConnectionEvent {
        finding: ConnectionFinding {
            timestamp,
            mode,
            classification,
            family: family.to_owned(),
            protocol: "unknown_or_unparsed".to_owned(),
            remote_address: None,
            remote_port: None,
            rule_class: RULE_CLASS_UNAVAILABLE.to_owned(),
            local_attribution: None,
            unparsed_reason: Some(reason),
        },
        tuple: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;

    fn ipv4_prefix(protocol: u8, port: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20 + 4];
        packet[0] = 0x45;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 10]);
        packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv6_prefix(next_header: u8, port: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 44];
        packet[0] = 0x60;
        packet[6] = next_header;
        packet[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
        packet[40..42].copy_from_slice(&53_000_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&port.to_be_bytes());
        packet
    }

    fn queued_connection_event(index: usize) -> ConnectionEvent {
        connection_event_from_prefix(
            Mode::Block,
            format!("unix-ms:{index}"),
            &ipv4_prefix(6, 443, &[]),
        )
    }

    #[test]
    fn drains_ready_connection_events_in_fifo_order_without_blocking_again() {
        let mut pending = (0..3).map(queued_connection_event).collect::<VecDeque<_>>();
        let mut observed_timeouts = Vec::new();
        let mut recorded = Vec::new();
        let first_timeout = Duration::from_millis(13);

        let status = drain_connection_events(
            first_timeout,
            &mut |timeout| {
                observed_timeouts.push(timeout);
                Ok::<_, ()>(pending.pop_front())
            },
            &mut |event| recorded.push(event.finding.timestamp),
        )
        .unwrap();

        assert_eq!(status, ConnectionEventDrain::Exhausted);
        assert_eq!(recorded, ["unix-ms:0", "unix-ms:1", "unix-ms:2"]);
        assert_eq!(
            observed_timeouts,
            [
                first_timeout,
                Duration::ZERO,
                Duration::ZERO,
                Duration::ZERO,
            ]
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn reports_an_empty_connection_event_queue_without_spinning() {
        let mut reads = 0;
        let status = drain_connection_events(
            Duration::ZERO,
            &mut |_| {
                reads += 1;
                Ok::<Option<ConnectionEvent>, ()>(None)
            },
            &mut drop,
        )
        .unwrap();

        assert_eq!(status, ConnectionEventDrain::Exhausted);
        assert_eq!(reads, 1);
    }

    #[test]
    fn bounds_a_connection_event_batch_without_losing_fifo_work() {
        let mut pending = (0..MAX_CONNECTION_EVENTS_PER_BATCH + 5)
            .map(queued_connection_event)
            .collect::<VecDeque<_>>();
        let mut recorded = Vec::new();

        let status = drain_connection_events(
            Duration::ZERO,
            &mut |_| Ok::<_, ()>(pending.pop_front()),
            &mut |event| recorded.push(event.finding.timestamp),
        )
        .unwrap();

        assert_eq!(status, ConnectionEventDrain::Pending);
        assert_eq!(recorded.len(), MAX_CONNECTION_EVENTS_PER_BATCH);
        assert_eq!(recorded[0], "unix-ms:0");
        assert_eq!(
            recorded[MAX_CONNECTION_EVENTS_PER_BATCH - 1],
            format!("unix-ms:{}", MAX_CONNECTION_EVENTS_PER_BATCH - 1)
        );
        assert_eq!(pending.len(), 5);
        assert_eq!(
            pending.front().unwrap().finding.timestamp,
            format!("unix-ms:{MAX_CONNECTION_EVENTS_PER_BATCH}")
        );
    }

    #[test]
    fn yields_a_connection_event_batch_when_its_monotonic_budget_expires() {
        let started = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let mut pending = (0..8).map(queued_connection_event).collect::<VecDeque<_>>();
        let mut recorded = Vec::new();

        let status = drain_connection_events_with_clock(
            Duration::ZERO,
            &mut |_| {
                elapsed.set(elapsed.get() + Duration::from_millis(7));
                Ok::<_, ()>(pending.pop_front())
            },
            &mut |event| recorded.push(event.finding.timestamp),
            &mut || started + elapsed.get(),
        )
        .unwrap();

        assert_eq!(status, ConnectionEventDrain::Pending);
        assert_eq!(recorded, ["unix-ms:0", "unix-ms:1", "unix-ms:2"]);
        assert_eq!(pending.len(), 5);
    }

    #[test]
    fn propagates_connection_event_reader_failures_after_recording_prior_events() {
        let mut reads = 0;
        let mut recorded = Vec::new();

        let result = drain_connection_events(
            Duration::ZERO,
            &mut |_| {
                reads += 1;
                if reads == 1 {
                    Ok(Some(queued_connection_event(0)))
                } else {
                    Err(())
                }
            },
            &mut |event| recorded.push(event.finding.timestamp),
        );

        assert!(result.is_err());
        assert_eq!(recorded, ["unix-ms:0"]);
        assert_eq!(reads, 2);
    }

    #[test]
    fn extracts_only_approved_ipv4_and_ipv6_endpoint_metadata() {
        let v4 = finding_from_prefix(Mode::Block, "t1".to_owned(), &ipv4_prefix(6, 443, b""));
        assert_eq!(v4.classification, FindingClassification::Rejected);
        assert_eq!(v4.family, "ipv4");
        assert_eq!(v4.protocol, "tcp");
        assert_eq!(v4.remote_address.as_deref(), Some("192.0.2.10"));
        assert_eq!(v4.remote_port, Some(443));
        assert_eq!(v4.unparsed_reason, None);

        let v6 = finding_from_prefix(Mode::Audit, "t2".to_owned(), &ipv6_prefix(17, 53));
        assert_eq!(v6.classification, FindingClassification::WouldBlock);
        assert_eq!(v6.family, "ipv6");
        assert_eq!(v6.protocol, "udp");
        assert_eq!(v6.remote_address.as_deref(), Some("2001:db8::10"));
        assert_eq!(v6.remote_port, Some(53));
        assert_eq!(v6.unparsed_reason, None);

        let event =
            connection_event_from_prefix(Mode::Block, "t3".to_owned(), &ipv4_prefix(6, 443, b""));
        assert_eq!(
            event.tuple,
            Some(SocketTuple {
                family: SocketFamily::Ipv4,
                protocol: SocketProtocol::Tcp,
                local_address: "10.0.0.2".parse().unwrap(),
                local_port: 40_000,
                remote_address: "192.0.2.10".parse().unwrap(),
                remote_port: 443,
            })
        );
        let json = serde_json::to_string(&event.finding).unwrap();
        assert!(!json.contains("10.0.0.2"));
        assert!(!json.contains("unparsed_reason"));
        assert_eq!(
            serde_json::from_str::<ConnectionFinding>(&json).unwrap(),
            event.finding
        );

        // The packet parser still reports a transport endpoint with port zero.
        // The Action decides whether it can recommend that endpoint.
        let event = connection_event_from_prefix(Mode::Audit, "t4".to_owned(), &ipv6_prefix(17, 0));
        assert_eq!(
            event.tuple,
            Some(SocketTuple {
                family: SocketFamily::Ipv6,
                protocol: SocketProtocol::Udp,
                local_address: "2001:db8::1".parse().unwrap(),
                local_port: 53_000,
                remote_address: "2001:db8::10".parse().unwrap(),
                remote_port: 0,
            })
        );
        assert_eq!(event.finding.unparsed_reason, None);
    }

    #[test]
    fn payload_and_complex_headers_never_enter_findings() {
        let marker = b"do-not-retain-payload-marker";
        let finding = finding_from_prefix(Mode::Block, "t".to_owned(), &ipv4_prefix(17, 9, marker));
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("do-not-retain-payload-marker"));

        let extension = finding_from_prefix(Mode::Audit, "t".to_owned(), &ipv6_prefix(44, 7));
        assert_eq!(extension.rule_class, RULE_CLASS_UNAVAILABLE);
        assert_eq!(extension.protocol, "unknown_or_unparsed");
        assert_eq!(extension.remote_address, None);
        assert_eq!(extension.remote_port, None);
        assert_eq!(
            extension.unparsed_reason,
            Some(UnparsedReason::UnsupportedIpv6Header)
        );
    }

    #[test]
    fn unparseable_headers_emit_only_fixed_reasons_in_both_modes() {
        let marker = b"::error::do-not-retain-payload-marker";
        let mut invalid_v4 = ipv4_prefix(6, 443, marker);
        invalid_v4[0] = 0x44;
        let mut fragment_offset = ipv4_prefix(6, 443, marker);
        fragment_offset[7] = 1;
        let mut more_fragments = ipv4_prefix(17, 9, marker);
        more_fragments[6] = 0x20;
        let mut missing_v4_port = ipv4_prefix(6, 443, b"");
        missing_v4_port[0] = 0x46;
        let mut extension = ipv6_prefix(44, 7);
        extension.extend_from_slice(marker);
        let cases = [
            (vec![], "unknown_or_unparsed", "short_header"),
            (vec![0x70], "unknown_or_unparsed", "unknown_ip_version"),
            (vec![0x45], "ipv4", "short_header"),
            (invalid_v4, "ipv4", "invalid_ipv4_header"),
            (fragment_offset, "ipv4", "ipv4_fragment"),
            (more_fragments, "ipv4", "ipv4_fragment"),
            (
                ipv4_prefix(1, 0, marker),
                "ipv4",
                "unsupported_ipv4_protocol",
            ),
            (missing_v4_port, "ipv4", "short_header"),
            (vec![0x60; 40], "ipv6", "short_header"),
            (extension, "ipv6", "unsupported_ipv6_header"),
        ];
        for (prefix, family, reason) in cases {
            for (mode, classification) in [
                (Mode::Block, FindingClassification::Rejected),
                (Mode::Audit, FindingClassification::WouldBlock),
            ] {
                let event = connection_event_from_prefix(mode, "t".to_owned(), &prefix);
                assert_eq!(event.tuple, None);
                assert_eq!(event.finding.classification, classification);
                assert_eq!(event.finding.family, family);
                assert_eq!(event.finding.rule_class, RULE_CLASS_UNAVAILABLE);
                assert_eq!(event.finding.protocol, "unknown_or_unparsed");
                assert_eq!(event.finding.remote_address, None);
                assert_eq!(event.finding.remote_port, None);

                let json = serde_json::to_string(&event.finding).unwrap();
                let value: serde_json::Value = serde_json::from_str(&json).unwrap();
                assert_eq!(value["unparsed_reason"], reason);
                for forbidden in [
                    "do-not-retain-payload-marker",
                    "::error::",
                    "192.0.2.10",
                    "2001:db8::10",
                    "10.0.0.2",
                ] {
                    assert!(!json.contains(forbidden));
                }
                assert_eq!(
                    serde_json::from_str::<ConnectionFinding>(&json).unwrap(),
                    event.finding
                );
            }
        }
        assert_eq!(
            finding_from_prefix(Mode::Audit, "t".to_owned(), &ipv6_prefix(6, 443)).protocol,
            "tcp"
        );
    }

    #[test]
    fn bounds_prefix_use_and_retained_finding_count() {
        let mut collection = FindingCollection::empty();
        let oversized = ipv4_prefix(6, 443, &[b'x'; PACKET_PREFIX_BYTES * 2]);
        for _ in 0..=MAX_FINDINGS {
            collection.record_prefix(Mode::Block, "t".to_owned(), &oversized);
        }
        assert_eq!(collection.retained.len(), MAX_FINDINGS);
        assert_eq!(collection.sampled_total, (MAX_FINDINGS + 1) as u64);
        assert!(collection.truncated);
        assert!(
            !serde_json::to_string(&collection)
                .unwrap()
                .contains(&"x".repeat(8))
        );
        assert!(bounded_timestamp_now().starts_with("unix-ms:"));
    }

    #[test]
    fn attaches_attribution_only_to_a_retained_finding() {
        let mut collection = FindingCollection::empty();
        let index = collection
            .record_finding(finding_from_prefix(
                Mode::Audit,
                "t".to_owned(),
                &ipv4_prefix(6, 443, b""),
            ))
            .unwrap();
        let attribution = LocalProcessAttribution {
            status: crate::attribution::AttributionStatus::Attributed,
            actor_class: crate::attribution::ActorClass::Runner,
            pid: Some(42),
            executable_basename: Some("curl".to_owned()),
            parent_executable_basenames: vec!["bash".to_owned()],
        };
        collection.record_attribution(index, attribution.clone());
        collection.record_attribution(index + 1, attribution.clone());
        assert_eq!(
            collection.retained[index].local_attribution,
            Some(attribution)
        );
    }
}
