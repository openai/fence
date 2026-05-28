use crate::config::Mode;
use crate::findings::{ConnectionFinding, bounded_timestamp_now, finding_from_prefix};
use crate::nft::{NFLOG_GROUP, NFLOG_PACKET_PREFIX_BYTES, NFLOG_PREFIX_AUDIT, NFLOG_PREFIX_BLOCK};
use netlink_packet_netfilter::{
    constants::{AF_INET, AF_INET6, AF_UNSPEC, NFULA_PAYLOAD, NFULA_PREFIX, NFULNL_MSG_PACKET},
    nflog::{
        NfLogMessage, config_request,
        nlas::config::{ConfigCmd, ConfigMode},
    },
};
use netlink_sys::{Socket, SocketAddr, constants::NETLINK_NETFILTER};
use std::io::ErrorKind;
use std::thread;
use std::time::{Duration, Instant};

const RECEIVE_BUFFER_BYTES: usize = 4096;
const CONFIG_TIMEOUT: Duration = Duration::from_secs(2);
const NLMSG_ERROR: u16 = 2;
const NFLOG_PACKET_MESSAGE: u16 = ((NfLogMessage::SUBSYS as u16) << 8) | NFULNL_MSG_PACKET as u16;
const NLA_TYPE_MASK: u16 = 0x3fff;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NflogError {
    pub code: &'static str,
    pub message: String,
}

impl NflogError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub struct NflogReader {
    socket: Socket,
    mode: Mode,
}

impl NflogReader {
    pub fn bind(mode: Mode) -> Result<Self, NflogError> {
        let mut socket = Socket::new(NETLINK_NETFILTER)
            .map_err(|error| io_error("nflog_socket_failed", error))?;
        socket
            .bind_auto()
            .map_err(|error| io_error("nflog_bind_failed", error))?;
        socket
            .connect(&SocketAddr::new(0, 0))
            .map_err(|error| io_error("nflog_connect_failed", error))?;
        socket
            .set_non_blocking(true)
            .map_err(|error| io_error("nflog_nonblocking_failed", error))?;

        macro_rules! send_request {
            ($request:expr) => {{
                let request = $request;
                let mut bytes = vec![0_u8; request.buffer_len()];
                request.serialize(&mut bytes);
                send_config_and_wait_for_ack(&socket, &bytes)?;
            }};
        }

        send_request!(config_request(AF_INET, 0, vec![ConfigCmd::PfBind.into()]));
        send_request!(config_request(AF_INET6, 0, vec![ConfigCmd::PfBind.into()]));
        send_request!(config_request(
            AF_UNSPEC,
            NFLOG_GROUP,
            vec![
                ConfigCmd::Bind.into(),
                ConfigMode::new_packet(NFLOG_PACKET_PREFIX_BYTES).into()
            ]
        ));

        Ok(Self { socket, mode })
    }

    pub fn next_finding(&self, timeout: Duration) -> Result<Option<ConnectionFinding>, NflogError> {
        let deadline = Instant::now() + timeout;
        loop {
            match receive_datagram(&self.socket) {
                Ok(bytes) => {
                    let payload = extract_logged_prefix(&bytes, self.mode)?;
                    return Ok(Some(finding_from_prefix(
                        self.mode,
                        bounded_timestamp_now(),
                        payload,
                    )));
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(io_error("nflog_receive_failed", error)),
            }
        }
    }
}

fn send_config_and_wait_for_ack(socket: &Socket, bytes: &[u8]) -> Result<(), NflogError> {
    socket
        .send(bytes, 0)
        .map_err(|error| io_error("nflog_config_send_failed", error))?;
    let deadline = Instant::now() + CONFIG_TIMEOUT;
    loop {
        match receive_datagram(socket) {
            Ok(response) => return parse_ack(&response),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(NflogError::new(
                        "nflog_config_timeout",
                        "timed out waiting for NFLOG configuration acknowledgement",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(io_error("nflog_config_receive_failed", error)),
        }
    }
}

fn receive_datagram(socket: &Socket) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![0_u8; RECEIVE_BUFFER_BYTES];
    let mut output = &mut bytes[..];
    let length = socket.recv(&mut output, 0)?;
    if length > RECEIVE_BUFFER_BYTES {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "NFLOG datagram exceeded bounded receive buffer",
        ));
    }
    bytes.truncate(length);
    Ok(bytes)
}

fn parse_ack(bytes: &[u8]) -> Result<(), NflogError> {
    let length = netlink_length(bytes)?;
    if message_type(bytes)? != NLMSG_ERROR || length < 20 {
        return Err(NflogError::new(
            "nflog_config_invalid_ack",
            "NFLOG configuration did not return a valid acknowledgement",
        ));
    }
    let code = i32::from_ne_bytes(bytes[16..20].try_into().expect("checked ACK length"));
    if code != 0 {
        return Err(NflogError::new(
            "nflog_config_rejected",
            format!(
                "kernel rejected NFLOG configuration with errno {}",
                code.abs()
            ),
        ));
    }
    Ok(())
}

fn extract_logged_prefix(bytes: &[u8], mode: Mode) -> Result<&[u8], NflogError> {
    let length = netlink_length(bytes)?;
    if message_type(bytes)? != NFLOG_PACKET_MESSAGE || length < 20 {
        return Err(NflogError::new(
            "nflog_invalid_event",
            "received a non-packet NFLOG event",
        ));
    }
    if u16::from_be_bytes([bytes[18], bytes[19]]) != NFLOG_GROUP {
        return Err(NflogError::new(
            "nflog_invalid_group",
            "received an event outside the owned NFLOG group",
        ));
    }
    let mut payload = None;
    let mut prefix = None;
    let mut offset = 20;
    while offset + 4 <= length {
        let attribute_length = usize::from(u16::from_ne_bytes([bytes[offset], bytes[offset + 1]]));
        if attribute_length < 4 || offset + attribute_length > length {
            return Err(NflogError::new(
                "nflog_invalid_attribute",
                "received an invalid NFLOG attribute length",
            ));
        }
        let attribute_type =
            u16::from_ne_bytes([bytes[offset + 2], bytes[offset + 3]]) & NLA_TYPE_MASK;
        let value = &bytes[offset + 4..offset + attribute_length];
        match attribute_type {
            NFULA_PAYLOAD => payload = Some(value),
            NFULA_PREFIX => prefix = Some(value.strip_suffix(&[0]).unwrap_or(value)),
            _ => {}
        }
        offset += (attribute_length + 3) & !3;
    }
    let expected_prefix = match mode {
        Mode::Block => NFLOG_PREFIX_BLOCK.as_bytes(),
        Mode::Audit => NFLOG_PREFIX_AUDIT.as_bytes(),
    };
    if prefix != Some(expected_prefix) {
        return Err(NflogError::new(
            "nflog_invalid_prefix",
            "received an event outside the owned NFLOG rule prefix",
        ));
    }
    let payload = payload.ok_or_else(|| {
        NflogError::new(
            "nflog_missing_payload_prefix",
            "NFLOG event omitted its bounded packet prefix",
        )
    })?;
    if payload.len() > NFLOG_PACKET_PREFIX_BYTES as usize {
        return Err(NflogError::new(
            "nflog_payload_prefix_too_large",
            "NFLOG event exceeded the configured packet-prefix bound",
        ));
    }
    Ok(payload)
}

fn netlink_length(bytes: &[u8]) -> Result<usize, NflogError> {
    if bytes.len() < 16 {
        return Err(NflogError::new(
            "nflog_invalid_datagram",
            "NFLOG datagram is shorter than its netlink header",
        ));
    }
    let length = u32::from_ne_bytes(bytes[..4].try_into().expect("checked header length")) as usize;
    if length > bytes.len() || length < 16 {
        return Err(NflogError::new(
            "nflog_invalid_datagram",
            "NFLOG datagram declares an invalid bounded length",
        ));
    }
    Ok(length)
}

fn message_type(bytes: &[u8]) -> Result<u16, NflogError> {
    netlink_length(bytes)?;
    Ok(u16::from_ne_bytes([bytes[4], bytes[5]]))
}

fn io_error(code: &'static str, error: std::io::Error) -> NflogError {
    NflogError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = value.len() + 4;
        let padded = (length + 3) & !3;
        let mut bytes = vec![0_u8; padded];
        bytes[..2].copy_from_slice(&(length as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&kind.to_ne_bytes());
        bytes[4..length].copy_from_slice(value);
        bytes
    }

    fn event(mode: Mode, payload: &[u8]) -> Vec<u8> {
        let label = match mode {
            Mode::Block => b"fence-v0-block\0".as_slice(),
            Mode::Audit => b"fence-v0-audit\0".as_slice(),
        };
        let mut bytes = vec![0_u8; 20];
        bytes[4..6].copy_from_slice(&NFLOG_PACKET_MESSAGE.to_ne_bytes());
        bytes[18..20].copy_from_slice(&NFLOG_GROUP.to_be_bytes());
        bytes.extend(attribute(NFULA_PREFIX, label));
        bytes.extend(attribute(NFULA_PAYLOAD, payload));
        let length = bytes.len() as u32;
        bytes[..4].copy_from_slice(&length.to_ne_bytes());
        bytes
    }

    #[test]
    fn validates_ack_and_extracts_only_owned_bounded_payload_prefix() {
        let mut ack = vec![0_u8; 20];
        ack[..4].copy_from_slice(&20_u32.to_ne_bytes());
        ack[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        assert!(parse_ack(&ack).is_ok());

        let block_event = event(Mode::Block, &[0x45; 64]);
        assert_eq!(
            extract_logged_prefix(&block_event, Mode::Block)
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            extract_logged_prefix(&block_event, Mode::Audit)
                .unwrap_err()
                .code,
            "nflog_invalid_prefix"
        );
        assert_eq!(
            extract_logged_prefix(&event(Mode::Block, &[0; 65]), Mode::Block)
                .unwrap_err()
                .code,
            "nflog_payload_prefix_too_large"
        );
    }
}
