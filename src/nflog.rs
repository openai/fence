use crate::config::Mode;
use crate::findings::{ConnectionFinding, bounded_timestamp_now, finding_from_prefix};
use crate::nft::{NFLOG_GROUP, NFLOG_PACKET_PREFIX_BYTES, NFLOG_PREFIX_AUDIT, NFLOG_PREFIX_BLOCK};
use netlink_sys::{Socket, SocketAddr, constants::NETLINK_NETFILTER};
use std::io::ErrorKind;
use std::thread;
use std::time::{Duration, Instant};

const RECEIVE_BUFFER_BYTES: usize = 4096;
const CONFIG_TIMEOUT: Duration = Duration::from_secs(2);
const NLMSG_ERROR: u16 = 2;
const NETLINK_HEADER_BYTES: usize = 16;
const NFGENMSG_BYTES: usize = 4;
const NLA_HEADER_BYTES: usize = 4;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFLOG_PACKET_MESSAGE: u16 = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET;
const NFLOG_CONFIG_MESSAGE: u16 = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
const NFULA_PAYLOAD: u16 = libc::NFULA_PAYLOAD as u16;
const NFULA_PREFIX: u16 = libc::NFULA_PREFIX as u16;
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

        send_config_and_wait_for_ack(
            &socket,
            &config_request(
                libc::AF_INET as u8,
                0,
                libc::NFULNL_CFG_CMD_PF_BIND as u8,
                None,
            ),
        )?;
        send_config_and_wait_for_ack(
            &socket,
            &config_request(
                libc::AF_INET6 as u8,
                0,
                libc::NFULNL_CFG_CMD_PF_BIND as u8,
                None,
            ),
        )?;
        send_config_and_wait_for_ack(
            &socket,
            &config_request(
                libc::AF_UNSPEC as u8,
                NFLOG_GROUP,
                libc::NFULNL_CFG_CMD_BIND as u8,
                Some(NFLOG_PACKET_PREFIX_BYTES),
            ),
        )?;

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

fn config_request(
    family: u8,
    group: u16,
    command: u8,
    packet_prefix_bytes: Option<u32>,
) -> Vec<u8> {
    let mut attributes = Vec::new();
    push_attribute(&mut attributes, libc::NFULA_CFG_CMD as u16, &[command]);

    if let Some(copy_range) = packet_prefix_bytes {
        let mut mode = [0_u8; 6];
        mode[..4].copy_from_slice(&copy_range.to_be_bytes());
        mode[4] = libc::NFULNL_COPY_PACKET as u8;
        push_attribute(&mut attributes, libc::NFULA_CFG_MODE as u16, &mode);
    }

    let length = NETLINK_HEADER_BYTES + NFGENMSG_BYTES + attributes.len();
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(
        &u32::try_from(length)
            .expect("fixed NFLOG configuration message length must fit in u32")
            .to_ne_bytes(),
    );
    bytes.extend_from_slice(&NFLOG_CONFIG_MESSAGE.to_ne_bytes());
    bytes.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.push(family);
    bytes.push(0);
    bytes.extend_from_slice(&group.to_be_bytes());
    bytes.extend_from_slice(&attributes);
    bytes
}

fn push_attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = NLA_HEADER_BYTES + value.len();
    bytes.extend_from_slice(
        &u16::try_from(length)
            .expect("fixed NFLOG configuration attribute length must fit in u16")
            .to_ne_bytes(),
    );
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len() + align_to_4(length) - length, 0);
}

fn align_to_4(length: usize) -> usize {
    (length + 3) & !3
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
            NFULA_PAYLOAD if payload.replace(value).is_some() => {
                return Err(NflogError::new(
                    "nflog_invalid_attribute",
                    "received a duplicate NFLOG payload attribute",
                ));
            }
            NFULA_PREFIX
                if prefix
                    .replace(value.strip_suffix(&[0]).unwrap_or(value))
                    .is_some() =>
            {
                return Err(NflogError::new(
                    "nflog_invalid_attribute",
                    "received a duplicate NFLOG prefix attribute",
                ));
            }
            _ => {}
        }
        offset += (attribute_length + 3) & !3;
    }
    if offset != length {
        return Err(NflogError::new(
            "nflog_invalid_attribute",
            "received trailing bytes outside aligned NFLOG attributes",
        ));
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

        let mut duplicate_payload = event(Mode::Block, &[0x45; 64]);
        duplicate_payload.extend(attribute(NFULA_PAYLOAD, &[0x45]));
        let length = duplicate_payload.len() as u32;
        duplicate_payload[..4].copy_from_slice(&length.to_ne_bytes());
        assert_eq!(
            extract_logged_prefix(&duplicate_payload, Mode::Block)
                .unwrap_err()
                .code,
            "nflog_invalid_attribute"
        );

        let mut duplicate_prefix = event(Mode::Block, &[0x45; 64]);
        duplicate_prefix.extend(attribute(NFULA_PREFIX, b"fence-v0-block\0"));
        let length = duplicate_prefix.len() as u32;
        duplicate_prefix[..4].copy_from_slice(&length.to_ne_bytes());
        assert_eq!(
            extract_logged_prefix(&duplicate_prefix, Mode::Block)
                .unwrap_err()
                .code,
            "nflog_invalid_attribute"
        );

        let mut trailing_byte = event(Mode::Block, &[0x45; 64]);
        trailing_byte.push(0);
        let length = trailing_byte.len() as u32;
        trailing_byte[..4].copy_from_slice(&length.to_ne_bytes());
        assert_eq!(
            extract_logged_prefix(&trailing_byte, Mode::Block)
                .unwrap_err()
                .code,
            "nflog_invalid_attribute"
        );
    }

    #[test]
    fn renders_fixed_kernel_nflog_configuration_requests() {
        assert_eq!(
            config_request(
                libc::AF_INET as u8,
                0,
                libc::NFULNL_CFG_CMD_PF_BIND as u8,
                None,
            ),
            [
                0x1c, 0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            config_request(
                libc::AF_INET6 as u8,
                0,
                libc::NFULNL_CFG_CMD_PF_BIND as u8,
                None,
            ),
            [
                0x1c, 0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            config_request(
                libc::AF_UNSPEC as u8,
                NFLOG_GROUP,
                libc::NFULNL_CFG_CMD_BIND as u8,
                Some(NFLOG_PACKET_PREFIX_BYTES),
            ),
            [
                0x28, 0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x10, 0x92, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x40, 0x02, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn aligns_kernel_nflog_configuration_attributes() {
        let mut bytes = Vec::new();
        push_attribute(&mut bytes, libc::NFULA_CFG_CMD as u16, &[1]);
        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes[5..], &[0, 0, 0]);

        push_attribute(
            &mut bytes,
            libc::NFULA_CFG_MODE as u16,
            &[0, 0, 0, 64, libc::NFULNL_COPY_PACKET as u8, 0],
        );
        assert_eq!(bytes.len(), 20);
        assert_eq!(&bytes[18..], &[0, 0]);
    }
}
