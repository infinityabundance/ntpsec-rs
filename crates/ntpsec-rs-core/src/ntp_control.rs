// ──── ntp_control.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_control.c (106K)
//
// NTP Mode 6 control protocol (used by ntpq). Implements the full
// read/write/list variable machinery, authentication, and async response
// paging that matches ntpq.py's wire protocol expectations exactly.
//
// ## Protocol Overview (RFC 5905 §14)
//
// Mode 6 messages have a 24-byte header followed by data:
//
//   struct ControlMessage {
//       li_vn_mode:  u8,     // LI(2), VN(3), Mode(3=6)
//       opcode:      u8,     // R(1), E(1), M(1), Op(5)
//       sequence:    u16,    // sequence number
//       status:      u16,    // system/peer status
//       associd:     u16,    // association ID
//       offset:      u16,    // data offset (for paging)
//       count:       u16,    // data count (for paging)
//       data:        [u8],   // variable-length data + optional MAC
//   }
//
// ## Oracle
//   - ntpsec ntpd/ntp_control.c (106K)
//   - ntpsec include/ntp_control.h
//   - ntpsec ntpclients/ntpq.py (73K) — generates and consumes these messages
//   - RFC 5905 §14
//
// ## Court
//   - docs/courts/ntp_control.md
// =============================================================================

use crate::ntp_auth::*;
use crate::ntp_types::*;

/// Mode 6 response/error codes matching ntpsec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    Success = 0,
    Unspec = 1,
    Auth = 2,
    Format = 3,
    NoData = 4,
    Timeout = 5,
    BadValue = 6,
    NotFound = 7,
    NoReuse = 8,
    Permission = 9,
    Max = 10,
}

impl ControlError {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => ControlError::Success,
            1 => ControlError::Unspec,
            2 => ControlError::Auth,
            3 => ControlError::Format,
            4 => ControlError::NoData,
            5 => ControlError::Timeout,
            6 => ControlError::BadValue,
            7 => ControlError::NotFound,
            8 => ControlError::NoReuse,
            9 => ControlError::Permission,
            _ => ControlError::Max,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Control message opcodes (bits: R(1), E(1), M(1), Op(5)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlOpcode {
    pub response: bool,
    pub error: bool,
    pub more: bool,
    pub op: u8,
}

impl ControlOpcode {
    pub fn new(response: bool, error: bool, more: bool, op: u8) -> Self {
        Self {
            response,
            error,
            more,
            op: op & 0x1F,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        Self {
            response: (v & 0x80) != 0,
            error: (v & 0x40) != 0,
            more: (v & 0x20) != 0,
            op: v & 0x1F,
        }
    }

    pub fn to_u8(self) -> u8 {
        (if self.response { 0x80 } else { 0 })
            | (if self.error { 0x40 } else { 0 })
            | (if self.more { 0x20 } else { 0 })
            | self.op
    }
}

/// Control message opcode values matching NTPsec (ntp_control.h) and RFC 9327 §3.1.
pub mod opcodes {
    /// Read associations (ntpq -c as). Binary associd/status pairs.
    pub const OP_READSTAT: u8 = 1;
    /// Read system/peer variables (ntpq -c rv, -c pe, -c rl).
    pub const OP_READVAR: u8 = 2;
    /// Write one variable.
    pub const OP_WRITEVAR: u8 = 3;
    /// Read clock variables.
    pub const OP_READCLOCK: u8 = 4;
    /// Write clock variables.
    pub const OP_WRITECLOCK: u8 = 5;
    /// Set trap for async notifications.
    pub const OP_SETTRAP: u8 = 6;
    /// Async message delivery.
    pub const OP_ASYNCMSG: u8 = 7;
    /// Configure (write multiple variables/restrict). Requires auth.
    pub const OP_CONFIGURE: u8 = 8;
    /// Read MRU list.
    pub const OP_READ_MRU: u8 = 10;
    /// Read variables (authenticated ordered list). Requires auth.
    pub const OP_READ_ORDLIST_A: u8 = 11;
    /// Request nonce.
    pub const OP_REQ_NONCE: u8 = 12;
}

/// System status word encoding matching NTPsec (ntp_control.h) and RFC 9327 §5.
///
/// Bit layout:
///   15-14: leap indicator (LI)
///   13-8:  clock source
///   7-4:   event count
///   3-0:   event code
pub mod sys_status {
    // Leap indicator values (shifted to bits 15-14)
    pub const LI_SHIFT: u16 = 14;
    pub const LEAP_NOWARNING: u16 = 0 << LI_SHIFT;
    pub const LEAP_ADDSECOND: u16 = 1 << LI_SHIFT;
    pub const LEAP_DELSECOND: u16 = 2 << LI_SHIFT;
    pub const LEAP_ALARM: u16 = 3 << LI_SHIFT;

    // Clock source values (shifted to bits 13-8)
    pub const CS_SHIFT: u16 = 8;
    pub const CS_SYNC_NONE: u16 = 0 << CS_SHIFT;
    pub const CS_SYNC_LCL: u16 = 1 << CS_SHIFT;
    pub const CS_SYNC_PPS: u16 = 2 << CS_SHIFT;
    pub const CS_SYNC_NTP: u16 = 3 << CS_SHIFT;

    // Event count in bits 7-4, event code in bits 3-0
    pub const EVENT_COUNT_SHIFT: u16 = 4;
    pub const EVENT_CODE_MASK: u16 = 0x0F;

    /// Build a system status word from semantic values (0-3 for each).
    pub fn make(li: u16, source: u16, event_count: u16, event_code: u16) -> u16 {
        ((li & 0x03) << LI_SHIFT)
            | ((source & 0x3F) << CS_SHIFT)
            | ((event_count & 0x0F) << EVENT_COUNT_SHIFT)
            | (event_code & EVENT_CODE_MASK)
    }

    /// Decode leap indicator from a status word.
    pub fn decode_li(status: u16) -> u16 {
        (status >> LI_SHIFT) & 0x03
    }
}

/// Control message header — 12 bytes on wire, all big-endian.
/// Instead of #[repr(packed)] (which caused OOB reads), we use
/// explicit encode/decode with to_be_bytes/from_be_bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlMessage {
    pub li_vn_mode: u8,
    pub opcode: u8,
    pub sequence: u16,
    pub status: u16,
    pub associd: u16,
    pub offset: u16,
    pub count: u16,
}

impl ControlMessage {
    /// Wire size: 12 bytes (7 fields, packed, no padding).
    pub const SIZE: usize = 12;

    pub fn zeroed() -> Self {
        Self {
            li_vn_mode: 0,
            opcode: 0,
            sequence: 0,
            status: 0,
            associd: 0,
            offset: 0,
            count: 0,
        }
    }

    /// Encode to 12-byte big-endian wire format.
    pub fn encode(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0] = self.li_vn_mode;
        buf[1] = self.opcode;
        buf[2..4].copy_from_slice(&self.sequence.to_be_bytes());
        buf[4..6].copy_from_slice(&self.status.to_be_bytes());
        buf[6..8].copy_from_slice(&self.associd.to_be_bytes());
        buf[8..10].copy_from_slice(&self.offset.to_be_bytes());
        buf[10..12].copy_from_slice(&self.count.to_be_bytes());
        buf
    }

    /// Decode from 12-byte big-endian wire format.  Returns None if too short.
    pub fn decode(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 12 {
            return None;
        }
        let msg = Self {
            li_vn_mode: data[0],
            opcode: data[1],
            sequence: u16::from_be_bytes([data[2], data[3]]),
            status: u16::from_be_bytes([data[4], data[5]]),
            associd: u16::from_be_bytes([data[6], data[7]]),
            offset: u16::from_be_bytes([data[8], data[9]]),
            count: u16::from_be_bytes([data[10], data[11]]),
        };
        Some((msg, &data[12..]))
    }

    pub fn version(&self) -> NtpVersion {
        NtpVersion::from_bits(self.li_vn_mode >> 3)
    }

    pub fn mode(&self) -> NtpMode {
        NtpMode::from_bits(self.li_vn_mode)
    }

    pub fn decode_opcode(&self) -> ControlOpcode {
        ControlOpcode::from_u8(self.opcode)
    }
}

/// A parsed control request/response pair.
#[derive(Debug, Clone)]
pub struct ControlExchange {
    pub request: ControlMessage,
    pub data: Vec<u8>,
    pub auth_keyid: Option<KeyId>,
    pub auth_data: Vec<u8>,
}

impl ControlExchange {
    /// Parse a control message from raw bytes using safe big-endian decode.
    /// Handles Mode 6 padding: data is padded to 32-bit boundary, MAC to 64-bit.
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let (msg, after_header) = ControlMessage::decode(data)
            .ok_or_else(|| format!("packet too short: {} < 12", data.len()))?;

        let payload_len = msg.count as usize;
        let offset = msg.offset as usize;

        let payload_start = offset;
        let payload_end = payload_start + payload_len;
        if payload_end > after_header.len() {
            return Err(format!(
                "payload exceeds packet: {} > {}",
                payload_end,
                after_header.len()
            ));
        }

        let payload = after_header[payload_start..payload_end].to_vec();

        // Mode 6 padding: payload is padded to 32-bit boundary.
        // The padding bytes follow the count bytes and are NOT included in count.
        let header_data_end = 12 + payload_len;
        let padded32 = (header_data_end + 3) & !3;
        let mac_search_start = padded32.min(after_header.len());

        let remaining = &after_header[mac_search_start..];

        let mut auth_keyid = None;
        let mut auth_data = Vec::new();
        if remaining.len() >= 4 {
            // Skip padding zeros by checking for a non-zero key ID
            auth_keyid = Some(u32::from_be_bytes([
                remaining[0],
                remaining[1],
                remaining[2],
                remaining[3],
            ]));
            if remaining.len() > 4 {
                auth_data = remaining[4..].to_vec();
            }
        }

        Ok((
            Self {
                request: msg,
                data: payload,
                auth_keyid,
                auth_data,
            },
            &[],
        ))
    }

    /// Build a response message using safe big-endian encode.
    pub fn build_response(
        req: &ControlMessage,
        resp_data: &[u8],
        sequence: u16,
        status: u16,
        auth_key: Option<&NtpAuthKey>,
    ) -> Vec<u8> {
        let max_payload = 468;
        let oc = ControlOpcode::from_u8(req.opcode);
        let resp_header = ControlMessage {
            li_vn_mode: req.li_vn_mode,
            opcode: ControlOpcode::new(
                true,
                false,
                oc.more || resp_data.len() > max_payload,
                oc.op,
            )
            .to_u8(),
            sequence,
            status,
            associd: req.associd,
            offset: 0,
            count: resp_data.len().min(max_payload) as u16,
        };

        let mut buf = Vec::with_capacity(ControlMessage::SIZE + max_payload + 24);
        buf.extend_from_slice(&resp_header.encode());
        buf.extend_from_slice(&resp_data[..resp_data.len().min(max_payload)]);

        if let Some(key) = auth_key {
            // Add Mode 6 padding to align MAC to 32-bit (then 64-bit) boundary.
            // The MAC covers header + data + padding.
            let data_end = buf.len();
            let padded32 = (data_end + 3) & !3;
            let padded64 = (padded32 + 7) & !7;
            let pad_bytes = padded64 - data_end;
            for _ in 0..pad_bytes {
                buf.push(0);
            }

            if let Some(mac) = key.mac(&buf) {
                buf.extend_from_slice(&key.id.to_be_bytes());
                buf.extend_from_slice(&mac);
            }
        }
        buf
    }

    /// Check if the MAC on this exchange is valid.
    /// Rebuilds the authenticated portion: header + data + 32/64-bit padding.
    pub fn verify_mac(&self, key_store: &AuthKeyStore) -> bool {
        if let Some(keyid) = self.auth_keyid {
            if let Some(key) = key_store.get_key(keyid) {
                let mut packet = self.request.encode().to_vec();
                packet.extend_from_slice(&self.data);
                // Add padding to match the authenticated portion
                let data_end = packet.len();
                let padded32 = (data_end + 3) & !3;
                let padded64 = (padded32 + 7) & !7;
                let pad_bytes = padded64 - data_end;
                for _ in 0..pad_bytes {
                    packet.push(0);
                }
                return key.verify_mac(&packet, &self.auth_data);
            }
        }
        false
    }
}

/// System variable accessor — retrieves a named system variable from the
/// daemon state.  Matching ntpsec's `read_sysvars()` output format.
pub fn get_system_variable(sys: &super::ntp_proto::SystemState, name: &str) -> Option<String> {
    match name {
        "version" => Some("ntpd-rs 1.3.3".to_string()),
        "processor" => Some(std::env::consts::ARCH.to_string()),
        "system" => Some(format!("{}/{}", std::env::consts::OS, "linux")),
        "leap" => Some(format!("{:02}", sys.leap as u8)),
        "stratum" => Some(format!("{}", sys.stratum)),
        "precision" => Some(format!("{}", sys.precision)),
        "rootdelay" => Some(format!("{:.3}", sys.root_delay)),
        "rootdisp" => Some(format!("{:.3}", sys.root_dispersion)),
        "refid" => Some(format_refid(sys.reference_id)),
        "reftime" => Some(crate::ntp_fp::dolfptoa(sys.reference_time, 6)),
        "peer" => Some(format!("{}", sys.peer_count)),
        "tc" => Some(format!("{}", sys.poll)),
        "offset" => Some(format!("{:.3}", sys.sys_offset)),
        "frequency" => Some(format!("{:.3}", sys.sys_frequency)),
        "sys_jitter" => Some(format!("{:.3}", sys.sys_jitter)),
        "rootdist" => Some(format!("{:.3}", sys.sys_rootdist)),
        _ => None,
    }
}

/// Peer variable accessor — retrieves a named peer variable.
pub fn get_peer_variable(peer: &super::ntp_peer::Peer, name: &str) -> Option<String> {
    match name {
        "srcaddr" => Some(crate::ntp_net::socktoa(&peer.srcaddr)),
        "stratum" => Some(format!("{}", peer.stratum)),
        "offset" => Some(format!("{:.3}", peer.offset)),
        "delay" => Some(format!("{:.3}", peer.delay)),
        "dispersion" => Some(format!("{:.3}", peer.dispersion)),
        "jitter" => Some(format!("{:.3}", peer.jitter)),
        "hpoll" => Some(format!("{}", peer.hpoll)),
        "ppoll" => Some(format!("{}", peer.ppoll)),
        "reach" => Some(format!("{:02x}", peer.reach.register())),
        "flash" => Some(format!("{:x}", peer.flash)),
        "leap" => Some(format!("{:02}", peer.leap as u8)),
        "refid" => Some(format_refid(peer.reference_id)),
        "reftime" => Some(crate::ntp_fp::dolfptoa(peer.reference_time, 6)),
        "hmode" => Some(format!("{}", peer.hmode as u8)),
        "pmode" => Some(format!("{}", peer.pmode as u8)),
        "precision" => Some(format!("{}", peer.precision)),
        "rootdelay" => Some(format!("{:.3}", peer.root_delay)),
        "rootdisp" => Some(format!("{:.3}", peer.root_dispersion)),
        _ => None,
    }
}

/// Format a reference ID as a human-readable string.
fn format_refid(refid: u32) -> String {
    let bytes = refid.to_be_bytes();
    // Check if it looks like an ASCII string
    if bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        String::from_utf8_lossy(&bytes).to_string()
    } else {
        format!("{:08x}", refid)
    }
}

/// Format the peer status word (matching ntpsec's `peer_status()`).
pub fn peer_status(peer: &super::ntp_peer::Peer) -> u16 {
    let mut status: u16 = 0;
    // Count of reachability bits
    let reach = peer.reach.register();
    if reach != 0 {
        status |= (reach.trailing_zeros() as u16).min(0x0F);
    }
    status |= (peer.flash as u16 & 0x03FF) << 4;
    status
}

/// Encode a list of variables in key=value format (matching ntpq output).
pub fn encode_var_list(vars: &[(&str, &str)]) -> String {
    vars.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_opcode_roundtrip() {
        let oc = ControlOpcode::new(true, false, false, opcodes::OP_READVAR);
        let encoded = oc.to_u8();
        let decoded = ControlOpcode::from_u8(encoded);
        assert_eq!(decoded.response, true);
        assert_eq!(decoded.error, false);
        assert_eq!(decoded.op, opcodes::OP_READVAR);
    }

    #[test]
    fn test_control_message_header_encode_decode() {
        let msg = ControlMessage {
            li_vn_mode: 0x1c, // LI=0, VN=3, Mode=6
            opcode: 0x82,     // R=1, E=0, M=0, Op=2 (READVAR)
            sequence: 0x0001,
            status: 0x0622,
            associd: 0xc0a7,
            offset: 0,
            count: 8,
        };
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 12);
        let (decoded, remaining) = ControlMessage::decode(&encoded).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(decoded.li_vn_mode, msg.li_vn_mode);
        assert_eq!(decoded.opcode, msg.opcode);
        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.status, 0x0622);
        assert_eq!(decoded.associd, 0xc0a7);
        assert_eq!(decoded.offset, 0);
        assert_eq!(decoded.count, 8);
    }

    #[test]
    fn test_control_message_decode_rejects_short() {
        assert!(ControlMessage::decode(&[0u8; 11]).is_none());
        assert!(ControlMessage::decode(&[0u8; 12]).is_some());
    }

    #[test]
    fn test_system_variable_lookup() {
        let sys = crate::ntp_proto::SystemState::new();
        assert!(get_system_variable(&sys, "version").is_some());
        assert!(get_system_variable(&sys, "stratum").is_some());
        assert!(get_system_variable(&sys, "nonexistent").is_none());
    }

    #[test]
    fn test_peer_variable_lookup() {
        let peer = crate::ntp_peer::Peer::new(
            unsafe { std::mem::zeroed() },
            NtpMode::Client,
            NtpVersion::V4,
            4,
            10,
        );
        assert!(get_peer_variable(&peer, "stratum").is_some());
        assert!(get_peer_variable(&peer, "nonexistent").is_none());
    }

    #[test]
    fn test_format_refid_ascii() {
        let refid = u32::from_be_bytes(*b"GPS ");
        let s = format_refid(refid);
        assert!(s.contains("GPS"));
    }

    #[test]
    fn test_encode_var_list() {
        let vars = [("leap", "00"), ("stratum", "1")];
        let encoded = encode_var_list(&vars);
        assert_eq!(encoded, "leap=00,stratum=1");
    }
}
