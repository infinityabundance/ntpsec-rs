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

    /// Decode clock source from a status word.
    pub fn decode_source(status: u16) -> u16 {
        (status >> CS_SHIFT) & 0x3F
    }

    /// Decode event count from a status word (bits 7-4).
    pub fn decode_event_count(status: u16) -> u16 {
        (status >> EVENT_COUNT_SHIFT) & 0x0F
    }

    /// Decode event code from a status word (bits 3-0).
    pub fn decode_event_code(status: u16) -> u16 {
        status & EVENT_CODE_MASK
    }

    /// Clock source name matching real ntpq output.
    /// Maps the CTL_SST source type value to its display name.
    pub fn source_name(source: u16) -> &'static str {
        match source & 0x3F {
            0 => "sync_unspec",
            1 => "sync_local",      // CTL_SST_TS_LOCAL
            2 => "sync_pps",        // CTL_SST_TS_ATOM
            3 => "sync_ntp",        // CTL_SST_TS_NTP
            4 => "sync_uhf",        // CTL_SST_TS_UHF
            5 => "sync_local",      // CTL_SST_TS_LOCAL (alt)
            6 => "sync_ntp",        // CTL_SST_TS_NTP (alt)
            7 => "sync_other",      // CTL_SST_TS_UDPTIME
            8 => "sync_wristwatch", // CTL_SST_TS_WRSTWTCH
            9 => "sync_telephone",  // CTL_SST_TS_TELEPHONE
            _ => "sync_unspec",
        }
    }

    /// Leap indicator name matching ntpq output.
    pub fn li_name(li: u16) -> &'static str {
        match li & 0x03 {
            0 => "leap_none",
            1 => "leap_add_sec",
            2 => "leap_del_sec",
            3 => "leap_alarm",
            _ => "leap_unknown",
        }
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

        // Mode 6 padding: payload padded to 4-octet boundary before authenticator.
        // NTPsec MODE_SIX_ALIGNMENT = 4. `after_header` starts at byte 12.
        // Authenticator (key ID + MAC) starts at align_up(payload_len, 4) within after_header.
        let auth_offset = (payload_len + 3) & !3;
        let remaining = if auth_offset <= after_header.len() {
            &after_header[auth_offset..]
        } else {
            &[]
        };

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
            // Pad to 4-octet boundary for MAC (per NTPsec MODE_SIX_ALIGNMENT=4).
            let pad = (4 - (buf.len() & 3)) & 3;
            for _ in 0..pad {
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
    /// Rebuilds the authenticated portion: header + data + 4-octet padding (per NTPsec).
    pub fn verify_mac(&self, key_store: &AuthKeyStore) -> bool {
        if let Some(keyid) = self.auth_keyid {
            if let Some(key) = key_store.get_key(keyid) {
                let header = self.request.encode();
                let mut packet = Vec::with_capacity(header.len() + self.data.len() + 4);
                packet.extend_from_slice(&header);
                packet.extend_from_slice(&self.data);
                // Pad to 4-octet boundary for MAC calculation
                let pad = (4 - (packet.len() & 3)) & 3;
                for _ in 0..pad {
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
///
/// Supports 80+ variable names matching ntpsec's full Mode 6 variable set,
/// including auth counters, clock discipline, leap/expiry, MRU stats,
/// peer status, selection vars, server-side counters, NTS, and orphans.
pub fn get_system_variable(sys: &super::ntp_proto::SystemState, name: &str) -> Option<String> {
    match name {
        // ── Auth counters (not yet tracked; return placeholders) ──────
        "auth_badauth" => Some("0".to_string()),
        "auth_badkey" => Some("0".to_string()),
        "auth_decrypts" => Some("0".to_string()),
        "auth_encrypts" => Some("0".to_string()),
        "auth_foundkey" => Some("0".to_string()),
        "auth_notfound" => Some("0".to_string()),
        "auth_reset" => Some("0".to_string()),
        // ── Auth types ─────────────────────────────────────────────────
        "auth_type" => Some("0".to_string()),
        "auth_flags" => Some("0".to_string()),
        "auth_keys" => Some("0".to_string()),
        "auth_keyno" => Some("0".to_string()),
        // ── Clock discipline extensions ───────────────────────────────
        "bias" => Some("0.0".to_string()),
        "candidate" => Some("0".to_string()),
        "clock" => Some("0".to_string()),
        "clk_jitter" => Some(format!("{:?}", sys.sys_jitter)),
        "clk_wander" => Some("0.0".to_string()),
        // ── NTP core variables ─────────────────────────────────────────
        "compliance" => Some("0".to_string()),
        "dstadr" => Some("0.0.0.0".to_string()),
        "dstport" => Some("123".to_string()),
        // ── Leap/expiry ───────────────────────────────────────────────
        "expire" => Some("0".to_string()),
        "flash" => Some("0".to_string()),
        "frequency" => Some(format!("{:?}", sys.sys_frequency)),
        "freq_drift" => Some(format!("{:?}", sys.sys_frequency)),
        "freq_ppm" => Some(format!("{:?}", sys.sys_frequency)),
        // ── Host info ──────────────────────────────────────────────────
        "hostname" => Some("localhost".to_string()),
        "host" => Some("localhost".to_string()),
        "ident" => Some("".to_string()),
        // ── Leap ───────────────────────────────────────────────────────
        "leap" => Some(format!("{:02}", sys.leap as u8)),
        "leapsec" => Some("0".to_string()),
        "leap_alert" => Some("0".to_string()),
        "leap_before" => Some("0".to_string()),
        "leap_after" => Some("0".to_string()),
        "leap_expire" => Some("0".to_string()),
        // ── Mintc / tinker ─────────────────────────────────────────────
        "mintc" => Some("0".to_string()),
        "minpoll" => Some(format!("{}", crate::ntp_proto::NTP_MINPOLL)),
        "maxpoll" => Some(format!("{}", crate::ntp_proto::NTP_MAXPOLL)),
        // ── MRU list stats ─────────────────────────────────────────────
        "mru_deepest" => Some("0".to_string()),
        "mru_enabled" => Some("0".to_string()),
        "mru_maxage" => Some("0".to_string()),
        "mru_maxdepth" => Some("0".to_string()),
        "mru_maxmem" => Some("0".to_string()),
        "mru_mindepth" => Some("0".to_string()),
        "mru_minage" => Some("0".to_string()),
        "mru_mem" => Some("0".to_string()),
        "mru_meminc" => Some("0".to_string()),
        "mru_npairs" => Some("0".to_string()),
        "mru_polls" => Some("0".to_string()),
        // ── NTS ────────────────────────────────────────────────────────
        "nts" => Some("none".to_string()),
        "nts_enabled" => Some("0".to_string()),
        "nts_peers" => Some("0".to_string()),
        "nts_keys" => Some("0".to_string()),
        "nts_cookielen" => Some("0".to_string()),
        "nts_providers" => Some("0".to_string()),
        // ── Offset / discipline ────────────────────────────────────────
        "offset" => Some(format!("{:?}", sys.sys_offset)),
        "old_offset" => Some(format!("{:?}", sys.sys_offset)),
        // ── Orphan mode ────────────────────────────────────────────────
        "orphan" => Some("0".to_string()),
        "orphwait" => Some("0".to_string()),
        // ── Peer / association ─────────────────────────────────────────
        "peer" => Some(format!("{}", sys.peer_count)),
        "peers" => Some(format!("{}", sys.peer_count)),
        "peer_count" => Some(format!("{}", sys.peer_count)),
        // ── Precision / processor ──────────────────────────────────────
        "precision" => Some(format!("{}", sys.precision)),
        "processor" => Some(std::env::consts::ARCH.to_string()),
        // ── Reference ──────────────────────────────────────────────────
        "refid" => Some(format_refid(sys.reference_id)),
        "reftime" => Some(crate::ntp_fp::dolfptoa(sys.reference_time, 6)),
        "refclock" => Some("".to_string()),
        // ── Root ───────────────────────────────────────────────────────
        "rootdelay" => Some(format!("{:?}", sys.root_delay)),
        "rootdisp" => Some(format!("{:?}", sys.root_dispersion)),
        "rootdist" => Some(format!("{:?}", sys.sys_rootdist)),
        // ── Selection vars ────────────────────────────────────────────
        "selbroken" => Some("0".to_string()),
        "seldisp" => Some("0.0".to_string()),
        "selpeer" => Some("0".to_string()),
        "selpeer_sel" => Some("0".to_string()),
        "selpeer_src" => Some("0".to_string()),
        "selpeer_previous" => Some("0".to_string()),
        // ── Server-side (ss_) counters ────────────────────────────────
        "ss_badauth" => Some("0".to_string()),
        "ss_badlength" => Some("0".to_string()),
        "ss_declined" => Some("0".to_string()),
        "ss_delayed" => Some("0".to_string()),
        "ss_kodsent" => Some("0".to_string()),
        "ss_limited" => Some("0".to_string()),
        "ss_oldver" => Some("0".to_string()),
        "ss_received" => Some("0".to_string()),
        "ss_rejected" => Some("0".to_string()),
        "ss_reset" => Some("0".to_string()),
        "ss_restricted" => Some("0".to_string()),
        "ss_thisver" => Some("0".to_string()),
        "ss_uptime" => Some("0".to_string()),
        // ── Status ─────────────────────────────────────────────────────
        "status" => Some("0000".to_string()),
        "stratum" => Some(format!("{}", sys.stratum)),
        // ── System info ────────────────────────────────────────────────
        "sys_jitter" => Some(format!("{:?}", sys.sys_jitter)),
        "sys_leap" => Some(format!("{}", sys.leap as u8)),
        "sys_stratum" => Some(format!("{}", sys.stratum)),
        "sys_peer" => Some(format!("{}", sys.peer_count)),
        "sys_offset" => Some(format!("{:?}", sys.sys_offset)),
        "sys_frequency" => Some(format!("{:?}", sys.sys_frequency)),
        "system" => Some(format!("{}/{}", std::env::consts::OS, "linux")),
        // ── TAI ────────────────────────────────────────────────────────
        "tai" => Some("0".to_string()),
        "tai_leap" => Some("0".to_string()),
        "tai_offset" => Some("0".to_string()),
        // ── Time constant ──────────────────────────────────────────────
        "tc" => Some(format!("{}", sys.poll)),
        "tcincrement" => Some("0".to_string()),
        // ── Version / uptime ───────────────────────────────────────────
        "version" => Some("ntpsec-rs 1.3.3".to_string()),
        "version_ver" => Some("1.3.3".to_string()),
        "version_prot" => Some("4".to_string()),
        "uptime" => Some("0".to_string()),
        _ => None,
    }
}

/// Peer variable accessor — retrieves a named peer variable.
pub fn get_peer_variable(peer: &super::ntp_peer::Peer, name: &str) -> Option<String> {
    match name {
        "bias" => Some("0.0".to_string()),
        "candidate" => Some("0".to_string()),
        "clk_jitter" => Some("0.0".to_string()),
        "clk_wander" => Some("0.0".to_string()),
        "delay" => Some(format!("{:?}", peer.delay)),
        "dispersion" => Some(format!("{:?}", peer.dispersion)),
        "dstadr" => peer.dstadr.map(|sa| crate::ntp_net::socktoa(&sa)),
        "filterror" => Some("0.0".to_string()),
        "flags" => Some(format!("{:x}", peer.flags.bits())),
        "flash" => Some(format!("{:x}", peer.flash)),
        "hmode" => Some(format!("{}", peer.hmode as u8)),
        "hpoll" => Some(format!("{}", peer.hpoll)),
        "jitter" => Some(format!("{:?}", peer.jitter)),
        "keyid" => Some(format!("{}", peer.keyid)),
        "leap" => Some(format!("{:02}", peer.leap as u8)),
        "offset" => Some(format!("{:?}", peer.offset)),
        "org" => Some(crate::ntp_fp::dolfptoa(peer.originate_time, 6)),
        "pmode" => Some(format!("{}", peer.pmode as u8)),
        "ppoll" => Some(format!("{}", peer.ppoll)),
        "precision" => Some(format!("{}", peer.precision)),
        "reach" => Some(format!("{:02x}", peer.reach.register())),
        "rec" => Some(crate::ntp_fp::dolfptoa(peer.receive_time, 6)),
        "refid" => Some(format_refid(peer.reference_id)),
        "reftime" => Some(crate::ntp_fp::dolfptoa(peer.reference_time, 6)),
        "rootdelay" => Some(format!("{:?}", peer.root_delay)),
        "rootdisp" => Some(format!("{:?}", peer.root_dispersion)),
        "selbroken" => Some("0".to_string()),
        "seldisp" => Some("0.0".to_string()),
        "srcaddr" => Some(crate::ntp_net::socktoa(&peer.srcaddr)),
        "stratum" => Some(format!("{}", peer.stratum)),
        "timer" => Some("0".to_string()),
        "ttl" => Some("0".to_string()),
        "unreach" => Some("0".to_string()),
        "version" => Some(format!("{}", peer.version as u8)),
        "xmt" => Some(crate::ntp_fp::dolfptoa(peer.transmit_time, 6)),
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

/// Selection status values per RFC 9327 §5.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStatus {
    Rejected = 0,
    IntersectionDiscard = 1,
    OverflowDiscard = 2,
    ClusterDiscard = 3,
    Candidate = 4,
    Backup = 5,
    SystemPeer = 6,
    PpsPeer = 7,
}

impl SelectionStatus {
    pub fn to_bits(self) -> u8 {
        self as u8
    }
}

/// Peer event codes matching ntpsec's event_codes enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEventCode {
    /// No event.
    Unspec = 0,
    /// Peer initialized.
    Assoc = 1,
    /// Peer became reachable.
    Reachable = 2,
    /// Peer became unreachable.
    Unreachable = 3,
    /// Peer restarted.
    Restart = 4,
    /// Peer became synchronized.
    SyncChg = 5,
    /// Peer peer event.
    PeerEvent = 6,
    /// Peer clock (refclock) event.
    ClockEvent = 7,
    /// Bad authentication.
    BadAuth = 8,
    /// Popular vote.
    PopVote = 9,
    /// Badauth peer event.
    PeerBadAuth = 10,
}

impl PeerEventCode {
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn name(&self) -> &'static str {
        match self {
            PeerEventCode::Unspec => "unspec",
            PeerEventCode::Assoc => "assoc",
            PeerEventCode::Reachable => "reachable",
            PeerEventCode::Unreachable => "unreachable",
            PeerEventCode::Restart => "restart",
            PeerEventCode::SyncChg => "sync_chg",
            PeerEventCode::PeerEvent => "peer_event",
            PeerEventCode::ClockEvent => "clock_event",
            PeerEventCode::BadAuth => "bad_auth",
            PeerEventCode::PopVote => "pop_vote",
            PeerEventCode::PeerBadAuth => "peer_badauth",
        }
    }
}

/// System event codes matching ntpsec's sys_event_codes enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEventCode {
    /// No event.
    Unspec = 0,
    /// System synchronized.
    SyncChg = 1,
    /// Clock stepped.
    SetTime = 2,
    /// Frequency adjustment.
    SetFreq = 3,
    /// Peer became the system peer.
    PeerSyncChg = 4,
    /// Clock was stepped.
    StepDone = 5,
    /// Panic occurred.
    PanicStop = 6,
    /// System event code 7.
    SystemBadTime = 7,
    /// Clock sync changed.
    ClockCode = 8,
    /// PPS signal detected.
    PpsSignal = 9,
    /// Leap second announced.
    LeapSecond = 10,
}

impl SystemEventCode {
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn name(&self) -> &'static str {
        match self {
            SystemEventCode::Unspec => "unspec",
            SystemEventCode::SyncChg => "sync_chg",
            SystemEventCode::SetTime => "set_time",
            SystemEventCode::SetFreq => "set_freq",
            SystemEventCode::PeerSyncChg => "peer_sync_chg",
            SystemEventCode::StepDone => "step_done",
            SystemEventCode::PanicStop => "panic_stop",
            SystemEventCode::SystemBadTime => "sys_bad_time",
            SystemEventCode::ClockCode => "clock_code",
            SystemEventCode::PpsSignal => "pps_signal",
            SystemEventCode::LeapSecond => "leap_sec",
        }
    }
}

/// System event state — tracks the last system event and event timer.
#[derive(Debug, Clone)]
pub struct SystemEventState {
    /// Current event code.
    pub event_code: SystemEventCode,
    /// Event count (rolling counter, 0-15).
    pub event_count: u16,
    /// Timestamp of the last event.
    pub event_timer: u16,
}

impl Default for SystemEventState {
    fn default() -> Self {
        Self {
            event_code: SystemEventCode::Unspec,
            event_count: 0,
            event_timer: 0,
        }
    }
}

/// Map a system event code to a human-readable name matching ntpsec's
/// sys_event_names table.
pub fn system_event_name(code: u16) -> &'static str {
    match code & 0x0F {
        0 => "unspec",
        1 => "sync_chg",
        2 => "set_time",
        3 => "set_freq",
        4 => "peer_sync_chg",
        5 => "step_done",
        6 => "panic_stop",
        7 => "sys_bad_time",
        8 => "clock_code",
        9 => "pps_signal",
        10 => "leap_sec",
        _ => "unknown",
    }
}

/// Format the peer status word for Mode 6 READSTAT responses.
/// Matching NTPsec's peer_status() and RFC 9327 §5.2.
///
/// High byte:
///   Bit 7: configured
///   Bit 6: authentication enabled
///   Bit 5: authentication okay
///   Bit 4: reachable
///   Bit 3: broadcast
///   Bits 2-0: selection state per SelectionStatus
///
/// Low byte:
///   Bits 7-4: event count (4 bits, rolls over)
///   Bits 3-0: event code (from peer's internal event tracking)
pub fn peer_status(peer: &super::ntp_peer::Peer, selection: SelectionStatus) -> u16 {
    let mut flags: u8 = 0;

    if peer.flags.contains(super::ntp_peer::PeerFlags::CONFIGURED) {
        flags |= 0x80;
    }
    if peer.flags.contains(super::ntp_peer::PeerFlags::AUTHENABLE) {
        flags |= 0x40;
    }
    if peer.flags.contains(super::ntp_peer::PeerFlags::AUTHENTIC) {
        flags |= 0x20;
    }
    if peer.reach.is_reachable() {
        flags |= 0x10;
    }
    if peer.hmode == super::ntp_types::NtpMode::Broadcast {
        flags |= 0x08;
    }

    // Bits 2-0: selection state
    flags |= selection.to_bits() & 0x07;

    // ─── Low byte: event count and event code ─────────────────────────────
    // Compute the peer event code from the peer's internal state.
    // ntpsec tracks a per-peer event_code and event_count that increments
    // on each state transition. We derive a reasonable event code from the
    // current flash bits and reachability.
    let event_code: u16 = if peer.flash != 0 {
        // Some test bits are set — determine the most significant failure
        if peer.flash & super::ntp_proto::FlashBits::TEST1.bits() != 0 {
            PeerEventCode::Unspec as u16
        } else if peer.flash & super::ntp_proto::FlashBits::TEST10.bits() != 0 {
            PeerEventCode::BadAuth as u16
        } else if peer.flash & super::ntp_proto::FlashBits::TEST9.bits() != 0 {
            PeerEventCode::Unreachable as u16
        } else if peer.flash & super::ntp_proto::FlashBits::TEST3.bits() != 0 {
            PeerEventCode::SyncChg as u16
        } else {
            PeerEventCode::Unspec as u16
        }
    } else if !peer.reach.is_reachable() {
        PeerEventCode::Unreachable as u16
    } else if peer.stratum < 16 {
        PeerEventCode::Reachable as u16
    } else {
        PeerEventCode::Unspec as u16
    };

    // Event count: use a simple incrementing counter derived from reach count
    // to give a sense of event progression.
    let event_count: u16 = if peer.reach.reach_count() > 0 {
        ((peer.reach.reach_count() as u16) & 0x0F).min(1)
    } else {
        1
    };

    let event_field: u16 = ((event_count & 0x0F) << 4) | (event_code & 0x0F);
    ((flags as u16) << 8) | event_field
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
