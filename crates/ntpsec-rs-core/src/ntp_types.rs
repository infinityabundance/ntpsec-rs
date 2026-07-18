// ──── ntp_types.rs ──────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_types.h
//
// NTPsec fundamental type definitions: sized integers, socket address storage,
// system time representation, NTP time format, and related constants.
//
// ## Oracle
//   - ntpsec include/ntp_types.h
//   - RFC 5905 §6 (NTP packet header)
//   - RFC 5905 §9 (Clock filter)
//
// ## Court
//   - docs/courts/ntp_types.md — byte-size assertions, sockaddr layout, NTP era
//     calculations verified against ntpsec's compile-time asserts.
// =============================================================================

use core::fmt;
use core::ops::{Add, Div, Mul, Sub};

// ──── Sized integer types ───────────────────────────────────────────────────

/// NTP signed 8-bit integer.
pub type s_char = i8;
/// NTP unsigned 8-bit integer.
pub type u_char = u8;
/// NTP unsigned 16-bit integer (network-order).
pub type u_short = u16;
/// NTP unsigned 32-bit integer (network-order).
pub type u_int32 = u32;
/// NTP signed 32-bit integer.
pub type int32 = i32;
/// NTP unsigned 64-bit integer.
pub type u_int64 = u64;
/// NTP signed 64-bit integer.
pub type int64 = i64;

/// NTP Boolean type.
pub type ntp_bool = bool;

// ──── NTP Timestamp Format ──────────────────────────────────────────────────

/// Number of seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
pub const NTP_EPOCH_OFFSET: u32 = 2_208_988_800;

/// NTP era length in seconds: 2^32.
pub const NTP_ERA_LENGTH: u64 = 1 << 32;

/// One second as an NTP fractional unit (2^32).
pub const NTP_FRAC_PER_SEC: u64 = 4_294_967_296;

/// NTP short format (32-bit): 16 bits seconds + 16 bits fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtpShort {
    pub seconds: u16,
    pub fraction: u16,
}

/// NTP timestamp format (64-bit): 32 bits seconds + 32 bits fraction.
/// The 64-bit signed version used for most computations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtpTs {
    pub seconds: u32,
    pub fraction: u32,
}

/// NTP 64-bit signed timestamp for arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtpTs64 {
    pub seconds: i64,
    pub fraction: u32,
}

/// Absolute-precision timestamp (l_fp in ntpsec C — "long fixed-point").
pub type LFP = NtpTs64;

// ──── System / socket address types ─────────────────────────────────────────

#[cfg(unix)]
pub type SockAddr = libc::sockaddr_storage;
#[cfg(unix)]
pub type SockAddrIn = libc::sockaddr_in;
#[cfg(unix)]
pub type SockAddrIn6 = libc::sockaddr_in6;
#[cfg(not(unix))]
compile_error!("ntpsec-rs-core requires a Unix-like OS");

/// Maximum NTP packet size (RFC 5905).
pub const NTP_MAX_PACKET_SIZE: usize = 512;

/// NTP leap indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeapIndicator {
    NoWarning = 0,        // 00
    AddLeapSecond = 1,    // 01 — last minute has 61 seconds
    RemoveLeapSecond = 2, // 10 — last minute has 59 seconds
    Alarm = 3,            // 11 — clock not synchronized
}

impl LeapIndicator {
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => LeapIndicator::NoWarning,
            1 => LeapIndicator::AddLeapSecond,
            2 => LeapIndicator::RemoveLeapSecond,
            _ => LeapIndicator::Alarm,
        }
    }

    pub const fn to_bits(self) -> u8 {
        self as u8
    }
}

/// NTP mode field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NtpMode {
    Reserved = 0,
    SymActive = 1,
    SymPassive = 2,
    Client = 3,
    Server = 4,
    Broadcast = 5,
    NtpControl = 6, // Mode 6 — ntpq control protocol
    Private = 7,    // Mode 7 — ntpdc private protocol (deprecated)
}

impl NtpMode {
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            0 => NtpMode::Reserved,
            1 => NtpMode::SymActive,
            2 => NtpMode::SymPassive,
            3 => NtpMode::Client,
            4 => NtpMode::Server,
            5 => NtpMode::Broadcast,
            6 => NtpMode::NtpControl,
            _ => NtpMode::Private,
        }
    }

    pub const fn to_bits(self) -> u8 {
        self as u8
    }
}

/// NTP version numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NtpVersion {
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
}

impl NtpVersion {
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            1 => NtpVersion::V1,
            2 => NtpVersion::V2,
            3 => NtpVersion::V3,
            _ => NtpVersion::V4,
        }
    }

    pub const fn to_bits(self) -> u8 {
        self as u8
    }

    /// The current NTP version in ntpsec.
    pub const fn current() -> Self {
        NtpVersion::V4
    }
}

/// NTP association states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtpAssociationState {
    /// Initial state — not yet synchronized.
    Initial = 0,
    /// Reachability probe.
    Probe = 1,
    /// Repeated probe.
    Repeat = 2,
    /// Exchange packets.
    Exchange = 3,
    /// Broadcast exchange.
    Bcast = 4,
}

// ──── Kiss Codes ────────────────────────────────────────────────────────────

/// Kiss codes sent as stratum 0 in server responses.
pub mod kiss_codes {
    /// Deny — server denies client access.
    pub const DENY: u32 = u32::from_be_bytes(*b"DENY");
    /// Rate — server is rate-limiting the client.
    pub const RATE: u32 = u32::from_be_bytes(*b"RATE");
    /// Restart — server suggests client restart.
    pub const RSTR: u32 = u32::from_be_bytes(*b"RSTR");
    /// Step — server stepped, client should re-sync.
    pub const STEP: u32 = u32::from_be_bytes(*b"STEP");
}

// ──── NTP Packet Header ─────────────────────────────────────────────────────

/// NTP packet header (RFC 5905 §6), 48 bytes big-endian.
/// Use encode_header()/decode_header() for safe wire serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpPacket {
    pub li_vn_mode: u8,
    pub stratum: u8,
    pub poll: u8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: u32,
    pub reference_ts: NtpTs,
    pub originate_ts: NtpTs,
    pub receive_ts: NtpTs,
    pub transmit_ts: NtpTs,
}

/// NTP packet header size in bytes (RFC 5905).
pub const NTP_HEADER_SIZE: usize = 48;

impl NtpPacket {
    pub fn zeroed() -> Self {
        Self {
            li_vn_mode: 0,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: 0,
            reference_ts: NtpTs {
                seconds: 0,
                fraction: 0,
            },
            originate_ts: NtpTs {
                seconds: 0,
                fraction: 0,
            },
            receive_ts: NtpTs {
                seconds: 0,
                fraction: 0,
            },
            transmit_ts: NtpTs {
                seconds: 0,
                fraction: 0,
            },
        }
    }

    /// Encode the 48-byte NTP header in big-endian wire format.
    pub fn encode_header(&self) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0] = self.li_vn_mode;
        b[1] = self.stratum;
        b[2] = self.poll;
        b[3] = self.precision as u8;
        b[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        b[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        b[12..16].copy_from_slice(&self.reference_id.to_be_bytes());
        b[16..20].copy_from_slice(&self.reference_ts.seconds.to_be_bytes());
        b[20..24].copy_from_slice(&self.reference_ts.fraction.to_be_bytes());
        b[24..28].copy_from_slice(&self.originate_ts.seconds.to_be_bytes());
        b[28..32].copy_from_slice(&self.originate_ts.fraction.to_be_bytes());
        b[32..36].copy_from_slice(&self.receive_ts.seconds.to_be_bytes());
        b[36..40].copy_from_slice(&self.receive_ts.fraction.to_be_bytes());
        b[40..44].copy_from_slice(&self.transmit_ts.seconds.to_be_bytes());
        b[44..48].copy_from_slice(&self.transmit_ts.fraction.to_be_bytes());
        b
    }

    /// Decode a 48-byte NTP header from big-endian wire format.
    pub fn decode_header(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 48 {
            return Err("NTP header too short");
        }
        Ok(Self {
            li_vn_mode: bytes[0],
            stratum: bytes[1],
            poll: bytes[2],
            precision: bytes[3] as i8,
            root_delay: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            root_dispersion: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            reference_id: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            reference_ts: NtpTs {
                seconds: u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
                fraction: u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            },
            originate_ts: NtpTs {
                seconds: u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
                fraction: u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
            },
            receive_ts: NtpTs {
                seconds: u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]),
                fraction: u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]),
            },
            transmit_ts: NtpTs {
                seconds: u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]),
                fraction: u32::from_be_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]),
            },
        })
    }

    pub fn leap_indicator(&self) -> LeapIndicator {
        LeapIndicator::from_bits(self.li_vn_mode >> 6)
    }

    pub fn version(&self) -> NtpVersion {
        NtpVersion::from_bits(self.li_vn_mode >> 3)
    }

    pub fn mode(&self) -> NtpMode {
        NtpMode::from_bits(self.li_vn_mode)
    }

    pub fn set_li_vn_mode(li: LeapIndicator, vn: NtpVersion, mode: NtpMode) -> u8 {
        (li.to_bits() << 6) | (vn.to_bits() << 3) | mode.to_bits()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leap_indicator_roundtrip() {
        for li in &[
            LeapIndicator::NoWarning,
            LeapIndicator::AddLeapSecond,
            LeapIndicator::RemoveLeapSecond,
            LeapIndicator::Alarm,
        ] {
            assert_eq!(*li, LeapIndicator::from_bits(li.to_bits()));
        }
    }

    #[test]
    fn test_ntp_mode_roundtrip() {
        for mode in &[
            NtpMode::Reserved,
            NtpMode::SymActive,
            NtpMode::SymPassive,
            NtpMode::Client,
            NtpMode::Server,
            NtpMode::Broadcast,
            NtpMode::NtpControl,
            NtpMode::Private,
        ] {
            assert_eq!(*mode, NtpMode::from_bits(mode.to_bits()));
        }
    }

    #[test]
    fn test_li_vn_mode_encoding() {
        let byte =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
        let pkt = NtpPacket {
            li_vn_mode: byte,
            ..NtpPacket::zeroed()
        };
        assert_eq!(pkt.leap_indicator(), LeapIndicator::NoWarning);
        assert_eq!(pkt.version(), NtpVersion::V4);
        assert_eq!(pkt.mode(), NtpMode::Client);
    }

    #[test]
    fn test_ntp_packet_size() {
        assert_eq!(core::mem::size_of::<NtpPacket>(), 48);
    }

    #[test]
    fn test_kiss_code_strings() {
        assert_eq!(kiss_codes::DENY, 0x44454e59); // "DENY" in big-endian
        assert_eq!(kiss_codes::RATE, 0x52415445); // "RATE"
        assert_eq!(kiss_codes::RSTR, 0x52535452); // "RSTR"
        assert_eq!(kiss_codes::STEP, 0x53544550); // "STEP"
    }
}
