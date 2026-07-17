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
/// Standard NTP packet header size (no extensions).
pub const NTP_HEADER_SIZE: usize = 48;

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

// ──── NTP Packet Header ─────────────────────────────────────────────────────

/// The on-wire NTP packet header (RFC 5905 §6).
/// This is the 48-byte request/response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct NtpPacket {
    /// Leap Version Mode (LVM): 2-bit LI, 3-bit VN, 3-bit Mode
    pub li_vn_mode: u8,
    /// Stratum: 0 (kiss), 1 (primary), 2–15 (secondary), 16 (unspec)
    pub stratum: u8,
    /// Maximum interval between successive messages in log2 seconds
    pub poll: u8,
    /// Clock precision in log2 seconds
    pub precision: i8,
    /// Root delay (short format)
    pub root_delay: u32,
    /// Root dispersion (short format)
    pub root_dispersion: u32,
    /// Reference clock identifier
    pub reference_id: u32,
    /// Reference timestamp
    pub reference_ts: NtpTs,
    /// Originate timestamp (T1 — client transmit)
    pub originate_ts: NtpTs,
    /// Receive timestamp (T2 — server receive)
    pub receive_ts: NtpTs,
    /// Transmit timestamp (T3 — server transmit)
    pub transmit_ts: NtpTs,
}

impl NtpPacket {
    /// Create a zeroed-out NTP packet.
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

    /// Decode LI from LI_VN_MODE byte.
    pub fn leap_indicator(&self) -> LeapIndicator {
        LeapIndicator::from_bits(self.li_vn_mode >> 6)
    }

    /// Decode VN from LI_VN_MODE byte.
    pub fn version(&self) -> NtpVersion {
        NtpVersion::from_bits(self.li_vn_mode >> 3)
    }

    /// Decode Mode from LI_VN_MODE byte.
    pub fn mode(&self) -> NtpMode {
        NtpMode::from_bits(self.li_vn_mode)
    }

    /// Encode LI + VN + Mode into a single byte.
    pub fn set_li_vn_mode(li: LeapIndicator, vn: NtpVersion, mode: NtpMode) -> u8 {
        (li.to_bits() << 6) | (vn.to_bits() << 3) | mode.to_bits()
    }
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

// ──── Stratum constants ─────────────────────────────────────────────────────

/// Kiss-o'-Death / unspecified.
pub const STRATUM_UNSPEC: u8 = 0;
/// Primary reference (e.g., GPS, atomic clock).
pub const STRATUM_PRIMARY: u8 = 1;
/// Secondary reference (NTP server).
pub const STRATUM_SECONDARY_MIN: u8 = 2;
pub const STRATUM_SECONDARY_MAX: u8 = 15;
/// Maximum valid stratum.
pub const STRATUM_MAX: u8 = 15;
/// Unsynchronized / invalid.
pub const STRATUM_UNSYNC: u8 = 16;

// ──── NTP port ──────────────────────────────────────────────────────────────

pub const NTP_PORT: u16 = 123;

// ──── Tests ─────────────────────────────────────────────────────────────────

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
