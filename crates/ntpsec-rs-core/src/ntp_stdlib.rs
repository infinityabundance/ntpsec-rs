// ──── ntp_stdlib.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_stdlib.h
//
// Standard library functions used by NTPsec: string formatting, character
// classification, and utility helpers.
//
// ## Oracle
//   - ntpsec include/ntp_stdlib.h
//   - ntpsec libntp/statestr.c
//   - ntpsec libntp/numtoa.c
// =============================================================================

use crate::ntp_types::*;

/// Event/state name table matching ntpsec's event strings.
pub const EVENT_NAMES: [&str; 8] = [
    "event_at_never",   // 0 — EVNT_UNSPEC
    "event_at_reach",   // 1 — EVNT_REACH
    "event_at_peer",    // 2 — EVNT_PEER
    "event_at_auth",    // 3 — EVNT_AUTH
    "event_at_sys",     // 4 — EVNT_SYS
    "event_at_clock",   // 5 — EVNT_CLOCK
    "event_at_set",     // 6 — EVNT_SET
    "event_at_unknown", // 7 — EVNT_UNKNOWN
];

/// Convert an IP address (u32) to a dotted-quad string (IPv4).
pub fn numtoa(addr: u32) -> String {
    let bytes = addr.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

/// Recoverable-allocated string buffer (replaces ntpsec's lib_strbuf).
pub struct NtpStrBuf {
    buffer: [u8; 256],
    pos: usize,
}

impl NtpStrBuf {
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; 256],
            pos: 0,
        }
    }

    pub fn clear(&mut self) {
        self.pos = 0;
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buffer[..self.pos]).unwrap_or("")
    }
}

/// MAC computation type.
///
/// Note: `DigestType` in `ntp_auth.rs` covers the same concept and should be
/// used for new code. This enum is retained for backward compatibility during
/// the forensic reconstruction transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacType {
    None,
    Md5,
    Sha1,
    Aes128Cmac,
    AesSivCmac, // NTS AEAD
}

impl MacType {
    pub fn digest_length(&self) -> usize {
        match self {
            MacType::None => 0,
            MacType::Md5 => 16,
            MacType::Sha1 => 20,
            MacType::Aes128Cmac => 16,
            MacType::AesSivCmac => 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numtoa() {
        assert_eq!(numtoa(0x7f000001), "127.0.0.1");
        assert_eq!(numtoa(0x01020304), "1.2.3.4");
    }

    #[test]
    fn test_strbuf() {
        let mut buf = NtpStrBuf::new();
        assert_eq!(buf.as_str(), "");
    }
}
