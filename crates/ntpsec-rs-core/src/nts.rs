// ──── nts.rs ────────────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/nts.c, include/nts.h (8K), include/nts2.h
//
// Network Time Security (NTS) core implementation.  NTS (RFC 8915) provides
// cryptographic authentication for NTPv4 using TLS-encrypted key
// establishment and AEAD-protected extension fields.
//
// ## NTS Architecture
//
// NTS has two phases:
//
//   1. **NTS-KE** (Key Establishment): A TLS handshake on port 4460 between
//      client and server that negotiates algorithms and exchanges NTS cookies.
//      Implemented in nts_client.rs / nts_server.rs.
//
//   2. **NTP Extension Fields**: AEAD-protected extension fields added to
//      normal NTP packets.  The cookie encodes the server's state (keys,
//      algorithm, etc.) encrypted with AES-SIV-CMAC-256.  Implemented in
//      nts_cookie.rs / nts_extens.rs.
//
// This module provides the shared NTS state structures, protocol constants,
// and unique identifier key management.
//
// ## Oracle
//   - ntpsec ntpd/nts.c (14K)
//   - ntpsec include/nts.h
//   - ntpsec include/nts2.h
//   - RFC 8915 — Network Time Security for NTP
//   - RFC 5297 — Synthetic Initialization Vector (SIV) Authenticated Encryption
//
// ## Court
//   - docs/courts/nts.md
// =============================================================================

use crate::ntp_types::*;

/// NTS-KE default port (RFC 8915 §4).
pub const NTS_KE_PORT: u16 = 4460;

/// NTS protocol version.
pub const NTS_VERSION: u8 = 1;

/// Maximum number of cookies per NTS-KE response (ntpsec default).
pub const NTS_MAX_COOKIES: usize = 8;

/// Maximum cookie size in bytes.
pub const NTS_MAX_COOKIE_SIZE: usize = 256;

/// NTS record types (RFC 8915 §4.1).
pub mod nts_record {
    /// End of message
    pub const END_OF_MESSAGE: u16 = 0;
    /// Negotiate NTPv4 server
    pub const NTPV4_SERVER_NEGOTIATION: u16 = 1;
    /// Negotiate NTPv4 port
    pub const NTPV4_PORT_NEGOTIATION: u16 = 2;
    /// NTS cookie
    pub const COOKIE: u16 = 3;
    /// NTS negotiation data
    pub const NTS_NEGOTIATION: u16 = 4;
    /// AEAD algorithm negotiation
    pub const NTS_AEAD: u16 = 5;
    /// Cookie placeholder (for empty cookie requests)
    pub const NTS_COOKIE_PLACEHOLDER: u16 = 6;
    /// Unassigned
    pub const UNASSIGNED: u16 = 7;
    /// Protocol warning
    pub const WARNING: u16 = 0x7f00;
    /// Protocol error
    pub const ERROR: u16 = 0x7f01;
    /// Protocol alarm
    pub const ALARM: u16 = 0x7f02;
}

/// NTS extension field types used in NTP packets (RFC 8915 §5).
pub mod nts_ef {
    /// NTS Cookie extension field
    pub const NTS_COOKIE: u16 = 0x0104;
    /// NTS Cookie Placeholder
    pub const NTS_COOKIE_PLACEHOLDER: u16 = 0x0105;
    /// NTS Authenticator (AEAD encryption)
    pub const NTS_AUTHENTICATOR: u16 = 0x0102;
    /// NTS Authenticator Error
    pub const NTS_AUTHENTICATOR_ERROR: u16 = 0x0103;
}

/// AEAD algorithm IDs used in NTS (RFC 8915 §5.2, ntpsec's `nts.h`).
pub mod aead_algorithms {
    /// AES-SIV-CMAC-256 (REQUIRED by RFC 8915).
    pub const AES_SIV_CMAC_256: u16 = 1;
    /// AES-128-GCM (not used by NTS).
    pub const AES_128_GCM: u16 = 2;
    /// AES-256-GCM (not used by NTS).
    pub const AES_256_GCM: u16 = 3;

    /// All supported AEAD algorithms in ntpsec.
    pub const SUPPORTED: &[u16] = &[AES_SIV_CMAC_256];
}

/// NTS unique identifier key (UIK) — used to derive cookie encryption keys.
#[derive(Debug, Clone)]
pub struct NtsUniqueKey {
    /// The raw key material (64 bytes for AES-SIV-CMAC-256).
    pub key_data: [u8; 64],
    /// The UIK identifier (opaque, used in references).
    pub id: Vec<u8>,
}

impl Default for NtsUniqueKey {
    fn default() -> Self {
        Self {
            key_data: [0u8; 64],
            id: Vec::new(),
        }
    }
}

impl NtsUniqueKey {
    pub fn new(key_data: [u8; 64], id: Vec<u8>) -> Self {
        Self { key_data, id }
    }

    /// Generate a random NTS unique key.
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut key = [0u8; 64];
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut rng = seed;
        for byte in key.iter_mut() {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = ((rng >> 32) & 0xFF) as u8;
        }
        // ID is the first 8 bytes as hex
        let id_str = format!("{:016x}", u64::from_be_bytes(key[..8].try_into().unwrap()));
        Self {
            key_data: key,
            id: id_str.into_bytes(),
        }
    }

    /// Get the key as a reference.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }

    /// Get the key identifier as a string.
    pub fn id_str(&self) -> String {
        String::from_utf8_lossy(&self.id).to_string()
    }
}

/// NTS state for a single association.
#[derive(Debug, Clone)]
pub struct NtsState {
    /// Client-to-server key.
    pub c2s_key: Option<Vec<u8>>,
    /// Server-to-client key.
    pub s2c_key: Option<Vec<u8>>,
    /// NTS cookies for this association.
    pub cookies: Vec<Vec<u8>>,
    /// The server's cookie — used by the server to regenerate the key material.
    pub server_cookie_data: Option<Vec<u8>>,
    /// AEAD algorithm negotiated.
    pub aead_algorithm: u16,
    /// NTS-KE protocol version.
    pub nts_version: u8,
    /// Whether NTS-KE has completed.
    pub nts_ke_done: bool,
    /// NTP port negotiated via NTS (0 = default 123).
    pub ntspe_port: u16,
    /// NTS-KE hostname.
    pub ke_hostname: Option<String>,
    /// NTS-KE port.
    pub ke_port: u16,
}

impl Default for NtsState {
    fn default() -> Self {
        Self::new()
    }
}

impl NtsState {
    pub fn new() -> Self {
        Self {
            c2s_key: None,
            s2c_key: None,
            cookies: Vec::new(),
            server_cookie_data: None,
            aead_algorithm: aead_algorithms::AES_SIV_CMAC_256,
            nts_version: NTS_VERSION,
            nts_ke_done: false,
            ntspe_port: 0,
            ke_hostname: None,
            ke_port: NTS_KE_PORT,
        }
    }

    /// Add an NTS cookie.
    pub fn add_cookie(&mut self, cookie: Vec<u8>) {
        if self.cookies.len() < NTS_MAX_COOKIES {
            self.cookies.push(cookie);
        }
    }

    /// Pop the first cookie (for use in an NTS request).
    pub fn pop_cookie(&mut self) -> Option<Vec<u8>> {
        if self.cookies.is_empty() {
            None
        } else {
            Some(self.cookies.remove(0))
        }
    }

    /// Number of cookies.
    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    /// Whether we have keys for NTS.
    pub fn is_nts_ready(&self) -> bool {
        self.nts_ke_done && self.c2s_key.is_some() && self.s2c_key.is_some()
    }
}

/// NTS-KE message record.
#[derive(Debug, Clone)]
pub struct NtsKeRecord {
    pub record_type: u16,
    pub body: Vec<u8>,
}

impl NtsKeRecord {
    pub fn new(record_type: u16, body: Vec<u8>) -> Self {
        Self { record_type, body }
    }

    /// Encode to wire format (4-byte header + body).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.body.len());
        buf.extend_from_slice(&self.record_type.to_be_bytes());
        buf.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Decode from wire format.
    pub fn decode(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 4 {
            return None;
        }
        let record_type = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + length {
            return None;
        }
        let body = data[4..4 + length].to_vec();
        let remaining = &data[4 + length..];
        Some((Self { record_type, body }, remaining))
    }

    /// Decode a sequence of records from a byte buffer.
    pub fn decode_all(data: &[u8]) -> Vec<Self> {
        let mut records = Vec::new();
        let mut remain = data;
        while let Some((rec, rest)) = Self::decode(remain) {
            if rec.record_type == nts_record::END_OF_MESSAGE {
                break;
            }
            records.push(rec);
            remain = rest;
        }
        records
    }
}

/// NTS warning/error codes (RFC 8915 §4.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtsErrorCode {
    /// No error
    None = 0,
    /// Internal error
    Internal = 1,
    /// Unknown record type
    UnknownRecord = 2,
    /// Bad request
    BadRequest = 3,
    /// Authentication failure
    AuthFailure = 4,
    /// No such algorithm
    UnknownAlgorithm = 5,
    /// Cookie too large
    CookieTooLarge = 6,
}

impl NtsErrorCode {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => NtsErrorCode::None,
            1 => NtsErrorCode::Internal,
            2 => NtsErrorCode::UnknownRecord,
            3 => NtsErrorCode::BadRequest,
            4 => NtsErrorCode::AuthFailure,
            5 => NtsErrorCode::UnknownAlgorithm,
            6 => NtsErrorCode::CookieTooLarge,
            _ => NtsErrorCode::Internal,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nts_state_new() {
        let state = NtsState::new();
        assert!(!state.is_nts_ready());
        assert_eq!(state.cookie_count(), 0);
    }

    #[test]
    fn test_nts_state_cookies() {
        let mut state = NtsState::new();
        state.add_cookie(vec![1, 2, 3]);
        state.add_cookie(vec![4, 5, 6]);
        assert_eq!(state.cookie_count(), 2);
        let cookie = state.pop_cookie().unwrap();
        assert_eq!(cookie, vec![1, 2, 3]);
        assert_eq!(state.cookie_count(), 1);
    }

    #[test]
    fn test_unique_key_generate() {
        let key1 = NtsUniqueKey::generate();
        let key2 = NtsUniqueKey::generate();
        assert_ne!(key1.key_data, key2.key_data);
        assert!(!key1.id.is_empty());
    }

    #[test]
    fn test_nts_ke_record_roundtrip() {
        let rec = NtsKeRecord::new(nts_record::COOKIE, vec![1, 2, 3, 4]);
        let encoded = rec.encode();
        let (decoded, remaining) = NtsKeRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.record_type, nts_record::COOKIE);
        assert_eq!(decoded.body, vec![1, 2, 3, 4]);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_nts_ke_record_decode_all() {
        let rec1 = NtsKeRecord::new(nts_record::COOKIE, vec![1, 2, 3]);
        let rec2 = NtsKeRecord::new(nts_record::NTPV4_SERVER_NEGOTIATION, vec![1]);
        let eom = NtsKeRecord::new(nts_record::END_OF_MESSAGE, vec![]);
        let mut data = rec1.encode();
        data.extend_from_slice(&rec2.encode());
        data.extend_from_slice(&eom.encode());
        let records = NtsKeRecord::decode_all(&data);
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_aead_algorithms() {
        assert!(aead_algorithms::SUPPORTED.contains(&aead_algorithms::AES_SIV_CMAC_256));
    }
}
