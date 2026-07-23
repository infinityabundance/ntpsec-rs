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

/// AEAD algorithm IDs used in NTS (RFC 8915 §4.1.3).
pub mod aead_algorithms {
    /// AEAD_AES_SIV_CMAC_256 (REQUIRED by RFC 8915).
    pub const AEAD_AES_SIV_CMAC_256: u16 = 15;
    /// AEAD_AES_SIV_CMAC_512.
    pub const AEAD_AES_SIV_CMAC_512: u16 = 16;
    /// AEAD_AES_GCM_128.
    pub const AEAD_AES_GCM_128: u16 = 18;

    /// Old alias kept for compatibility.
    pub const AES_SIV_CMAC_256: u16 = AEAD_AES_SIV_CMAC_256;
    /// Old alias kept for compatibility.
    pub const AES_128_GCM: u16 = 2;
    /// Old alias kept for compatibility.
    pub const AES_256_GCM: u16 = 3;

    /// All supported AEAD algorithms.
    pub const SUPPORTED: &[u16] = &[AEAD_AES_SIV_CMAC_256];
}

/// Strongly-typed AEAD algorithm identifiers (RFC 8915 §4.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    AeadAesSivCmac256 = 15, // 32-byte key
    AeadAesSivCmac512 = 16, // 64-byte key
    AeadAesGcm128 = 18,     // 16-byte key
}

impl AeadAlgorithm {
    /// Return the key length in bytes required by this AEAD algorithm (RFC 8915 §4.1.3).
    pub fn key_length(&self) -> usize {
        match self {
            AeadAlgorithm::AeadAesSivCmac256 => 32,
            AeadAlgorithm::AeadAesSivCmac512 => 64,
            AeadAlgorithm::AeadAesGcm128 => 16,
        }
    }

    /// Convert from the u16 wire-encoding used in NTS-KE records (RFC 8915 §4.1.3).
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            15 => Some(AeadAlgorithm::AeadAesSivCmac256),
            16 => Some(AeadAlgorithm::AeadAesSivCmac512),
            18 => Some(AeadAlgorithm::AeadAesGcm128),
            _ => None,
        }
    }

    /// Convert to the u16 wire-encoding used in NTS-KE records.
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// NTS-KE session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtsKeState {
    Idle,
    Connecting,
    Negotiating,
    Established,
    Error(String),
}

impl NtsKeState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, NtsKeState::Established | NtsKeState::Error(_))
    }

    pub fn is_established(&self) -> bool {
        matches!(self, NtsKeState::Established)
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            NtsKeState::Error(msg) => Some(msg.as_str()),
            _ => None,
        }
    }
}

/// NTS-KE negotiated parameters.
#[derive(Debug, Clone)]
pub struct NtsKeNegotiation {
    pub aead_algorithm: AeadAlgorithm,
    pub cookies: Vec<Vec<u8>>,          // raw cookie bodies
    pub server_offer: Vec<NtsKeRecord>, // additional server offers
}

impl NtsKeNegotiation {
    pub fn new(aead_algorithm: AeadAlgorithm, cookies: Vec<Vec<u8>>) -> Self {
        Self {
            aead_algorithm,
            cookies,
            server_offer: Vec::new(),
        }
    }

    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    pub fn take_cookie(&mut self) -> Option<Vec<u8>> {
        if self.cookies.is_empty() {
            None
        } else {
            Some(self.cookies.remove(0))
        }
    }
}

// ──── NTS-KE Record Protocol ────────────────────────────────────────────
//
// RFC 8915 §4.1 defines the NTS-KE record wire format:
//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  ┌─────────────────────────────────────────────────────────────────┐
//  │         Record Type (16)       │         Body Length (16)       │
//  ├─────────────────────────────────────────────────────────────────┤
//  │                          Body (variable)                        │
//  └─────────────────────────────────────────────────────────────────┘
//
// Record types are defined in the `nts_record` module above.

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
    /// Returns `(record, remaining_bytes)` on success.
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
    /// Stops at END_OF_MESSAGE (type 0) or when no more data is available.
    pub fn decode_all(data: &[u8]) -> Vec<Self> {
        let mut records = Vec::new();
        let mut remain = data;
        loop {
            if remain.is_empty() {
                break;
            }
            match Self::decode(remain) {
                Some((rec, rest)) => {
                    if rec.record_type == nts_record::END_OF_MESSAGE {
                        break;
                    }
                    records.push(rec);
                    remain = rest;
                }
                None => break,
            }
        }
        records
    }
}

/// NTS-KE client — manages the NTS-KE state machine and record exchange.
///
/// In a deployed system this struct would drive the actual TLS connection
/// to the NTS-KE server.  The handshake() method here demonstrates the
/// protocol flow by constructing the negotiation request, processing the
/// server's response, and extracting cookies and negotiated algorithms.
///
/// The actual TLS transport layer lives in nts_client.rs; this struct
/// provides the protocol-aware framing layer.
pub struct NtsKeClient {
    state: NtsKeState,
    host: String,
    port: u16,
    cookies: Vec<Vec<u8>>,
    aead: Option<AeadAlgorithm>,
}

impl NtsKeClient {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            state: NtsKeState::Idle,
            host: host.to_string(),
            port,
            cookies: Vec::new(),
            aead: None,
        }
    }

    /// Perform the NTS-KE handshake.
    ///
    /// The full handshake (RFC 8915 §4) proceeds as follows:
    ///
    ///   1. Open a TLS connection to the NTS-KE server on the configured
    ///      host:port (typically port 4460).
    ///   2. Send a Negotiation Request record listing the client's supported
    ///      AEAD algorithms.
    ///   3. Optionally send NTPv4 Server Negotiation and/or NTPv4 Port
    ///      Negotiation records.
    ///   4. Send an End-of-Message record.
    ///   5. Read and process the server's response records:
    ///        - AEAD Algorithm Offer: the server's chosen algorithm.
    ///        - NTS Cookie: one or more encrypted cookies.
    ///        - NTPv4 Server Negotiation / Port Negotiation: server's
    ///          NTP endpoint information.
    ///        - End-of-Message: signals the end of the response.
    ///   6. Close the TLS session.
    ///
    /// This implementation performs the protocol framing (record construction
    /// and parsing) but requires the TLS transport to be wired in from the
    /// nts_client module.  For the oracle-free / offline development path,
    /// the method returns an error indicating that TLS is not yet connected.
    pub fn handshake(&mut self) -> Result<NtsKeNegotiation, String> {
        self.state = NtsKeState::Connecting;

        // ── Build the negotiation request ──────────────────────────────
        let mut request_records: Vec<NtsKeRecord> = Vec::new();

        // Advertise AES-SIV-CMAC-256 as the preferred AEAD algorithm.
        let aead_body = AeadAlgorithm::AeadAesSivCmac256
            .to_u16()
            .to_be_bytes()
            .to_vec();
        request_records.push(NtsKeRecord::new(nts_record::NTS_AEAD, aead_body));

        // Optionally request NTPv4 server negotiation (RFC 8915 §4.1.2).
        // In the simplest case this is an empty body.
        request_records.push(NtsKeRecord::new(
            nts_record::NTPV4_SERVER_NEGOTIATION,
            vec![],
        ));

        // End-of-message marks the end of the client's request.
        request_records.push(NtsKeRecord::new(nts_record::END_OF_MESSAGE, vec![]));

        // ── Serialize the request ──────────────────────────────────────
        let _request_wire: Vec<u8> = request_records.iter().flat_map(|r| r.encode()).collect();

        // ── TLS transport stub ─────────────────────────────────────────
        // The actual TLS send/recv would happen here, driven by the
        // nts_client module.  Since that module is a stub during the
        // oracle-free development path, we record that we *would* send
        // `request_wire` and then receive a response.
        //
        // When TLS is wired, replace this entire block with:
        //
        //   let tls = NtsTlsTransport::connect(&self.host, self.port)?;
        //   tls.send_all(&request_wire).map_err(|e| ...)?;
        //   let response_wire = tls.receive_all().map_err(|e| ...)?;
        //
        // For offline testing, return a clear error so callers know the
        // transport layer is not yet available.

        self.state = NtsKeState::Negotiating;

        // Stub: handshake not yet wired through TLS transport.
        self.state =
            NtsKeState::Error("NTS-KE TLS transport not wired: nts_client is a stub".to_string());
        Err("NTS-KE handshake requires TLS transport (nts_client not yet implemented)".to_string())
    }

    /// Start a handshake with pre-built wire-format request data.
    /// Used for testing / offline development paths where the caller
    /// supplies both request and response bytes directly.
    pub fn handshake_with_data(
        &mut self,
        request: &[u8],
        response: &[u8],
    ) -> Result<NtsKeNegotiation, String> {
        self.state = NtsKeState::Connecting;

        // Verify the request encodes (round-trip check for tests).
        let req_records = NtsKeRecord::decode_all(request);
        if req_records.is_empty() {
            self.state = NtsKeState::Error("empty request".to_string());
            return Err("empty NTS-KE request".to_string());
        }

        self.state = NtsKeState::Negotiating;

        // Parse the server's response records.
        let resp_records = NtsKeRecord::decode_all(response);

        let mut aead_algorithm: Option<AeadAlgorithm> = None;
        let mut cookies: Vec<Vec<u8>> = Vec::new();
        let mut server_offer: Vec<NtsKeRecord> = Vec::new();

        for rec in &resp_records {
            match rec.record_type {
                t if t == nts_record::NTS_AEAD => {
                    // The AEAD algorithm offer body is the u16 algorithm ID
                    // in network byte order.
                    if rec.body.len() >= 2 {
                        let alg_id = u16::from_be_bytes([rec.body[0], rec.body[1]]);
                        aead_algorithm = AeadAlgorithm::from_u16(alg_id);
                    }
                }
                t if t == nts_record::COOKIE => {
                    // Each COOKIE record body *is* the encrypted cookie.
                    cookies.push(rec.body.clone());
                }
                t if t == nts_record::END_OF_MESSAGE => {
                    // Stop processing; server terminates with EOM.
                    break;
                }
                _ => {
                    // Collect any other records as server offers.
                    server_offer.push(rec.clone());
                }
            }
        }

        let aead = aead_algorithm.ok_or_else(|| {
            self.state = NtsKeState::Error("no AEAD algorithm negotiated".to_string());
            "no AEAD algorithm negotiated".to_string()
        })?;

        if cookies.is_empty() {
            self.state = NtsKeState::Error("no cookies received".to_string());
            return Err("no cookies received from NTS-KE server".to_string());
        }

        self.aead = Some(aead);
        self.cookies = cookies.clone();
        self.state = NtsKeState::Established;

        Ok(NtsKeNegotiation {
            aead_algorithm: aead,
            cookies,
            server_offer,
        })
    }

    pub fn state(&self) -> &NtsKeState {
        &self.state
    }

    pub fn cookies(&self) -> &[Vec<u8>] {
        &self.cookies
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn aead(&self) -> Option<AeadAlgorithm> {
        self.aead
    }

    /// Reset the client to `Idle` state, keeping host/port configuration.
    pub fn reset(&mut self) {
        self.state = NtsKeState::Idle;
        self.cookies.clear();
        self.aead = None;
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

// ──── NTS-KE record type constants (RFC 8915 §4.1, top-level aliases) ──

// NTS-KE record type constants (RFC 8915 §4.1).
pub const NTS_KE_RECORD_END_OF_MESSAGE: u16 = 0;
pub const NTS_KE_RECORD_NEXT_PROTOCOL: u16 = 1;
pub const NTS_KE_RECORD_ERROR: u16 = 2;
pub const NTS_KE_RECORD_WARNING: u16 = 3;
pub const NTS_KE_RECORD_AEAD_ALGORITHM: u16 = 4;
pub const NTS_KE_RECORD_NEW_COOKIE: u16 = 5;
pub const NTS_KE_RECORD_NTPV4_SERVER: u16 = 6;
pub const NTS_KE_RECORD_NTPV4_PORT: u16 = 7;
pub const NTS_KE_RECORD_CRITICAL_BIT: u16 = 0x8000;

// AEAD algorithm identifiers (RFC 8915 §4.1.3).
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;
pub const AEAD_AES_SIV_CMAC_512: u16 = 16;
pub const AEAD_AES_GCM_128: u16 = 18;

// ──── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nts_state_new() {
        let state = NtsState::new();
        assert!(!state.is_nts_ready());
        assert_eq!(state.cookie_count(), 0);
        assert_eq!(state.nts_version, NTS_VERSION);
        assert_eq!(state.ke_port, NTS_KE_PORT);
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
    fn test_nts_state_max_cookies() {
        let mut state = NtsState::new();
        for i in 0..NTS_MAX_COOKIES + 2 {
            state.add_cookie(vec![i as u8]);
        }
        assert_eq!(state.cookie_count(), NTS_MAX_COOKIES);
    }

    #[test]
    fn test_unique_key_generate() {
        let key1 = NtsUniqueKey::generate();
        let key2 = NtsUniqueKey::generate();
        assert_ne!(key1.key_data, key2.key_data);
        assert!(!key1.id.is_empty());
        assert_eq!(key1.key_data.len(), 64);
    }

    #[test]
    fn test_nts_ke_record_new() {
        let rec = NtsKeRecord::new(nts_record::COOKIE, vec![1, 2, 3, 4]);
        assert_eq!(rec.record_type, nts_record::COOKIE);
        assert_eq!(rec.body, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_record_encode_decode_roundtrip() {
        let rec = NtsKeRecord::new(nts_record::COOKIE, vec![1, 2, 3, 4]);
        let encoded = rec.encode();
        let (decoded, remaining) = NtsKeRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.record_type, nts_record::COOKIE);
        assert_eq!(decoded.body, vec![1, 2, 3, 4]);
        assert!(remaining.is_empty());
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
    fn test_decode_all() {
        // Extended decode_all test with multiple record types.
        let rec1 = NtsKeRecord::new(nts_record::NTS_AEAD, vec![0, 1]);
        let rec2 = NtsKeRecord::new(nts_record::COOKIE, vec![10, 20, 30]);
        let eom = NtsKeRecord::new(nts_record::END_OF_MESSAGE, vec![]);
        let mut data = rec1.encode();
        data.extend_from_slice(&rec2.encode());
        data.extend_from_slice(&eom.encode());
        // Add trailing data that should be ignored after EOM
        let trailing = NtsKeRecord::new(nts_record::COOKIE, vec![99]);
        data.extend_from_slice(&trailing.encode());

        let records = NtsKeRecord::decode_all(&data);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record_type, nts_record::NTS_AEAD);
        assert_eq!(records[1].record_type, nts_record::COOKIE);
    }

    #[test]
    fn test_aead_key_length() {
        assert_eq!(AeadAlgorithm::AeadAesSivCmac256.key_length(), 32);
        assert_eq!(AeadAlgorithm::AeadAesSivCmac512.key_length(), 64);
        assert_eq!(AeadAlgorithm::AeadAesGcm128.key_length(), 16);
    }

    #[test]
    fn test_aead_algorithms() {
        assert!(aead_algorithms::SUPPORTED.contains(&aead_algorithms::AES_SIV_CMAC_256));
    }

    #[test]
    fn test_aead_algorithm_from_to_u16() {
        for v in [15u16, 16, 18] {
            let alg = AeadAlgorithm::from_u16(v).unwrap();
            assert_eq!(alg.to_u16(), v);
        }
        assert!(AeadAlgorithm::from_u16(0).is_none());
        assert!(AeadAlgorithm::from_u16(99).is_none());
    }

    #[test]
    fn test_nts_ke_state() {
        let state = NtsKeState::Idle;
        assert!(!state.is_terminal());
        assert!(!state.is_established());

        let state = NtsKeState::Connecting;
        assert!(!state.is_terminal());

        let state = NtsKeState::Negotiating;
        assert!(!state.is_terminal());

        let state = NtsKeState::Established;
        assert!(state.is_terminal());
        assert!(state.is_established());

        let state = NtsKeState::Error("something broke".to_string());
        assert!(state.is_terminal());
        assert!(!state.is_established());
        assert_eq!(state.error_message(), Some("something broke"));
    }

    #[test]
    fn test_nts_ke_state_error_none() {
        let state = NtsKeState::Idle;
        assert_eq!(state.error_message(), None);
    }

    #[test]
    fn test_nts_ke_client_new() {
        let client = NtsKeClient::new("ntp.example.com", NTS_KE_PORT);
        assert_eq!(client.host(), "ntp.example.com");
        assert_eq!(client.port(), NTS_KE_PORT);
        assert_eq!(*client.state(), NtsKeState::Idle);
        assert!(client.cookies().is_empty());
        assert!(client.aead().is_none());
    }

    #[test]
    fn test_nts_ke_client_reset() {
        let mut client = NtsKeClient::new("ntp.example.com", NTS_KE_PORT);
        client.reset();
        assert_eq!(*client.state(), NtsKeState::Idle);
        assert!(client.cookies().is_empty());
        assert!(client.aead().is_none());
    }

    #[test]
    fn test_nts_ke_client_handshake_with_data() {
        let mut client = NtsKeClient::new("ntp.example.com", NTS_KE_PORT);

        // Build a mock server response with one AEAD offer and two cookies.
        let aead_rec = NtsKeRecord::new(
            nts_record::NTS_AEAD,
            (15u16).to_be_bytes().to_vec(), // AEAD_AES_SIV_CMAC_256
        );
        let cookie1 = NtsKeRecord::new(nts_record::COOKIE, vec![0xAA; 32]);
        let cookie2 = NtsKeRecord::new(nts_record::COOKIE, vec![0xBB; 32]);
        let eom = NtsKeRecord::new(nts_record::END_OF_MESSAGE, vec![]);

        let mut response = Vec::new();
        response.extend_from_slice(&aead_rec.encode());
        response.extend_from_slice(&cookie1.encode());
        response.extend_from_slice(&cookie2.encode());
        response.extend_from_slice(&eom.encode());

        // Build a minimal request (just AEAD and EOM).
        let req_aead = NtsKeRecord::new(nts_record::NTS_AEAD, (15u16).to_be_bytes().to_vec());
        let req_eom = NtsKeRecord::new(nts_record::END_OF_MESSAGE, vec![]);
        let mut request = Vec::new();
        request.extend_from_slice(&req_aead.encode());
        request.extend_from_slice(&req_eom.encode());

        let negotiation = client.handshake_with_data(&request, &response).unwrap();
        assert_eq!(negotiation.aead_algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(negotiation.cookie_count(), 2);
        assert_eq!(negotiation.cookies[0], vec![0xAA; 32]);
        assert_eq!(negotiation.cookies[1], vec![0xBB; 32]);
        assert_eq!(*client.state(), NtsKeState::Established);
        assert_eq!(client.aead(), Some(AeadAlgorithm::AeadAesSivCmac256));
    }

    #[test]
    fn test_nts_ke_client_handshake_with_data_empty_response() {
        let mut client = NtsKeClient::new("ntp.example.com", NTS_KE_PORT);
        let request = NtsKeRecord::new(nts_record::END_OF_MESSAGE, vec![]).encode();
        let result = client.handshake_with_data(&request, &[]);
        assert!(result.is_err());
        assert!(client.state().error_message().is_some());
    }

    #[test]
    fn test_nts_ke_client_handshake_stub_returns_error() {
        let mut client = NtsKeClient::new("ntp.example.com", NTS_KE_PORT);
        let result = client.handshake();
        assert!(result.is_err());
        // The error should mention TLS transport being a stub.
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("TLS") || err_msg.contains("transport") || err_msg.contains("stub")
        );
    }

    #[test]
    fn test_nts_ke_negotiation_new() {
        let mut neg = NtsKeNegotiation::new(
            AeadAlgorithm::AeadAesSivCmac256,
            vec![vec![1, 2, 3], vec![4, 5, 6]],
        );
        assert_eq!(neg.cookie_count(), 2);
        assert_eq!(neg.take_cookie(), Some(vec![1, 2, 3]));
        assert_eq!(neg.cookie_count(), 1);
    }

    #[test]
    fn test_nts_error_code() {
        assert_eq!(NtsErrorCode::from_u16(0), NtsErrorCode::None);
        assert_eq!(NtsErrorCode::from_u16(1), NtsErrorCode::Internal);
        assert_eq!(NtsErrorCode::from_u16(2), NtsErrorCode::UnknownRecord);
        assert_eq!(NtsErrorCode::from_u16(3), NtsErrorCode::BadRequest);
        assert_eq!(NtsErrorCode::from_u16(4), NtsErrorCode::AuthFailure);
        assert_eq!(NtsErrorCode::from_u16(5), NtsErrorCode::UnknownAlgorithm);
        assert_eq!(NtsErrorCode::from_u16(6), NtsErrorCode::CookieTooLarge);
        assert_eq!(NtsErrorCode::from_u16(99), NtsErrorCode::Internal);
        assert_eq!(NtsErrorCode::None.to_u16(), 0);
        assert_eq!(NtsErrorCode::Internal.to_u16(), 1);
    }

    #[test]
    fn test_record_encode_decode_minimal() {
        // Empty body
        let rec = NtsKeRecord::new(nts_record::END_OF_MESSAGE, vec![]);
        let encoded = rec.encode();
        assert_eq!(encoded.len(), 4);
        let (decoded, remaining) = NtsKeRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.record_type, nts_record::END_OF_MESSAGE);
        assert!(decoded.body.is_empty());
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_record_decode_truncated() {
        // Only 2 bytes (need 4 for header)
        let result = NtsKeRecord::decode(&[0x00, 0x01]);
        assert!(result.is_none());

        // Header says body is 10 bytes but only 2 available
        let result = NtsKeRecord::decode(&[0x00, 0x01, 0x00, 0x0A, 0xFF, 0xFF]);
        assert!(result.is_none());
    }

    #[test]
    fn test_nts_ke_record_constants() {
        assert_eq!(NTS_KE_RECORD_END_OF_MESSAGE, 0);
        assert_eq!(NTS_KE_RECORD_NEXT_PROTOCOL, 1);
        assert_eq!(NTS_KE_RECORD_ERROR, 2);
        assert_eq!(NTS_KE_RECORD_WARNING, 3);
        assert_eq!(NTS_KE_RECORD_AEAD_ALGORITHM, 4);
        assert_eq!(NTS_KE_RECORD_NEW_COOKIE, 5);
        assert_eq!(NTS_KE_RECORD_NTPV4_SERVER, 6);
        assert_eq!(NTS_KE_RECORD_NTPV4_PORT, 7);
        assert_eq!(NTS_KE_RECORD_CRITICAL_BIT, 0x8000);
        assert_eq!(AEAD_AES_SIV_CMAC_256, 15);
        assert_eq!(AEAD_AES_SIV_CMAC_512, 16);
        assert_eq!(AEAD_AES_GCM_128, 18);
    }
}
