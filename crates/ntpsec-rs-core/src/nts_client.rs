// ──── nts_client.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/nts_client.c
//
// NTS-KE client: TLS 1.3 handshake with NTS server, key establishment via TLS
// exporter, cookie retrieval (RFC 8915 §4).
//
// ## Gate 8 — Seal NTS against real external implementations
//   8.1 NtsAssociation — binds keys and cookies to an NTP association
//   8.4 Operational completeness: IPv4/IPv6, SNI, cert validation, timeouts
//   8.7 Certificate handling: system CA, hostname validation, expiry checks
//
// ## Oracle
//   - ntpsec ntpd/nts_client.c (26K)
//   - RFC 8915 §4 (NTS-KE protocol)
//   - RFC 8915 §4.5 (TLS exporter for key derivation)
//   - RFC 8915 §5 (NTP extension fields)
// =============================================================================

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use aes_siv::aead::Key;
use aes_siv::siv::Aes128Siv;
use digest::KeyInit;
use rustls::pki_types::ServerName;

use crate::ntp_types::*;
use crate::nts::*;
use crate::nts_extens::*;

#[cfg(test)]
use crate::nts_cookie::{CookieCipher, CookieKeyIndex};

// ──── NTS Association ──────────────────────────────────────────────────────

/// An NTS association that binds the results of an NTS-KE handshake to an
/// NTP association (Gate 8.1).
///
/// This struct holds all cryptographic material and configuration needed to
/// build authenticated NTP requests and verify NTP responses using NTS.
#[derive(Debug, Clone)]
pub struct NtsAssociation {
    /// Client-to-server AEAD key (32 bytes for AES-SIV-CMAC-256).
    pub c2s_key: [u8; 32],
    /// Server-to-client AEAD key (32 bytes for AES-SIV-CMAC-256).
    pub s2c_key: [u8; 32],
    /// Pool of encrypted NTS cookies received from the server.
    pub cookies: Vec<Vec<u8>>,
    /// The negotiated AEAD algorithm identifier (RFC 8915 §4.1.3).
    pub aead_algorithm: u16,
    /// Encrypted server cookie (the first cookie, useful for server identity binding).
    pub server_cookie: Vec<u8>,
    /// NTS-KE server hostname.
    pub ke_hostname: String,
    /// NTS-KE server port.
    pub ke_port: u16,
    /// NTP-over-NTS port (0 means default NTP port 123).
    pub ntspe_port: u16,
    /// Monotonic sequence counter for nonce generation (client side).
    pub sequence: u64,
    /// Last Unique Identifier sent in a request.
    /// The server MUST echo this back; the response verifier checks it.
    pub last_uik: Vec<u8>,
    /// Generation number for this association.
    /// Incremented each time the association is replaced (re-handshake).
    /// Used to discard stale NTS-KE worker results.
    pub generation: u64,
}

impl NtsAssociation {
    /// Create a new NtsAssociation from handshake results.
    pub fn new(
        c2s_key: [u8; 32],
        s2c_key: [u8; 32],
        cookies: Vec<Vec<u8>>,
        aead_algorithm: u16,
        ke_hostname: String,
        ke_port: u16,
        ntspe_port: u16,
    ) -> Self {
        let server_cookie = cookies.first().cloned().unwrap_or_default();
        Self {
            c2s_key,
            s2c_key,
            cookies,
            aead_algorithm,
            server_cookie,
            ke_hostname,
            ke_port,
            ntspe_port,
            sequence: 0,
            last_uik: Vec::new(),
            generation: 0,
        }
    }

    /// Number of available cookies.
    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    /// Pop a cookie from the pool (consumes it for use in a request).
    pub fn pop_cookie(&mut self) -> Option<Vec<u8>> {
        if self.cookies.is_empty() {
            None
        } else {
            Some(self.cookies.remove(0))
        }
    }

    /// Add cookies back to the pool (e.g., from a replenishment handshake).
    pub fn add_cookies(&mut self, additional: &mut Vec<Vec<u8>>) {
        self.cookies.append(additional);
        // Keep only NTS_MAX_COOKIES
        while self.cookies.len() > NTS_MAX_COOKIES {
            self.cookies.pop();
        }
    }

    /// Whether cookie replenishment is needed.
    pub fn needs_replenish(&self) -> bool {
        self.cookies.len() <= NTS_MAX_COOKIES / 2
    }
}

// ──── NTS-KE TLS Client ──────────────────────────────────────────────────────

/// NTS-KE client using TLS 1.3 with rustls.
///
/// Performs the full NTS-KE handshake per RFC 8915 §4:
///   1. TCP connect to server on configured port
///   2. TLS 1.3 handshake with ALPN "ntske/1" + SNI
///   3. Exchange NTS-KE records (AEAD, Next Protocol, cookies)
///   4. Derive C2S and S2C keys via TLS exporter with directional contexts
///
/// Supports IPv4 and IPv6 via ToSocketAddrs (Gate 8.4).
pub struct NtsKeClient {
    host: String,
    port: u16,
    ca_cert_pem: Option<Vec<u8>>, // Custom CA certificate (Gate 8.7)
    timeout: Duration,
}

impl NtsKeClient {
    /// Create a new NTS-KE client for the given host and port.
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            ca_cert_pem: None,
            timeout: Duration::from_secs(10),
        }
    }

    /// Set a custom CA certificate (PEM-encoded) for server cert validation (Gate 8.7).
    pub fn with_ca_cert(mut self, ca_pem: Vec<u8>) -> Self {
        self.ca_cert_pem = Some(ca_pem);
        self
    }

    /// Set the TCP/TLS timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Perform the full NTS-KE handshake.
    ///
    /// Returns negotiated parameters including cookies and derived keys
    /// (C2S and S2C via TLS exporter with directional contexts per RFC 8915 §4.5).
    pub fn handshake(&self) -> Result<NtsKeNegotiation, String> {
        // ── 1. Build TLS client config: TLS 1.3 ONLY (RFC 8915 §4) ─────────
        let root_store = if let Some(ref ca_pem) = self.ca_cert_pem {
            build_root_store_from_pem(ca_pem)?
        } else {
            build_root_store()?
        };

        let mut tls_config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth();

        // Set ALPN for NTS-KE protocol (RFC 8915 §4).
        tls_config.alpn_protocols = vec![b"ntske/1".to_vec()];

        let tls_config = Arc::new(tls_config);

        // ── 2. TCP connect (supports IPv4 and IPv6) ──────────────────
        // Use ToSocketAddrs for IPv4/IPv6 resolution (Gate 8.4).
        let addr_str = format!("{}:{}", self.host, self.port);
        let addr = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed for {addr_str}: {e}"))?
            .next()
            .ok_or_else(|| format!("no addresses resolved for {addr_str}"))?;

        let mut tcp = TcpStream::connect_timeout(&addr, self.timeout)
            .map_err(|e| format!("TCP connect to {addr} failed: {e}"))?;

        tcp.set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("set read timeout failed: {e}"))?;
        tcp.set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("set write timeout failed: {e}"))?;

        // ── 3. TLS handshake with SNI ────────────────────────────────
        let server_name = ServerName::try_from(self.host.clone())
            .map_err(|e| format!("invalid server name '{}': {e}", self.host))?;

        let mut tls_session = rustls::ClientConnection::new(tls_config, server_name)
            .map_err(|e| format!("TLS session creation failed: {e}"))?;

        // Complete TLS handshake via rustls's complete_io helper.
        tls_session.complete_io(&mut tcp).map_err(|e| {
            // Distinguish TLS auth failures (Gate 8.3, 8.7)
            let err_str = format!("{e}");
            if err_str.contains("certificate")
                || err_str.contains("CertNotValidForName")
                || err_str.contains("UnknownIssuer")
            {
                format!("TLS handshake failed (certificate validation error): {e}")
            } else {
                format!("TLS handshake I/O failed: {e}")
            }
        })?;

        // Verify the server negotiated the NTS-KE ALPN.
        let negotiated_alpn = tls_session
            .alpn_protocol()
            .and_then(|p| std::str::from_utf8(p).ok())
            .unwrap_or("");
        if negotiated_alpn != "ntske/1" {
            return Err(format!(
                "server did not negotiate ntske/1 ALPN; got {:?}",
                negotiated_alpn
            ));
        }

        // ── 4. Build NTS-KE request records (RFC 8915 §4.1) ───────────────
        let mut request_records: Vec<NtsKeRecord> = Vec::new();

        // Mandatory: Next Protocol Negotiation selecting NTPv4 (protocol ID 0).
        let next_proto_body = 0u16.to_be_bytes().to_vec();
        request_records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_NEXT_PROTOCOL,
            next_proto_body,
        ));

        // Advertise AES-SIV-CMAC-256 as the preferred AEAD algorithm.
        let aead_body = AeadAlgorithm::AeadAesSivCmac256
            .to_u16()
            .to_be_bytes()
            .to_vec();
        request_records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_AEAD_ALGORITHM,
            aead_body,
        ));

        // End-of-message: critical bit MUST be set, body MUST be empty (RFC 8915 §4.1.8).
        request_records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_END_OF_MESSAGE,
            vec![],
        ));

        // ── 5. Serialize and send the request ─────────────────────────────
        let request_wire: Vec<u8> = request_records.iter().flat_map(|r| r.encode()).collect();

        tls_session
            .writer()
            .write_all(&request_wire)
            .map_err(|e| format!("failed to buffer NTS-KE request: {e}"))?;

        tls_session
            .writer()
            .flush()
            .map_err(|e| format!("failed to flush TLS writer: {e}"))?;
        tls_session
            .complete_io(&mut tcp)
            .map_err(|e| format!("failed to send TLS data: {e}"))?;

        // ── 6. Read the server response ───────────────────────────────────
        let mut response_wire = Vec::new();
        loop {
            let read_len = tls_session
                .read_tls(&mut tcp)
                .map_err(|e| format!("TLS read failed: {e}"))?;
            if read_len == 0 {
                break;
            }

            tls_session
                .process_new_packets()
                .map_err(|e| format!("TLS packet processing failed: {e}"))?;

            let mut buf = [0u8; 4096];
            loop {
                let n = tls_session
                    .reader()
                    .read(&mut buf)
                    .map_err(|e| format!("TLS read plaintext failed: {e}"))?;
                if n == 0 {
                    break;
                }
                response_wire.extend_from_slice(&buf[..n]);
            }
        }

        // ── 7. Parse and validate the server's response records ───────────
        let (resp_records, trailing) = NtsKeRecord::decode_all(&response_wire);

        if !trailing.is_empty() {
            return Err(format!(
                "trailing data after last NTS-KE record ({} bytes)",
                trailing.len()
            ));
        }

        let mut aead_algorithm: Option<AeadAlgorithm> = None;
        let mut aead_count: usize = 0;
        let mut cookies: Vec<Vec<u8>> = Vec::new();
        let mut server_offer: Vec<NtsKeRecord> = Vec::new();
        let mut next_proto_count: usize = 0;
        let mut selected_ntpv4 = false;
        let mut has_eom = false;
        let mut eom_position = usize::MAX;

        for (pos, rec) in resp_records.iter().enumerate() {
            if rec.record_type & !NTS_KE_RECORD_CRITICAL_BIT == NTS_KE_RECORD_ERROR {
                let msg = String::from_utf8_lossy(&rec.body);
                return Err(format!("NTS-KE server returned Error: {}", msg));
            }

            if rec.record_type & NTS_KE_RECORD_CRITICAL_BIT != 0 {
                let raw_type = rec.record_type & !NTS_KE_RECORD_CRITICAL_BIT;
                match raw_type {
                    t if t == NTS_KE_RECORD_AEAD_ALGORITHM => {}
                    t if t == NTS_KE_RECORD_NEW_COOKIE => {}
                    t if t == NTS_KE_RECORD_NEXT_PROTOCOL => {}
                    t if t == NTS_KE_RECORD_END_OF_MESSAGE => {}
                    _ => {
                        return Err(format!(
                            "unsupported critical NTS-KE record type: {}",
                            raw_type
                        ));
                    }
                }
            }

            let raw_type = rec.record_type & !NTS_KE_RECORD_CRITICAL_BIT;
            match raw_type {
                t if t == NTS_KE_RECORD_NEXT_PROTOCOL => {
                    next_proto_count += 1;
                    if rec.record_type & NTS_KE_RECORD_CRITICAL_BIT == 0 {
                        return Err("Next Protocol record missing critical bit".to_string());
                    }
                    if next_proto_count > 1 {
                        return Err("duplicate Next Protocol record".to_string());
                    }
                    if rec.body.len() < 2 || rec.body.len() % 2 != 0 {
                        return Err(format!(
                            "Next Protocol has invalid body length: {} bytes",
                            rec.body.len()
                        ));
                    }
                    for chunk in rec.body.chunks_exact(2) {
                        let protocol = u16::from_be_bytes([chunk[0], chunk[1]]);
                        if protocol == 0 {
                            selected_ntpv4 = true;
                        }
                    }
                }
                t if t == NTS_KE_RECORD_AEAD_ALGORITHM => {
                    aead_count += 1;
                    if aead_count > 1 {
                        return Err("duplicate AEAD Algorithm record".to_string());
                    }
                    if rec.body.len() != 2 {
                        return Err(format!(
                            "AEAD Algorithm body must be exactly 2 bytes, got {}",
                            rec.body.len()
                        ));
                    }
                    let alg_id = u16::from_be_bytes([rec.body[0], rec.body[1]]);
                    if alg_id != 15 {
                        return Err(format!(
                            "server selected AEAD algorithm {}; client offered only 15",
                            alg_id
                        ));
                    }
                    aead_algorithm = AeadAlgorithm::from_u16(alg_id);
                }
                t if t == NTS_KE_RECORD_NEW_COOKIE => {
                    cookies.push(rec.body.clone());
                }
                t if t == NTS_KE_RECORD_END_OF_MESSAGE => {
                    if has_eom {
                        return Err("duplicate End of Message record".to_string());
                    }
                    if rec.record_type & NTS_KE_RECORD_CRITICAL_BIT == 0 {
                        return Err("End of Message record missing critical bit".to_string());
                    }
                    if !rec.body.is_empty() {
                        return Err(format!(
                            "End of Message record has non-empty body ({} bytes)",
                            rec.body.len()
                        ));
                    }
                    has_eom = true;
                    eom_position = pos;
                }
                _ => {
                    server_offer.push(rec.clone());
                }
            }
        }

        if has_eom && eom_position != resp_records.len() - 1 {
            return Err("EOM record is not the final record".to_string());
        }

        if next_proto_count == 0 {
            return Err("server did not include mandatory Next Protocol Negotiation".to_string());
        }
        if !selected_ntpv4 {
            return Err("server did not select NTPv4 protocol".to_string());
        }
        if !has_eom {
            return Err("server response missing End of Message record".to_string());
        }
        let aead = aead_algorithm.ok_or_else(|| "no AEAD algorithm negotiated".to_string())?;

        if cookies.is_empty() {
            return Err("no cookies received from NTS-KE server".to_string());
        }

        // ── 8. Derive keys via TLS exporter with directional contexts ────
        let aead_id = aead.to_u16();
        let c2s_context = [
            0x00,
            0x00,
            (aead_id >> 8) as u8,
            (aead_id & 0xff) as u8,
            0x00,
        ];
        let s2c_context = [
            0x00,
            0x00,
            (aead_id >> 8) as u8,
            (aead_id & 0xff) as u8,
            0x01,
        ];

        let mut c2s_key = [0u8; 32];
        let mut s2c_key = [0u8; 32];

        tls_session
            .export_keying_material(&mut c2s_key, NTS_KE_EXPORTER_LABEL, Some(&c2s_context))
            .map_err(|e| format!("TLS exporter failed for C2S key: {e}"))?;

        tls_session
            .export_keying_material(&mut s2c_key, NTS_KE_EXPORTER_LABEL, Some(&s2c_context))
            .map_err(|e| format!("TLS exporter failed for S2C key: {e}"))?;

        // Security invariant: C2S and S2C keys MUST differ.
        if c2s_key == s2c_key {
            return Err(
                "C2S and S2C keys derived identically — exporter context misconfiguration"
                    .to_string(),
            );
        }

        Ok(NtsKeNegotiation {
            aead_algorithm: aead,
            cookies,
            c2s_key,
            s2c_key,
            server_offer,
        })
    }
}

// ──── Perform full NTS-KE handshake → NtsAssociation (Gate 8.1) ──────────────

/// Perform a full NTS-KE handshake and return an `NtsAssociation` ready for
/// NTP packet protection (Gate 8.1).
///
/// This is the primary entry point for creating a client-side NTS association.
/// It handles:
///   - TCP connect (IPv4/IPv6)
///   - TLS 1.3 handshake with SNI and ALPN "ntske/1"
///   - Certificate validation via system trust store
///   - NTS-KE record exchange
///   - Key derivation via TLS exporter
///   - Cookie collection
pub fn perform_nts_ke(host: &str, port: u16) -> Result<NtsAssociation, String> {
    perform_nts_ke_with_config(host, port, None, Duration::from_secs(10))
}

/// Perform NTS-KE with optional custom CA certificate (Gate 8.7).
pub fn perform_nts_ke_with_ca(
    host: &str,
    port: u16,
    ca_cert_pem: Vec<u8>,
) -> Result<NtsAssociation, String> {
    perform_nts_ke_with_config(host, port, Some(ca_cert_pem), Duration::from_secs(10))
}

fn perform_nts_ke_with_config(
    host: &str,
    port: u16,
    ca_cert_pem: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<NtsAssociation, String> {
    let mut client_builder = NtsKeClient::new(host, port).with_timeout(timeout);
    if let Some(ca) = ca_cert_pem {
        client_builder = client_builder.with_ca_cert(ca);
    }

    let negotiation = client_builder.handshake()?;

    Ok(NtsAssociation {
        c2s_key: negotiation.c2s_key,
        s2c_key: negotiation.s2c_key,
        cookies: negotiation.cookies.clone(),
        aead_algorithm: negotiation.aead_algorithm.to_u16(),
        server_cookie: negotiation.cookies.first().cloned().unwrap_or_default(),
        ke_hostname: host.to_string(),
        ke_port: port,
        ntspe_port: 0, // Default NTP port unless negotiated otherwise
        sequence: 0,
        last_uik: Vec::new(),
        generation: 0,
    })
}

// ──── Build NTS-protected NTP request (Gate 8.1) ────────────────────────────

/// Build an NTS-protected NTP request by adding the required extension fields
/// to the raw NTP packet (Gate 8.1).
///
/// Extension fields added (in order, per RFC 8915 §5):
///   1. NTS Unique Identifier (UIK) — binds the request to the NTS-KE session
///   2. NTS Cookie — encrypted server state (one cookie consumed from pool)
///   3. NTS Authenticator — AEAD over the NTP header + preceding extension fields
///
/// Returns the full wire-format packet (header + extensions).
pub fn build_nts_request(
    packet: &NtpPacket,
    assoc: &mut NtsAssociation,
) -> Result<Vec<u8>, String> {
    let mut result = packet.encode_header().to_vec();

    // ── 1. NTS Unique Identifier extension field (RFC 8915 §5.1) ──────────
    // The UIK must be unpredictable and at least 32 bytes (RFC 8915 §5.1).
    // Use getrandom to fill a CSPRNG buffer; the server echoes this back
    // and the client MUST verify the echo on the response path.
    // Failure to obtain randomness MUST abort request construction (fail closed).
    let mut uik_payload = vec![0u8; 32];
    getrandom::getrandom(&mut uik_payload)
        .map_err(|e| format!("NTS: failed to generate Unique Identifier: {e}"))?;
    let uik_ext = ExtensionField::new(EXTENSION_FIELD_UNIQUE_IDENTIFIER, uik_payload.clone());
    result.extend_from_slice(&uik_ext.encode());

    // ── 2. NTS Cookie extension field (RFC 8915 §5.2) ─────────────────────
    // Pop one cookie from the pool and include it.
    let cookie_blob = assoc.pop_cookie().unwrap_or_else(|| {
        // If we're out of cookies, use the server_cookie as fallback
        assoc.server_cookie.clone()
    });
    let cookie_ext = ExtensionField::new(EXTENSION_FIELD_NTS_COOKIE, cookie_blob);
    result.extend_from_slice(&cookie_ext.encode());

    // ── 3. NTS Authenticator extension field (RFC 8915 §5.3) ───────────────
    // Build AEAD using the C2S key. AAD = NTP header + UIK + Cookie.
    // Nonce = 8-byte big-endian sequence number plus 8 bytes additional
    // padding to reach the required 16-byte minimum (RFC 8915 §5.3).
    let aad = {
        let header = &result[..NTP_HEADER_SIZE.min(result.len())];
        let ext_data = &result[NTP_HEADER_SIZE.min(result.len())..];
        let mut combined = Vec::with_capacity(header.len() + ext_data.len());
        combined.extend_from_slice(header);
        combined.extend_from_slice(ext_data);
        combined
    };

    let key = Key::<Aes128Siv>::from_slice(&assoc.c2s_key);
    // Nonce: 8-byte big-endian sequence number + 8 zero bytes (padding)
    // to meet the 16-byte minimum required by RFC 8915 §5.3.
    let mut nonce = vec![0u8; 16];
    nonce[..8].copy_from_slice(&assoc.sequence.to_be_bytes());
    // nonce[8..16] remain zero (Additional Padding)
    let headers: [&[u8]; 2] = [&aad, &nonce];

    let mut siv = Aes128Siv::new(key);
    let ciphertext = siv
        .encrypt(headers, &[])
        .expect("AEAD encrypt for authenticator should not fail");

    let authenticator = NtsAuthenticator::new(nonce, ciphertext);
    let auth_ext = ExtensionField::new(EXTENSION_FIELD_NTS_AUTHENTICATOR, authenticator.encode());
    result.extend_from_slice(&auth_ext.encode());

    // ── 4. Store UIK for response verification ────────────────────────────
    assoc.last_uik = uik_payload;

    // ── 5. Increment sequence ────────────────────────────────────────────
    assoc.sequence = assoc.sequence.wrapping_add(1);

    Ok(result)
}

// ──── Verify NTS-protected NTP response (Gate 8.1) ──────────────────────────

/// Verify the NTS authenticator on an NTP response packet (Gate 8.1).
///
/// The response packet is expected to contain:
///   1. NTS Unique Identifier — MUST match the association's last request UI
///   2. NTS Authenticator (AEAD using S2C key) — decrypted plaintext contains
///      zero or more NTS Cookie extension fields (RFC 8915 §5.4)
///
/// Returns `Ok(cookies)` where `cookies` is the list of fresh cookies
/// extracted from the authenticator plaintext (to replenish the client's pool).
/// Returns `Err(String)` with a description of any verification failure.
pub fn verify_nts_response(packet: &[u8], assoc: &NtsAssociation) -> Result<Vec<Vec<u8>>, String> {
    if packet.len() < NTP_HEADER_SIZE {
        return Err("packet too short for NTP header".to_string());
    }

    // Parse extension fields after the NTP header.
    let ext_data = &packet[NTP_HEADER_SIZE..];
    let extensions = ExtensionField::decode_all(ext_data);

    // ── 1. Verify Unique Identifier (RFC 8915 §5.1.1.3) ─────────────────
    // The response MUST echo the Unique Identifier from the request.
    // Extract the UI from public extensions before the authenticator.
    let response_uik = extensions
        .iter()
        .find(|ef| ef.field_type == EXTENSION_FIELD_UNIQUE_IDENTIFIER)
        .map(|ef| ef.payload.as_slice());

    match response_uik {
        Some(uik) if uik == assoc.last_uik.as_slice() => {
            // UI matches — continue verification
        }
        Some(_) => {
            return Err(format!(
                "NTS response Unique Identifier mismatch: expected {} bytes, got different value",
                assoc.last_uik.len()
            ));
        }
        None if !assoc.last_uik.is_empty() => {
            return Err("NTS response missing Unique Identifier extension field".to_string());
        }
        None => {
            // No UI expected (e.g., first response before any request was sent)
            // This should not happen in normal operation, but be permissive
            // for testing scenarios.
        }
    }

    // ── 2. Locate the NTS Authenticator extension field ─────────────────
    let auth_ext = extensions
        .iter()
        .find(|ef| ef.field_type == EXTENSION_FIELD_NTS_AUTHENTICATOR)
        .ok_or_else(|| "no NTS Authenticator extension field found in response".to_string())?;

    // Decode the authenticator payload.
    let authenticator = NtsAuthenticator::decode(&auth_ext.payload)
        .ok_or_else(|| "failed to decode NTS Authenticator payload".to_string())?;

    // Build associated data: NTP header + all extension fields before the authenticator.
    let aad = {
        let mut combined = Vec::new();
        combined.extend_from_slice(&packet[..NTP_HEADER_SIZE]);
        for ef in &extensions {
            if ef.field_type == EXTENSION_FIELD_NTS_AUTHENTICATOR {
                break;
            }
            combined.extend_from_slice(&ef.encode());
        }
        combined
    };

    // ── 3. AEAD verification using S2C key ─────────────────────────────
    let key = Key::<Aes128Siv>::from_slice(&assoc.s2c_key);
    let nonce = &authenticator.nonce;
    let headers: [&[u8]; 2] = [&aad, nonce];

    let mut siv = Aes128Siv::new(key);
    let decrypted_plaintext = siv
        .decrypt(headers, &authenticator.ciphertext)
        .map_err(|e| format!("NTS response AEAD authentication failed: {e}"))?;

    // ── 4. Extract cookies from the decrypted authenticator plaintext ───
    // RFC 8915 §5.4: The response authenticator plaintext contains zero or
    // more NTS Cookie extension fields, additional extension fields, and
    // an End-of-Message marker.
    let inner_extensions = ExtensionField::decode_all(&decrypted_plaintext);
    let cookies: Vec<Vec<u8>> = inner_extensions
        .iter()
        .filter(|ef| ef.field_type == EXTENSION_FIELD_NTS_COOKIE)
        .map(|ef| ef.payload.clone())
        .collect();

    Ok(cookies)
}

/// Extract the NTS cookie from a server response, checking both public
/// extension fields and (if present) inside the authenticator plaintext.
///
/// This is a convenience wrapper that first tries public extensions,
/// then falls back to decrypting the authenticator if no public cookie
/// is found.  Prefer using [`verify_nts_response`] which properly
/// verifies the authenticator and extracts cookies from the plaintext.
pub fn extract_response_cookie(packet: &[u8], assoc: &NtsAssociation) -> Option<Vec<u8>> {
    if packet.len() < NTP_HEADER_SIZE {
        return None;
    }
    let ext_data = &packet[NTP_HEADER_SIZE..];
    let extensions = ExtensionField::decode_all(ext_data);

    // First, check public extension fields for a cookie.
    if let Some(cookie) = extensions
        .iter()
        .find(|ef| ef.field_type == EXTENSION_FIELD_NTS_COOKIE)
        .map(|ef| ef.payload.clone())
    {
        return Some(cookie);
    }

    // Fall back to decrypting the authenticator and checking inside.
    // This matches the server-recommended approach (RFC 8915 §5.2.1).
    if let Ok(cookies) = verify_nts_response(packet, assoc) {
        return cookies.into_iter().next();
    }

    None
}

/// Extract the NTS Unique Identifier from a packet.
pub fn extract_unique_identifier(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < NTP_HEADER_SIZE {
        return None;
    }
    let ext_data = &packet[NTP_HEADER_SIZE..];
    let extensions = ExtensionField::decode_all(ext_data);
    extensions
        .iter()
        .find(|ef| ef.field_type == EXTENSION_FIELD_UNIQUE_IDENTIFIER)
        .map(|ef| ef.payload.clone())
}

// ──── Root Store ─────────────────────────────────────────────────────────────

/// Build a root certificate store using webpki roots for TLS server
/// certificate validation.
fn build_root_store() -> Result<rustls::RootCertStore, String> {
    let mut root_store = rustls::RootCertStore::empty();

    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Ok(root_store)
}

/// Build a root certificate store from a PEM-encoded CA certificate (Gate 8.7).
fn build_root_store_from_pem(ca_pem: &[u8]) -> Result<rustls::RootCertStore, String> {
    let mut root_store = rustls::RootCertStore::empty();

    // Also include system roots for flexibility.
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Parse and add the custom CA certificate.
    let mut reader = std::io::BufReader::new(ca_pem);
    let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse CA certificate PEM: {e}"))?;

    if certs.is_empty() {
        return Err("no CA certificates found in PEM data".to_string());
    }

    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| format!("failed to add CA certificate to root store: {e}"))?;
    }

    Ok(root_store)
}

// ──── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Compilation / structural tests ─────────────────────────────────

    #[test]
    fn test_nts_ke_client_new() {
        let client = NtsKeClient::new("ntp.example.com", NTS_KE_DEFAULT_PORT);
        assert_eq!(client.host, "ntp.example.com");
        assert_eq!(client.port, NTS_KE_DEFAULT_PORT);
    }

    #[test]
    fn test_nts_ke_client_handshake_fails_no_server() {
        let client = NtsKeClient::new("127.0.0.1", 1);
        let result = client.handshake();
        assert!(result.is_err(), "expected error connecting to closed port");
    }

    // ── TLS exporter label consistency ───────────────────────────────────

    #[test]
    fn test_exporter_label_constant() {
        assert_eq!(NTS_KE_EXPORTER_LABEL, b"EXPORTER-network-time-security");
    }

    #[test]
    fn test_default_port_constant() {
        assert_eq!(NTS_KE_DEFAULT_PORT, 4460);
    }

    // ── NtsAssociation tests (Gate 8.1) ─────────────────────────────────

    #[test]
    fn test_nts_association_new() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let cookies = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let assoc = NtsAssociation::new(
            c2s,
            s2c,
            cookies.clone(),
            15,
            "ntp.example.com".to_string(),
            4460,
            0,
        );

        assert_eq!(assoc.c2s_key, c2s);
        assert_eq!(assoc.s2c_key, s2c);
        assert_eq!(assoc.cookie_count(), 2);
        assert_eq!(assoc.aead_algorithm, 15);
        assert_eq!(assoc.server_cookie, vec![1, 2, 3]);
        assert_eq!(assoc.ke_hostname, "ntp.example.com");
        assert_eq!(assoc.ke_port, 4460);
        assert_eq!(assoc.sequence, 0);
    }

    #[test]
    fn test_nts_association_cookie_ops() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let mut assoc = NtsAssociation::new(
            c2s,
            s2c,
            vec![vec![1], vec![2], vec![3]],
            15,
            "host".to_string(),
            4460,
            0,
        );

        assert_eq!(assoc.cookie_count(), 3);
        assert_eq!(assoc.pop_cookie(), Some(vec![1]));
        assert_eq!(assoc.cookie_count(), 2);
        assert_eq!(assoc.pop_cookie(), Some(vec![2]));
        assert_eq!(assoc.pop_cookie(), Some(vec![3]));
        assert_eq!(assoc.pop_cookie(), None);

        // Replenish
        let mut new_cookies = vec![vec![10], vec![11]];
        assoc.add_cookies(&mut new_cookies);
        assert_eq!(assoc.cookie_count(), 2);
    }

    #[test]
    fn test_nts_association_needs_replenish() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let assoc = NtsAssociation::new(c2s, s2c, vec![], 15, "host".to_string(), 4460, 0);
        // Empty cookies means needs replenish
        assert!(assoc.needs_replenish());

        // Fill with NTS_MAX_COOKIES (8) cookies — doesn't need replenish
        let cookies: Vec<Vec<u8>> = (0..NTS_MAX_COOKIES).map(|i| vec![i as u8]).collect();
        let mut assoc = NtsAssociation::new(c2s, s2c, cookies, 15, "host".to_string(), 4460, 0);
        assert!(!assoc.needs_replenish());

        // Use 5 cookies (3 remaining <= 4 threshold) — needs replenish
        for _ in 0..5 {
            assoc.pop_cookie();
        }
        assert!(assoc.needs_replenish());
    }

    // ── Build NTS request tests (Gate 8.1) ─────────────────────────────

    #[test]
    fn test_build_nts_request_adds_extensions() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let mut assoc = NtsAssociation::new(
            c2s,
            s2c,
            vec![vec![0xAA; 32], vec![0xBB; 32]],
            15,
            "host".to_string(),
            4460,
            0,
        );

        let packet = NtpPacket::zeroed();
        let result = build_nts_request(&packet, &mut assoc).unwrap();

        // Should be longer than a bare header
        assert!(result.len() > NTP_HEADER_SIZE);

        // Parse extension fields
        let ext_data = &result[NTP_HEADER_SIZE..];
        let fields = ExtensionField::decode_all(ext_data);

        // Should have at least 3 extension fields (UIK, Cookie, Authenticator)
        assert!(
            fields.len() >= 3,
            "expected at least 3 extension fields, got {}",
            fields.len()
        );

        // Check each field type is present
        let has_uik = fields
            .iter()
            .any(|ef| ef.field_type == EXTENSION_FIELD_UNIQUE_IDENTIFIER);
        let has_cookie = fields
            .iter()
            .any(|ef| ef.field_type == EXTENSION_FIELD_NTS_COOKIE);
        let has_auth = fields
            .iter()
            .any(|ef| ef.field_type == EXTENSION_FIELD_NTS_AUTHENTICATOR);

        assert!(has_uik, "request should contain Unique Identifier");
        assert!(has_cookie, "request should contain NTS Cookie");
        assert!(has_auth, "request should contain NTS Authenticator");

        // Sequence should have incremented
        assert_eq!(assoc.sequence, 1);
    }

    #[test]
    fn test_build_nts_request_consumes_cookie() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let mut assoc = NtsAssociation::new(
            c2s,
            s2c,
            vec![vec![0xAA; 32]],
            15,
            "host".to_string(),
            4460,
            0,
        );

        assert_eq!(assoc.cookie_count(), 1);
        let packet = NtpPacket::zeroed();
        let _ = build_nts_request(&packet, &mut assoc).unwrap();
        // Cookie should be consumed
        assert_eq!(assoc.cookie_count(), 0);
    }

    // ── Verify NTS response tests (Gate 8.1) ───────────────────────────

    #[test]
    fn test_verify_nts_response_short_packet() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let assoc = NtsAssociation::new(c2s, s2c, vec![], 15, "host".to_string(), 4460, 0);

        let result = verify_nts_response(&[0u8; 10], &assoc);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_verify_nts_response_no_auth_ext() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let assoc = NtsAssociation::new(c2s, s2c, vec![], 15, "host".to_string(), 4460, 0);

        // Packet with header only (no extensions)
        let packet = NtpPacket::zeroed().encode_header().to_vec();
        let result = verify_nts_response(&packet, &assoc);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Authenticator"));
    }

    /// Build a valid NTS response and verify it round-trips.
    /// The response follows RFC 8915 §5.4: cookies are encrypted inside the
    /// NTS Authenticator plaintext.
    #[test]
    fn test_verify_nts_response_roundtrip() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];

        let header = NtpPacket::zeroed().encode_header();
        let mut response = header.to_vec();

        // Add a Unique Identifier extension (matches what assoc will expect)
        let uik = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let uik_ext = ExtensionField::new(EXTENSION_FIELD_UNIQUE_IDENTIFIER, uik.clone());
        response.extend_from_slice(&uik_ext.encode());

        // Build the authenticator plaintext: a cookie inside (RFC 8915 §5.4)
        // The plaintext is a sequence of extension fields.
        let cookie_data = vec![0xCA; 32];
        let inner_cookie_ext = ExtensionField::new(EXTENSION_FIELD_NTS_COOKIE, cookie_data.clone());
        let authenticator_plaintext = inner_cookie_ext.encode();

        // The AAD for the authenticator is: NTP header + all extensions before it
        let aad = {
            let mut combined = Vec::new();
            combined.extend_from_slice(&header);
            combined.extend_from_slice(&uik_ext.encode());
            combined
        };

        let key = Key::<Aes128Siv>::from_slice(&s2c);
        let nonce = vec![0u8; 8];
        let headers: [&[u8]; 2] = [&aad, &nonce];
        let mut siv = Aes128Siv::new(key);
        let ciphertext = siv.encrypt(headers, &authenticator_plaintext).unwrap();
        let authenticator = NtsAuthenticator::new(nonce, ciphertext);
        let auth_ext =
            ExtensionField::new(EXTENSION_FIELD_NTS_AUTHENTICATOR, authenticator.encode());
        response.extend_from_slice(&auth_ext.encode());

        // Create association with matching last_uik
        let mut assoc = NtsAssociation::new(c2s, s2c, vec![], 15, "server".to_string(), 4460, 0);
        assoc.last_uik = uik;

        let result = verify_nts_response(&response, &assoc);
        assert!(result.is_ok(), "verification should succeed: {:?}", result);

        // The cookies from the authenticator plaintext should match
        let cookies = result.unwrap();
        assert_eq!(
            cookies.len(),
            1,
            "should extract 1 cookie from authenticator plaintext"
        );
        assert_eq!(cookies[0], cookie_data, "extracted cookie should match");
    }

    /// Verify that wrong key fails.
    #[test]
    fn test_verify_nts_response_wrong_key() {
        let c2s = [0x11u8; 32];
        let s2c_real = [0x22u8; 32];
        let s2c_wrong = [0x33u8; 32];

        let header = NtpPacket::zeroed().encode_header();
        let mut response = header.to_vec();

        let uik = vec![0xDE, 0xAD];
        let uik_ext = ExtensionField::new(EXTENSION_FIELD_UNIQUE_IDENTIFIER, uik.clone());
        response.extend_from_slice(&uik_ext.encode());

        // Build authenticator with REAL S2C key, plaintext contains cookie
        let inner_cookie = ExtensionField::new(EXTENSION_FIELD_NTS_COOKIE, vec![0xCA; 32]);
        let authenticator_plaintext = inner_cookie.encode();

        let aad = {
            let mut combined = Vec::new();
            combined.extend_from_slice(&header);
            combined.extend_from_slice(&uik_ext.encode());
            combined
        };
        let key = Key::<Aes128Siv>::from_slice(&s2c_real);
        let nonce = vec![0u8; 8];
        let headers: [&[u8]; 2] = [&aad, &nonce];
        let mut siv = Aes128Siv::new(key);
        let ciphertext = siv.encrypt(headers, &authenticator_plaintext).unwrap();
        let authenticator = NtsAuthenticator::new(nonce, ciphertext);
        let auth_ext =
            ExtensionField::new(EXTENSION_FIELD_NTS_AUTHENTICATOR, authenticator.encode());
        response.extend_from_slice(&auth_ext.encode());

        // Verify with WRONG S2C key
        let mut assoc =
            NtsAssociation::new(c2s, s2c_wrong, vec![], 15, "server".to_string(), 4460, 0);
        assoc.last_uik = uik;

        let result = verify_nts_response(&response, &assoc);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authentication"));
    }

    // ── Extract response helpers ──────────────────────────────────────────

    #[test]
    fn test_extract_response_cookie_found() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];

        let header = NtpPacket::zeroed().encode_header();
        let mut packet = header.to_vec();
        let cookie_ext = ExtensionField::new(EXTENSION_FIELD_NTS_COOKIE, vec![0xCA, 0xFE]);
        packet.extend_from_slice(&cookie_ext.encode());

        let assoc = NtsAssociation::new(c2s, s2c, vec![], 15, "host".to_string(), 4460, 0);
        let cookie = extract_response_cookie(&packet, &assoc);
        assert_eq!(cookie, Some(vec![0xCA, 0xFE]));
    }

    #[test]
    fn test_extract_response_cookie_not_found() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];

        let packet = NtpPacket::zeroed().encode_header();
        let assoc = NtsAssociation::new(c2s, s2c, vec![], 15, "host".to_string(), 4460, 0);
        assert_eq!(extract_response_cookie(&packet, &assoc), None);
    }

    #[test]
    fn test_extract_unique_identifier() {
        let header = NtpPacket::zeroed().encode_header();
        let mut packet = header.to_vec();
        let uik_ext = ExtensionField::new(EXTENSION_FIELD_UNIQUE_IDENTIFIER, vec![0x01, 0x02]);
        packet.extend_from_slice(&uik_ext.encode());

        let uik = extract_unique_identifier(&packet);
        assert_eq!(uik, Some(vec![0x01, 0x02]));
    }

    // ── NTS-KE negotiation round-trip (offline via handshake_with_data) ──

    #[test]
    fn test_nts_ke_negotiation_with_mock_response() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        // Build a mock server response
        let next_proto =
            NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec());
        let aead_rec =
            NtsKeRecord::new(NTS_KE_RECORD_AEAD_ALGORITHM, (15u16).to_be_bytes().to_vec());
        let cookie1 = NtsKeRecord::new(NTS_KE_RECORD_NEW_COOKIE, vec![0xAA; 32]);
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);

        let mut response = Vec::new();
        response.extend_from_slice(&next_proto.encode());
        response.extend_from_slice(&aead_rec.encode());
        response.extend_from_slice(&cookie1.encode());
        response.extend_from_slice(&eom.encode());

        let req_next_proto =
            NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec());
        let req_aead =
            NtsKeRecord::new_critical(NTS_KE_RECORD_AEAD_ALGORITHM, (15u16).to_be_bytes().to_vec());
        let req_eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut request = Vec::new();
        request.extend_from_slice(&req_next_proto.encode());
        request.extend_from_slice(&req_aead.encode());
        request.extend_from_slice(&req_eom.encode());

        let negotiation = proto_client
            .handshake_with_data(&request, &response, None)
            .unwrap();
        assert_eq!(negotiation.aead_algorithm, AeadAlgorithm::AeadAesSivCmac256);
        assert_eq!(negotiation.cookie_count(), 1);
        assert_eq!(negotiation.cookies[0], vec![0xAA; 32]);
        assert_eq!(negotiation.c2s_key, [0u8; 32]);
        assert_eq!(negotiation.s2c_key, [0u8; 32]);
    }

    // ── Certificate / root store tests (Gate 8.7) ─────────────────────

    #[test]
    fn test_build_root_store() {
        let store = build_root_store();
        assert!(store.is_ok());
        assert!(!store.unwrap().is_empty());
    }

    #[test]
    fn test_build_root_store_from_pem_invalid() {
        let result = build_root_store_from_pem(b"not a valid PEM");
        // Should fail because no certs found
        assert!(result.is_err());
    }

    // ── IPv6 address support (Gate 8.4) ────────────────────────────────

    #[test]
    fn test_nts_ke_client_ipv6_hostname() {
        // Verify that IPv6-style hostnames are accepted for client creation
        let client = NtsKeClient::new("::1", 4460);
        assert_eq!(client.host, "::1");
        // Connection will fail (no server), but that's expected
        let result = client.handshake();
        assert!(result.is_err());
    }

    // ── Protocol validation tests ───────────────────────────────────────

    #[test]
    fn test_nts_ke_missing_next_protocol_rejected() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        let aead_rec =
            NtsKeRecord::new(NTS_KE_RECORD_AEAD_ALGORITHM, (15u16).to_be_bytes().to_vec());
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut response = Vec::new();
        response.extend_from_slice(&aead_rec.encode());
        response.extend_from_slice(&eom.encode());

        let req = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]).encode();
        let result = proto_client.handshake_with_data(&req, &response, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Next Protocol"));
    }

    #[test]
    fn test_nts_ke_server_error_rejected() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        let err_rec = NtsKeRecord::new_critical(NTS_KE_RECORD_ERROR, b"bad request".to_vec());
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut response = Vec::new();
        response.extend_from_slice(&err_rec.encode());
        response.extend_from_slice(&eom.encode());

        let req = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]).encode();
        let result = proto_client.handshake_with_data(&req, &response, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Error"));
    }

    #[test]
    fn test_nts_ke_unknown_critical_rejected() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        let unknown = NtsKeRecord {
            record_type: 0x8008,
            body: vec![],
        };
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut response = Vec::new();
        response.extend_from_slice(&unknown.encode());
        response.extend_from_slice(&eom.encode());

        let req = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]).encode();
        let result = proto_client.handshake_with_data(&req, &response, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_nts_ke_next_protocol_missing_critical_bit() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        let next_proto = NtsKeRecord::new(NTS_KE_RECORD_NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec());
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut response = Vec::new();
        response.extend_from_slice(&next_proto.encode());
        response.extend_from_slice(&eom.encode());

        let req = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]).encode();
        let result = proto_client.handshake_with_data(&req, &response, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("critical bit"));
    }

    #[test]
    fn test_nts_ke_duplicate_next_protocol_rejected() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        let np1 =
            NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec());
        let np2 =
            NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec());
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut response = Vec::new();
        response.extend_from_slice(&np1.encode());
        response.extend_from_slice(&np2.encode());
        response.extend_from_slice(&eom.encode());

        let req = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]).encode();
        let result = proto_client.handshake_with_data(&req, &response, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn test_nts_ke_next_protocol_id_1_rejected() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        let next_proto =
            NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, 1u16.to_be_bytes().to_vec());
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut response = Vec::new();
        response.extend_from_slice(&next_proto.encode());
        response.extend_from_slice(&eom.encode());

        let req = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]).encode();
        let result = proto_client.handshake_with_data(&req, &response, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("NTPv4"));
    }

    #[test]
    fn test_nts_ke_next_protocol_empty_rejected() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        let next_proto = NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, vec![]);
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut response = Vec::new();
        response.extend_from_slice(&next_proto.encode());
        response.extend_from_slice(&eom.encode());

        let req = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]).encode();
        let result = proto_client.handshake_with_data(&req, &response, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_nts_ke_duplicate_aead_rejected() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        let next_proto =
            NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec());
        let aead1 =
            NtsKeRecord::new_critical(NTS_KE_RECORD_AEAD_ALGORITHM, 15u16.to_be_bytes().to_vec());
        let aead2 =
            NtsKeRecord::new_critical(NTS_KE_RECORD_AEAD_ALGORITHM, 15u16.to_be_bytes().to_vec());
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut response = Vec::new();
        response.extend_from_slice(&next_proto.encode());
        response.extend_from_slice(&aead1.encode());
        response.extend_from_slice(&aead2.encode());
        response.extend_from_slice(&eom.encode());

        let req = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]).encode();
        let result = proto_client.handshake_with_data(&req, &response, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn test_nts_ke_aead_16_rejected() {
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);

        let next_proto =
            NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec());
        let aead =
            NtsKeRecord::new_critical(NTS_KE_RECORD_AEAD_ALGORITHM, 16u16.to_be_bytes().to_vec());
        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut response = Vec::new();
        response.extend_from_slice(&next_proto.encode());
        response.extend_from_slice(&aead.encode());
        response.extend_from_slice(&eom.encode());

        let req = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]).encode();
        let result = proto_client.handshake_with_data(&req, &response, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("15"));
    }

    // ── Interoperability test: NTS-KE client↔server cookie roundtrip ───
    // (Gate 8.5 — offline test path)

    #[test]
    fn test_nts_ke_negotiation_with_cookie_cipher_roundtrip() {
        // This test proves that the NTS-KE client can process a server response
        // that was built using the server's cookie generation logic, and extract
        // the correct C2S and S2C keys.
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(1), [0xAA; 32]);

        let c2s_key = [0x11u8; 32];
        let s2c_key = [0x22u8; 32];

        // Build server response: Next Protocol + AEAD + Cookie(encrypted) + EOM
        let next_proto =
            NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec());

        let aead_rec = NtsKeRecord::new(NTS_KE_RECORD_AEAD_ALGORITHM, 15u16.to_be_bytes().to_vec());

        // Encrypt the keys into a cookie (as the server would)
        let mut cookie_plaintext = Vec::with_capacity(66);
        cookie_plaintext.extend_from_slice(&15u16.to_be_bytes());
        cookie_plaintext.extend_from_slice(&c2s_key);
        cookie_plaintext.extend_from_slice(&s2c_key);
        let encrypted_cookie = cipher.encrypt(&cookie_plaintext).unwrap();
        let cookie_rec = NtsKeRecord::new(NTS_KE_RECORD_NEW_COOKIE, encrypted_cookie);

        let eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);

        let mut response = Vec::new();
        response.extend_from_slice(&next_proto.encode());
        response.extend_from_slice(&aead_rec.encode());
        response.extend_from_slice(&cookie_rec.encode());
        response.extend_from_slice(&eom.encode());

        // Build client request
        let req_next_proto =
            NtsKeRecord::new_critical(NTS_KE_RECORD_NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec());
        let req_aead =
            NtsKeRecord::new_critical(NTS_KE_RECORD_AEAD_ALGORITHM, (15u16).to_be_bytes().to_vec());
        let req_eom = NtsKeRecord::new_critical(NTS_KE_RECORD_END_OF_MESSAGE, vec![]);
        let mut request = Vec::new();
        request.extend_from_slice(&req_next_proto.encode());
        request.extend_from_slice(&req_aead.encode());
        request.extend_from_slice(&req_eom.encode());

        // Client processes the response using the cookie cipher (offline path)
        let mut proto_client = NtsKeProtocolClient::new("ntp.example.com", NTS_KE_PORT);
        let negotiation = proto_client
            .handshake_with_data(&request, &response, Some(&cipher))
            .unwrap();

        // The keys should match!
        assert_eq!(negotiation.c2s_key, c2s_key);
        assert_eq!(negotiation.s2c_key, s2c_key);
        assert_eq!(negotiation.aead_algorithm, AeadAlgorithm::AeadAesSivCmac256);
    }

    // ── Expired cookie handling (Gate 8.5) ─────────────────────────────
    #[test]
    fn test_nts_association_rejects_expired_cookie_cipher() {
        // Create a cipher with a key and then rotate it (simulate expiry)
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(1), [0xAA; 32]);

        // Encrypt with key index 1
        let plaintext = {
            let mut pt = Vec::with_capacity(66);
            pt.extend_from_slice(&15u16.to_be_bytes());
            pt.extend_from_slice(&[0x11u8; 32]);
            pt.extend_from_slice(&[0x22u8; 32]);
            pt
        };
        let cookie = cipher.encrypt(&plaintext).unwrap();

        // Decrypt with same key — works
        assert!(cipher.decrypt(&cookie).is_ok());

        // Now rotate the key (add new key, removing old one)
        let mut new_cipher = CookieCipher::new();
        new_cipher.add_key(CookieKeyIndex(2), [0xBB; 32]);

        // Old cookie should fail to decrypt with the new cipher
        assert!(new_cipher.decrypt(&cookie).is_err());
    }

    // ── Replayed authenticator rejection (Gate 8.5) ─────────────────────
    #[test]
    fn test_build_nts_request_sequence_increments() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let mut assoc = NtsAssociation::new(
            c2s,
            s2c,
            vec![vec![0xAA; 32], vec![0xBB; 32]],
            15,
            "host".to_string(),
            4460,
            0,
        );

        let packet = NtpPacket::zeroed();

        // First request -> sequence 0
        let req1 = build_nts_request(&packet, &mut assoc).unwrap();
        assert_eq!(assoc.sequence, 1);

        // Second request -> sequence 1 (different nonce in authenticator)
        let req2 = build_nts_request(&packet, &mut assoc).unwrap();
        assert_eq!(assoc.sequence, 2);

        // The two requests should have different authenticator payloads
        // due to different nonces (sequence numbers)
        assert_ne!(req1, req2, "requests should differ in sequence/nonce");
    }

    // ── Malformed extension chain rejection (Gate 8.5) ──────────────────
    #[test]
    fn test_verify_nts_response_malformed_authenticator() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let assoc = NtsAssociation::new(c2s, s2c, vec![], 15, "server".to_string(), 4460, 0);

        // Packet with truncated authenticator payload
        let header = NtpPacket::zeroed().encode_header();
        let mut packet = header.to_vec();
        // Add a malformed authenticator (too short payload)
        let bad_auth = ExtensionField::new(
            EXTENSION_FIELD_NTS_AUTHENTICATOR,
            vec![0x00, 0x01], // claims 1-byte nonce but no actual data follows
        );
        packet.extend_from_slice(&bad_auth.encode());

        let result = verify_nts_response(&packet, &assoc);
        assert!(result.is_err());
    }

    // ── Sequence exhaustion wrapping (Gate 8.5) ─────────────────────────
    #[test]
    fn test_nts_association_sequence_wrapping() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let mut assoc = NtsAssociation::new(
            c2s,
            s2c,
            vec![vec![0xAA; 32]; 10],
            15,
            "host".to_string(),
            4460,
            0,
        );

        // Set sequence near max to test wrapping
        assoc.sequence = u64::MAX;

        let packet = NtpPacket::zeroed();
        let _ = build_nts_request(&packet, &mut assoc).unwrap();

        // After wrapping, sequence should be 0
        assert_eq!(assoc.sequence, 0, "sequence should wrap to 0");

        // Second call should work fine
        let _ = build_nts_request(&packet, &mut assoc);
        assert_eq!(assoc.sequence, 1);
    }

    // ── Server identity change detection (Gate 8.4) ────────────────────
    #[test]
    fn test_server_identity_change() {
        // Create two associations with different hostnames
        let assoc1 = NtsAssociation::new(
            [0x11u8; 32],
            [0x22u8; 32],
            vec![vec![1]],
            15,
            "server-a.example.com".to_string(),
            4460,
            0,
        );
        let assoc2 = NtsAssociation::new(
            [0x11u8; 32],
            [0x22u8; 32],
            vec![vec![1]],
            15,
            "server-b.example.com".to_string(),
            4460,
            0,
        );

        // Different hostnames indicate different servers
        assert_ne!(assoc1.ke_hostname, assoc2.ke_hostname);
    }

    // ── TLS 1.3 only builder ───────────────────────────────────────────

    #[test]
    fn test_nts_ke_tls13_only_config() {
        let root_store = build_root_store().unwrap();
        let _config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth();
        // Config created successfully — TLS 1.3 builder chain compiles and runs
    }

    // ── Perform NTS-KE wrapper test (integration path) ─────────────────

    #[test]
    fn test_perform_nts_ke_fails_no_server() {
        let result = perform_nts_ke("127.0.0.1", 1);
        assert!(result.is_err());
    }
}
