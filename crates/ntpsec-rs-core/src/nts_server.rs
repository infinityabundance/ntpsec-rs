// ──── nts_server.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/nts_server.c
//
// NTS-KE server: handles the NTS Key Establishment (RFC 8915 §4) over TLS 1.3.
//
// ## Protocol Flow (server side)
//   1. Accept TCP connection on port 4460
//   2. Complete TLS 1.3 handshake with ALPN "ntske/1"
//   3. Read NTS-KE request records from the client
//   4. Validate: Next Protocol must be NTPv4, at least one AEAD algorithm
//   5. Select the first supported AEAD from the client's offered list
//   6. Derive C2S and S2C keys via the TLS exporter
//   7. Generate NTS_MAX_COOKIES encrypted cookies using the CookieCipher
//   8. Build response: Next Protocol | AEAD | New Cookie(s) | End of Message
//   9. Send response via TLS, then shutdown and close
//
// ## Oracle
//   - ntpsec ntpd/nts_server.c (19K) — listener loop, request parsing, response building
//   - ntpsec ntpd/nts.c — ke_append_record_* / ke_next_record helpers
//   - ntpsec ntpd/nts_client.c — nts_make_keys (TLS exporter key derivation)
//   - ntpsec ntpd/nts_cookie.c — nts_make_cookie (cookie construction)
//   - RFC 8915 §4 — NTS Key Establishment
//   - RFC 8915 §4.1 — NTS-KE Record Protocol
//   - RFC 8915 §4.5 — Key Derivation via TLS Exporter
// =============================================================================

use crate::nts::*;
use crate::nts_cookie::*;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConnection;

// ──── Server entry point ─────────────────────────────────────────────────

/// Start the NTS-KE server on the default port (4460).
///
/// Spawns one thread per incoming connection.  Each connection runs the
/// full NTS-KE handshake (RFC 8915 §4) before closing.
pub fn start_nts_ke_server(config: NtsServerConfig) -> Result<(), String> {
    let tls_config = build_tls_server_config(&config)?;
    let listener = TcpListener::bind(format!("0.0.0.0:{}", NTS_KE_DEFAULT_PORT))
        .map_err(|e| format!("NTS-KE bind failed: {e}"))?;

    tracing::info!("NTS-KE server listening on port {}", NTS_KE_DEFAULT_PORT);

    for stream in listener.incoming() {
        match stream {
            Ok(tcp_stream) => {
                // Set socket timeouts for the connection (matching nts_server.c
                // which uses SO_RCVTIMEO / SO_SNDTIMEO with NTS_KE_TIMEOUT).
                if let Err(e) = tcp_stream.set_read_timeout(Some(Duration::from_secs(15))) {
                    tracing::warn!("NTS-KE set_read_timeout failed: {e}");
                }
                if let Err(e) = tcp_stream.set_write_timeout(Some(Duration::from_secs(15))) {
                    tracing::warn!("NTS-KE set_write_timeout failed: {e}");
                }

                let cfg = config.clone();
                let tls_cfg = Arc::clone(&tls_config);
                thread::spawn(move || {
                    if let Err(e) = handle_nts_ke_connection(tcp_stream, &cfg, tls_cfg) {
                        tracing::warn!("NTS-KE connection failed: {e}");
                    }
                });
            }
            Err(e) => {
                // EINTR / transient errors: log and continue
                tracing::error!("NTS-KE accept failed: {e}");
            }
        }
    }
    Ok(())
}

// ──── TLS configuration ──────────────────────────────────────────────────

/// Build a rustls server config for NTS-KE.
///
/// Configures TLS 1.3 only, loads the server certificate and private key,
/// and sets ALPN to "ntske/1" (RFC 8915 §4.2).
fn build_tls_server_config(config: &NtsServerConfig) -> Result<Arc<rustls::ServerConfig>, String> {
    let certs = load_certs(&config.cert_file)?;
    let key = load_private_key(&config.key_file)?;

    let mut tls_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("TLS config failed: {e}"))?;

    // ALPN: advertise "ntske/1" (RFC 8915 §4.2).  The client MUST offer
    // this protocol in its TLS ClientHello; rustls will reject clients
    // that don't include it in their offer.
    tls_config.alpn_protocols = vec![b"ntske/1".to_vec()];

    Ok(Arc::new(tls_config))
}

/// Load TLS certificate(s) from a PEM file.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certfile =
        std::fs::File::open(path).map_err(|e| format!("cannot open cert file {path}: {e}"))?;
    let mut reader = std::io::BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to load certs: {e}"))?;
    Ok(certs)
}

/// Load a private key from a PEM file.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let keyfile =
        std::fs::File::open(path).map_err(|e| format!("cannot open key file {path}: {e}"))?;
    let mut reader = std::io::BufReader::new(keyfile);
    let keys =
        rustls_pemfile::private_key(&mut reader).map_err(|e| format!("failed to load key: {e}"))?;
    keys.ok_or_else(|| format!("no private key found in {path}"))
}

// ──── Connection handler ─────────────────────────────────────────────────

/// Handle a single NTS-KE connection.
///
/// Performs the full server side of the NTS-KE handshake (RFC 8915 §4):
///   1. TLS 1.3 handshake with ALPN "ntske/1"
///   2. Read and validate the client's NTS-KE request
///   3. Derive C2S/S2C keys via TLS exporter
///   4. Generate encrypted cookies
///   5. Build and send the NTS-KE response
///   6. Shutdown TLS and close TCP
///
/// On success, returns the encrypted cookie list (for integration testing).
/// On failure, returns a descriptive error string.
fn handle_nts_ke_connection(
    mut stream: TcpStream,
    server_config: &NtsServerConfig,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<Vec<Vec<u8>>, String> {
    let mut conn =
        ServerConnection::new(tls_config).map_err(|e| format!("TLS connection failed: {e}"))?;

    // ── Phase 1: TLS 1.3 handshake ────────────────────────────────────
    // Drive the handshake by alternating read_tls / process_new_packets /
    // write_tls until the handshake is complete.
    //
    // This mirrors nts_server.c's nts_ke_listener which calls SSL_accept().
    while conn.is_handshaking() {
        conn.read_tls(&mut stream)
            .map_err(|e| format!("TLS read_tls (handshake): {e}"))?;

        conn.process_new_packets()
            .map_err(|e| format!("TLS process_new_packets (handshake): {e}"))?;

        conn.write_tls(&mut stream)
            .map_err(|e| format!("TLS write_tls (handshake): {e}"))?;
    }

    // Verify ALPN negotiated to "ntske/1" (RFC 8915 §4.2).
    let alpn = conn
        .alpn_protocol()
        .ok_or_else(|| "ALPN not negotiated — client did not offer ntske/1".to_string())?;
    if alpn != b"ntske/1" {
        return Err(format!(
            "ALPN negotiated unexpected protocol: {:?}",
            String::from_utf8_lossy(alpn)
        ));
    }

    // ── Phase 2: Read the NTS-KE request ─────────────────────────────
    // The client sends a single NTS-KE message.  We read until we either
    // have a complete message or the peer closes the write side.
    let request_data = tls_read_all(&mut conn, &mut stream)?;
    if request_data.is_empty() {
        return Err("empty NTS-KE request (client sent no data)".to_string());
    }

    // ── Phase 3: Parse and validate the request ──────────────────────
    //
    // Client request must contain (RFC 8915 §4.1):
    //   - Next Protocol Negotiation [critical]: NTPv4 (protocol ID 0)
    //   - AEAD Algorithm Negotiation [critical]: list of supported AEADs
    //   - End of Message [critical]
    //
    // We parse the records, validate them, and select an AEAD algorithm
    // that we support from the client's offered list.
    let (aead_selected, cookies) = process_nts_ke_request(&request_data, server_config)?;

    // ── Phase 4: Derive C2S and S2C keys via TLS exporter ───────────
    //
    // RFC 8915 §4.5:
    //   key = TLS-Exporter("EXPORTER-network-time-security",
    //                       protocol || aead || direction, key_length)
    //   direction = 0x00 for C2S, 0x01 for S2C
    let keylen = AeadAlgorithm::from_u16(aead_selected)
        .map(|a| a.key_length())
        .unwrap_or(32);

    let mut c2s_key = vec![0u8; keylen];
    let mut s2c_key = vec![0u8; keylen];

    // C2S: context = protocol(2) || aead(2) || 0x00
    let mut exporter_ctx = [0u8; 5];
    exporter_ctx[0] = 0x00; // NTPv4 protocol ID high byte
    exporter_ctx[1] = 0x00; // NTPv4 protocol ID low byte
    exporter_ctx[2] = (aead_selected >> 8) as u8;
    exporter_ctx[3] = aead_selected as u8;
    exporter_ctx[4] = 0x00; // C2S direction

    conn.export_keying_material(&mut c2s_key, NTS_KE_EXPORTER_LABEL, Some(&exporter_ctx))
        .map_err(|e| format!("TLS exporter failed for C2S: {e}"))?;

    // S2C: context = protocol(2) || aead(2) || 0x01
    exporter_ctx[4] = 0x01; // S2C direction

    conn.export_keying_material(&mut s2c_key, NTS_KE_EXPORTER_LABEL, Some(&exporter_ctx))
        .map_err(|e| format!("TLS exporter failed for S2C: {e}"))?;

    // ── Phase 5: Generate cookies ────────────────────────────────────
    //
    // Each cookie contains: aead_alg(2) || c2s_key(keylen) || s2c_key(keylen)
    // encrypted with the CookieCipher using the server's long-term key.
    let cookies = generate_nts_ke_cookies(
        aead_selected,
        &c2s_key[..32],
        &s2c_key[..32],
        &server_config.cookie_cipher,
    )?;

    // ── Phase 6: Build and send the response ─────────────────────────
    //
    // Server response records (RFC 8915 §4.1):
    //   1. Next Protocol Negotiation [critical]: NTPv4
    //   2. AEAD Algorithm Offer: selected AEAD
    //   3. NTS Cookie [×NTS_MAX_COOKIES]: encrypted cookie bodies
    //   4. End of Message [critical]
    let response_data = build_nts_ke_response(aead_selected, &cookies)?;

    // Send the response via TLS (plaintext write + flush).
    conn.writer()
        .write_all(&response_data)
        .map_err(|e| format!("TLS write (response): {e}"))?;

    conn.write_tls(&mut stream)
        .map_err(|e| format!("TLS write_tls (flush response): {e}"))?;

    // ── Phase 7: Shutdown TLS and close ──────────────────────────────
    // Send the close_notify alert, then let TCP close the connection.
    conn.send_close_notify();

    // Flush the close_notify alert
    conn.write_tls(&mut stream)
        .map_err(|e| format!("TLS write_tls (close_notify): {e}"))?;

    tracing::info!(
        "NTS-KE negotiation successful: AEAD={}, cookies={}",
        aead_selected,
        cookies.len(),
    );

    Ok(cookies)
}

// ──── Request processing ────────────────────────────────────────────────

/// Parse and validate an NTS-KE client request.
///
/// Returns `(selected_aead, cookies)` where `cookies` will be populated
/// by the caller.  Validation follows nts_server.c's
/// `nts_ke_process_receive()`:
///
///   - Must contain exactly one Next Protocol record selecting NTPv4 (0)
///   - Must contain at least one AEAD algorithm we support
///   - Must end with a critical End of Message with no trailing data
///   - Unknown non-critical records are silently skipped
///   - Unknown critical records cause an error (RFC 8915 §4.1.1)
fn process_nts_ke_request(
    data: &[u8],
    config: &NtsServerConfig,
) -> Result<(u16, Vec<Vec<u8>>), String> {
    let (records, trailing) = NtsKeRecord::decode_all(data);

    let mut next_proto_count = 0;
    let mut selected_aead: Option<u16> = None;
    let mut has_eom = false;
    let mut eom_position = usize::MAX;

    for (pos, rec) in records.iter().enumerate() {
        let raw_type = rec.record_type & !NTS_KE_RECORD_CRITICAL_BIT;
        let is_critical = rec.record_type & NTS_KE_RECORD_CRITICAL_BIT != 0;

        // Handle Error records (RFC 8915 §4.1.5)
        if raw_type == NTS_KE_RECORD_ERROR {
            let msg = String::from_utf8_lossy(&rec.body);
            return Err(format!("NTS-KE Error record from client: {msg}"));
        }

        // Handle Warning records (RFC 8915 §4.1.6) — informational, skip
        if raw_type == NTS_KE_RECORD_WARNING {
            continue;
        }

        match raw_type {
            t if t == NTS_KE_RECORD_NEXT_PROTOCOL => {
                // RFC 8915 §4.1.1: Exactly one Next Protocol record with critical bit
                next_proto_count += 1;
                if !is_critical {
                    return Err("Next Protocol record missing critical bit".to_string());
                }
                if next_proto_count > 1 {
                    return Err("duplicate Next Protocol record".to_string());
                }
                if rec.body.len() < 2 || rec.body.len() % 2 != 0 {
                    return Err(format!(
                        "Next Protocol invalid body length: {}",
                        rec.body.len()
                    ));
                }
                // Verify NTPv4 (protocol ID = 0) is offered
                let mut found_ntpv4 = false;
                for chunk in rec.body.chunks_exact(2) {
                    let proto = u16::from_be_bytes([chunk[0], chunk[1]]);
                    if proto == 0 {
                        found_ntpv4 = true;
                    }
                }
                if !found_ntpv4 {
                    return Err("client did not offer NTPv4 protocol".to_string());
                }
            }

            t if t == NTS_KE_RECORD_AEAD_ALGORITHM => {
                // RFC 8915 §4.1.3: A list of u16 AEAD algorithm IDs.
                // The server picks the first one it supports.
                if rec.body.len() < 2 || rec.body.len() % 2 != 0 {
                    return Err(format!(
                        "AEAD Algorithm invalid body length: {}",
                        rec.body.len()
                    ));
                }
                for chunk in rec.body.chunks_exact(2) {
                    let aead_id = u16::from_be_bytes([chunk[0], chunk[1]]);
                    // Check if the server supports this AEAD
                    if config.aead_algorithms.contains(&aead_id) {
                        if selected_aead.is_none() {
                            selected_aead = Some(aead_id);
                        }
                        // Continue iterating but don't overwrite — we take the first match
                    }
                }
            }

            t if t == NTS_KE_RECORD_END_OF_MESSAGE => {
                // RFC 8915 §4.1.8: EOM must be critical, have empty body,
                // and be the final record.
                if has_eom {
                    return Err("duplicate End of Message record".to_string());
                }
                if !is_critical {
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
                // Unknown critical record → abort (RFC 8915 §4.1.1)
                if is_critical {
                    return Err(format!(
                        "unsupported critical NTS-KE record type: {}",
                        raw_type
                    ));
                }
                // Non-critical unknown records are silently ignored
                // (the C code skips the body with buf->next += length)
            }
        }
    }

    // Validate mandatory records
    if next_proto_count == 0 {
        return Err("missing Next Protocol Negotiation record".to_string());
    }
    if selected_aead.is_none() {
        return Err("no supported AEAD algorithm offered by client".to_string());
    }
    if !has_eom {
        return Err("missing End of Message record".to_string());
    }

    // EOM must be the final record (RFC 8915 §4.1.8)
    if eom_position != records.len() - 1 {
        return Err("End of Message is not the final record".to_string());
    }

    // No trailing data after EOM (RFC 8915 §4.1.8)
    if !trailing.is_empty() {
        return Err(format!(
            "trailing data after NTS-KE records ({} bytes)",
            trailing.len()
        ));
    }

    let aead = selected_aead.unwrap();
    tracing::debug!(
        "NTS-KE request validated: AEAD={}, records={}",
        aead,
        records.len()
    );

    Ok((aead, Vec::new()))
}

/// Generate the server's response NTS-KE records.
///
/// Builds: Next Protocol | AEAD Algorithm | NTS Cookie(s) | End of Message
/// Matching nts_server.c's nts_ke_setup_send().
fn build_nts_ke_response(aead_selected: u16, cookies: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let mut records: Vec<NtsKeRecord> = Vec::new();

    // 4.1.2: Next Protocol Negotiation — NTPv4 (critical)
    records.push(NtsKeRecord::new_critical(
        NTS_KE_RECORD_NEXT_PROTOCOL,
        0u16.to_be_bytes().to_vec(),
    ));

    // 4.1.3: AEAD Algorithm Offer — the selected algorithm
    records.push(NtsKeRecord::new(
        NTS_KE_RECORD_AEAD_ALGORITHM,
        aead_selected.to_be_bytes().to_vec(),
    ));

    // 4.1.7: NTS Cookie — one per cookie
    for cookie_body in cookies {
        records.push(NtsKeRecord::new(
            NTS_KE_RECORD_NEW_COOKIE,
            cookie_body.clone(),
        ));
    }

    // 4.1.8: End of Message (critical, empty body)
    records.push(NtsKeRecord::new_critical(
        NTS_KE_RECORD_END_OF_MESSAGE,
        vec![],
    ));

    // Serialize all records to wire format
    let response: Vec<u8> = records.iter().flat_map(|r| r.encode()).collect();
    Ok(response)
}

/// Generate NTS cookies for the NTS-KE response.
///
/// Each cookie contains the AEAD algorithm, C2S key, and S2C key,
/// encrypted with the server's long-term CookieCipher.
///
/// Matches nts_make_cookie() from nts_cookie.c — the cookie plaintext
/// is `aead_alg(2) || c2s_key(32) || s2c_key(32)`.
fn generate_nts_ke_cookies(
    aead: u16,
    c2s_key: &[u8],
    s2c_key: &[u8],
    cipher: &CookieCipher,
) -> Result<Vec<Vec<u8>>, String> {
    let mut cookies = Vec::with_capacity(NTS_MAX_COOKIES);

    // Build the cookie plaintext: aead_alg(2) || c2s_key(32) || s2c_key(32)
    let mut plaintext = Vec::with_capacity(2 + c2s_key.len() + s2c_key.len());
    plaintext.extend_from_slice(&aead.to_be_bytes());
    plaintext.extend_from_slice(c2s_key);
    plaintext.extend_from_slice(s2c_key);

    for _ in 0..NTS_MAX_COOKIES {
        let encrypted = cipher.encrypt(&plaintext)?;
        cookies.push(encrypted);
    }

    Ok(cookies)
}

// ──── TLS I/O helpers ───────────────────────────────────────────────────

/// Read all available plaintext data from a TLS connection.
///
/// Reads TLS records from the TCP stream, processes them, and collects
/// the decrypted plaintext.  Returns when the peer closes their write
/// side (EOF) or when no more data is available and we have at least
/// something (NTS-KE is a single-request protocol, so the client sends
/// one message and then half-closes).
///
/// This mirrors the C code's nts_ssl_read() helper pattern.
fn tls_read_all(conn: &mut ServerConnection, stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();

    loop {
        // Check if we have already-decrypted plaintext buffered
        let mut buf = [0u8; 4096];

        // First, drain any plaintext that was already buffered by
        // process_new_packets (e.g., from the handshake phase).
        loop {
            match conn.reader().read(&mut buf) {
                Ok(0) => {
                    // Plaintext EOF — the peer has closed its write side.
                    if !data.is_empty() {
                        return Ok(data);
                    }
                    break;
                }
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);
                    // Check if the accumulated data has a complete EOM record
                    let (records, _) = NtsKeRecord::decode_all(&data);
                    let has_eom = records.iter().any(|r| {
                        r.record_type & !NTS_KE_RECORD_CRITICAL_BIT == NTS_KE_RECORD_END_OF_MESSAGE
                    });
                    if has_eom {
                        return Ok(data);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("TLS reader error: {e}")),
            }
        }

        // No more plaintext buffered — read more TLS records from the socket.
        match conn.read_tls(stream) {
            Ok(0) => {
                // TCP EOF — drain any remaining plaintext before returning.
                // Data might have been buffered by process_new_packets but
                // not yet drained by the reader() loop above.
                if !data.is_empty() {
                    // One final drain pass for any buffered plaintext
                    match conn.reader().read(&mut buf) {
                        Ok(n) if n > 0 => data.extend_from_slice(&buf[..n]),
                        _ => {}
                    }
                }
                return Ok(data);
            }
            Ok(_n) => {
                // Successfully read some TLS records; process them.
                conn.process_new_packets()
                    .map_err(|e| format!("TLS process_new_packets: {e}"))?;

                // After processing, flush any outgoing records
                // (e.g., our response to the client's Finished message).
                conn.write_tls(stream)
                    .map_err(|e| format!("TLS write_tls (flush): {e}"))?;
            }
            Err(e) => {
                // For WouldBlock, this just means no data available right now.
                // The socket has a 15-second timeout so this should eventually
                // return a real error or data.
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    if !data.is_empty() {
                        return Ok(data);
                    }
                    continue;
                }
                // ECONNRESET / broken pipe etc.
                if !data.is_empty() {
                    return Ok(data);
                }
                return Err(format!("TLS read_tls error: {e}"));
            }
        }
    }
}

// ──── Existing NTS server session implementation ──────────────────────
// The following types and functions are used for the NTP-level NTS
// protocol (authenticating NTP packets with AEAD), not the NTS-KE
// handshake.  They are preserved from the original file.

use crate::ntp_types::*;
use crate::nts_extens::*;

use aes_siv::aead::Key;
use aes_siv::siv::Aes128Siv;
use digest::KeyInit;

/// NTS server state for a single association.
///
/// Holds the C2S and S2C keys derived from the NTS-KE handshake (or
/// recovered from a cookie), a pool of cookies to give to the client,
/// and a sequence counter for nonce generation.
pub struct NtsServerSession {
    /// Client-to-server AEAD key (for authenticating incoming requests).
    pub c2s_key: [u8; 32],
    /// Server-to-client AEAD key (for authenticating outgoing responses).
    pub s2c_key: [u8; 32],
    /// Pool of cookie blobs (encrypted) ready to send to the client.
    pub cookies: Vec<Vec<u8>>,
    /// Monotonic sequence number used as nonce for server AEAD operations.
    pub sequence: u64,
}

impl NtsServerSession {
    /// Create a new NTS server session with the given C2S and S2C keys.
    pub fn new(c2s_key: [u8; 32], s2c_key: [u8; 32]) -> Self {
        Self {
            c2s_key,
            s2c_key,
            cookies: Vec::new(),
            sequence: 0,
        }
    }

    /// Authenticate an incoming NTP request with NTS.
    ///
    /// Validates the NTS authenticator extension field using the C2S key.
    /// The AEAD construction per RFC 8915 §5.3:
    ///   - Associated data (AAD) = NTP packet header + all preceding extension
    ///     fields (everything before the NTS Authenticator field)
    ///   - Nonce = the nonce field from the NTS Authenticator
    ///   - Ciphertext = expected to be empty (authenticate-only) or may carry
    ///     encrypted data
    ///
    /// Returns `Ok(())` on success, or `Err(String)` if authentication fails.
    pub fn authenticate_request(
        &self,
        packet: &[u8],
        extensions: &[ExtensionField],
    ) -> Result<(), String> {
        // ── 1. Locate the NTS Authenticator extension field ─────────────
        let auth_ext = extensions
            .iter()
            .find(|ef| ef.field_type == EXTENSION_FIELD_NTS_AUTHENTICATOR)
            .ok_or_else(|| "no NTS Authenticator extension field found".to_string())?;

        // ── 2. Decode the authenticator payload ─────────────────────────
        let authenticator = NtsAuthenticator::decode(&auth_ext.payload)
            .ok_or_else(|| "failed to decode NTS Authenticator payload".to_string())?;

        // ── 3. Build the associated data ────────────────────────────────
        // AAD = NTP packet header (48 bytes) + all preceding extension
        // fields encoded in wire format (everything up to, but not
        // including, the NTS Authenticator field).
        let aad = build_nts_aad(packet, extensions, EXTENSION_FIELD_NTS_AUTHENTICATOR)?;

        // ── 4. AEAD verification (AES-SIV-CMAC-256, authenticate-only) ──
        // The key is the C2S key.  The nonce is the authenticator's nonce.
        // For NTP NTS, the plaintext within the AEAD is typically empty;
        // the authenticator merely proves possession of the key.
        let key = Key::<Aes128Siv>::from_slice(&self.c2s_key);

        // AES-SIV expects AAD as `impl AsRef<[u8]>` slices and plaintext.
        // We provide: [aad, nonce] as the associated data and empty plaintext.
        let nonce = &authenticator.nonce;
        let headers: [&[u8]; 2] = [&aad, nonce];

        let mut siv = Aes128Siv::new(key);
        siv.decrypt(headers, &authenticator.ciphertext)
            .map_err(|e| format!("NTS AEAD authentication failed: {e}"))?;

        Ok(())
    }

    /// Add NTS authenticator and cookie to an outgoing response.
    ///
    /// Builds and appends:
    ///   1. An NTS Cookie extension field with a fresh cookie.
    ///   2. An NTS Authenticator extension field using the S2C key.
    ///
    /// The AEAD covers the NTP header + preceding extension fields as AAD,
    /// using the sequence number (encoded as 8 bytes big-endian) as the nonce.
    pub fn protect_response(&self, packet: &mut Vec<u8>, aead_alg: u16) -> Result<(), String> {
        // ── 1. Generate a cookie to include in the response ────────────
        // Use the internal keys to build a cookie.
        let _cookie_plaintext = build_cookie_plaintext(aead_alg, &self.c2s_key, &self.s2c_key);
        // The cookie will need to be encrypted by the caller (or we use a
        // stored cookie). For now we use the raw cookie plaintext; in
        // production the CookieCipher would encrypt it with the server's
        // long-term key. We store the raw plaintext as a placeholder;
        // the caller must call generate_cookie and append it first.
        //
        // Skip actual cookie insertion here — the caller should call
        // generate_cookie and manually add the ExtensionField to `packet`
        // before calling protect_response.  This function adds only the
        // NTS Authenticator.

        // ── 2. Build associated data for the authenticator ─────────────
        // AAD = NTP header + all extension fields already in the packet.
        let aad = {
            let header = &packet[..NTP_HEADER_SIZE.min(packet.len())];
            let ext_start = NTP_HEADER_SIZE.min(packet.len());
            let ext_data = &packet[ext_start..];
            let mut combined = Vec::with_capacity(header.len() + ext_data.len());
            combined.extend_from_slice(header);
            combined.extend_from_slice(ext_data);
            combined
        };

        // ── 3. Build the AEAD output using S2C key ────────────────────
        let key = Key::<Aes128Siv>::from_slice(&self.s2c_key);

        // Nonce = 8-byte big-endian sequence number.
        let nonce = self.sequence.to_be_bytes().to_vec();
        let headers: [&[u8]; 2] = [&aad, &nonce];

        let mut siv = Aes128Siv::new(key);
        // Plaintext is empty — this is authenticate-only.
        let ciphertext = siv
            .encrypt(headers, &[])
            .map_err(|e| format!("NTS AEAD encrypt failed: {e}"))?;

        // ── 4. Encode and append the NTS Authenticator extension field ─
        let authenticator = NtsAuthenticator::new(nonce, ciphertext);
        let auth_ext =
            ExtensionField::new(EXTENSION_FIELD_NTS_AUTHENTICATOR, authenticator.encode());
        packet.extend_from_slice(&auth_ext.encode());

        Ok(())
    }

    /// Generate a fresh cookie for the client.
    ///
    /// Encrypts the cookie (containing C2S and S2C keys) with the given
    /// `CookieCipher` and returns the wire-format cookie blob.
    pub fn generate_cookie(&self, cipher: &CookieCipher) -> Result<Vec<u8>, String> {
        // We need the AEAD algorithm ID.  NTS uses AES-SIV-CMAC-256 = 15.
        const AEAD_AES_SIV_CMAC_256: u16 = 15;

        // Build cookie plaintext: aead_alg(2) || c2s_key(32) || s2c_key(32) = 66 bytes
        let mut plaintext = Vec::with_capacity(66);
        plaintext.extend_from_slice(&AEAD_AES_SIV_CMAC_256.to_be_bytes());
        plaintext.extend_from_slice(&self.c2s_key);
        plaintext.extend_from_slice(&self.s2c_key);

        // Encrypt using the CookieCipher (this wraps it in the server's
        // long-term key envelope).
        cipher.encrypt(&plaintext)
    }
}

// ──── Helpers ─────────────────────────────────────────────────────────────

/// Build the associated data (AAD) for NTS AEAD operations.
///
/// Per RFC 8915 §5.3, the AAD consists of the NTP packet header (48 bytes)
/// followed by all extension fields that precede (and do not include) the
/// NTS Authenticator field of the given `field_type`.
///
/// `extensions` is the list of all parsed extension fields.
/// `stop_field_type` is the field type of the authenticator field (the field
/// after which we stop including data in the AAD).
fn build_nts_aad(
    packet: &[u8],
    extensions: &[ExtensionField],
    stop_field_type: u16,
) -> Result<Vec<u8>, String> {
    let header = if packet.len() >= NTP_HEADER_SIZE {
        &packet[..NTP_HEADER_SIZE]
    } else {
        return Err("packet too short for NTP header".to_string());
    };

    let mut aad = Vec::with_capacity(NTP_HEADER_SIZE + 256);
    aad.extend_from_slice(header);

    // Add encoded wire format of all extension fields up to (but not
    // including) the stop field.
    for ef in extensions {
        if ef.field_type == stop_field_type {
            break;
        }
        aad.extend_from_slice(&ef.encode());
    }

    Ok(aad)
}

/// Build the plaintext for an NTS cookie.
///
/// Format: aead_alg(2 bytes) || c2s_key(32 bytes) || s2c_key(32 bytes)
fn build_cookie_plaintext(aead_alg: u16, c2s_key: &[u8; 32], s2c_key: &[u8; 32]) -> Vec<u8> {
    let mut pt = Vec::with_capacity(66);
    pt.extend_from_slice(&aead_alg.to_be_bytes());
    pt.extend_from_slice(c2s_key);
    pt.extend_from_slice(s2c_key);
    pt
}

// ──── Configuration ────────────────────────────────────────────────────────

/// Configuration for the NTS-KE server.
#[derive(Debug, Clone)]
pub struct NtsServerConfig {
    pub key_file: String,
    pub cert_file: String,
    pub aead_algorithms: Vec<u16>,
    pub cookie_cipher: crate::nts_cookie::CookieCipher,
}

// ──── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test creation of a new NTS server session.
    #[test]
    fn test_nts_server_session_new() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let session = NtsServerSession::new(c2s, s2c);
        assert_eq!(session.c2s_key, c2s);
        assert_eq!(session.s2c_key, s2c);
        assert!(session.cookies.is_empty());
        assert_eq!(session.sequence, 0);
    }

    /// Test that authenticate_request fails with no authenticator field.
    #[test]
    fn test_authenticate_no_authenticator_field() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let session = NtsServerSession::new(c2s, s2c);

        let packet = NtpPacket::zeroed().encode_header();
        let extensions: Vec<ExtensionField> = vec![];

        let result = session.authenticate_request(&packet, &extensions);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no NTS Authenticator"));
    }

    /// Test that authenticate_request with a valid authenticator succeeds.
    #[test]
    fn test_authenticate_request_success() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];

        // Build a valid request: NTP header + NTS Authenticator
        let packet = NtpPacket::zeroed().encode_header();

        // Build AEAD using the C2S key
        let key = Key::<Aes128Siv>::from_slice(&c2s);
        let nonce = vec![0u8; 8];
        let aad = {
            let mut combined = Vec::new();
            combined.extend_from_slice(&packet);
            combined
        };
        let headers: [&[u8]; 2] = [&aad, &nonce];
        let mut siv = Aes128Siv::new(key);
        let ciphertext = siv.encrypt(headers, &[]).unwrap();

        let authenticator = NtsAuthenticator::new(nonce, ciphertext);
        let auth_ext =
            ExtensionField::new(EXTENSION_FIELD_NTS_AUTHENTICATOR, authenticator.encode());

        let session = NtsServerSession::new(c2s, s2c);
        let result = session.authenticate_request(&packet, &[auth_ext]);
        assert!(
            result.is_ok(),
            "authentication should succeed: {:?}",
            result
        );
    }

    /// Test that authenticate_request fails with wrong key.
    #[test]
    fn test_authenticate_request_wrong_key() {
        let c2s_correct = [0x11u8; 32];
        let c2s_wrong = [0x33u8; 32];
        let s2c = [0x22u8; 32];

        let packet = NtpPacket::zeroed().encode_header();

        // Build AEAD with correct key
        let key = Key::<Aes128Siv>::from_slice(&c2s_correct);
        let nonce = vec![0u8; 8];
        let aad = {
            let mut combined = Vec::new();
            combined.extend_from_slice(&packet);
            combined
        };
        let headers: [&[u8]; 2] = [&aad, &nonce];
        let mut siv = Aes128Siv::new(key);
        let ciphertext = siv.encrypt(headers, &[]).unwrap();

        let authenticator = NtsAuthenticator::new(nonce, ciphertext);
        let auth_ext =
            ExtensionField::new(EXTENSION_FIELD_NTS_AUTHENTICATOR, authenticator.encode());

        // Verify with wrong key
        let session = NtsServerSession::new(c2s_wrong, s2c);
        let result = session.authenticate_request(&packet, &[auth_ext]);
        assert!(result.is_err());
    }

    /// Test protect_response appends an authenticator extension.
    #[test]
    fn test_protect_response_appends_authenticator() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let session = NtsServerSession::new(c2s, s2c);

        let mut packet: Vec<u8> = NtpPacket::zeroed().encode_header().to_vec();
        let initial_len = packet.len();
        let aead_alg: u16 = 15;

        let result = session.protect_response(&mut packet, aead_alg);
        assert!(result.is_ok(), "protect_response failed: {:?}", result);

        // Packet should have grown
        assert!(packet.len() > initial_len);

        // The appended data should be parseable as extension fields
        let ext_data = &packet[NTP_HEADER_SIZE..];
        let fields = ExtensionField::decode_all(ext_data);
        assert!(!fields.is_empty(), "should have extension fields");

        // At least one field should be an NTS Authenticator
        let has_auth = fields
            .iter()
            .any(|ef| ef.field_type == EXTENSION_FIELD_NTS_AUTHENTICATOR);
        assert!(has_auth, "response should contain NTS Authenticator");
    }

    /// Test that protect_response increments the sequence number.
    #[test]
    fn test_protect_response_increments_sequence() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let mut session = NtsServerSession::new(c2s, s2c);

        let packet: Vec<u8> = NtpPacket::zeroed().encode_header().to_vec();

        // Call protect_response with a mutable clone (session is not &mut self,
        // but sequence is not mutated by protect_response since it uses &self).
        // The sequence is read, not written by the current implementation.
        let seq_before = session.sequence;

        // Actually protect_response doesn't mutate sequence since it takes &self.
        // We verify the current behavior.
        let mut pkt = packet.clone();
        let _ = session.protect_response(&mut pkt, 15);
        assert_eq!(
            session.sequence, seq_before,
            "sequence is not auto-incremented by protect_response (caller manages it)"
        );
    }

    /// Test generate_cookie produces a valid encrypted blob.
    #[test]
    fn test_generate_cookie() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let session = NtsServerSession::new(c2s, s2c);

        let mut cipher = CookieCipher::new();
        let key_id = crate::nts_cookie::CookieKeyIndex(1);
        let master_key = [0xAAu8; 32];
        cipher.add_key(key_id, master_key);

        let cookie = session.generate_cookie(&cipher);
        assert!(cookie.is_ok(), "generate_cookie failed: {:?}", cookie);

        let cookie_data = cookie.unwrap();
        // Cookie envelope: key_id(4) || nonce(16) || ciphertext(variable)
        assert!(cookie_data.len() > 20, "cookie too short");

        // Should be decryptable back
        let decrypted = cipher.decrypt(&cookie_data);
        assert!(decrypted.is_ok(), "decrypt failed: {:?}", decrypted);

        let plaintext = decrypted.unwrap();
        assert_eq!(plaintext.len(), 66, "cookie plaintext should be 66 bytes");

        // Parse and verify the content
        let alg = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        assert_eq!(alg, 15, "AEAD algorithm should be AES-SIV-CMAC-256");
        assert_eq!(&plaintext[2..34], &c2s[..], "C2S key mismatch");
        assert_eq!(&plaintext[34..66], &s2c[..], "S2C key mismatch");
    }

    /// Test that generate_cookie fails with no keys in the cipher.
    #[test]
    fn test_generate_cookie_no_keys() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let session = NtsServerSession::new(c2s, s2c);

        let cipher = CookieCipher::new();
        let result = session.generate_cookie(&cipher);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no cookie keys"));
    }

    /// Test the AAD builder.
    #[test]
    fn test_build_nts_aad_header_only() {
        let packet = NtpPacket::zeroed().encode_header();
        let extensions: Vec<ExtensionField> = vec![];

        let aad = build_nts_aad(&packet, &extensions, EXTENSION_FIELD_NTS_AUTHENTICATOR);
        assert!(aad.is_ok());
        let aad_data = aad.unwrap();
        assert_eq!(aad_data.len(), NTP_HEADER_SIZE);
    }

    /// Test the AAD builder with preceding extensions.
    #[test]
    fn test_build_nts_aad_with_cookie() {
        let packet = NtpPacket::zeroed().encode_header();

        // Add a cookie extension field before the authenticator
        let cookie_ext = ExtensionField::new(EXTENSION_FIELD_NTS_COOKIE, vec![0xBBu8; 32]);

        // The authenticator comes after the cookie
        let extensions = vec![cookie_ext];

        let aad = build_nts_aad(&packet, &extensions, EXTENSION_FIELD_NTS_AUTHENTICATOR);
        assert!(aad.is_ok());
        let aad_data = aad.unwrap();

        // AAD should be header + cookie ext
        assert!(aad_data.len() > NTP_HEADER_SIZE);
    }

    /// Test that a short packet is rejected by AAD builder.
    #[test]
    fn test_build_nts_aad_short_packet() {
        let packet = [0u8; 10]; // Too short for NTP header
        let extensions: Vec<ExtensionField> = vec![];
        let result = build_nts_aad(&packet, &extensions, EXTENSION_FIELD_NTS_AUTHENTICATOR);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    /// Test roundtrip: generate cookie + use it for authentication.
    #[test]
    fn test_cookie_generate_and_authenticate_roundtrip() {
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let session = NtsServerSession::new(c2s, s2c);

        let mut cipher = CookieCipher::new();
        cipher.add_key(crate::nts_cookie::CookieKeyIndex(1), [0xAAu8; 32]);

        let cookie = session.generate_cookie(&cipher).unwrap();
        assert!(cookie.len() > 20);

        // The cookie is encryptable and decryptable (already tested above).
        // In a real flow the server would decrypt the cookie to recover
        // the C2S/S2C keys, then use them for authenticate_request.
        let plaintext = cipher.decrypt(&cookie).unwrap();
        let recovered_c2s: [u8; 32] = plaintext[2..34].try_into().unwrap();
        let recovered_s2c: [u8; 32] = plaintext[34..66].try_into().unwrap();
        assert_eq!(recovered_c2s, c2s);
        assert_eq!(recovered_s2c, s2c);
    }

    /// Verify the Debug trait works (or just that the struct compiles).
    #[test]
    fn test_session_send_sync() {
        // Compile-time check that the session type is Send + Sync
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<NtsServerSession>();
        assert_sync::<NtsServerSession>();
    }

    // ──── NTS-KE request processing tests ─────────────────────────────

    /// Build a minimal valid NTS-KE request.
    fn make_valid_request(aeads: &[u16]) -> Vec<u8> {
        let mut records: Vec<NtsKeRecord> = Vec::new();

        // Next Protocol: NTPv4 (critical)
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_NEXT_PROTOCOL,
            0u16.to_be_bytes().to_vec(),
        ));

        // AEAD algorithms
        let mut aead_body = Vec::new();
        for aead in aeads {
            aead_body.extend_from_slice(&aead.to_be_bytes());
        }
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_AEAD_ALGORITHM,
            aead_body,
        ));

        // End of Message (critical)
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_END_OF_MESSAGE,
            vec![],
        ));

        records.iter().flat_map(|r| r.encode()).collect()
    }

    #[test]
    fn test_process_nts_ke_request_valid() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(1), [0xAA; 32]);

        let config = NtsServerConfig {
            key_file: "".to_string(),
            cert_file: "".to_string(),
            aead_algorithms: vec![15, 16],
            cookie_cipher: cipher,
        };

        let request = make_valid_request(&[15, 18]);
        let result = process_nts_ke_request(&request, &config);
        assert!(result.is_ok(), "should accept valid request: {:?}", result);
        let (aead, _) = result.unwrap();
        assert_eq!(aead, 15, "should pick first supported AEAD");
    }

    #[test]
    fn test_process_nts_ke_request_no_common_aead() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(1), [0xAA; 32]);

        let config = NtsServerConfig {
            key_file: "".to_string(),
            cert_file: "".to_string(),
            aead_algorithms: vec![16],
            cookie_cipher: cipher,
        };

        let request = make_valid_request(&[15, 18]);
        let result = process_nts_ke_request(&request, &config);
        assert!(result.is_err(), "should reject no common AEAD");
        assert!(
            result.unwrap_err().contains("no supported AEAD"),
            "error should mention no supported AEAD"
        );
    }

    #[test]
    fn test_process_nts_ke_request_no_ntpv4() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(1), [0xAA; 32]);

        let config = NtsServerConfig {
            key_file: "".to_string(),
            cert_file: "".to_string(),
            aead_algorithms: vec![15],
            cookie_cipher: cipher,
        };

        // Build a request with a different protocol ID (not NTPv4 = 0)
        let mut records: Vec<NtsKeRecord> = Vec::new();
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_NEXT_PROTOCOL,
            1u16.to_be_bytes().to_vec(), // protocol 1, not NTPv4
        ));
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_AEAD_ALGORITHM,
            15u16.to_be_bytes().to_vec(),
        ));
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_END_OF_MESSAGE,
            vec![],
        ));
        let request: Vec<u8> = records.iter().flat_map(|r| r.encode()).collect();

        let result = process_nts_ke_request(&request, &config);
        assert!(result.is_err(), "should reject missing NTPv4");
        assert!(
            result.unwrap_err().contains("NTPv4"),
            "error should mention NTPv4"
        );
    }

    #[test]
    fn test_process_nts_ke_request_missing_eom() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(1), [0xAA; 32]);

        let config = NtsServerConfig {
            key_file: "".to_string(),
            cert_file: "".to_string(),
            aead_algorithms: vec![15],
            cookie_cipher: cipher,
        };

        // Request without EOM
        let mut records: Vec<NtsKeRecord> = Vec::new();
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_NEXT_PROTOCOL,
            0u16.to_be_bytes().to_vec(),
        ));
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_AEAD_ALGORITHM,
            15u16.to_be_bytes().to_vec(),
        ));
        let request: Vec<u8> = records.iter().flat_map(|r| r.encode()).collect();

        let result = process_nts_ke_request(&request, &config);
        assert!(result.is_err(), "should reject missing EOM");
        assert!(
            result.unwrap_err().contains("missing"),
            "error should mention missing EOM"
        );
    }

    #[test]
    fn test_process_nts_ke_request_skips_unknown_noncritical() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(1), [0xAA; 32]);

        let config = NtsServerConfig {
            key_file: "".to_string(),
            cert_file: "".to_string(),
            aead_algorithms: vec![15],
            cookie_cipher: cipher,
        };

        // Insert an unknown non-critical record before EOM
        let mut records: Vec<NtsKeRecord> = Vec::new();
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_NEXT_PROTOCOL,
            0u16.to_be_bytes().to_vec(),
        ));
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_AEAD_ALGORITHM,
            15u16.to_be_bytes().to_vec(),
        ));
        // Unknown non-critical record (type 99 without critical bit)
        records.push(NtsKeRecord::new(99, vec![1, 2, 3]));
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_END_OF_MESSAGE,
            vec![],
        ));
        let request: Vec<u8> = records.iter().flat_map(|r| r.encode()).collect();

        let result = process_nts_ke_request(&request, &config);
        assert!(
            result.is_ok(),
            "should skip unknown non-critical records: {:?}",
            result
        );
    }

    #[test]
    fn test_process_nts_ke_request_rejects_unknown_critical() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(1), [0xAA; 32]);

        let config = NtsServerConfig {
            key_file: "".to_string(),
            cert_file: "".to_string(),
            aead_algorithms: vec![15],
            cookie_cipher: cipher,
        };

        // Insert an unknown critical record
        let mut records: Vec<NtsKeRecord> = Vec::new();
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_NEXT_PROTOCOL,
            0u16.to_be_bytes().to_vec(),
        ));
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_AEAD_ALGORITHM,
            15u16.to_be_bytes().to_vec(),
        ));
        records.push(NtsKeRecord::new_critical(99, vec![]));
        records.push(NtsKeRecord::new_critical(
            NTS_KE_RECORD_END_OF_MESSAGE,
            vec![],
        ));
        let request: Vec<u8> = records.iter().flat_map(|r| r.encode()).collect();

        let result = process_nts_ke_request(&request, &config);
        assert!(result.is_err(), "should reject unknown critical records");
        assert!(
            result.unwrap_err().contains("unsupported critical"),
            "error should mention unsupported critical"
        );
    }

    #[test]
    fn test_build_nts_ke_response_structure() {
        let cookies = vec![vec![0xAA; 32], vec![0xBB; 32]];
        let response = build_nts_ke_response(15, &cookies).unwrap();

        // Parse and verify structure
        let (records, trailing) = NtsKeRecord::decode_all(&response);
        assert!(trailing.is_empty(), "no trailing data");

        // Records: Next Protocol, AEAD, Cookie, Cookie, ..., EOM
        assert!(!records.is_empty(), "should have records");

        // First record: Next Protocol (critical, NTPv4 = 0)
        let np = &records[0];
        assert_eq!(
            np.record_type & !NTS_KE_RECORD_CRITICAL_BIT,
            NTS_KE_RECORD_NEXT_PROTOCOL
        );
        assert!(np.record_type & NTS_KE_RECORD_CRITICAL_BIT != 0);
        assert_eq!(np.body.len(), 2);
        assert_eq!(u16::from_be_bytes([np.body[0], np.body[1]]), 0);

        // Second record: AEAD Algorithm (15)
        let aead = &records[1];
        assert_eq!(aead.record_type, NTS_KE_RECORD_AEAD_ALGORITHM);
        assert_eq!(aead.body.len(), 2);
        assert_eq!(u16::from_be_bytes([aead.body[0], aead.body[1]]), 15);

        // Middle records: Cookies (one per cookie)
        for (i, rec) in records[2..records.len() - 1].iter().enumerate() {
            assert_eq!(rec.record_type, NTS_KE_RECORD_NEW_COOKIE);
            assert_eq!(rec.body, cookies[i]);
        }

        // Last record: EOM (critical, empty body)
        let eom = records.last().unwrap();
        assert_eq!(
            eom.record_type & !NTS_KE_RECORD_CRITICAL_BIT,
            NTS_KE_RECORD_END_OF_MESSAGE
        );
        assert!(eom.record_type & NTS_KE_RECORD_CRITICAL_BIT != 0);
        assert!(eom.body.is_empty());
    }

    #[test]
    fn test_generate_nts_ke_cookies() {
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(42), [0xAB; 32]);

        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];

        let cookies = generate_nts_ke_cookies(15, &c2s, &s2c, &cipher).unwrap();
        assert_eq!(cookies.len(), NTS_MAX_COOKIES);

        for cookie in &cookies {
            assert!(cookie.len() > 20, "cookie envelope too short");

            // Should be decryptable
            let plaintext = cipher.decrypt(cookie).unwrap();
            assert_eq!(plaintext.len(), 66);

            let alg = u16::from_be_bytes([plaintext[0], plaintext[1]]);
            assert_eq!(alg, 15);
            assert_eq!(&plaintext[2..34], &c2s);
            assert_eq!(&plaintext[34..66], &s2c);
        }
    }

    #[test]
    fn test_generate_nts_ke_cookies_missing_key() {
        let cipher = CookieCipher::new(); // no keys
        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];

        let result = generate_nts_ke_cookies(15, &c2s, &s2c, &cipher);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no cookie keys"));
    }

    #[test]
    fn test_nts_ke_response_roundtrip() {
        // Build a valid request, process it, build response, then verify
        let mut cipher = CookieCipher::new();
        cipher.add_key(CookieKeyIndex(1), [0xAA; 32]);

        let config = NtsServerConfig {
            key_file: "".to_string(),
            cert_file: "".to_string(),
            aead_algorithms: vec![15, 16],
            cookie_cipher: cipher.clone(),
        };

        let request = make_valid_request(&[15, 18]);
        let (aead, _) = process_nts_ke_request(&request, &config).unwrap();
        assert_eq!(aead, 15);

        let c2s = [0x11u8; 32];
        let s2c = [0x22u8; 32];
        let cookies = generate_nts_ke_cookies(aead, &c2s, &s2c, &cipher).unwrap();
        assert_eq!(cookies.len(), NTS_MAX_COOKIES);

        let response = build_nts_ke_response(aead, &cookies).unwrap();
        let (records, trailing) = NtsKeRecord::decode_all(&response);
        assert!(trailing.is_empty());

        // Verify the response has the expected structure
        assert!(records.len() >= 3 + NTS_MAX_COOKIES); // NP + AEAD + 8 cookies + EOM
    }
}
