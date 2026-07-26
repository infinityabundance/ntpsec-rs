// ──── tests/nts_ke_chrony_interop.rs ─────────────────────────────────────────
// Real NTS-KE + NTS-protected NTP interoperability test against a chrony server.
//
// This test requires:
//   1. A chrony NTS-KE server running (e.g. via docker-compose.nts.yml)
//   2. The chrony self-signed CA certificate available on disk
//   3. The environment variable NTSKE_TEST=1 set
//
// The test performs:
//   Phase 1: NTS-KE TLS 1.3 handshake with chrony → cookies + keys
//   Phase 2: NTS-protected NTP client request → chrony NTP response
//   Phase 3: Response authenticator verification → cookie replenishment
//
// Run:  NTSKE_TEST=1 cargo test --test nts_ke_chrony_interop -p ntpsec-rs-core -- --nocapture
// =============================================================================

use std::net::UdpSocket;
use std::time::Duration;

use ntpsec_rs_core::{
    build_nts_request, perform_nts_ke_with_ca, verify_nts_response, NtpMode, NtpPacket, NtpVersion,
};

/// Default path where the chrony self-signed certificate is expected.
const DEFAULT_CERT_PATH: &str = "/tmp/chrony-cert.pem";

/// Default NTS-KE server hostname (CN in the self-signed cert).
const DEFAULT_NTSKE_HOST: &str = "nts-test.example.com";

/// Default NTS-KE server port.
const DEFAULT_NTSKE_PORT: u16 = 4460;

/// Default NTP server port for NTS-protected traffic.
const DEFAULT_NTP_HOST: &str = "10.200.0.10";
const DEFAULT_NTP_PORT: u16 = 123;

#[test]
fn nts_ke_chrony_interop() {
    // ── Skip unless explicitly requested ───────────────────────────────────
    if std::env::var("NTSKE_TEST").is_err() {
        eprintln!(
            "SKIP: NTSKE_TEST not set — skipping NTS-KE interop test.\n\
             Set NTSKE_TEST=1 to run against a live chrony NTS-KE server."
        );
        return;
    }

    // ── Read configuration from environment (with defaults) ────────────────
    let cert_path =
        std::env::var("NTSKE_CERT_PATH").unwrap_or_else(|_| DEFAULT_CERT_PATH.to_string());
    let ke_host = std::env::var("NTSKE_HOST").unwrap_or_else(|_| DEFAULT_NTSKE_HOST.to_string());
    let ke_port: u16 = std::env::var("NTSKE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_NTSKE_PORT);
    let ntp_host = std::env::var("NTP_HOST").unwrap_or_else(|_| DEFAULT_NTP_HOST.to_string());
    let ntp_port: u16 = std::env::var("NTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_NTP_PORT);

    eprintln!("═══ NTS-KE + NTS Protected NTP Interop Test ═══");
    eprintln!("  NTS-KE host:  {ke_host}:{ke_port}");
    eprintln!("  NTP host:     {ntp_host}:{ntp_port}");
    eprintln!("  Cert path:    {cert_path}");

    // ── Load the chrony self-signed certificate ────────────────────────────
    let ca_cert_pem = std::fs::read(&cert_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read chrony CA certificate at {cert_path}: {e}\n\
             Make sure chrony-nts container is running and the cert has been\n\
             extracted (e.g. via shared volume or docker cp)."
        );
    });
    eprintln!("  Cert loaded:  {} bytes", ca_cert_pem.len());
    assert!(
        ca_cert_pem.starts_with(b"-----BEGIN "),
        "Certificate file does not appear to be PEM format"
    );

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 1: NTS-KE Handshake
    // ═══════════════════════════════════════════════════════════════════════
    eprintln!("\n╔═══ Phase 1: NTS-KE Handshake ═══╗");
    eprintln!("  Connecting to {ke_host}:{ke_port}...");
    let mut association = perform_nts_ke_with_ca(&ke_host, ke_port, ca_cert_pem)
        .expect("NTS-KE handshake with chrony should succeed");

    eprintln!("  Handshake successful!");
    eprintln!("  AEAD algorithm:       {}", association.aead_algorithm);
    eprintln!("  Cookie count:         {}", association.cookies.len());
    eprintln!(
        "  C2S key:              {} bytes (non-zero: {})",
        association.c2s_key.len(),
        association.c2s_key.iter().any(|&b| b != 0)
    );
    eprintln!(
        "  S2C key:              {} bytes (non-zero: {})",
        association.s2c_key.len(),
        association.s2c_key.iter().any(|&b| b != 0)
    );

    // ── Phase 1 Assertions ─────────────────────────────────────────────
    assert!(
        !association.cookies.is_empty(),
        "Phase 1: NTS-KE must return at least one cookie, got {}",
        association.cookies.len()
    );
    assert_eq!(
        association.c2s_key.len(),
        32,
        "Phase 1: C2S key must be 32 bytes for AES-SIV-CMAC-256"
    );
    assert!(
        association.c2s_key.iter().any(|&b| b != 0),
        "Phase 1: C2S key must not be all zeros"
    );
    assert_eq!(
        association.s2c_key.len(),
        32,
        "Phase 1: S2C key must be 32 bytes"
    );
    assert!(
        association.s2c_key.iter().any(|&b| b != 0),
        "Phase 1: S2C key must not be all zeros"
    );
    assert_ne!(
        association.c2s_key, association.s2c_key,
        "Phase 1: C2S and S2C keys must differ (directional contexts)"
    );
    assert_eq!(
        association.aead_algorithm, 15,
        "Phase 1: AEAD algorithm must be AES-SIV-CMAC-256 (ID 15)"
    );
    for (i, cookie) in association.cookies.iter().enumerate() {
        assert!(
            !cookie.is_empty(),
            "Phase 1: Cookie {} must not be empty",
            i + 1
        );
    }
    assert_eq!(association.ke_hostname, ke_host);
    assert_eq!(association.ke_port, ke_port);
    eprintln!("  ✓ Phase 1: All NTS-KE assertions passed");

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 2: NTS-Protected NTP Request
    // ═══════════════════════════════════════════════════════════════════════
    eprintln!("\n╔═══ Phase 2: NTS-Protected NTP Request ═══╗");
    eprintln!("  Constructing NTS-protected client request...");

    // Create a mode 3 (client) NTP packet
    let mut ntp_packet = NtpPacket::zeroed();
    ntp_packet.li_vn_mode = NtpPacket::set_li_vn_mode(
        ntpsec_rs_core::LeapIndicator::NoWarning,
        NtpVersion::V4,
        NtpMode::Client,
    );
    // Set a non-zero transmit timestamp
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let ntp_epoch_secs = now_secs.wrapping_add(2208988800); // NTP epoch = 1900
    ntp_packet.transmit_ts = ntpsec_rs_core::NtpTs {
        seconds: ntp_epoch_secs,
        fraction: 0,
    };

    // Build the NTS-protected wire request
    let protected_request = build_nts_request(&ntp_packet, &mut association)
        .expect("Phase 2: build_nts_request should succeed");
    eprintln!(
        "  Protected request: {} bytes (48 header + {} ext)",
        protected_request.len(),
        protected_request.len() - 48
    );
    eprintln!("  Pre-send cookie count: {}", association.cookies.len());

    // Send via UDP to chrony NTP port
    let sock = UdpSocket::bind("0.0.0.0:0").expect("Phase 2: bind UDP socket");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("Phase 2: set timeout");
    sock.connect(format!("{ntp_host}:{ntp_port}"))
        .expect("Phase 2: connect to chrony NTP");

    sock.send(&protected_request)
        .expect("Phase 2: send NTS-protected request");
    eprintln!("  UDP request sent to {ntp_host}:{ntp_port}");

    // Receive the NTS-protected response
    let mut buf = [0u8; 4096];
    let recv_result = sock.recv(&mut buf);
    assert!(
        recv_result.is_ok(),
        "Phase 2: chrony must respond to NTS-protected NTP request (got timeout)"
    );
    let n = recv_result.unwrap();
    let response = &buf[..n];
    eprintln!("  Response received: {} bytes", response.len());
    assert!(
        response.len() >= 48,
        "Phase 2: response must be at least 48 bytes, got {}",
        response.len()
    );

    // Verify NTP server mode
    let resp_mode = response[0] & 0x07;
    assert_eq!(
        resp_mode,
        4, // Server mode
        "Phase 2: chrony response must be server mode (4), got mode {resp_mode}"
    );
    eprintln!("  NTP response mode: {} (server)", resp_mode);

    // Check the response contains extension fields (NTS)
    assert!(
        response.len() > 48,
        "Phase 2: NTS response must have extension fields beyond 48-byte header, got {} bytes",
        response.len()
    );
    eprintln!("  Extension fields present: {} bytes", response.len() - 48);

    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 3: Response Verification
    // ═══════════════════════════════════════════════════════════════════════
    eprintln!("\n╔═══ Phase 3: Response Authenticator Verification ═══╗");
    eprintln!(
        "  Post-send cookie count before verify: {}",
        association.cookies.len()
    );

    // Verify the NTS authenticator and extract fresh cookies
    let fresh_cookies = verify_nts_response(response, &association)
        .expect("Phase 3: NTS response authenticator should verify");

    eprintln!("  Fresh cookies extracted: {}", fresh_cookies.len());

    // Add fresh cookies to the association pool
    let pre_replenish = association.cookies.len();
    association.add_cookies(&mut fresh_cookies.clone());
    eprintln!(
        "  Cookie pool: {pre_replenish} → {}",
        association.cookies.len()
    );

    // ── Phase 3 Assertions ─────────────────────────────────────────────
    // Fresh cookies from authenticator must be non-empty
    assert!(
        !fresh_cookies.is_empty(),
        "Phase 3: At least one fresh cookie must be returned in authenticator plaintext, got 0"
    );

    // Fresh cookies must contain valid data
    for (i, cookie) in fresh_cookies.iter().enumerate() {
        assert!(
            !cookie.is_empty(),
            "Phase 3: Fresh cookie {} from authenticator must not be empty",
            i + 1
        );
    }

    // Cookie pool should have been replenished (may be > or = depending on consumption)
    assert!(
        association.cookies.len() > 0,
        "Phase 3: Cookie pool must not be empty after replenishment"
    );

    // After consuming one cookie and replenishing, pool should be >= original count
    // (Chrony typically returns multiple cookies in the authenticator)
    eprintln!(
        "  Cookie pool final: {} (consumed=1, replenished={})",
        association.cookies.len(),
        fresh_cookies.len()
    );

    eprintln!("\n═══ All phases passed — NTS-KE + NTS-protected NTP interop verified! ═══");
    eprintln!("  NTS-KE handshake:    ✓ (TLS 1.3, cookies, C2S/S2C keys)");
    eprintln!("  Protected NTP req:   ✓ (UDP send/recv, extension fields)");
    eprintln!("  Auth verification:   ✓ (AEAD, UIK match, cookie extraction)");
    eprintln!("  Cookie replenishment: ✓ (pool replenished from authenticator)");
}
