// ──── tests/nts_ke_chrony_interop.rs ─────────────────────────────────────────
// Real NTS-KE interoperability test against a chrony NTS server.
//
// This test requires:
//   1. A chrony NTS-KE server running (e.g. via docker-compose.nts.yml)
//   2. The chrony self-signed CA certificate available on disk
//   3. The environment variable NTSKE_TEST=1 set (otherwise the test is
//      silently skipped via #[ignore])
//
// Run from host (with Docker topology running):
//   NTSKE_TEST=1 cargo test --test nts_ke_chrony_interop -p ntpsec-rs-core -- --nocapture
//
// Run inside Docker (test-runner container):
//   NTSKE_TEST=1 /test-runner.sh   (or directly: /nts-ke-interop-test)
// =============================================================================

use ntpsec_rs_core::perform_nts_ke_with_ca;

/// The default path where the chrony self-signed certificate is expected.
const DEFAULT_CERT_PATH: &str = "/tmp/chrony-cert.pem";

/// The default NTS-KE server hostname (CN in the self-signed cert).
const DEFAULT_NTSKE_HOST: &str = "nts-test.example.com";

/// The default NTS-KE server port.
const DEFAULT_NTSKE_PORT: u16 = 4460;

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
    let host = std::env::var("NTSKE_HOST").unwrap_or_else(|_| DEFAULT_NTSKE_HOST.to_string());
    let port: u16 = std::env::var("NTSKE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_NTSKE_PORT);

    eprintln!("═══ NTS-KE Chrony Interop Test ═══");
    eprintln!("  Host:          {host}");
    eprintln!("  Port:          {port}");
    eprintln!("  Cert path:     {cert_path}");

    // ── Load the chrony self-signed certificate ────────────────────────────
    let ca_cert_pem = std::fs::read(&cert_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read chrony CA certificate at {cert_path}: {e}\n\
             Make sure chrony-nts container is running and the cert has been\n\
             extracted (e.g. via shared volume or docker cp)."
        );
    });
    eprintln!("  Cert loaded:   {} bytes", ca_cert_pem.len());

    // Verify it looks like a PEM certificate
    assert!(
        ca_cert_pem.starts_with(b"-----BEGIN "),
        "Certificate file does not appear to be PEM format"
    );

    // ── Perform NTS-KE handshake ───────────────────────────────────────────
    eprintln!("\n--- Connecting to {host}:{port} ---");
    let association = perform_nts_ke_with_ca(&host, port, ca_cert_pem)
        .expect("NTS-KE handshake with chrony should succeed");

    eprintln!("--- Handshake successful! ---");
    eprintln!("  AEAD algorithm:       {}", association.aead_algorithm);
    eprintln!("  Cookie count:         {}", association.cookies.len());
    let c2s_hex: String = association
        .c2s_key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let s2c_hex: String = association
        .s2c_key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    eprintln!("  C2S key (hex):        {c2s_hex}");
    eprintln!("  S2C key (hex):        {s2c_hex}");
    eprintln!("  Server hostname:      {}", association.ke_hostname);
    eprintln!("  Server port:          {}", association.ke_port);

    // ── Assertions ─────────────────────────────────────────────────────────

    // Must have received at least one cookie
    assert!(
        !association.cookies.is_empty(),
        "NTS-KE handshake must return at least one cookie, got {}",
        association.cookies.len()
    );

    // C2S key must be 32 bytes (AES-SIV-CMAC-256) and non-zero
    assert_eq!(
        association.c2s_key.len(),
        32,
        "C2S key must be 32 bytes for AES-SIV-CMAC-256"
    );
    assert!(
        association.c2s_key.iter().any(|&b| b != 0),
        "C2S key must not be all zeros"
    );

    // S2C key must be 32 bytes (AES-SIV-CMAC-256) and non-zero
    assert_eq!(
        association.s2c_key.len(),
        32,
        "S2C key must be 32 bytes for AES-SIV-CMAC-256"
    );
    assert!(
        association.s2c_key.iter().any(|&b| b != 0),
        "S2C key must not be all zeros"
    );

    // C2S and S2C keys must be different (directional context separation)
    assert_ne!(
        association.c2s_key, association.s2c_key,
        "C2S and S2C keys must differ (TLS exporter directional contexts)"
    );

    // AEAD algorithm must be AES-SIV-CMAC-256 (ID 15)
    assert_eq!(
        association.aead_algorithm, 15,
        "AEAD algorithm must be AES-SIV-CMAC-256 (ID 15)"
    );

    // Each cookie should be non-empty
    for (i, cookie) in association.cookies.iter().enumerate() {
        assert!(!cookie.is_empty(), "Cookie {} must not be empty", i + 1);
    }

    // Association metadata must match what we connected to
    assert_eq!(association.ke_hostname, host);
    assert_eq!(association.ke_port, port);

    eprintln!("\n═══ All assertions passed — NTS-KE interop verified! ═══");
}
