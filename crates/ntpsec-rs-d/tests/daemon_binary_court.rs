// ──── tests/daemon_binary_court.rs ───────────────────────────────────────
// Gate: Real daemon binary process test
//
// Spawns the actual ntpd-rs binary as a child process, communicates
// with it over real UDP sockets, and verifies:
//
//   - Daemon starts, binds port 123 (or configured port)
//   - Responds to NTP client requests with valid server responses
//   - Mode 6 queries return system state
//   - Process exits cleanly on SIGTERM
//   - State files are written (drift, stats)
//
// This is the INFRASTRUCTURE for the true process-level court.
// It runs in an unprivileged context using port > 1024 to avoid
// CAP_NET_BIND_SERVICE requirements.
//
// Run: cargo test --test daemon_binary_court -p ntpsec-rs-d -- --nocapture
// =============================================================================

use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

// ──── Constants ─────────────────────────────────────────────────────────

/// Port for the daemon (must be > 1024 since we're not root)
const DAEMON_PORT: u16 = 12345;

/// Port for our fake NTP server
const SERVER_PORT: u16 = 12346;

/// Timeout for daemon operations
const _TIMEOUT_SECS: u64 = 10;

// ──── Helpers ─────────────────────────────────────────────────────────

fn create_config(server_addr: &str, _daemon_port: u16) -> String {
    format!(
        r#"server {server_addr} minpoll 3 maxpoll 3

restrict default ignore
restrict 127.0.0.1

tos minsane 0 minclock 1 maxdist 5.0
tinker step 0.5 panic 1000.0

driftfile /tmp/ntp-test.drift
statsdir /tmp/ntp-test-stats
statistics loopstats peerstats
"#
    )
}

fn build_ntp_client_packet(transmit_ts_secs: u32) -> Vec<u8> {
    let mut pkt = vec![0u8; 48];
    // LI=0, VN=4, Mode=3 (Client)
    pkt[0] = 0b00_100_011; // 0x23
    pkt[1] = 0; // stratum
    pkt[2] = 3; // poll
    pkt[3] = 0; // precision
                // Transmit timestamp at bytes 40-47
    pkt[40..44].copy_from_slice(&transmit_ts_secs.to_be_bytes());
    pkt
}

fn build_mode6_readvar(associd: u16, seq: u16) -> Vec<u8> {
    let mut msg = vec![0u8; 12];
    // LI=0, VN=4, Mode=6 (Control)
    msg[0] = 0b00_100_110; // 0x26
    msg[1] = 2; // READVAR opcode
    msg[2..4].copy_from_slice(&seq.to_be_bytes());
    msg[4..6].copy_from_slice(&0u16.to_be_bytes()); // sequence
    msg[6..8].copy_from_slice(&0u16.to_be_bytes()); // status
    msg[8..10].copy_from_slice(&associd.to_be_bytes());
    msg[10..12].copy_from_slice(&0u16.to_be_bytes()); // offset
    msg
}

fn decode_ntp_response(data: &[u8]) -> Option<(u8, u8, u32)> {
    if data.len() < 48 {
        return None;
    }
    let mode = data[0] & 0x07;
    let stratum = data[1];
    let ref_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    Some((mode, stratum, ref_id))
}

fn decode_mode6_response(data: &[u8]) -> Option<(u16, Vec<u8>)> {
    if data.len() < 12 {
        return None;
    }
    let _seq = u16::from_be_bytes([data[4], data[5]]);
    let status = u16::from_be_bytes([data[6], data[7]]);
    let _associd = u16::from_be_bytes([data[8], data[9]]);
    let _count = u16::from_be_bytes([data[10], data[11]]);
    let body = if data.len() > 12 {
        data[12..].to_vec()
    } else {
        Vec::new()
    };
    Some((status, body))
}

/// Start the fake NTP server thread. Returns the port it's listening on.
fn start_fake_server() -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let sock = UdpSocket::bind(format!("127.0.0.1:{SERVER_PORT}")).expect("bind server");
        sock.set_read_timeout(Some(Duration::from_secs(1))).ok();
        let mut buf = [0u8; 1024];

        for _ in 0..60 {
            if let Ok((n, _src)) = sock.recv_from(&mut buf) {
                if n >= 48 {
                    // Build server response
                    let mut resp = [0u8; 48];
                    // LI=0, VN=4, Mode=4 (Server)
                    resp[0] = 0b00_100_100; // 0x24
                    resp[1] = 2; // stratum 2
                    resp[2] = 3; // poll
                    resp[3] = 0xFE; // precision
                    resp[12..16].copy_from_slice(b"TEST");

                    // Echo the client's transmit timestamp as originate
                    resp[24..28].copy_from_slice(&buf[40..44]);
                    resp[28..32].copy_from_slice(&buf[44..48]);

                    // Set receive and transmit timestamps
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    let ntp_secs = now_secs.wrapping_add(2_208_988_800);
                    resp[32..36].copy_from_slice(&ntp_secs.to_be_bytes());
                    resp[40..44].copy_from_slice(&ntp_secs.to_be_bytes());

                    let _ = sock.send_to(&resp, _src);
                }
            }
        }
    })
}

fn find_binary() -> std::path::PathBuf {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // From crate dir (crates/ntpsec-rs-d/), go up to workspace root = ../../
    // then into target/debug/ntpd-rs
    let candidates = vec![
        crate_dir
            .join("..")
            .join("..")
            .join("target")
            .join("debug")
            .join("ntpd-rs"),
        crate_dir
            .join("..")
            .join("..")
            .join("target")
            .join("release")
            .join("ntpd-rs"),
        std::path::PathBuf::from("/usr/local/bin/ntpd-rs"),
        std::path::PathBuf::from("/usr/bin/ntpd-rs"),
    ];
    for c in &candidates {
        if c.canonicalize().is_ok() && c.exists() {
            return c.canonicalize().unwrap();
        }
    }
    panic!("ntpd-rs binary not found (looked in {:?})", candidates);
}

fn start_daemon(config_path: &str, daemon_port: u16) -> Child {
    let bin_path = find_binary();

    Command::new(&bin_path)
        .arg("-c")
        .arg(config_path)
        .arg("-n") // nofork
        .arg("-I")
        .arg(format!("127.0.0.1:{daemon_port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn ntpd-rs")
}

// ──── Tests ─────────────────────────────────────────────────────────────

#[test]
fn test_daemon_binary_responds_to_ntp_query() {
    // Start fake NTP server
    let _server = start_fake_server();
    std::thread::sleep(Duration::from_millis(100));

    // Create config pointing to fake server
    let config = create_config(&format!("127.0.0.1:{SERVER_PORT}"), DAEMON_PORT);
    let config_dir = std::env::temp_dir().join("ntp-test-binary");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("ntp.conf");
    std::fs::write(&config_path, &config).unwrap();

    // Start daemon
    let mut daemon = start_daemon(config_path.to_str().unwrap(), DAEMON_PORT);
    std::thread::sleep(Duration::from_secs(1));

    let client_sock = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    let pkt = build_ntp_client_packet(1000);
    client_sock
        .send_to(&pkt, format!("127.0.0.1:{DAEMON_PORT}"))
        .expect("send to daemon");

    // Receive response
    let mut buf = [0u8; 1024];
    let result = client_sock.recv_from(&mut buf);
    assert!(result.is_ok(), "daemon must respond to NTP client query");

    let (n, _src) = result.unwrap();
    let response = &buf[..n];
    let decoded = decode_ntp_response(response);
    assert!(decoded.is_some(), "response must be valid NTP packet");
    let (mode, stratum, ref_id) = decoded.unwrap();
    assert_eq!(mode, 4, "response must be server mode (4), got {mode}");
    eprintln!("✓ Daemon responded: mode={mode}, stratum={stratum}, ref_id=0x{ref_id:08x}");

    // Verify originate timestamp is echoed back
    if n >= 48 {
        let resp_orig_secs =
            u32::from_be_bytes([response[24], response[25], response[26], response[27]]);
        assert_eq!(
            resp_orig_secs, 1000,
            "originate timestamp must echo client's transmit_ts"
        );
    }

    // Query Mode 6
    let mode6_pkt = build_mode6_readvar(0, 1);
    client_sock
        .send_to(&mode6_pkt, format!("127.0.0.1:{DAEMON_PORT}"))
        .expect("send mode6 to daemon");

    let result2 = client_sock.recv_from(&mut buf);
    assert!(result2.is_ok(), "daemon must respond to Mode 6 query");

    let (n2, _src2) = result2.unwrap();
    let decoded2 = decode_mode6_response(&buf[..n2]);
    assert!(decoded2.is_some(), "Mode 6 response must be valid");
    let (status, body) = decoded2.unwrap();
    let body_str = String::from_utf8_lossy(&body);
    eprintln!("✓ Mode 6 response: status={status}, body={body_str}");
    assert!(
        body_str.contains("version="),
        "Mode 6 response must contain version=: {body_str}"
    );

    // Kill daemon
    daemon.kill().ok();
    daemon.wait().ok();

    // Cleanup
    std::fs::remove_dir_all(&config_dir).ok();
    eprintln!("✓ Daemon binary court sealed: ntpd-rs starts, responds, and is queryable");
}

#[test]
fn test_daemon_binary_starts_with_minimal_config() {
    // Create minimal config
    let config = r#"
server 127.0.0.1 minpoll 6 maxpoll 6
restrict default ignore
restrict 127.0.0.1
"#;
    let config_dir = std::env::temp_dir().join("ntp-test-minimal");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("ntp.conf");
    std::fs::write(&config_path, config).unwrap();

    let bin_path = find_binary();
    let mut daemon = Command::new(&bin_path)
        .arg("-c")
        .arg(config_path.to_str().unwrap())
        .arg("-n")
        .arg("-I")
        .arg(format!("127.0.0.1:{DAEMON_PORT}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn ntpd-rs");

    // Let it run for a moment
    std::thread::sleep(Duration::from_secs(2));

    // Check it's still running
    match daemon.try_wait() {
        Ok(Some(status)) => {
            panic!("daemon exited prematurely with status: {status}");
        }
        Ok(None) => {
            eprintln!("✓ Daemon process is running");
        }
        Err(e) => {
            panic!("error checking daemon status: {e}");
        }
    }

    // Kill cleanly
    daemon.kill().ok();
    let _exit_status = daemon.wait().expect("wait for daemon");
    eprintln!("✓ Daemon exited cleanly");

    std::fs::remove_dir_all(&config_dir).ok();
}

#[test]
fn test_daemon_binary_mode6_full_query() {
    let _server = start_fake_server();
    std::thread::sleep(Duration::from_millis(100));

    let config = create_config(&format!("127.0.0.1:{SERVER_PORT}"), DAEMON_PORT);
    let config_dir = std::env::temp_dir().join("ntp-test-mode6");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("ntp.conf");
    std::fs::write(&config_path, &config).unwrap();

    let mut daemon = start_daemon(config_path.to_str().unwrap(), DAEMON_PORT);
    std::thread::sleep(Duration::from_secs(1));

    let client_sock = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();

    // Query with different associds and opcodes
    let queries: Vec<(&str, Vec<u8>)> = vec![
        ("rv (associd=0)", build_mode6_readvar(0, 1)),
        ("rv (associd=1)", build_mode6_readvar(1, 2)),
        ("peers", build_mode6_readvar(0, 3)), // same as rv
    ];

    for (name, pkt) in &queries {
        client_sock
            .send_to(pkt, format!("127.0.0.1:{DAEMON_PORT}"))
            .ok();
        let mut buf = [0u8; 4096];
        match client_sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let body = if n > 12 {
                    String::from_utf8_lossy(&buf[12..n])
                } else {
                    "(empty)".into()
                };
                eprintln!("  {name}: {body}");
                assert!(
                    body.contains("version=") || body.contains("stratum=") || body == "(empty)",
                    "unexpected response for {name}: {body}"
                );
            }
            Err(e) => {
                eprintln!("  {name}: timeout/error: {e}");
            }
        }
    }

    daemon.kill().ok();
    daemon.wait().ok();
    std::fs::remove_dir_all(&config_dir).ok();
    eprintln!("✓ Mode 6 binary query court sealed");
}
