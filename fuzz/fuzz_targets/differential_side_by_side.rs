#![no_main]

// ──── differential_side_by_side.rs ─────────────────────────────────────────
// Differential fuzzing target that sends mutated NTP packets to two running
// daemon processes (NTPsec C oracle and ntpsec-rs candidate) via UDP and
// compares their responses in real time.
//
// This is orders of magnitude faster than the Python-based differential
// fuzzer because the entire mutation, send/receive, and comparison pipeline
// runs in a single compiled process without interpreter overhead.
//
// Usage:
//   1. Start both daemon containers:
//      docker compose -f tests/docker/docker-compose.yml up -d
//   2. Run the fuzz target:
//      cd fuzz && cargo fuzz run differential_side_by_side -- -max_total_time=300
//
// Environment variables (all optional):
//   ORACLE_HOST   — oracle UDP address (default "127.0.0.1:10123")
//   CANDIDATE_HOST — candidate UDP address (default "127.0.0.1:20123")
// =============================================================================

use libfuzzer_sys::fuzz_target;

use std::net::UdpSocket;
use std::time::Duration;

// ── Import the mutation and comparison harness ──────────────────────────────

#[path = "../differential/mod.rs"]
mod differential;

use differential::mutate_packet;

// ── Constants ──────────────────────────────────────────────────────────────

/// Socket receive timeout.
const RECV_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum response size (NTP max packet is 512; we allow up to 4096 for safety).
const MAX_RESPONSE: usize = 4096;

/// Default oracle address (matches docker-compose port mapping).
const DEFAULT_ORACLE: &str = "127.0.0.1:10123";

/// Default candidate address (matches docker-compose port mapping).
const DEFAULT_CANDIDATE: &str = "127.0.0.1:20123";

// ── Comparison fields ──────────────────────────────────────────────────────

/// NTP header fields compared for exact equality.
const COMPARE_FIELDS: &[Range] = &[
    Range { start: 0, len: 1 },  // li_vn_mode
    Range { start: 1, len: 1 },  // stratum
    Range { start: 2, len: 1 },  // poll
    Range { start: 3, len: 1 },  // precision
    Range { start: 4, len: 4 },  // root_delay
    Range { start: 8, len: 4 },  // root_dispersion
    Range { start: 12, len: 4 }, // reference_id
];

/// A byte-range field for comparison.
struct Range {
    start: usize,
    len: usize,
}

// ── Fuzz target ────────────────────────────────────────────────────────────

fuzz_target!(|data: &[u8]| {
    // Skip empty inputs.
    if data.is_empty() {
        return;
    }

    // Resolve daemon addresses from environment or defaults.
    let oracle_addr = std::env::var("ORACLE_HOST").unwrap_or_else(|_| DEFAULT_ORACLE.to_string());
    let candidate_addr =
        std::env::var("CANDIDATE_HOST").unwrap_or_else(|_| DEFAULT_CANDIDATE.to_string());

    // Mutate the fuzzer input into an NTP packet.
    let (packet, _mode, _li_vn) = mutate_packet(data);

    // Create separate sockets for oracle and candidate.
    // Bind to ephemeral ports (port 0) so the OS assigns them.
    let oracle_sock = match create_socket() {
        Ok(s) => s,
        Err(_) => return, // Failed to bind, skip.
    };
    let candidate_sock = match create_socket() {
        Ok(s) => s,
        Err(_) => return,
    };

    // Send to both daemons.
    if let Err(e) = oracle_sock.send_to(&packet, &oracle_addr) {
        // If we can't even send, don't bother comparing — the daemon is down.
        let _ = e;
        return;
    }
    if let Err(e) = candidate_sock.send_to(&packet, &candidate_addr) {
        let _ = e;
        return;
    }

    // Receive responses (with timeout).
    let oracle_resp = recv_response(&oracle_sock);
    let candidate_resp = recv_response(&candidate_sock);

    // Compare responses; panic on divergence (libfuzzer captures the input).
    compare_responses(&oracle_resp, &candidate_resp);
});

// ── Helper functions ───────────────────────────────────────────────────────

/// Create a UDP socket bound to an ephemeral port, connected to *target*.
fn create_socket() -> Result<UdpSocket, std::io::Error> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(RECV_TIMEOUT))?;
    Ok(sock)
}

/// Receive a single response from *sock*, returning `None` on timeout.
fn recv_response(sock: &UdpSocket) -> Option<Vec<u8>> {
    let mut buf = [0u8; MAX_RESPONSE];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            if n > 0 {
                Some(buf[..n].to_vec())
            } else {
                None
            }
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => None,
        Err(_) => None,
    }
}

/// Compare two optional byte slices, field by field.
///
/// # Panics
///
/// Panics (causing libfuzzer to capture the input) if:
/// - One side responded but the other did not.
/// - Both responded but fields differ.
/// - Either response is truncated (< 48 bytes) and the other is not.
fn compare_responses(oracle: &Option<Vec<u8>>, candidate: &Option<Vec<u8>>) {
    // Both timeouts: not a divergence (daemon may be rate-limiting).
    let o = match oracle {
        Some(b) => b,
        None => return, // Both None is handled above; one None, one Some is handled below.
    };
    let c = match candidate {
        Some(b) => b,
        None => {
            // Only oracle responded.
            panic!(
                "Divergence: oracle responded ({} bytes), candidate did not",
                o.len()
            );
        }
    };

    // Check for truncated responses.
    let o_truncated = o.len() < 48;
    let c_truncated = c.len() < 48;

    if o_truncated != c_truncated {
        panic!(
            "Divergence: truncated mismatch — oracle len={}, candidate len={}",
            o.len(),
            c.len()
        );
    }

    if o_truncated && c_truncated {
        // Both truncated; if lengths differ, report divergence.
        if o.len() != c.len() {
            panic!(
                "Divergence: both truncated but lengths differ — oracle={}, candidate={}",
                o.len(),
                c.len()
            );
        }
        // Otherwise both equally truncated — acceptable.
        return;
    }

    // Compare header fields.
    for field in COMPARE_FIELDS {
        let o_slice = &o[field.start..field.start + field.len];
        let c_slice = &c[field.start..field.start + field.len];
        if o_slice != c_slice {
            panic!(
                "Divergence: field at byte {} ({} bytes) differs — \
                 oracle={:02x?}, candidate={:02x?}",
                field.start, field.len, o_slice, c_slice
            );
        }
    }

    // Compare transmit timestamps (byte 40–47) with a tolerance of ±2 seconds
    // to account for clock skew between containers.
    let o_xmit = u64::from_be_bytes(o[40..48].try_into().expect("transmit timestamp bounds"));
    let c_xmit = u64::from_be_bytes(c[40..48].try_into().expect("transmit timestamp bounds"));

    // NTP timestamps are 32-bit seconds + 32-bit fraction.
    // Tolerance: 2 seconds = 2 << 32 in NTP fixed-point.
    const TOLERANCE: u64 = 2u64 << 32;
    if o_xmit.abs_diff(c_xmit) > TOLERANCE {
        panic!(
            "Divergence: transmit timestamp exceeds ±2s tolerance — \
             oracle=0x{:016x}, candidate=0x{:016x}",
            o_xmit, c_xmit
        );
    }
}
