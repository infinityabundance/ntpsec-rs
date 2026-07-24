// ──── ntptrace-rs — NTP trace tool ──────────────────────────────────────────
//
// Forensic Rust reconstruction of ntptrace. Traces the NTP synchronization
// chain from a host back to the reference clock. Recursively follows the
// sys.peer chain, printing stratum, offset, and delay for each hop.
//
// ## Oracle
//   - ntpsec ntpclients/ntptrace.py (5K)
// =============================================================================

use clap::Parser;
use ntpsec_rs_core::control_client::*;

/// NTP trace tool — forensic Rust reconstruction of ntptrace.
#[derive(Parser, Debug)]
#[command(
    name = "ntptrace-rs",
    about = "Trace NTP synchronization chain to the reference clock source",
    version
)]
struct Cli {
    /// Host to start tracing from
    #[arg(default_value = "127.0.0.1")]
    host: String,

    /// Maximum trace depth
    #[arg(short = 'd', long, default_value = "10")]
    max_depth: u32,

    /// Timeout per host in seconds
    #[arg(short = 't', long, default_value = "5")]
    timeout: u32,
}

/// Print the trace header matching real ntptrace output format.
fn print_header() {
    println!(
        " {:>15}  {:>15}  {:>2}  {:>10}  {:>10}",
        "host", "refid", "st", "offset", "delay"
    );
    println!("{}", "-".repeat(60));
}

/// Print a single trace hop matching real ntptrace output format.
fn print_hop(host: &str, refid: &str, stratum: u8, offset: f64, delay: f64, depth: u32) {
    let indent = "  ".repeat(depth as usize);
    println!(
        "{}{:>15}  {:>15}  {:>2}  {:>10.6}  {:>10.6}",
        indent, host, refid, stratum, offset, delay
    );
}

/// Format a NTP timestamp value in ntpq style (seconds.fraction).
/// If the value contains a '.', use it as-is; otherwise append ".0".
fn fmt_ntp_value(val: &str) -> String {
    if val.contains('.') {
        val.to_string()
    } else {
        format!("{}.0", val)
    }
}

fn main() {
    let cli = Cli::parse();
    println!(
        "ntptrace-rs v{} — NTP trace tool (Rust)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Tracing from: {} (max depth: {})", cli.host, cli.max_depth);
    println!();

    print_header();

    // Start tracing from the given host
    trace_host(&cli.host, &cli.host, 0, cli.max_depth, cli.timeout);
}

/// Recursively trace a host in the NTP synchronization chain.
///
/// Queries the daemon at `host` for its system variables, displays its
/// current peer (the one it's synchronized to), and if that peer has a
/// lower stratum, follows the chain by querying that peer.
///
/// Handles dead hosts (timeout, connection refused) gracefully by
/// reporting the error and stopping the trace at that point.
fn trace_host(current_host: &str, original_host: &str, depth: u32, max_depth: u32, timeout: u32) {
    if depth > max_depth {
        eprintln!("ntptrace-rs: maximum depth ({max_depth}) reached at {current_host}");
        return;
    }

    // Create a fresh client for each query to avoid sequence conflicts.
    let mut client = ControlClient::new(timeout, 1);

    // ── Query system variables ─────────────────────────────────────────
    let sys = match client.read_system_vars(current_host, 123) {
        Ok(sys) => sys,
        Err(QueryError::Timeout) => {
            eprintln!("ntptrace-rs: timeout querying {current_host}");
            print_hop(current_host, "TIMEOUT", 16, 0.0, 0.0, depth);
            return;
        }
        Err(QueryError::Network(e)) => {
            eprintln!("ntptrace-rs: connection failed to {current_host}: {e}");
            print_hop(current_host, "UNREACH", 16, 0.0, 0.0, depth);
            return;
        }
        Err(e) => {
            eprintln!("ntptrace-rs: error querying {current_host}: {e}");
            print_hop(current_host, "ERROR", 16, 0.0, 0.0, depth);
            return;
        }
    };

    let stratum = sys.stratum();
    let refid = sys.get("refid").unwrap_or("").to_string();
    let offset = sys
        .get("offset")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let delay = sys
        .get("delay")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);

    print_hop(current_host, &refid, stratum, offset, delay, depth);

    // If stratum >= 15, we've reached the end of the chain (unsynchronized).
    // Refclock sources (stratum 0-1) or references below stratum 15 continue.
    if stratum >= 15 {
        return;
    }

    // ── Find the system peer (associd of the synchronization source) ──
    let syspeer = match sys.get("syspeer") {
        Some(peer_id) => peer_id.parse::<u16>().ok(),
        None => sys.get("associd").and_then(|v| v.parse::<u16>().ok()),
    };

    let peer_host = match syspeer {
        Some(associd) => {
            // Read peer variables to get the peer's address
            match client.read_peer_vars(current_host, 123, associd) {
                Ok(pv) => pv.get("srcadr").map(|s| s.to_string()),
                Err(_) => None,
            }
        }
        None => None,
    };

    // ── Follow the chain ──────────────────────────────────────────────
    if let Some(next_host) = peer_host {
        // Clean up the host string (remove any port suffix, brackets)
        let next_host = next_host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(':')
            .next()
            .unwrap_or(&next_host)
            .to_string();

        // Avoid infinite loops
        if next_host == current_host || next_host == original_host {
            return;
        }

        trace_host(&next_host, original_host, depth + 1, max_depth, timeout);
    }
}
