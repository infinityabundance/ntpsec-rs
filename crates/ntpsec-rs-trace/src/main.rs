// ──── ntptrace-rs — NTP trace tool ──────────────────────────────────────────
//
// Forensic Rust reconstruction of ntptrace. Traces the NTP synchronization
// chain from a host back to the reference clock.
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
    about = "Trace NTP synchronization chain",
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

fn main() {
    let cli = Cli::parse();
    println!(
        "ntptrace-rs v{} — NTP trace tool (Rust)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Tracing from: {} (max depth: {})", cli.host, cli.max_depth);
    println!();

    // Column headers
    println!(
        "{:>15}  {:>15}  {:>3}  {:>10}",
        "host", "refid", "st", "offset"
    );
    println!("{}", "-".repeat(50));

    // Start tracing from the given host
    trace_host(&cli.host, &cli.host, 0, cli.max_depth, cli.timeout);
}

/// Recursively trace a host in the NTP synchronization chain.
///
/// Queries the daemon at `host` for its system variables, displays its
/// current peer (the one it's synchronized to), and if that peer has a
/// lower stratum, follows the chain by querying that peer.
fn trace_host(current_host: &str, original_host: &str, depth: u32, max_depth: u32, timeout: u32) {
    if depth > max_depth {
        return;
    }

    // Create a fresh client for each query to avoid sequence conflicts.
    let mut client = ControlClient::new(timeout, 1);

    // ── Query system variables ─────────────────────────────────────────
    let sys = match client.read_system_vars(current_host, 123) {
        Ok(sys) => sys,
        Err(_) => {
            eprintln!("ERROR: could not query {current_host}");
            return;
        }
    };

    let stratum = sys.stratum();
    let refid = sys.get("refid").unwrap_or("").to_string();
    let offset = sys
        .get("offset")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);

    println!(
        "{:>15}  {:>15}  {:>3}  {:>10.6}",
        current_host, refid, stratum, offset
    );

    // If stratum >= 15, we've reached the end of the chain.
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
        // Clean up the host string (remove any port suffix)
        let next_host = next_host.trim_start_matches('[').trim_end_matches(']');
        let next_host = next_host.split(':').next().unwrap_or(next_host);
        let next_host = next_host.to_string();

        // Avoid infinite loops
        if next_host != current_host && next_host != original_host {
            trace_host(&next_host, original_host, depth + 1, max_depth, timeout);
        }
    }
}
