// ──── ntpmon-rs — NTP real-time monitor ─────────────────────────────────────
//
// Forensic Rust reconstruction of ntpmon. Real-time display of NTP
// daemon status.
//
// ## Oracle
//   - ntpsec ntpclients/ntpmon.py (21K)
// =============================================================================

use clap::Parser;
use ntpsec_rs_core::control_client::*;

/// NTP real-time monitor — forensic Rust reconstruction of ntpmon.
#[derive(Parser, Debug)]
#[command(name = "ntpmon-rs", about = "NTP real-time monitor", version)]
struct Cli {
    /// Host to monitor
    #[arg(default_value = "127.0.0.1")]
    host: String,

    /// Port
    #[arg(short = 'p', long, default_value = "123")]
    port: u16,

    /// Refresh interval in seconds
    #[arg(short = 'r', long, default_value = "2")]
    interval: u32,

    /// Number of iterations (0 = infinite)
    #[arg(short = 'n', long, default_value = "0")]
    count: u32,
}

fn main() {
    let cli = Cli::parse();
    println!(
        "ntpmon-rs v{} — NTP monitor (Rust)",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "Monitoring: {}:{} (every {}s)",
        cli.host, cli.port, cli.interval
    );

    // Create a control client with a 5-second timeout.
    let mut client = ControlClient::new(5, 1);

    let max_iterations = if cli.count == 0 { u32::MAX } else { cli.count };

    for iter in 0..max_iterations {
        // ── Query system variables ─────────────────────────────────────
        match client.read_system_vars(&cli.host, cli.port) {
            Ok(sys) => {
                let stratum = sys.stratum();
                let leap = sys.leap_str().to_string();
                let display = sys.get("display").unwrap_or("").to_string();
                let offset = sys
                    .get("offset")
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let freq = sys
                    .get("frequency")
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0);

                println!(
                    "[{}] stratum={} leap={} offset={:.6} freq={:.3} {}",
                    iter + 1,
                    stratum,
                    leap,
                    offset,
                    freq,
                    display
                );
            }
            Err(e) => {
                eprintln!("ERROR reading system variables: {e}");
                break;
            }
        }

        // ── Query associations ─────────────────────────────────────────
        match client.read_associations(&cli.host, cli.port) {
            Ok(assocs) => {
                let reachable = assocs.iter().filter(|a| a.reachable).count();
                let configured = assocs.iter().filter(|a| a.configured).count();
                println!(
                    "  associations: {} configured, {} reachable",
                    configured, reachable
                );

                // Show each reachable peer's stratum and offset
                for a in &assocs {
                    if !a.configured && !a.reachable {
                        continue;
                    }
                    if let Ok(pv) = client.read_peer_vars(&cli.host, cli.port, a.associd) {
                        let peer_stratum = pv.stratum();
                        let offset = pv
                            .get("offset")
                            .and_then(|v| v.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        let delay = pv
                            .get("delay")
                            .and_then(|v| v.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        let remote = pv.get("srcadr").unwrap_or("").to_string();
                        println!(
                            "    associd={} remote={} stratum={} offset={:.6} delay={:.6}",
                            a.associd, remote, peer_stratum, offset, delay
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("ERROR reading associations: {e}");
                break;
            }
        }

        // ── Sleep or exit ──────────────────────────────────────────────
        if iter + 1 >= max_iterations {
            break;
        }

        std::thread::sleep(std::time::Duration::from_secs(cli.interval as u64));
    }
}
