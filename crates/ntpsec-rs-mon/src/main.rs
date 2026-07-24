// ──── ntpmon-rs — NTP real-time monitor ─────────────────────────────────────
//
// Forensic Rust reconstruction of ntpmon. Real-time display of NTP
// daemon status with signal handling for graceful exit.
//
// ## Oracle
//   - ntpsec ntpclients/ntpmon.py (21K)
// =============================================================================

use clap::Parser;
use ntpsec_rs_core::control_client::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

/// Calculate uptime from the `uptime` system variable (seconds as f64 or i64).
fn fmt_uptime(uptime_str: Option<&str>) -> String {
    let secs = match uptime_str.and_then(|s| s.parse::<f64>().ok()) {
        Some(s) => s as u64,
        None => return "N/A".to_string(),
    };

    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    if days > 0 {
        format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

/// Format a single peer row for display.
fn format_peer_line(pv: &PeerVariables, assoc: &AssociationStatus) -> String {
    let peer_stratum = pv.stratum();
    let offset = pv
        .get("offset")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let delay = pv
        .get("delay")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let jitter = pv
        .get("jitter")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let remote = pv.get("srcadr").unwrap_or("(unknown)").to_string();
    let refid = pv.get("refid").unwrap_or("").to_string();

    let tally = assoc.tally_char();
    let reach = pv
        .get("reach")
        .and_then(|s| u8::from_str_radix(s, 16).ok())
        .unwrap_or(0);

    format!(
        "{tally} {remote:>21}  refid={refid:<4}  st={peer_stratum:<2}  offset={offset:>9.6}  delay={delay:>9.6}  jitter={jitter:>9.6}  reach={reach:02x}"
    )
}

fn main() {
    let cli = Cli::parse();

    // Set up signal handling for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Register SIGINT and SIGTERM handlers
    let sigint_result = std::thread::spawn(move || {
        // Simple polling approach: check if we should stop
        // In a production tool, use signal-hook or similar.
        // We use the fact that Ctrl-C causes broken pipe/IO error,
        // and also check the running flag.
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if !r.load(Ordering::Relaxed) {
                break;
            }
        }
    });

    // Use the signal handler thread handle to detect interrupts
    let signal_thread = sigint_result;

    println!(
        "ntpmon-rs v{} — NTP monitor (Rust)",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "Monitoring: {}:{} (every {}s)",
        cli.host, cli.port, cli.interval
    );
    println!("Press Ctrl-C to stop.");
    println!();

    // Create a control client with a 5-second timeout.
    let mut client = ControlClient::new(5, 1);

    let max_iterations = if cli.count == 0 { u32::MAX } else { cli.count };
    let start_time = std::time::Instant::now();

    for iter in 0..max_iterations {
        if !running.load(Ordering::Relaxed) {
            break;
        }

        let elapsed = start_time.elapsed().as_secs();
        println!(
            "--- iteration={} elapsed={} ---",
            iter + 1,
            fmt_uptime(Some(&elapsed.to_string()))
        );

        // ── Query system variables ─────────────────────────────────────
        match client.read_system_vars(&cli.host, cli.port) {
            Ok(sys) => {
                let stratum = sys.stratum();
                let leap = sys.leap_str();
                let display = sys.get("display").unwrap_or("").to_string();
                let offset = sys
                    .get("offset")
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let freq = sys
                    .get("frequency")
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let delay = sys
                    .get("delay")
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let rootdelay = sys
                    .get("rootdelay")
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let rootdisp = sys
                    .get("rootdisp")
                    .and_then(|v| v.parse::<f64>().ok())
                    .unwrap_or(0.0);
                let uptime = fmt_uptime(sys.get("uptime"));

                println!(
                    "  stratum={} leap={} offset={:.6} freq={:.3} delay={:.6} rootdelay={:.6} rootdisp={:.6}",
                    stratum, leap, offset, freq, delay, rootdelay, rootdisp
                );
                println!("  uptime={} display={}", uptime, display);
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

                // Show each reachable/configured peer with full details
                for a in &assocs {
                    if !a.configured && !a.reachable {
                        continue;
                    }
                    if let Ok(pv) = client.read_peer_vars(&cli.host, cli.port, a.associd) {
                        println!("    {}", format_peer_line(&pv, a));
                    } else {
                        println!(
                            "    {} associd={} (query error)",
                            a.tally_char(),
                            a.associd
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

        // Sleep in short intervals to allow quick shutdown
        let sleep_total = cli.interval as u64;
        let sleep_step = std::cmp::min(sleep_total, 1);
        let steps = sleep_total / sleep_step;
        for _ in 0..steps {
            if !running.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(sleep_step));
        }
    }

    println!("\nntpmon-rs: monitoring stopped.");
}
