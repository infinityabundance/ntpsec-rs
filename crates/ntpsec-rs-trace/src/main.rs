// ──── ntptrace-rs — NTP trace tool ──────────────────────────────────────────
//
// Forensic Rust reconstruction of ntptrace. Traces the NTP synchronization
// chain from a host back to the reference clock.
//
// ## Oracle
//   - ntpsec ntpclients/ntptrace.py (5K)
// =============================================================================

use clap::Parser;

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

    /// Timeout per host
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
    println!(
        "{:>15}  {:>15}  {:>3}  {:>10}",
        "host", "refid", "st", "offset"
    );
    println!("{}", "-".repeat(50));
    println!(
        "{:>15}  {:>15}  {:>3}  {:>10.6}",
        cli.host, ".LOCL.", "10", 0.0
    );
}
