// ──── ntploggps-rs — NTP GPS logger ─────────────────────────────────────────
//
// Forensic Rust reconstruction of ntploggps. Logs GPS statistics.
//
// ## Oracle
//   - ntpsec ntpclients/ntploggps.py (8K)
// =============================================================================

use clap::Parser;

/// NTP GPS logger — forensic Rust reconstruction of ntploggps.
#[derive(Parser, Debug)]
#[command(name = "ntploggps-rs", about = "NTP GPS logger", version)]
struct Cli {
    /// Log file path
    #[arg(short = 'o', long, default_value = "/var/log/ntp/gps.log")]
    output: String,

    /// Poll interval in seconds
    #[arg(short = 'p', long, default_value = "60")]
    interval: u32,

    /// Daemonize
    #[arg(short = 'd', long)]
    daemonize: bool,
}

fn main() {
    let cli = Cli::parse();
    println!(
        "ntploggps-rs v{} — GPS logger (Rust)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Log: {}", cli.output);
    println!("(Stub — GPS logging in Phase 2)");
}
