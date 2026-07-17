// ──── ntpmon-rs — NTP real-time monitor ─────────────────────────────────────
//
// Forensic Rust reconstruction of ntpmon. Real-time display of NTP
// daemon status.
//
// ## Oracle
//   - ntpsec ntpclients/ntpmon.py (21K)
// =============================================================================

use clap::Parser;

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
    println!("ntpmon-rs v{} — NTP monitor (Rust)", env!("CARGO_PKG_VERSION"));
    println!("Monitoring: {}:{} (every {}s)", cli.host, cli.port, cli.interval);
    println!("(Stub — curses TUI in Phase 2)");
}
