// ──── ntplogtemp-rs — NTP temperature logger ────────────────────────────────
//
// Forensic Rust reconstruction of ntplogtemp. Logs temperature data for
// environmental compensation.
//
// ## Oracle
//   - ntpsec ntpclients/ntplogtemp.py (10K)
// =============================================================================

use clap::Parser;

/// NTP temperature logger — forensic Rust reconstruction of ntplogtemp.
#[derive(Parser, Debug)]
#[command(name = "ntplogtemp-rs", about = "NTP temperature logger", version)]
struct Cli {
    /// Log file path
    #[arg(short = 'o', long, default_value = "/var/log/ntp/temp.log")]
    output: String,

    /// Poll interval in seconds
    #[arg(short = 'p', long, default_value = "300")]
    interval: u32,

    /// Daemonize
    #[arg(short = 'd', long)]
    daemonize: bool,

    /// Temperature sensor device
    #[arg(short = 's', long)]
    sensor: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    println!("ntplogtemp-rs v{} — Temperature logger (Rust)", env!("CARGO_PKG_VERSION"));
    println!("Log: {}", cli.output);
    println!("(Stub — temperature logging in Phase 2)");
}
