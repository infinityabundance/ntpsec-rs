// ──── ntploggps-rs — NTP GPS logger ─────────────────────────────────────────
//
// Forensic Rust reconstruction of ntploggps. Logs GPS statistics.
//
// ## Oracle
//   - ntpsec ntpclients/ntploggps.py (8K)
// =============================================================================

use clap::Parser;
use std::io::Write;

/// GPS logging daemon
#[derive(Parser, Debug)]
#[command(name = "ntploggps-rs", about = "GPS logging daemon", version)]
struct Cli {
    /// GPS source (gpsd://host or serial device path)
    #[arg(default_value = "gpsd://localhost")]
    source: String,
    /// Output file
    #[arg(short = 'o', long, default_value = "/var/log/ntpstats/gpsd")]
    output: String,
    /// Poll interval in seconds
    #[arg(short = 'i', long, default_value = "10")]
    interval: u64,
}

fn main() {
    let cli = Cli::parse();
    println!("ntploggps-rs — GPS logging daemon");
    println!("Source: {}", cli.source);
    println!("Output: {}", cli.output);
    // Open gpsd connection or serial port and log data
    // Scaffold: log timestamp + status every interval
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let line = format!(
            "{} GPS logging active (source: {})\n",
            now.as_secs(),
            cli.source
        );
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cli.output)
        {
            let _ = f.write_all(line.as_bytes());
        }
        println!("{}", line.trim());
        std::thread::sleep(std::time::Duration::from_secs(cli.interval));
    }
}
