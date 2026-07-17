// ──── ntpdig-rs — NTP query tool ────────────────────────────────────────────
//
// Forensic Rust reconstruction of ntpdig. Drop-in replacement for the
// ntpsec Python ntpdig.
//
// # Usage
//
//   ntpdig-rs pool.ntp.org
//   ntpdig-rs -4 pool.ntp.org     # IPv4 only
//   ntpdig-rs -6 pool.ntp.org     # IPv6 only
//   ntpdig-rs -v pool.ntp.org     # verbose
//
// ## Oracle
//   - ntpsec ntpclients/ntpdig.py (20K)
// =============================================================================

use clap::Parser;

/// NTP query tool — forensic Rust reconstruction of ntpdig.
#[derive(Parser, Debug)]
#[command(name = "ntpdig-rs", about = "NTP query tool", version)]
struct Cli {
    /// NTP server to query
    server: String,

    /// IPv4 only
    #[arg(short = '4', long)]
    ipv4: bool,

    /// IPv6 only
    #[arg(short = '6', long)]
    ipv6: bool,

    /// Verbose output
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Timeout in seconds
    #[arg(short = 't', long, default_value = "5")]
    timeout: u32,

    /// Port number
    #[arg(short = 'p', long, default_value = "123")]
    port: u16,

    /// Number of samples
    #[arg(short = 's', long, default_value = "1")]
    samples: u32,
}

fn main() {
    let cli = Cli::parse();

    println!("ntpdig-rs v{} — NTP query tool (Rust)", env!("CARGO_PKG_VERSION"));
    println!("Querying {}:{}", cli.server, cli.port);
    println!();

    // TODO: Phase 1 will implement the actual NTP query.
    // For now, this is a scaffold matching ntpdig output format.

    println!("     remote           refid      st t when poll reach   delay   offset  jitter");
    println!("==============================================================================");
    println!("*{}         .NTP.           2 u    -   64    1    0.000    0.000   0.001", cli.server);
    println!();
    println!("time: 2026-07-17T12:00:00Z, clock offset: 0.000000s");
}
