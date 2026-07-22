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

use std::time::Duration;

use clap::Parser;
use ntpsec_rs_core::ntpdig_proto::*;

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

    println!(
        "ntpdig-rs v{} — NTP query tool (Rust)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Querying {}:{}", cli.server, cli.port);
    println!();

    let mut client = NtpDigClient::new(Duration::from_secs(cli.timeout as u64), cli.samples);

    let result = match client.query(&cli.server, cli.port) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    };

    // --- Main output table ---
    println!("     remote           refid      st t when poll reach   delay   offset  jitter");
    println!("==============================================================================");
    println!(
        "*{:<15}  {:<12} {:2} u    -   64    1  {:>7.3}  {:>7.3}  {:>7.3}",
        result.remote,
        result.refid_string,
        result.stratum,
        result.delay * 1000.0,
        result.offset * 1000.0,
        result.dispersion * 1000.0,
    );
    println!();

    // --- Time line ---
    println!(
        "time: {}Z, clock offset: {:.6}s",
        result.when, result.offset
    );

    // --- Verbose details ---
    if cli.verbose {
        println!();
        println!("  Verbose details:");
        println!("    Root delay:      {:.6} s", result.root_delay);
        println!("    Root dispersion: {:.6} s", result.root_dispersion);
        println!(
            "    Precision:       2^{} ({:.6} s)",
            result.precision,
            2.0f64.powi(result.precision as i32)
        );
        println!("    Leap indicator:  {:?}", result.leap);
        println!("    Round-trip delay: {:.6} s", result.delay);
        println!("    Dispersion:      {:.6} s", result.dispersion);
    }
}
