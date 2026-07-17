// ──── ntpsweep-rs — NTP network sweep tool ──────────────────────────────────
//
// Forensic Rust reconstruction of ntpsweep. Sweeps a network subnet for
// NTP servers.
//
// ## Oracle
//   - ntpsec ntpclients/ntpsweep.py (8K)
// =============================================================================

use clap::Parser;

/// NTP network sweep tool — forensic Rust reconstruction of ntpsweep.
#[derive(Parser, Debug)]
#[command(name = "ntpsweep-rs", about = "NTP network sweep tool", version)]
struct Cli {
    /// Network to sweep (CIDR)
    network: Option<String>,

    /// Host list file
    #[arg(short = 'f', long)]
    host_file: Option<String>,

    /// Timeout per host
    #[arg(short = 't', long, default_value = "5")]
    timeout: u32,

    /// Maximum hosts
    #[arg(short = 'm', long, default_value = "256")]
    max_hosts: u32,
}

fn main() {
    let cli = Cli::parse();
    println!("ntpsweep-rs v{} — Network sweep tool (Rust)", env!("CARGO_PKG_VERSION"));
    if let Some(net) = &cli.network {
        println!("Sweeping: {}", net);
    }
    println!("(Stub — network sweep in Phase 2)");
}
