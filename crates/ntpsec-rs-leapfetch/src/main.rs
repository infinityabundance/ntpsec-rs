// ──── ntpleapfetch-rs — NTP leap second fetcher ─────────────────────────────
//
// Forensic Rust reconstruction of ntpleapfetch. Downloads leap second
// files from NIST/IERS and installs them.
//
// ## Oracle
//   - ntpsec ntpclients/ntpleapfetch (shell, 14K)
// =============================================================================

use clap::Parser;

/// NTP leap second fetcher — forensic Rust reconstruction of ntpleapfetch.
#[derive(Parser, Debug)]
#[command(name = "ntpleapfetch-rs", about = "NTP leap second fetcher", version)]
struct Cli {
    /// Leap file output path
    #[arg(short = 'o', long, default_value = "/var/lib/ntp/leap-seconds")]
    output: String,

    /// URL for leap second file
    #[arg(short = 'u', long, default_value = "https://www.ietf.org/timezones/data/leap-seconds.list")]
    url: String,

    /// Force download even if file is current
    #[arg(short = 'f', long)]
    force: bool,

    /// Verbose output
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    println!("ntpleapfetch-rs v{} — Leap second fetcher (Rust)", env!("CARGO_PKG_VERSION"));
    println!("URL: {}", cli.url);
    println!("Output: {}", cli.output);
    println!("(Stub — download functionality in Phase 2)");
}
