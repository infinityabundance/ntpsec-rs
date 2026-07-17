// ──── ntpviz-rs — NTP visualization tool ────────────────────────────────────
//
// Forensic Rust reconstruction of ntpviz. Generates plots from NTP
// statistics files (loopstats, peerstats, clockstats).
//
// ## Oracle
//   - ntpsec ntpclients/ntpviz.py (76K)
// =============================================================================

use clap::Parser;

/// NTP visualization tool — forensic Rust reconstruction of ntpviz.
#[derive(Parser, Debug)]
#[command(name = "ntpviz-rs", about = "NTP visualization tool", version)]
struct Cli {
    /// Statistics directory
    #[arg(short = 's', long, default_value = "/var/log/ntpstats")]
    statsdir: String,

    /// Output directory for plots
    #[arg(short = 'o', long, default_value = "/var/www/ntp")]
    output: String,

    /// Type of plot: loop, peer, clock, all
    #[arg(short = 't', long, default_value = "all")]
    plot_type: String,

    /// Days of data to include
    #[arg(short = 'd', long, default_value = "7")]
    days: u32,

    /// Generate HTML index page
    #[arg(short = 'i', long)]
    html: bool,
}

fn main() {
    let cli = Cli::parse();
    println!("ntpviz-rs v{} — NTP visualization tool (Rust)", env!("CARGO_PKG_VERSION"));
    println!("Stats: {} -> Output: {}", cli.statsdir, cli.output);
    println!("(Stub — plotting in Phase 2)");
}
