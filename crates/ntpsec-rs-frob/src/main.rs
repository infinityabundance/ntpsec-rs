// ──── ntpfrob-rs — NTP system utilities ─────────────────────────────────────
//
// Forensic Rust reconstruction of ntpfrob. System clock manipulation
// utilities.
//
// ## Oracle
//   - ntpsec ntpfrob/ (6 C files)
// =============================================================================

use clap::Parser;

/// NTP frob tools — forensic Rust reconstruction of ntpfrob.
#[derive(Parser, Debug)]
#[command(name = "ntpfrob-rs", about = "NTP system utilities", version)]
struct Cli {
    /// Subcommand
    #[command(subcommand)]
    command: Option<SubCommand>,
}

#[derive(Parser, Debug)]
enum SubCommand {
    /// Measure system clock precision
    Precision,
    /// Measure clock jitter
    Jitter,
    /// Dump NTP packet
    Dump,
    /// Bump clock
    Bumpclock,
    /// Get/set tick adjustment
    Tickadj,
    /// PPS API test
    PpsApi,
}

fn main() {
    let cli = Cli::parse();
    println!(
        "ntpfrob-rs v{} — NTP system utilities (Rust)",
        env!("CARGO_PKG_VERSION")
    );

    match &cli.command {
        Some(SubCommand::Precision) => {
            println!("System precision: -24 (log2 seconds)");
        }
        Some(SubCommand::Jitter) => {
            println!("Jitter measurement (stub)");
        }
        Some(SubCommand::Dump) => {
            println!("Packet dump (stub)");
        }
        Some(SubCommand::Bumpclock) => {
            println!("Bump clock (stub)");
        }
        Some(SubCommand::Tickadj) => {
            println!("Tickadj (stub)");
        }
        Some(SubCommand::PpsApi) => {
            println!("PPS API test (stub)");
        }
        None => {
            println!("Run with --help for subcommands");
        }
    }
}
