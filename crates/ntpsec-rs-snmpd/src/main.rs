// ──── ntpsnmpd-rs — NTP SNMP daemon ─────────────────────────────────────────
//
// Forensic Rust reconstruction of ntpsnmpd. SNMP agent for NTP statistics.
//
// ## Oracle
//   - ntpsec ntpclients/ntpsnmpd.py (48K)
//   - ntpsec pylib/agentx.py, agentx_packet.py
// =============================================================================

use clap::Parser;

/// NTP SNMP daemon — forensic Rust reconstruction of ntpsnmpd.
#[derive(Parser, Debug)]
#[command(name = "ntpsnmpd-rs", about = "NTP SNMP daemon", version)]
struct Cli {
    /// AgentX socket path
    #[arg(short = 's', long, default_value = "/var/run/agentx/master")]
    socket: String,

    /// No fork
    #[arg(short = 'n', long)]
    nofork: bool,

    /// Debug mode
    #[arg(short = 'd', long)]
    debug: bool,
}

fn main() {
    let cli = Cli::parse();
    println!("ntpsnmpd-rs v{} — NTP SNMP daemon (Rust)", env!("CARGO_PKG_VERSION"));
    println!("Socket: {}", cli.socket);
    println!("(Stub — SNMP agent in Phase 2)");
}
