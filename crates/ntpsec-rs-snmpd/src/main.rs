// ──── ntpsnmpd-rs — NTP SNMP daemon ─────────────────────────────────────────
//
// Forensic Rust reconstruction of ntpsnmpd. SNMP agent for NTP statistics.
//
// ## Oracle
//   - ntpsec ntpclients/ntpsnmpd.py (48K)
//   - ntpsec pylib/agentx.py, agentx_packet.py
// =============================================================================

use clap::Parser;

/// NTP SNMP daemon — forensic Rust reconstruction of ntpsnmpd
#[derive(Parser, Debug)]
#[command(name = "ntpsnmpd-rs", about = "NTP SNMP monitoring daemon", version)]
struct Cli {
    /// Host to query
    #[arg(default_value = "127.0.0.1")]
    host: String,
    /// Port
    #[arg(short = 'p', long, default_value = "123")]
    port: u16,
    /// SNMP port
    #[arg(short = 's', long, default_value = "161")]
    snmp_port: u16,
}

fn main() {
    let cli = Cli::parse();
    println!(
        "ntpsnmpd-rs v{} — NTP SNMP daemon (Rust)",
        env!("CARGO_PKG_VERSION")
    );
    println!("Monitoring NTP daemon at {}:{}", cli.host, cli.port);
    println!("SNMP agent on port {} (not yet implemented)", cli.snmp_port);
    println!("Full SNMP agent requires the `snmp` crate — deferred.");
    // Show the current NTP status
    let mut client = ntpsec_rs_core::control_client::ControlClient::new(5, 1);
    match client.read_system_vars(&cli.host, cli.port) {
        Ok(sys) => {
            println!("System state:");
            println!("  stratum={}", sys.stratum());
            println!("  leap={}", sys.leap_str());
            println!("  offset={}", sys.get("offset").unwrap_or("unknown"));
            println!("  frequency={}", sys.get("frequency").unwrap_or("unknown"));
        }
        Err(e) => {
            eprintln!("ERROR: could not query NTP daemon: {e}");
        }
    }
}
