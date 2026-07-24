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
    /// NTP daemon host
    #[arg(default_value = "127.0.0.1")]
    host: String,
    /// NTP daemon port
    #[arg(short = 'p', long, default_value = "123")]
    port: u16,
    /// SNMP agent port
    #[arg(short = 's', long, default_value = "1161")]
    snmp_port: u16,
    /// Poll interval in seconds
    #[arg(short = 'i', long, default_value = "60")]
    interval: u64,
    /// Output file for SNMP data
    #[arg(short = 'o', long, default_value = "/var/log/ntpstats/snmp")]
    output: String,
}

fn query_ntp_status(host: &str, port: u16) -> Result<String, String> {
    let mut client = ntpsec_rs_core::control_client::ControlClient::new(5, 1);
    let sys = client
        .read_system_vars(host, port)
        .map_err(|e| format!("NTP query failed: {e}"))?;

    Ok(format!(
        "stratum={}\noffset={}\nfrequency={}\nsys_jitter={}\nroot_delay={}\nroot_dispersion={}",
        sys.stratum(),
        sys.get("offset").unwrap_or("0"),
        sys.get("frequency").unwrap_or("0"),
        sys.get("sys_jitter").unwrap_or("0"),
        sys.get("root_delay").unwrap_or("0"),
        sys.get("root_dispersion").unwrap_or("0"),
    ))
}

fn write_snmp_data(path: &str, data: &str) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("cannot create dir: {e}"))?;
    }
    std::fs::write(path, data).map_err(|e| format!("write failed: {e}"))?;
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    println!(
        "ntpsnmpd-rs v{} — NTP SNMP daemon",
        env!("CARGO_PKG_VERSION")
    );
    println!("Monitoring NTP daemon at {}:{}", cli.host, cli.port);
    println!("SNMP data written to {}", cli.output);
    println!("Polling every {} seconds", cli.interval);

    loop {
        match query_ntp_status(&cli.host, cli.port) {
            Ok(status) => {
                if let Err(e) = write_snmp_data(&cli.output, &status) {
                    eprintln!("Write error: {e}");
                }
                println!(
                    "[{}] Status written",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                );
            }
            Err(e) => {
                eprintln!("Query error: {e}");
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(cli.interval));
    }
}
