// ──── ntpsweep-rs — NTP network sweep tool ──────────────────────────────────
//
// Forensic Rust reconstruction of ntpsweep. Sweeps a list of NTP servers
// and reports their offset, delay, and stratum.
//
// ## Oracle
//   - ntpsec ntpclients/ntpsweep.py (8K)
// =============================================================================

use std::time::Duration;

use clap::Parser;
use ntpsec_rs_core::ntpdig_proto::*;

/// NTP network sweep tool — forensic Rust reconstruction of ntpsweep.
#[derive(Parser, Debug)]
#[command(name = "ntpsweep-rs", about = "NTP network sweep tool", version)]
struct Cli {
    /// NTP servers to query
    hosts: Vec<String>,

    /// Host list file (one host per line)
    #[arg(short = 'f', long)]
    host_file: Option<String>,

    /// Timeout per host in seconds
    #[arg(short = 't', long, default_value = "5")]
    timeout: u32,

    /// Port number
    #[arg(short = 'p', long, default_value = "123")]
    port: u16,
}

fn query_host(client: &mut NtpDigClient, host: &str, port: u16) {
    match client.query(host, port) {
        Ok(result) => {
            println!(
                "{} offset={:.6}s delay={:.6}s stratum={} refid={}",
                host, result.offset, result.delay, result.stratum, result.refid_string,
            );
        }
        Err(e) => {
            println!("{} ERROR: {}", host, e);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let mut hosts: Vec<String> = cli.hosts;

    // Read hosts from file if specified
    if let Some(path) = &cli.host_file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        hosts.push(line.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading host file {}: {}", path, e);
                std::process::exit(1);
            }
        }
    }

    if hosts.is_empty() {
        eprintln!("No hosts specified. Provide hosts as arguments or with -f.");
        std::process::exit(1);
    }

    let mut client = NtpDigClient::new(Duration::from_secs(cli.timeout as u64), 1);

    for host in &hosts {
        query_host(&mut client, host, cli.port);
    }
}
