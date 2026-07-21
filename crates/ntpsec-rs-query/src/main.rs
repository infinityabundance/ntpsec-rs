// ──── ntpq-rs — NTP query client ────────────────────────────────────────────
//
// Forensic Rust reconstruction of ntpq. Drop-in replacement for the
// ntpsec Python ntpq — same CLI, same output format, same behavior at
// the wire level.
//
// ## Phase 2.4
//   - ControlClient stack in ntpsec-rs-core
//   - -c rv (read system variables)
//   - -c associations (binary READSTAT)
//   - -c peers (billboard)
//
// =============================================================================

use clap::Parser;
use ntpsec_rs_core::control_client::*;

/// NTP query tool — forensic Rust reconstruction of ntpq.
#[derive(Parser, Debug)]
#[command(name = "ntpq-rs", about = "NTP query tool", version)]
struct Cli {
    /// Host to query (default: localhost)
    #[arg(default_value = "127.0.0.1")]
    host: String,

    /// Port number (default: 123 for NTP mode 6)
    #[arg(short = 'p', long, default_value = "123")]
    port: u16,

    /// Execute a command
    #[arg(short = 'c', long)]
    command: Vec<String>,

    /// Verbose output
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Numeric output only (no DNS resolution)
    #[arg(short = 'n', long)]
    numeric: bool,

    /// Output in key=value format (for scripting)
    #[arg(short = 'K', long)]
    key_value: bool,

    /// Debug level
    #[arg(short = 'd', long)]
    debug: bool,

    /// Authentication key ID
    #[arg(short = 'a', long)]
    auth_key: Option<u32>,

    /// Authentication key file
    #[arg(short = 'k', long)]
    key_file: Option<String>,

    /// Timeout in seconds
    #[arg(short = 't', long, default_value = "5")]
    timeout: u32,
}

/// Known ntpq commands matching ntpq.py.
pub mod ntpq_commands {
    pub const ASSOCIATIONS: &str = "associations";
    pub const PEERS: &str = "peers";
    pub const READVAR: &str = "rv";
    pub const READLIST: &str = "rl";
    pub const WRITEVAR: &str = "wv";
    pub const MRULIST: &str = "mrulist";
    pub const SYSINFO: &str = "sysinfo";
    pub const SYSSTATS: &str = "sysstats";
    pub const CLOCKVAR: &str = "clockvar";
    pub const CONFIGURE: &str = "config";
    pub const SAVECONFIG: &str = "saveconfig";
    pub const AUTHINFO: &str = "authinfo";
    pub const IOSTATS: &str = "iostats";
    pub const TIMERSTATS: &str = "timerstats";
    pub const KERNINFO: &str = "kerninfo";
    pub const LOOPINFO: &str = "loopinfo";
    pub const IFSTATS: &str = "ifstats";
    pub const RESLIST: &str = "reslist";
    pub const VERSION: &str = "version";
    pub const HELP: &str = "help";
}

fn main() {
    let cli = Cli::parse();

    if cli.command.is_empty() {
        eprintln!("ntpq-rs: no command specified (use -c)");
        std::process::exit(1);
    }

    let mut client = ControlClient::new(cli.timeout, 1);

    for cmd in &cli.command {
        let result = match cmd.as_str() {
            ntpq_commands::READVAR => {
                // Parse optional associd from "rv 12345" or "rv associd=12345"
                let associd = parse_rv_associd(cmd);
                if associd == 0 {
                    match client.read_system_vars(&cli.host, cli.port) {
                        Ok(sys) => {
                            let mut ver = String::new();
                            // First line: status header
                            ver.push_str(&format!(
                                "associd={} status={:04x} {}\n",
                                sys.associd,
                                sys.status,
                                sys.leap_str()
                            ));
                            // Variables in key=value format
                            let keys = [
                                "version",
                                "processor",
                                "system",
                                "leap",
                                "stratum",
                                "precision",
                                "rootdelay",
                                "rootdisp",
                                "refid",
                                "reftime",
                                "peer",
                                "tc",
                                "offset",
                                "frequency",
                                "sys_jitter",
                                "rootdist",
                            ];
                            for key in &keys {
                                if let Some(val) = sys.get(key) {
                                    // Quote version string values
                                    if *key == "version" || *key == "processor" || *key == "system"
                                    {
                                        ver.push_str(&format!("{}=\"{}\", ", key, val));
                                    } else {
                                        ver.push_str(&format!("{}={}, ", key, val));
                                    }
                                }
                            }
                            ver.push('\n');
                            Ok(ver)
                        }
                        Err(e) => Err(format!("{e}")),
                    }
                } else {
                    // Peer-specific READVAR
                    match client.read_peer_vars(&cli.host, cli.port, associd) {
                        Ok(pv) => {
                            let mut out =
                                format!("associd={} status={:04x}\n", pv.associd, pv.status);
                            let keys = [
                                "srcaddr",
                                "stratum",
                                "offset",
                                "delay",
                                "dispersion",
                                "jitter",
                                "hpoll",
                                "ppoll",
                                "reach",
                                "flash",
                                "leap",
                                "refid",
                                "reftime",
                                "hmode",
                                "pmode",
                                "precision",
                            ];
                            for key in &keys {
                                if let Some(val) = pv.get(key) {
                                    out.push_str(&format!("{}={}, ", key, val));
                                }
                            }
                            out.push('\n');
                            Ok(out)
                        }
                        Err(e) => Err(format!("{e}")),
                    }
                }
            }
            ntpq_commands::ASSOCIATIONS => match client.read_associations(&cli.host, cli.port) {
                Ok(assocs) => Ok(format_associations(&assocs)),
                Err(e) => Err(format!("{e}")),
            },
            ntpq_commands::PEERS => {
                // Peers = READSTAT + per-association READVAR
                match client.read_associations(&cli.host, cli.port) {
                    Ok(assocs) => {
                        let mut rows = Vec::new();
                        for a in &assocs {
                            if !a.reachable {
                                continue;
                            }
                            if let Ok(pv) = client.read_peer_vars(&cli.host, cli.port, a.associd) {
                                let tally = a.tally_char();
                                let remote = pv.get("srcaddr").unwrap_or("unknown").to_string();
                                let refid = pv.get("refid").unwrap_or("").to_string();
                                let stratum = pv.stratum();
                                let delay =
                                    pv.get("delay").and_then(|s| s.parse().ok()).unwrap_or(0.0);
                                let offset =
                                    pv.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0.0);
                                let jitter =
                                    pv.get("jitter").and_then(|s| s.parse().ok()).unwrap_or(0.0);
                                rows.push((tally, remote, refid, stratum, delay, offset, jitter));
                            }
                        }
                        Ok(format_peers(&rows))
                    }
                    Err(e) => Err(format!("{e}")),
                }
            }
            _ => Err(format!("unknown command: {cmd}")),
        };

        match result {
            Ok(output) => print!("{}", output),
            Err(e) => eprintln!("{}", e),
        }
    }
}

/// Parse associd from "rv" or "rv 12345" or "rv associd=12345".
fn parse_rv_associd(cmd: &str) -> u16 {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 2 {
        return 0; // associd=0 = system
    }
    let arg = parts[1];
    // Try "associd=12345" format
    if let Some(val) = arg.strip_prefix("associd=") {
        return val.parse().unwrap_or(0);
    }
    // Try bare number
    arg.parse().unwrap_or(0)
}
