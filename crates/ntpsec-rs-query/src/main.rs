// ──── ntpq-rs — NTP query client ────────────────────────────────────────────
//
// Forensic Rust reconstruction of ntpq. Single renderer path through
// the ControlClient stack — no duplicated formatting logic.
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

enum CliCommand {
    ReadVar { associd: u16 },
    Associations,
    Peers,
    MruList,
    Monitor,
    Trace,
}

fn parse_cli_command(input: &str) -> Result<CliCommand, String> {
    let mut words = input.split_whitespace();
    let command = words.next().unwrap_or_default();

    match command {
        "rv" => {
            // Extra arguments are an error
            let associd_str = words.next();
            if words.next().is_some() {
                return Err(format!(
                    "too many arguments for 'rv': expected 0 or 1 associd, got extra arguments"
                ));
            }
            let associd = match associd_str {
                Some(a) => {
                    let val = if let Some(stripped) = a.strip_prefix("associd=") {
                        stripped
                    } else {
                        a
                    };
                    val.parse::<u16>()
                        .map_err(|_| format!("invalid associd: '{val}'"))?
                }
                None => 0u16,
            };
            Ok(CliCommand::ReadVar { associd })
        }
        "associations" | "as" => Ok(CliCommand::Associations),
        "peers" | "pe" => Ok(CliCommand::Peers),
        "mrulist" => Ok(CliCommand::MruList),
        "monitor" | "ntpmon" => Ok(CliCommand::Monitor),
        "trace" | "ntptrace" => Ok(CliCommand::Trace),
        _ => Err(format!("unknown command: {command}")),
    }
}

fn main() {
    let cli = Cli::parse();

    let mut client = ControlClient::new(cli.timeout, 1);

    for cmd in &cli.command {
        let result: Result<String, String> = match parse_cli_command(cmd) {
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
            Ok(CliCommand::ReadVar { associd }) => {
                if associd == 0 {
                    client
                        .read_system_vars(&cli.host, cli.port)
                        .map(|sys| format_readvar(&sys))
                        .map_err(|e| format!("{e}"))
                } else {
                    client
                        .read_peer_vars(&cli.host, cli.port, associd)
                        .map(|pv| format_peer_readvar(&pv))
                        .map_err(|e| format!("{e}"))
                }
            }
            Ok(CliCommand::Associations) => client
                .read_associations(&cli.host, cli.port)
                .map(|assocs| format_associations(&assocs))
                .map_err(|e| format!("{e}")),
            Ok(CliCommand::Peers) => {
                let assoc_result = client.read_associations(&cli.host, cli.port);
                match assoc_result {
                    Ok(assocs) => {
                        let mut rows = Vec::new();
                        for a in &assocs {
                            if !a.configured && !a.reachable {
                                continue;
                            }
                            match client.read_peer_vars(&cli.host, cli.port, a.associd) {
                                Ok(pv) => rows.push(PeerRow::from_association(&pv, a)),
                                Err(e) => {
                                    rows.push(PeerRow {
                                        tally: ' ',
                                        remote: format!("? (error: {e})"),
                                        refid: String::new(),
                                        associd: a.associd,
                                        stratum: 16,
                                        peer_type: 'u',
                                        when: None,
                                        poll: 64,
                                        reach: 0,
                                        delay: 0.0,
                                        offset: 0.0,
                                        jitter: 0.0,
                                    });
                                }
                            }
                        }
                        Ok(format_peers(&rows))
                    }
                    Err(e) => Err(format!("{e}")),
                }
            }
            Ok(CliCommand::MruList) => client
                .read_mru_list(&cli.host, cli.port)
                .map(|entries| ntpsec_rs_core::control_client::MruEntry::format_list(&entries))
                .map_err(|e| format!("{e}")),
            Ok(CliCommand::Monitor) => match client.read_system_vars(&cli.host, cli.port) {
                Ok(sys) => match client.read_associations(&cli.host, cli.port) {
                    Ok(assocs) => {
                        let mut output =
                            format!("=== System Variables ===\n{}", format_readvar(&sys));
                        output.push_str(&format!(
                            "\n=== Associations ({} total) ===\n",
                            assocs.len()
                        ));
                        for a in &assocs {
                            output.push_str(&format!(
                                "  associd={} status={:04x} configured={} reachable={}\n",
                                a.associd, a.status, a.configured, a.reachable
                            ));
                        }
                        Ok(output)
                    }
                    Err(e) => Err(format!("{e}")),
                },
                Err(e) => Err(format!("{e}")),
            },
            Ok(CliCommand::Trace) => {
                let sys_result = client.read_system_vars(&cli.host, cli.port);
                match sys_result {
                    Ok(sys) => {
                        let stratum = sys.stratum();
                        let refid = sys.get("refid").unwrap_or("").to_string();
                        let offset_val = sys
                            .get("offset")
                            .and_then(|v| v.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        let syspeer = sys.get("syspeer").unwrap_or("").to_string();
                        Ok(format!(
                            "{:>15}  {:>15}  {:>3}  {:>10.6}  syspeer={}\n",
                            cli.host, refid, stratum, offset_val, syspeer
                        ))
                    }
                    Err(e) => Err(format!("{e}")),
                }
            }
        };

        match result {
            Ok(output) => print!("{}", output),
            Err(e) => eprintln!("ERROR: {}", e),
        }
    }
}
