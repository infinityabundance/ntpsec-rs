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

fn main() {
    let cli = Cli::parse();

    let mut client = ControlClient::new(cli.timeout, 1);

    for cmd in &cli.command {
        // Split command into words: "rv 12345" → ["rv", "12345"]
        let mut words = cmd.split_whitespace();
        let command = words.next().unwrap_or_default();

        let result: Result<String, String> = match command {
            "rv" => {
                let associd = parse_associd(words.next());
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
            "associations" | "as" => client
                .read_associations(&cli.host, cli.port)
                .map(|assocs| format_associations(&assocs))
                .map_err(|e| format!("{e}")),
            "peers" | "pe" => {
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
            _ => Err(format!("unknown command: {command}")),
        };

        match result {
            Ok(output) => print!("{}", output),
            Err(e) => eprintln!("ERROR: {}", e),
        }
    }
}

/// Parse optional associd from command argument.
///   "12345"        → 12345
///   "associd=12345" → 12345
///   None           → 0 (system)
fn parse_associd(arg: Option<&str>) -> u16 {
    let arg = match arg {
        Some(a) => a,
        None => return 0,
    };
    if let Some(val) = arg.strip_prefix("associd=") {
        val.parse().unwrap_or(0)
    } else {
        arg.parse().unwrap_or(0)
    }
}
