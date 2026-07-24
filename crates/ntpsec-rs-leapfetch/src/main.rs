// ──── ntpleapfetch-rs — NTP leap second fetcher ─────────────────────────────
//
// Forensic Rust reconstruction of ntpleapfetch. Downloads leap second
// files from NIST/IERS and installs them.
//
// ## Oracle
//   - ntpsec ntpclients/ntpleapfetch (shell, 14K)
// =============================================================================

use std::io::Write;

use clap::Parser;

/// NTP leap second fetcher — forensic Rust reconstruction of ntpleapfetch.
#[derive(Parser, Debug)]
#[command(name = "ntpleapfetch-rs", about = "NTP leap second fetcher", version)]
struct Cli {
    /// Leap file output path
    #[arg(short = 'o', long, default_value = "/var/lib/ntp/leap-seconds")]
    output: String,

    /// URL for leap second file
    #[arg(
        short = 'u',
        long,
        default_value = "https://www.ietf.org/timezones/data/leap-seconds.list"
    )]
    url: String,

    /// Force download even if file is current
    #[arg(short = 'f', long)]
    force: bool,

    /// Verbose output
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Print to stdout instead of writing file
    #[arg(short = 'p', long)]
    print: bool,
}

/// Parse the NTP timestamp from a leap-seconds.list file.
/// Returns the expiry time as Unix seconds, or None if not found.
fn parse_expiry(content: &str) -> Option<u64> {
    for line in content.lines() {
        if line.starts_with("#@") {
            // Format: #@ expiry_timestamp
            let timestamp_str = line.trim_start_matches("#@").trim();
            return timestamp_str.parse::<u64>().ok();
        }
    }
    None
}

fn main() {
    let cli = Cli::parse();

    eprintln!(
        "ntpleapfetch-rs v{} — Leap second fetcher (Rust)",
        env!("CARGO_PKG_VERSION")
    );

    if cli.verbose {
        eprintln!("URL:    {}", cli.url);
        eprintln!("Output: {}", cli.output);
    }

    // Check if the output already exists
    if !cli.force && std::path::Path::new(&cli.output).exists() {
        if cli.verbose {
            eprintln!("File exists, checking freshness...");
        }
        // Read the existing file to check its expiry
        let existing_content = match std::fs::read_to_string(&cli.output) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "Warning: could not read existing file (will re-download): {}",
                    e
                );
                // Proceed to download
                String::new()
            }
        };

        if !existing_content.is_empty() {
            let expiry = parse_expiry(&existing_content);
            if let Some(exp) = expiry {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now < exp {
                    eprintln!(
                        "Leap file is current (expires {}) — use -f to force download",
                        exp
                    );
                    return;
                } else if cli.verbose {
                    eprintln!("Leap file expired at {} — re-downloading", exp);
                }
            }
        }
    }

    // Download the leap second file
    eprint!("Downloading leap second data... ");
    let response = match ureq::get(&cli.url).call() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("\nDownload failed: {}", e);
            std::process::exit(1);
        }
    };

    let body = match response.into_string() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("\nFailed to read response body: {}", e);
            std::process::exit(1);
        }
    };
    eprintln!("{} bytes", body.len());

    // Basic validation: should contain the IERS header
    if !body.contains("leap-seconds") && !body.contains("#@") {
        eprintln!("Warning: downloaded file does not look like a leap-seconds file");
        if !cli.force {
            eprintln!("Use -f to override this check");
            std::process::exit(1);
        }
    }

    if cli.print {
        print!("{}", body);
    } else {
        // Write to file
        let path = &cli.output;
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::File::create(path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(body.as_bytes()) {
                    eprintln!("Error writing to {}: {}", path, e);
                    std::process::exit(1);
                }
                eprintln!("Wrote {} bytes to {}", body.len(), path);
            }
            Err(e) => {
                eprintln!("Error creating {}: {}", path, e);
                std::process::exit(1);
            }
        }
    }
}
