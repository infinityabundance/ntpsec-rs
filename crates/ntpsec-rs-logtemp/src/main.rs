// ──── ntplogtemp-rs — NTP temperature logger ────────────────────────────────
//
// Forensic Rust reconstruction of ntplogtemp. Logs temperature data for
// environmental compensation.
//
// ## Oracle
//   - ntpsec ntpclients/ntplogtemp.py (10K)
// =============================================================================

use clap::Parser;
use std::io::Write;

/// Temperature logging daemon
#[derive(Parser, Debug)]
#[command(name = "ntplogtemp-rs", about = "Temperature logging daemon", version)]
struct Cli {
    /// Temperature source path (sysfs)
    #[arg(default_value = "/sys/class/thermal/thermal_zone0/temp")]
    source: String,
    /// Output file
    #[arg(short = 'o', long, default_value = "/var/log/ntpstats/temperature")]
    output: String,
    /// Poll interval in seconds
    #[arg(short = 'i', long, default_value = "60")]
    interval: u64,
}

fn read_temperature(path: &str) -> Result<f64, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let millidegrees: f64 = content
        .trim()
        .parse()
        .map_err(|e| format!("bad temp data: {e}"))?;
    Ok(millidegrees / 1000.0)
}

fn main() {
    let cli = Cli::parse();
    println!("ntplogtemp-rs — Temperature logging daemon");
    println!("Source: {}", cli.source);
    println!("Output: {}", cli.output);

    loop {
        match read_temperature(&cli.source) {
            Ok(temp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let line = format!("{} {:.3}\n", now.as_secs(), temp);
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&cli.output)
                {
                    let _ = f.write_all(line.as_bytes());
                }
                println!("{} {:.1}°C", now.as_secs(), temp);
            }
            Err(e) => {
                eprintln!("Error: {e}");
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(cli.interval));
    }
}
