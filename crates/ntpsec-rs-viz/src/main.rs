// ──── ntpviz-rs — NTP visualization tool ────────────────────────────────────
//
// Forensic Rust reconstruction of ntpviz. Reads and displays NTP statistics
// files (loopstats, peerstats, clockstats).
//
// ## Oracle
//   - ntpsec ntpclients/ntpviz.py (76K)
// =============================================================================

use std::io::{self, BufRead};

use clap::Parser;

/// NTP visualization tool — forensic Rust reconstruction of ntpviz.
#[derive(Parser, Debug)]
#[command(name = "ntpviz-rs", about = "NTP visualization tool", version)]
struct Cli {
    /// Path to an NTP statistics file (loopstats, peerstats, clockstats)
    file: String,

    /// Show summary statistics
    #[arg(short = 's', long)]
    summary: bool,
}

/// Parse a loopstats line: MJD second offset drift jitter
fn parse_loopstats(line: &str) -> Option<(f64, f64, f64, f64)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 5 {
        let mjd: f64 = parts[0].parse().ok()?;
        let sec: f64 = parts[1].parse().ok()?;
        let offset: f64 = parts[2].parse().ok()?;
        let drift: f64 = parts[3].parse().ok()?;
        let jitter: f64 = parts[4].parse().ok()?;
        Some((mjd + sec / 86400.0, offset, drift, jitter))
    } else {
        None
    }
}

/// Parse a peerstats line: MJD second srcaddr dstaddr offset delay jitter
fn parse_peerstats(line: &str) -> Option<(String, f64, f64, f64)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 7 {
        Some((
            parts[2].to_string(),
            parts[4].parse().ok()?,
            parts[5].parse().ok()?,
            parts[6].parse().ok()?,
        ))
    } else {
        None
    }
}

fn main() {
    let cli = Cli::parse();

    let file = std::fs::File::open(&cli.file).unwrap_or_else(|e| {
        eprintln!("Error opening {}: {}", cli.file, e);
        std::process::exit(1);
    });

    let reader = io::BufReader::new(file);
    let mut line_count = 0usize;

    // Try to detect file type from first line
    let mut lines: Vec<String> = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error reading {}: {}", cli.file, e);
                std::process::exit(1);
            }
        };
        if !line.trim().is_empty() && !line.starts_with('#') {
            lines.push(line);
            line_count += 1;
        }
    }

    if lines.is_empty() {
        println!("(empty file)");
        return;
    }

    // Print header
    println!("File: {}", cli.file);
    println!("Records: {}", line_count);
    println!();

    if cli.summary {
        // Try loopstats
        let offsets: Vec<f64> = lines
            .iter()
            .filter_map(|l| parse_loopstats(l))
            .map(|(_, o, _, _)| o)
            .collect();
        if !offsets.is_empty() {
            let mean = offsets.iter().sum::<f64>() / offsets.len() as f64;
            let min = offsets.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = offsets.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let stddev = (offsets.iter().map(|o| (o - mean).powi(2)).sum::<f64>()
                / offsets.len() as f64)
                .sqrt();

            println!("Loopstats summary:");
            println!("  samples: {}", offsets.len());
            println!("  mean offset: {:.6} ms", mean);
            println!("  min offset:  {:.6} ms", min);
            println!("  max offset:  {:.6} ms", max);
            println!("  stddev:      {:.6} ms", stddev);
            return;
        }

        // Try peerstats
        let peer_offsets: Vec<(String, f64)> = lines
            .iter()
            .filter_map(|l| parse_peerstats(l))
            .map(|(addr, offset, _, _)| (addr, offset))
            .collect();
        if !peer_offsets.is_empty() {
            println!("Peerstats summary by peer:");
            let mut by_peer: std::collections::BTreeMap<String, Vec<f64>> =
                std::collections::BTreeMap::new();
            for (addr, offset) in &peer_offsets {
                by_peer.entry(addr.clone()).or_default().push(*offset);
            }
            for (addr, vals) in &by_peer {
                let mean = vals.iter().sum::<f64>() / vals.len() as f64;
                println!(
                    "  {}: {} samples, mean offset {:.6} ms",
                    addr,
                    vals.len(),
                    mean
                );
            }
            return;
        }
    }

    // Default: print all lines
    for line in &lines {
        println!("{}", line);
    }
}
