// ──── main.rs ────────────────────────────────────────────────────────────────
// Standalone CLI for loading, unloading, and monitoring the NTP XDP timestamp
// program.
//
// ## Usage
//
// ```bash
// # Attach to interface and monitor timestamps
// ntpsec-rs-xdp --interface eth0
//
// # Attach and show raw events
// ntpsec-rs-xdp -i eth0 --verbose
//
// # Detach from interface
// ntpsec-rs-xdp -i eth0 --detach
// ```
// =============================================================================

use std::process;
use std::time::{Duration, Instant};

use clap::Parser;
use ntpsec_rs_xdp::{NtpXdpTimestamp, XdpCollector, XdpError};

/// Standalone XDP NTP timestamp monitor.
#[derive(Parser, Debug)]
#[command(name = "ntpsec-rs-xdp", about = "XDP NTP timestamp monitor")]
struct Cli {
    /// Network interface to attach to.
    #[arg(short = 'i', long = "interface")]
    interface: String,

    /// Detach the XDP program from the interface.
    #[arg(long)]
    detach: bool,

    /// Run in verbose mode, printing every timestamp event.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Number of events to capture before exiting (0 = run forever).
    #[arg(short = 'n', long, default_value = "0")]
    count: u64,

    /// Duration in seconds to run before exiting.
    #[arg(short = 't', long)]
    duration: Option<u64>,
}

fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    if cli.detach {
        tracing::info!(
            "Detach requested. Use 'ip link set dev {} xdp off' or bpftool",
            cli.interface
        );
        process::exit(0);
    }

    // Start the XDP collector
    let mut collector = match XdpCollector::start(&cli.interface) {
        Ok(c) => {
            tracing::info!("XDP collector started on '{}'", cli.interface);
            c
        }
        Err(e) => {
            tracing::error!("Failed to start XDP collector: {}", e);
            process::exit(1);
        }
    };

    // Statistics
    let start = Instant::now();
    let mut total_events: u64 = 0;
    let mut last_report = Instant::now();
    let mut events_since_report: u64 = 0;

    // Event polling loop
    let max_duration = cli.duration.map(Duration::from_secs);
    let max_count = if cli.count > 0 { Some(cli.count) } else { None };

    loop {
        // Check duration limit
        if let Some(max_dur) = max_duration {
            if start.elapsed() >= max_dur {
                tracing::info!("Duration limit reached ({:.1?})", max_dur);
                break;
            }
        }

        let events = collector.poll();
        for event in &events {
            total_events += 1;
            events_since_report += 1;

            if cli.verbose {
                println!(
                    "XDP TS: {}:{} -> {} ({:.1?})",
                    event.source_addr(),
                    event.src_port,
                    event.dest_addr(),
                    event.duration_since_boot(),
                );
            } else {
                print!(".");
            }

            if let Some(max) = max_count {
                if total_events >= max {
                    break;
                }
            }
        }

        if let Some(max) = max_count {
            if total_events >= max {
                tracing::info!("Count limit reached ({})", max);
                break;
            }
        }

        // Print periodic stats
        if last_report.elapsed() >= Duration::from_secs(5) && events_since_report > 0 {
            let rate = events_since_report as f64 / last_report.elapsed().as_secs_f64();
            tracing::info!(
                "XDP: {} events total | rate: {:.1} events/s | elapsed: {:.1?}",
                total_events,
                rate,
                start.elapsed(),
            );
            events_since_report = 0;
            last_report = Instant::now();
        }

        // Brief sleep to avoid busy-wait
        std::thread::sleep(Duration::from_millis(10));
    }

    // Cleanup
    tracing::info!("Shutting down XDP collector...");
    match collector.stop() {
        Ok(()) => tracing::info!("XDP collector stopped cleanly"),
        Err(e) => tracing::error!("Error stopping XDP collector: {}", e),
    }

    let elapsed = start.elapsed();
    tracing::info!(
        "Captured {} NTP timestamp events in {:.1?} ({:.1} events/s)",
        total_events,
        elapsed,
        if elapsed.as_secs_f64() > 0.0 {
            total_events as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        }
    );
}
