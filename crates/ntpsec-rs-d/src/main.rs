// ──── ntpd-rs — NTPsec daemon ───────────────────────────────────────────────
//
// Forensic Rust reconstruction of ntpd — drop-in replacement.
//
// ## Pipeline
//
//   1. Parse config (ntp_config)
//   2. Create DaemonEngine from config
//   3. Create I/O adapters (real or lab)
//   4. Open sockets (ntpsec-rs-io)
//   5. Enter main event loop using DaemonEngine:
//      a. engine.tick(now) → actions → execute (timers)
//      b. recv → engine.handle(PacketReceived) → actions → execute
//      c. Sleep until next timer event
//   6. Handle signals, log rotation, stats output
//
// ## CLI behavior matching ntpsec
//
//   ntpd-rs -c /etc/ntp.conf -n    # foreground (nofork)
//   ntpd-rs -g -x                   # step-then-slew
//   ntpd-rs -q                      # query-only mode
//   ntpd-rs --lab-daemon            # deterministic replay
//
// ## Oracle
//   - ntpsec ntpd/ntpd.c (29K)
//
// =============================================================================

use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ntpsec_rs_core::daemon_engine::*;
use ntpsec_rs_core::ntp_config::*;
use ntpsec_rs_core::ntp_io::*;

use ntpsec_rs_core::Adjustment;

/// NTPsec daemon — forensic Rust reconstruction.
#[derive(Parser, Debug)]
#[command(name = "ntpd-rs", about = "NTP daemon", version = "1.3.3")]
struct Cli {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/ntp.conf")]
    config: PathBuf,

    /// No fork (run in foreground)
    #[arg(short = 'n', long)]
    nofork: bool,

    /// Force clock step on first sync
    #[arg(short = 'g', long)]
    panicgate: bool,

    /// Slew-only mode (never step the clock)
    #[arg(short = 'x', long)]
    slew: bool,

    /// Query-only mode (set clock once and exit)
    #[arg(short = 'q', long)]
    query: bool,

    /// Specify drift file
    #[arg(short = 'f', long)]
    driftfile: Option<PathBuf>,

    /// Lab daemon mode (deterministic replay)
    #[arg(long)]
    lab_daemon: bool,

    /// Load NTP packet trace file for lab replay
    #[arg(long)]
    trace: Option<PathBuf>,

    /// Record NTP packet trace to file
    #[arg(long)]
    record_trace: Option<PathBuf>,

    /// Enable seccomp sandboxing
    #[arg(long)]
    seccomp: bool,

    /// User to drop privileges to
    #[arg(short = 'u', long, default_value = "ntp")]
    user: String,
}

fn main() {
    let cli = Cli::parse();

    // Initialize tracing/syslog
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();

    tracing::info!(
        "ntpd-rs v{} — NTPsec daemon (Rust)",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!("Config: {}", cli.config.display());

    // Parse config file
    let config = match read_config_file(&cli.config) {
        Ok(tree) => {
            tracing::info!("Loaded {} configuration directives", tree.options.len());
            for err in &tree.errors {
                tracing::warn!("Config error: {}", err);
            }
            tree
        }
        Err(e) => {
            tracing::error!("Failed to read config: {}", e);
            std::process::exit(1);
        }
    };

    // ──── Lab Daemon Mode ────────────────────────────────────────────
    if cli.lab_daemon {
        return run_lab_daemon(config, &cli);
    }

    // ──── Create Daemon Engine ───────────────────────────────────────
    let mut engine = DaemonEngine::new(config);

    // Apply CLI overrides
    if cli.slew {
        engine.loop_filter.step_threshold = f64::MAX;
    }
    if cli.panicgate {
        engine.loop_filter.panic_threshold = f64::MAX;
    }

    // ──── Create I/O adapters ─────────────────────────────────────────
    let mut clock = ntpsec_rs_io::RealSystemClock::new();
    let mut network = ntpsec_rs_io::RealNetworkIo::new();
    let mut store = ntpsec_rs_io::FileStateStore::new(&std::path::Path::new("/var/lib/ntp"));

    // Load drift file if available
    if let Ok(freq) = store.load_drift() {
        engine.loop_filter.frequency = freq;
        tracing::info!("Loaded drift: {:.3} ppm", freq);
    }

    // Bind to NTP port
    if let Err(e) = network.bind("0.0.0.0:123") {
        tracing::warn!("Cannot bind to port 123: {e} (try running as root)");
    }

    // Query-only mode: set clock once and exit
    if cli.query {
        tracing::info!("Query-only mode: polling peers and setting clock");
        run_query_mode(&mut engine, &mut clock, &mut network, &mut store);
        return;
    }

    // ──── Signal Handling ─────────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    signal_hook_init(r);

    // ──── Main Event Loop ────────────────────────────────────────────
    tracing::info!("Entering main event loop with {} peers", engine.peers.len());

    let mut iteration: u64 = 0;

    while running.load(Ordering::Relaxed) {
        iteration += 1;

        // 1. Get current time
        let now = clock.now();

        // 2. Drain due timers → execute actions
        let timer_actions = engine.tick(now);
        execute_actions(&timer_actions, &mut clock, &mut network, &mut store);

        // 3. Non-blocking receive — check for packets
        match network.recv() {
            Ok(dgram) => {
                let event = DaemonEvent::PacketReceived(dgram);
                let actions = engine.handle(event);
                execute_actions(&actions, &mut clock, &mut network, &mut store);
            }
            Err(IoError::RecvFailed(_)) => {
                // No data available — normal, continue
            }
            Err(e) => {
                if iteration % 100 == 0 {
                    tracing::debug!("Recv error: {e}");
                }
            }
        }

        // 4. Periodic status log
        if iteration % 100 == 0 {
            tracing::info!(
                "Status: peers={} stratum={} offset={:.6}s freq={:.3}ppm",
                engine.system.peer_count,
                engine.system.stratum,
                engine.system.sys_offset,
                engine.loop_filter.frequency_ppm(),
            );
        }

        // 5. Sleep — in production this would be epoll/kqueue
        // For now, 1s polling is sufficient for single-peer setups
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // ──── Shutdown ───────────────────────────────────────────────────
    let shutdown_actions = engine.handle(DaemonEvent::Shutdown);
    execute_actions(&shutdown_actions, &mut clock, &mut network, &mut store);
    tracing::info!("ntpd-rs shutting down");
}

/// Execute DaemonActions against generic I/O adapters.
/// Works for both real (RealSystemClock, FileStateStore) and lab
/// (SimulatedClock, MemoryStateStore) modes.
fn execute_actions<C: SystemClock, N: NetworkIo, S: StateStore>(
    actions: &[DaemonAction],
    clock: &mut C,
    network: &mut N,
    store: &mut S,
) {
    for action in actions {
        match action {
            DaemonAction::Send { destination, bytes } => {
                // Send via network adapter
                if let Err(e) = network.send(bytes, destination) {
                    tracing::warn!("Send failed: {e}");
                }
            }
            DaemonAction::AdjustClock(adj) => match adj {
                Adjustment::Step(offset) => {
                    if let Err(e) = clock.step(*offset) {
                        tracing::error!("Step failed: {e}");
                    } else {
                        tracing::info!("Stepped clock by {:.6}s", offset);
                    }
                }
                Adjustment::Slew(offset, freq) => {
                    if let Err(e) = clock.slew(*offset, *freq) {
                        tracing::error!("Slew failed: {e}");
                    } else {
                        tracing::trace!("Slewed clock by {:.6}s at {:.3}ppm", offset, freq);
                    }
                }
                Adjustment::Panic(offset) => {
                    tracing::error!("Panic: offset {:.6}s exceeds threshold!", offset);
                    std::process::exit(1);
                }
                Adjustment::Ignore => {}
            },
            DaemonAction::PersistDrift(freq) => {
                if let Err(e) = store.save_drift(*freq) {
                    tracing::error!("Failed to save drift: {e}");
                } else {
                    tracing::debug!("Saved drift: {:.3} ppm", freq);
                }
            }
            DaemonAction::Log(msg) => {
                tracing::info!("{}", msg);
            }
            DaemonAction::AppendStatistic { stream, line } => {
                if let Err(e) = store.append_stats(stream, line) {
                    tracing::warn!("Failed to write to {stream}: {e}");
                }
            }
        }
    }
}

/// Run in query-only mode (-q): poll peers once, set clock, exit.
fn run_query_mode(
    engine: &mut DaemonEngine,
    clock: &mut ntpsec_rs_io::RealSystemClock,
    network: &mut ntpsec_rs_io::RealNetworkIo,
    store: &mut ntpsec_rs_io::FileStateStore,
) {
    // In query mode, we run a few iterations to collect data
    // then apply the best offset and exit.
    let max_iterations = 10;
    for _i in 0..max_iterations {
        let now = clock.now();

        // Drain timers — triggers polls
        let timer_actions = engine.tick(now);
        execute_actions(&timer_actions, clock, network, store);

        // Try to receive responses
        match network.recv() {
            Ok(dgram) => {
                let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
                execute_actions(&actions, clock, network, store);
            }
            Err(IoError::RecvFailed(_)) => {}
            Err(e) => {
                tracing::debug!("Recv error: {e}");
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // After collection, step the clock if we have a valid offset
    if engine.system.peer_count > 0 && engine.system.sys_offset.is_finite() {
        tracing::info!("Setting clock: offset={:.6}s", engine.system.sys_offset);
        if let Err(e) = clock.step(engine.system.sys_offset) {
            tracing::error!("Failed to step clock: {e}");
        }
    } else {
        tracing::warn!("No synchronization source available");
    }
}

/// Run in lab mode with deterministic simulation.
fn run_lab_daemon(config: ConfigTree, cli: &Cli) {
    tracing::info!("Starting lab daemon (deterministic replay mode)");

    let mut engine = DaemonEngine::new(config);
    if cli.panicgate {
        engine.loop_filter.panic_threshold = f64::MAX;
    }

    // Load trace file if specified
    let mut trace = if let Some(trace_path) = cli.trace.as_ref() {
        match std::fs::read_to_string(trace_path) {
            Ok(content) => match PacketTrace::from_json(&content) {
                Ok(t) => {
                    tracing::info!(
                        "Loaded trace with {} entries from {}",
                        t.len(),
                        trace_path.display()
                    );
                    t
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse trace '{}': {}, starting empty",
                        trace_path.display(),
                        e
                    );
                    PacketTrace::new()
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Cannot read trace '{}': {}, starting empty",
                    trace_path.display(),
                    e
                );
                PacketTrace::new()
            }
        }
    } else {
        PacketTrace::new()
    };

    // Replay datagrams from the trace into the network
    let replay_dgrams: Vec<ReceivedDatagram> = trace
        .iter()
        .filter(|e| e.direction == TraceDirection::Received)
        .map(|e| ReceivedDatagram {
            bytes: e.bytes.clone(),
            source: e.source,
            destination: e.destination,
            rx_timestamp: e.timestamp,
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        })
        .collect();

    let replay_count = replay_dgrams.len();
    let mut clock = SimulatedClock::unix_epoch();
    let mut store = MemoryStateStore::new();
    let mut network = ReplayNetwork::new(replay_dgrams);

    tracing::info!(
        "Lab daemon initialized with {} peers, {} timers, {} replay datagrams",
        engine.peers.len(),
        engine.timers.len(),
        replay_count,
    );

    // Load simulated drift (none initially)
    if let Ok(freq) = store.load_drift() {
        engine.loop_filter.frequency = freq;
    }

    // Lab mode runs for a fixed number of iterations
    for iter in 0..10 {
        let now = clock.now();

        // Process timers via generic executor
        let timer_actions = engine.tick(now);
        execute_actions(&timer_actions, &mut clock, &mut network, &mut store);

        // Replay buffered received datagrams
        loop {
            match network.recv() {
                Ok(dgram) => {
                    let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
                    execute_actions(&actions, &mut clock, &mut network, &mut store);
                }
                Err(_) => break,
            }
        }

        // Log stats
        if iter % 3 == 0 {
            tracing::info!(
                "[lab status] peers={} stratum={} offset={:.6}s freq={:.3}ppm sent={}",
                engine.system.peer_count,
                engine.system.stratum,
                engine.system.sys_offset,
                engine.loop_filter.frequency_ppm(),
                network.sent_packets.len(),
            );
        }

        // Advance simulated time
        clock.advance(4.0);
    }

    // Record outbound trace if requested
    if let Some(record_path) = cli.record_trace.as_ref() {
        // Append sent packets to the trace
        for (dest, bytes) in &network.sent_packets {
            trace.push(TraceEntry {
                timestamp: clock.now(),
                direction: TraceDirection::Sent,
                source: NetAddr::ipv4(0x7f000001, 123),
                destination: *dest,
                bytes: bytes.clone(),
            });
        }
        if std::fs::write(record_path, trace.to_json()).is_ok() {
            tracing::info!(
                "Recorded trace with {} entries to {}",
                trace.len(),
                record_path.display()
            );
        }
    }

    // Final state
    tracing::info!(
        "Lab daemon final state: {} peers, stratum={}, offset={:.6}s, freq={:.3}ppm, sent={} packets",
        engine.peers.len(),
        engine.system.stratum,
        engine.system.sys_offset,
        engine.loop_filter.frequency_ppm(),
        network.sent_packets.len(),
    );
}

/// Initialize signal handlers for graceful shutdown.
fn signal_hook_init(running: Arc<AtomicBool>) {
    // Simple signal handling placeholder
    // In production, use signal_hook crate
    let _ = running;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_default_config() {
        // Verify that default config path is /etc/ntp.conf
        let cli = Cli::parse_from(["ntpd-rs"]);
        assert_eq!(cli.config, PathBuf::from("/etc/ntp.conf"));
    }

    #[test]
    fn test_cli_custom_config() {
        let cli = Cli::parse_from(["ntpd-rs", "-c", "/tmp/test.conf"]);
        assert_eq!(cli.config, PathBuf::from("/tmp/test.conf"));
    }

    #[test]
    fn test_cli_flags() {
        let cli = Cli::parse_from(["ntpd-rs", "-n", "-g", "-x", "-q", "--lab-daemon"]);
        assert!(cli.nofork);
        assert!(cli.panicgate);
        assert!(cli.slew);
        assert!(cli.query);
        assert!(cli.lab_daemon);
    }

    #[test]
    fn test_cli_driftfile() {
        let cli = Cli::parse_from(["ntpd-rs", "-f", "/tmp/drift"]);
        assert_eq!(cli.driftfile, Some(PathBuf::from("/tmp/drift")));
    }

    #[test]
    fn test_execute_actions_no_panic() {
        // Just verify execute_actions doesn't crash with any action variant
        let mut clock = ntpsec_rs_io::RealSystemClock::new();
        let mut network = ntpsec_rs_io::RealNetworkIo::new();
        let mut store = ntpsec_rs_io::FileStateStore::new(&std::path::Path::new("/tmp"));

        let actions = vec![
            DaemonAction::Log("test log".to_string()),
            DaemonAction::AdjustClock(Adjustment::Ignore),
            DaemonAction::Send {
                destination: NetAddr::ipv4(0x7f000001, 123),
                bytes: vec![0u8; 48],
            },
            DaemonAction::PersistDrift(0.0),
            DaemonAction::AppendStatistic {
                stream: "loopstats".to_string(),
                line: "test".to_string(),
            },
        ];
        execute_actions(&actions, &mut clock, &mut network, &mut store);
    }
}
