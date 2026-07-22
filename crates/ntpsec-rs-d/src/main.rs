// ──── ntpd-rs — NTPsec daemon ────────────────────────────────────────────
//
// Forensic Rust reconstruction of ntpd.  Phase 2.5A: process lifecycle,
// signal handling, graceful shutdown, configuration reload.
//
// ## Signal handling
//
//   SIGINT / SIGTERM  → graceful shutdown (drift persist, socket close, exit 0)
//   SIGHUP            → reload configuration
//
// ## Exit codes
//
//   0  Clean shutdown after SIGTERM/SIGINT
//   1  Configuration error, fatal runtime error
//   2  Permission/port binding failure
//
// =============================================================================

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ntpsec_rs_core::daemon_engine::*;
use ntpsec_rs_core::ntp_config::*;
use ntpsec_rs_core::ntp_io::*;

// ──── CLI ─────────────────────────────────────────────────────────────────

/// NTPsec daemon — forensic Rust reconstruction of ntpd.
#[derive(Parser, Debug)]
#[command(name = "ntpd-rs", about = "NTP daemon", version)]
struct Cli {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/ntp.conf")]
    config: PathBuf,

    /// Do not fork (foreground operation)
    #[arg(short = 'n', long)]
    nofork: bool,

    /// Override panic threshold (disable panic on large offset)
    #[arg(short = 'g', long)]
    panicgate: bool,

    /// Override step threshold (always slew)
    #[arg(short = 'x', long)]
    slew: bool,

    /// Query-only mode: poll peers once, set clock, exit
    #[arg(short = 'q', long)]
    query: bool,

    /// Drift file path (overrides config)
    #[arg(short = 'f', long)]
    driftfile: Option<PathBuf>,

    /// Lab daemon mode (deterministic, no real I/O)
    #[arg(short = 'l', long)]
    lab_daemon: bool,

    /// Enable trace recording
    #[arg(short = 'r', long)]
    trace: bool,

    /// Record trace to file
    #[arg(long)]
    record_trace: Option<PathBuf>,

    /// Enable seccomp sandbox
    #[arg(short = 's', long)]
    seccomp: bool,

    /// Drop privileges to this user after binding
    #[arg(short = 'u', long)]
    user: Option<String>,
}

// ──── Main ────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();

    tracing::info!(
        "ntpd-rs v{} — NTPsec daemon (Rust)",
        env!("CARGO_PKG_VERSION")
    );

    // ──── Parse Config ─────────────────────────────────────────────────
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

    // ──── Create Engine & I/O ─────────────────────────────────────────
    let mut engine = DaemonEngine::new(config);
    let mut clock = ntpsec_rs_io::RealSystemClock::new();
    let mut network = ntpsec_rs_io::RealNetworkIo::new();
    let mut store = ntpsec_rs_io::FileStateStore::new(&std::path::Path::new("/var/lib/ntp"));

    // Apply CLI overrides
    if cli.slew {
        engine.loop_filter.step_threshold = f64::MAX;
    }
    if cli.panicgate {
        engine.loop_filter.panic_threshold = f64::MAX;
    }

    // Load drift file
    if let Ok(freq) = store.load_drift() {
        engine.loop_filter.frequency = freq;
        tracing::info!("Loaded drift: {:.3} ppm", freq);
    }

    // ──── Bind Privileged Port ───────────────────────────────────────
    if let Err(e) = network.bind("0.0.0.0:123") {
        tracing::error!("Cannot bind to port 123: {e}");
        std::process::exit(2);
    }
    tracing::info!("Bound to port 123/udp");

    // Query-only mode
    if cli.query {
        tracing::info!("Query-only mode: polling peers and setting clock");
        run_query_mode(&mut engine, &mut clock, &mut network, &mut store);
        return;
    }

    // ──── Signal Handling ────────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let wants_reload = Arc::new(AtomicBool::new(false));
    let sig_exit_code = Arc::new(std::sync::Mutex::new(0i32));

    init_signal_handlers(running.clone(), wants_reload.clone(), sig_exit_code.clone());

    // ──── Main Event Loop ────────────────────────────────────────────
    tracing::info!("Entering main event loop with {} peers", engine.peers.len());
    let mut iteration: u64 = 0;

    while running.load(Ordering::Relaxed) {
        iteration += 1;

        // Check for SIGHUP config reload
        if wants_reload.swap(false, Ordering::Relaxed) {
            tracing::info!("SIGHUP received — reloading configuration");
            match read_config_file(&cli.config) {
                Ok(new_config) => {
                    engine.apply_config(new_config);
                    tracing::info!("Configuration reloaded");
                }
                Err(e) => {
                    tracing::error!("SIGHUP config reload failed: {e}");
                }
            }
        }

        // 1. Drain due timers
        let now = clock.now();
        let timer_actions = engine.tick(now);
        execute_actions(&timer_actions, &mut clock, &mut network, &mut store);

        // 2. Non-blocking receive
        match network.recv() {
            Ok(dgram) => {
                let event = DaemonEvent::PacketReceived(dgram);
                let actions = engine.handle(event);
                execute_actions(&actions, &mut clock, &mut network, &mut store);
            }
            Err(IoError::RecvFailed(_)) => {}
            Err(e) => {
                if iteration % 100 == 0 {
                    tracing::debug!("Recv error: {e}");
                }
            }
        }

        // 3. Periodic status
        if iteration % 100 == 0 {
            tracing::info!(
                "Status: peers={} stratum={} offset={:.6}s freq={:.3}ppm",
                engine.system.peer_count,
                engine.system.stratum,
                engine.system.sys_offset,
                engine.loop_filter.frequency_ppm(),
            );
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // ──── Graceful Shutdown ──────────────────────────────────────────
    tracing::info!("Shutting down...");

    // 1. Flush statistics
    let stats_actions = engine.handle(DaemonEvent::Shutdown);
    execute_actions(&stats_actions, &mut clock, &mut network, &mut store);

    // 2. Persist drift
    execute_actions(
        &[DaemonAction::PersistDrift(engine.loop_filter.frequency)],
        &mut clock,
        &mut network,
        &mut store,
    );

    // 3. Close sockets
    drop(network);
    tracing::info!("Sockets closed");

    // 4. Explicit exit code
    let exit_code = {
        let guard = sig_exit_code.lock().unwrap();
        *guard
    };
    tracing::info!("ntpd-rs stopped (exit code {})", exit_code);
    std::process::exit(exit_code);
}

// ──── Signal Handling ─────────────────────────────────────────────────────

/// Initialize signal handlers using signal-hook.
fn init_signal_handlers(
    running: Arc<AtomicBool>,
    wants_reload: Arc<AtomicBool>,
    exit_code: Arc<std::sync::Mutex<i32>>,
) {
    // SIGTERM: graceful shutdown, exit 0
    let r = running.clone();
    let ec = exit_code.clone();
    let mut term_sig = signal_hook::iterator::Signals::new(&[signal_hook::consts::SIGTERM])
        .expect("Failed to register SIGTERM handler");
    std::thread::spawn(move || {
        for _ in term_sig.forever() {
            tracing::info!("Received SIGTERM");
            r.store(false, Ordering::Relaxed);
            let mut code = ec.lock().unwrap();
            *code = 0;
            break;
        }
    });

    // SIGINT: same as SIGTERM
    let r = running.clone();
    let ec = exit_code.clone();
    let mut int_sig = signal_hook::iterator::Signals::new(&[signal_hook::consts::SIGINT])
        .expect("Failed to register SIGINT handler");
    std::thread::spawn(move || {
        for _ in int_sig.forever() {
            tracing::info!("Received SIGINT");
            r.store(false, Ordering::Relaxed);
            let mut code = ec.lock().unwrap();
            *code = 0;
            break;
        }
    });

    // SIGHUP: reload configuration
    let reload = wants_reload.clone();
    let mut hup_sig = signal_hook::iterator::Signals::new(&[signal_hook::consts::SIGHUP])
        .expect("Failed to register SIGHUP handler");
    std::thread::spawn(move || {
        for _ in hup_sig.forever() {
            tracing::info!("Received SIGHUP — will reload at next iteration");
            reload.store(true, Ordering::Relaxed);
        }
    });
}

// ──── Action Executor ─────────────────────────────────────────────────────

fn execute_actions<C: SystemClock, N: NetworkIo, S: StateStore>(
    actions: &[DaemonAction],
    clock: &mut C,
    network: &mut N,
    store: &mut S,
) {
    for action in actions {
        match action {
            DaemonAction::Send { destination, bytes } => {
                if let Err(e) = network.send(bytes, destination) {
                    tracing::warn!("Send failed: {e}");
                }
            }
            DaemonAction::AdjustClock(adj) => match adj {
                Adjustment::Step(offset) => {
                    if let Err(e) = clock.step(*offset) {
                        tracing::error!("Step failed: {e}");
                    }
                }
                Adjustment::Slew(offset, freq) => {
                    if let Err(e) = clock.slew(*offset, *freq) {
                        tracing::error!("Slew failed: {e}");
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

// ──── Query Mode ──────────────────────────────────────────────────────────

/// Run a single poll cycle against configured peers, adjust the clock, and exit.
fn run_query_mode<C: SystemClock, N: NetworkIo, S: StateStore>(
    engine: &mut DaemonEngine,
    clock: &mut C,
    network: &mut N,
    store: &mut S,
) {
    tracing::info!("Query mode: polling {} peers", engine.peers.len());

    // Tick to start polls
    let now = clock.now();
    let actions = engine.tick(now);
    execute_actions(&actions, clock, network, store);

    // Wait for responses (up to 10 seconds)
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(100));

        match network.recv() {
            Ok(dgram) => {
                let event = DaemonEvent::PacketReceived(dgram);
                let actions = engine.handle(event);
                execute_actions(&actions, clock, network, store);
            }
            Err(IoError::RecvFailed(_)) => continue,
            Err(e) => {
                tracing::debug!("Recv error: {e}");
            }
        }

        // If we have a clock update, apply it and exit
        if engine.system.sys_offset.abs() > 0.001 {
            let now = clock.now();
            let adj = engine
                .loop_filter
                .local_clock(engine.system.sys_offset, now);
            if let Adjustment::Step(offset) = adj {
                if clock.step(offset).is_ok() {
                    tracing::info!("Set clock: offset {:.6}s", offset);
                }
            }
            break;
        }
    }

    // Persist drift
    execute_actions(
        &[DaemonAction::PersistDrift(engine.loop_filter.frequency)],
        clock,
        network,
        store,
    );

    tracing::info!("Query mode done");
}

// ──── Lab Daemon ──────────────────────────────────────────────────────────

/// Run in lab/ replay mode: deterministic engine, no real sockets or clock.
fn run_lab_daemon(config: ConfigTree, cli: &Cli) {
    tracing::info!("Lab daemon mode (deterministic, no real I/O)");

    let mut engine = DaemonEngine::new(config);
    let mut clock = SimulatedClock::unix_epoch();
    let mut network = ReplayNetwork::new(Vec::new());
    let mut store = MemoryStateStore::new();

    // Apply CLI overrides
    if cli.slew {
        engine.loop_filter.step_threshold = f64::MAX;
    }
    if cli.panicgate {
        engine.loop_filter.panic_threshold = f64::MAX;
    }

    // Deterministic run: simulate 10 minutes of operation
    let iterations = if cli.query { 10 } else { 600 };

    for i in 0..iterations {
        let now = clock.now();

        // Timer dispatch
        let timer_actions = engine.tick(now);
        execute_actions(&timer_actions, &mut clock, &mut network, &mut store);

        clock.advance(1.0);

        if (i + 1) % 100 == 0 {
            tracing::info!(
                "Lab tick {}: peers={} stratum={} offset={:.6}s",
                i + 1,
                engine.system.peer_count,
                engine.system.stratum,
                engine.system.sys_offset,
            );
        }
    }

    // Shutdown
    let shutdown_actions = engine.handle(DaemonEvent::Shutdown);
    execute_actions(&shutdown_actions, &mut clock, &mut network, &mut store);

    tracing::info!(
        "Lab run complete: {} ticks, {} packets sent",
        iterations,
        network.sent_packets.len(),
    );
}

// ──── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_default_config() {
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

    #[test]
    fn test_signal_handler_init() {
        // Verify signal handlers can be registered (doesn't test delivery)
        let running = Arc::new(AtomicBool::new(true));
        let reload = Arc::new(AtomicBool::new(false));
        let ec = Arc::new(std::sync::Mutex::new(0));
        // Just verify registration doesn't panic
        init_signal_handlers(running, reload, ec);
    }

    #[test]
    fn test_lab_daemon_runs() {
        // Create a minimal lab config and verify it completes without panic
        let config = parse_config("server 127.127.1.0\n");
        let mut engine = DaemonEngine::new(config);
        let mut clock = SimulatedClock::unix_epoch();
        let mut network = ReplayNetwork::new(Vec::new());
        let mut store = MemoryStateStore::new();

        for _ in 0..10 {
            let now = clock.now();
            let actions = engine.tick(now);
            execute_actions(&actions, &mut clock, &mut network, &mut store);
            clock.advance(1.0);
        }

        let shutdown = engine.handle(DaemonEvent::Shutdown);
        execute_actions(&shutdown, &mut clock, &mut network, &mut store);
    }
}
