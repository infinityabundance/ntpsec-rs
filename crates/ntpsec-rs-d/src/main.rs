// ──── ntpd-rs — NTPsec daemon ────────────────────────────────────────────
//
// Forensic Rust reconstruction of ntpd.  Phase 2.5A: process lifecycle,
// signal handling, graceful shutdown, configuration reload.
//
// ## Production daemon features
//
//   - Daemon mode: fork to background (default), `-n` to stay in foreground
//   - PID file: `-p`/`--pidfile` writes PID to file, deleted on shutdown
//   - Log file: `-l`/`--logfile` redirects stderr to file
//   - chroot jail: `-i`/`--jaildir` (before privilege drop)
//   - Interface binding: `-I`/--interface` for specific listen addresses
//   - Key file: `-k`/--keyfile` loads symmetric keys
//   - Trusted keys: `-t`/--trustedkey` marks key IDs as trusted
//   - Wait-sync: `-w`/--wait-sync` blocks until clock synchronized
//   - Nice: `-N`/--nice` sets high scheduling priority
//   - IPv4/IPv6: `-4`/`-6` force address family
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

use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ntpsec_rs_core::daemon_engine::*;
use ntpsec_rs_core::ntp_config::*;
use ntpsec_rs_core::ntp_io::*;
use ntpsec_rs_core::ntp_sandbox;

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
    #[arg(long)]
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

    // ──── Production daemon flags ────────────────────────────────────
    /// Path to PID file (e.g. /var/run/ntpd.pid)
    #[arg(short = 'p', long)]
    pidfile: Option<PathBuf>,

    /// Path to log file
    #[arg(short = 'l', long)]
    logfile: Option<PathBuf>,

    /// chroot jail directory
    #[arg(short = 'i', long)]
    jaildir: Option<PathBuf>,

    /// Listen on a specific network interface (IP or interface name; repeatable)
    #[arg(short = 'I', long)]
    interface: Vec<String>,

    /// Path to symmetric key file (ntp.keys)
    #[arg(short = 'k', long)]
    keyfile: Option<PathBuf>,

    /// Trusted key numbers (repeatable)
    #[arg(short = 't', long)]
    trustedkey: Vec<u32>,

    /// Wait for clock synchronization before entering main loop
    #[arg(short = 'w', long)]
    wait_sync: bool,

    /// Run at high priority (nice -10)
    #[arg(short = 'N', long)]
    nice: bool,

    /// Force IPv4 DNS resolution
    #[arg(short = '4')]
    ipv4: bool,

    /// Force IPv6 DNS resolution
    #[arg(short = '6')]
    ipv6: bool,
}

/// Resolved listen addresses from CLI `-I` flags (empty = bind all).
fn resolve_listen_addresses(cli: &Cli) -> Vec<String> {
    if cli.interface.is_empty() {
        // Default: bind all interfaces with address-family awareness
        if cli.ipv6 {
            vec!["[::]:123".to_string()]
        } else if cli.ipv4 {
            vec!["0.0.0.0:123".to_string()]
        } else {
            vec!["0.0.0.0:123".to_string()]
        }
    } else {
        // User specified explicit interfaces/IPs
        cli.interface
            .iter()
            .map(|iface| {
                // If it already looks like an address with port, use as-is
                if iface.contains(':') {
                    iface.clone()
                } else {
                    // Otherwise treat as IP address on port 123
                    format!("{iface}:123")
                }
            })
            .collect()
    }
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

    // Record daemon start time for uptime tracking
    engine.system.start_time = clock.now();

    // Determine stats/drift directory from config or default
    let stats_dir = std::path::PathBuf::from("/var/lib/ntp");
    let drift_path = cli
        .driftfile
        .as_ref()
        .cloned()
        .unwrap_or_else(|| stats_dir.join("ntp.drift"));
    let mut store = ntpsec_rs_io::FileStateStore::with_drift_path(&stats_dir, &drift_path);
    std::fs::create_dir_all(&stats_dir).ok();
    // Ensure stats dir exists and is writable
    if let Err(e) = std::fs::create_dir_all(&stats_dir) {
        tracing::warn!("Cannot create stats dir {:?}: {e}", stats_dir);
    }

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
        tracing::info!("Loaded drift ({:.3} ppm) from {:?}", freq, drift_path);
    }

    // ──── Load Key Files ────────────────────────────────────────────
    let key_paths = collect_key_paths(&engine.config);
    if let Err(e) = load_key_files(&mut engine.auth, &key_paths) {
        tracing::warn!("Key file loading issue: {e}");
    }

    // ──── Open Refclocks ────────────────────────────────────────────
    {
        let refclock_actions = engine.refclocks.open_all();
        execute_actions(&refclock_actions, &mut clock, &mut network, &mut store);
    }

    // ──── Bind Privileged Port(s) ──────────────────────────────────────
    let addrs = resolve_listen_addresses(&cli);
    for addr in &addrs {
        if let Err(e) = network.bind(addr) {
            tracing::error!("Cannot bind to {addr}: {e}");
            std::process::exit(2);
        }
        tracing::info!("Bound to {addr}");
    }
    if addrs.is_empty() {
        tracing::error!("No listen addresses configured");
        std::process::exit(2);
    }

    // Query-only mode (no forking)
    if cli.query {
        tracing::info!("Query-only mode: polling peers and setting clock");
        run_query_mode(&mut engine, &mut clock, &mut network, &mut store);
        return;
    }

    // ──── Daemonize: fork to background ─────────────────────────────
    // Unless `-n` is given, fork now.  The parent prints the child PID
    // and exits immediately.  The child continues as a background daemon.
    if !cli.nofork {
        // fork() returns 0 to the child, the child's PID to the parent,
        // or -1 on error.
        let pid = unsafe { libc::fork() };
        if pid == -1 {
            eprintln!("fork failed: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        } else if pid == 0 {
            // ── Child ──
            // Create a new session (become session leader, detach from terminal)
            unsafe { libc::setsid() };
        } else {
            // ── Parent ──
            // Print PID so init/supervisor can track the child
            println!("ntpd-rs started, PID: {pid}");

            // Write PID file from the parent (we know the child's PID)
            if let Some(ref pidfile) = cli.pidfile {
                write_pid_file(pidfile, pid);
            }

            std::process::exit(0);
        }
    }

    // ── Child (or foreground) continues here ──

    // Redirect stdin to /dev/null (daemon convention — never read from tty)
    if !cli.nofork {
        if let Ok(null) = std::fs::File::open("/dev/null") {
            let fd = std::os::unix::io::IntoRawFd::into_raw_fd(null);
            unsafe { libc::dup2(fd, libc::STDIN_FILENO) };
        }
    }

    // Redirect stderr (and stdout) to log file if `-l` given
    if let Some(ref logfile) = cli.logfile {
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(logfile)
        {
            let fd = std::os::unix::io::IntoRawFd::into_raw_fd(file);
            unsafe {
                libc::dup2(fd, libc::STDOUT_FILENO);
                libc::dup2(fd, libc::STDERR_FILENO);
            }
            tracing::info!("Logging to {:?}", logfile);
        } else {
            eprintln!("Warning: cannot open logfile {:?}", logfile);
        }
    } else if !cli.nofork {
        // Daemonized without explicit logfile: redirect stdout/stderr to /dev/null
        if let Ok(null) = std::fs::File::open("/dev/null") {
            let fd = std::os::unix::io::IntoRawFd::into_raw_fd(null);
            unsafe {
                libc::dup2(fd, libc::STDOUT_FILENO);
                libc::dup2(fd, libc::STDERR_FILENO);
            }
        }
    }

    // ──── Write PID file (child PID) ────────────────────────────────
    // If daemonized, the parent already wrote it above; this is for the
    // foreground (`-n`) case where the PID file should still be written.
    if cli.nofork {
        if let Some(ref pidfile) = cli.pidfile {
            let pid = unsafe { libc::getpid() };
            write_pid_file(pidfile, pid);
        }
    }

    // ──── Chroot Jail ──────────────────────────────────────────────
    // Must happen BEFORE privilege drop (needs root / CAP_SYS_CHROOT).
    // The admin must ensure all required paths (drift, stats, keys)
    // exist inside the jail directory.
    if let Some(ref jaildir) = cli.jaildir {
        // Ensure the jail directory exists
        if let Err(e) = std::fs::create_dir_all(jaildir) {
            eprintln!("Cannot create jaildir {:?}: {e}", jaildir);
            std::process::exit(1);
        }
        let c_jail = std::ffi::CString::new(jaildir.as_os_str().as_bytes()).unwrap_or_else(|_| {
            eprintln!("Jaildir path contains NUL byte");
            std::process::exit(1);
        });
        let ret = unsafe { libc::chroot(c_jail.as_ptr()) };
        if ret != 0 {
            eprintln!(
                "chroot to {:?} failed: {}",
                jaildir,
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
        // Change working directory to root inside the jail
        if unsafe { libc::chdir(std::ffi::CString::new("/").unwrap().as_ptr()) } != 0 {
            eprintln!(
                "chdir after chroot failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
        tracing::info!("chroot to {:?}", jaildir);
    }

    // ──── Prepare State Paths Before Drop ─────────────────────────
    if let Some(ref user) = cli.user {
        // Resolve user once — fail hard if unknown (no unwrap_or(0))
        let (target_uid, target_gid) = match lookup_user(user) {
            Some((u, g)) => (u, g),
            None => {
                tracing::error!("User '{}' not found — cannot drop privileges", user);
                std::process::exit(2);
            }
        };

        // Ensure stats dir exists and is owned by the target user
        if let Err(e) = std::fs::create_dir_all(&stats_dir) {
            tracing::warn!("Cannot create stats dir {:?}: {e}", stats_dir);
        } else if let Err(e) = chown_path(&stats_dir, target_uid, target_gid) {
            tracing::warn!("Cannot chown stats dir: {e}");
        }

        // Ensure drift file parent directory exists and is owned
        if let Some(parent) = drift_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!("Cannot create drift parent {:?}: {e}", parent);
            } else if let Err(e) = chown_path(parent, target_uid, target_gid) {
                tracing::warn!("Cannot chown drift parent: {e}");
            }
        }
    }

    // ──── Drop Privileges ──────────────────────────────────────────
    if let Some(ref user) = cli.user {
        match drop_privileges(user) {
            Ok(()) => tracing::info!("Dropped privileges to '{}'", user),
            Err(e) => {
                tracing::error!("Failed to drop privileges: {e}");
                std::process::exit(2);
            }
        }
    }

    // ──── Start NTS-KE Server (privileges already dropped) ──────────
    if let Some(nts_config) = engine.nts_config.as_ref() {
        let config = nts_config.clone();
        std::thread::spawn(move || {
            if let Err(e) = ntpsec_rs_core::nts_server::start_nts_ke_server(config) {
                tracing::error!("NTS-KE server failed: {e}");
            }
        });
        tracing::info!("NTS-KE server started on port 4460");
    }

    // ──── Apply Nice (high priority) ───────────────────────────────
    if cli.nice {
        // PRIO_PROCESS = 0, who = 0 (calling process)
        let ret = unsafe { libc::setpriority(0, 0, -10) };
        if ret != 0 {
            tracing::warn!(
                "setpriority failed (not root?): {}",
                std::io::Error::last_os_error()
            );
        } else {
            tracing::info!("Priority set to -10 (high)");
        }
    }

    // ──── Load Key File from CLI (-k) ──────────────────────────────
    if let Some(ref keyfile) = cli.keyfile {
        match std::fs::read_to_string(keyfile) {
            Ok(content) => match engine.auth.parse_keys_file(&content) {
                Ok(count) => tracing::info!("Loaded {} keys from '{}'", count, keyfile.display()),
                Err(e) => tracing::warn!("Failed to parse keys from '{}': {e}", keyfile.display()),
            },
            Err(e) => tracing::warn!("Cannot read key file '{}': {e}", keyfile.display()),
        }
    }

    // ──── Mark Trusted Keys (-t) ───────────────────────────────────
    for key_id in &cli.trustedkey {
        engine.auth.add_trusted_key(*key_id);
        tracing::info!("Trusted key {}", key_id);
    }

    // ──── Signal Handling (must be BEFORE seccomp — threads need clone/clone3) ─
    let running = Arc::new(AtomicBool::new(true));
    let wants_reload = Arc::new(AtomicBool::new(false));
    let sig_exit_code = Arc::new(std::sync::Mutex::new(0i32));

    init_signal_handlers(running.clone(), wants_reload.clone(), sig_exit_code.clone());

    // ──── Seccomp Sandbox (after signal threads are created) ────────
    if cli.seccomp {
        ntp_sandbox::enable_sandbox().unwrap_or_else(|e| {
            tracing::error!("Seccomp requested but unavailable: {e}");
            std::process::exit(1);
        });
        tracing::info!("Seccomp sandbox enabled");
    }

    // ──── Wait for Synchronization (-w) ─────────────────────────────
    if cli.wait_sync {
        tracing::info!("Waiting for clock synchronization...");
        let max_wait_secs = 300; // 5 minute timeout
        let start = std::time::Instant::now();
        loop {
            // Process timers
            let now = clock.now();
            let timer_actions = engine.tick(now);
            execute_actions(&timer_actions, &mut clock, &mut network, &mut store);

            // Process any arriving packets
            match network.recv() {
                Ok(dgram) => {
                    let event = DaemonEvent::PacketReceived(dgram);
                    let actions = engine.handle(event);
                    execute_actions(&actions, &mut clock, &mut network, &mut store);
                }
                Err(IoError::RecvFailed(_)) => {}
                Err(_) => {}
            }

            // Check if synchronized (stratum < 16 = synchronized)
            if engine.system.stratum < 16 {
                tracing::info!(
                    "Clock synchronized (stratum={}, offset={:.6}s)",
                    engine.system.stratum,
                    engine.system.sys_offset,
                );
                break;
            }

            if start.elapsed().as_secs() > max_wait_secs as u64 {
                tracing::warn!("Wait-sync timeout after {max_wait_secs}s — continuing anyway");
                break;
            }

            std::thread::sleep(Duration::from_millis(250));
        }
    }

    // ──── Main Event Loop ────────────────────────────────────────────
    tracing::info!("Entering main event loop with {} peers", engine.peers.len());
    let mut iteration: u64 = 0;

    while running.load(Ordering::Relaxed) {
        iteration += 1;

        // Check for SIGHUP config reload — parse BEFORE mutating state
        if wants_reload.swap(false, Ordering::Relaxed) {
            tracing::info!("SIGHUP received — reloading configuration");
            match read_config_file(&cli.config) {
                Ok(new_config) => {
                    if new_config.errors.is_empty() {
                        // Build new engine state atomically before swap
                        let mut new_engine = DaemonEngine::new(new_config);
                        // Inherit only portable discipline state — NOT system state
                        // (peer_count, stratum, reference_id, etc. must be recomputed
                        // from the new peer set after the next clock_update)
                        new_engine.loop_filter.frequency = engine.loop_filter.frequency;
                        new_engine.loop_filter.wander = engine.loop_filter.wander;
                        new_engine.loop_filter.jitter = engine.loop_filter.jitter;
                        new_engine.precision = engine.precision;
                        // Preserve start time, uptime, and counters across reload
                        new_engine.system.start_time = engine.system.start_time;
                        new_engine.system.uptime_secs = engine.system.uptime_secs;
                        new_engine.system.auth_counters = engine.system.auth_counters.clone();
                        new_engine.system.server_counters = engine.system.server_counters.clone();
                        new_engine.system.sel_broken = engine.system.sel_broken;
                        // Load key files for the new config — abort swap on failure
                        let new_key_paths = collect_key_paths(&new_engine.config);
                        match load_key_files(&mut new_engine.auth, &new_key_paths) {
                            Ok(()) => {
                                // Re-apply CLI trusted keys and keyfile on reload
                                for key_id in &cli.trustedkey {
                                    new_engine.auth.add_trusted_key(*key_id);
                                }
                                if let Some(ref keyfile) = cli.keyfile {
                                    if let Ok(content) = std::fs::read_to_string(keyfile) {
                                        let _ = new_engine.auth.parse_keys_file(&content);
                                    }
                                }
                                // Transactional swap
                                engine = new_engine;
                                tracing::info!("Configuration reloaded (transactional)");
                            }
                            Err(e) => {
                                tracing::error!(
                                    "SIGHUP key loading failed (keeping old config): {e}"
                                );
                            }
                        }
                    } else {
                        tracing::error!("SIGHUP config has errors — keeping old config");
                        for err in &new_config.errors {
                            tracing::error!("  Config error: {err}");
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("SIGHUP config reload failed (keeping old config): {e}");
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

        // 3. Poll refclocks for samples (every 10 iterations)
        if iteration % 10 == 0 {
            let now = clock.now();
            let refclock_actions = engine.refclocks.poll_all(now);
            for action in refclock_actions {
                match action {
                    DaemonAction::RefclockSample {
                        associd,
                        packet,
                        rx_time,
                    } => {
                        let event = DaemonEvent::RefclockSample {
                            associd,
                            packet,
                            rx_time,
                        };
                        let actions = engine.handle(event);
                        execute_actions(&actions, &mut clock, &mut network, &mut store);
                    }
                    other => {
                        execute_actions(&[other], &mut clock, &mut network, &mut store);
                    }
                }
            }
        }

        // 4. Periodic status & statistics
        if iteration % 100 == 0 {
            tracing::info!(
                "Status: peers={} stratum={} offset={:.6}s freq={:.3}ppm",
                engine.system.peer_count,
                engine.system.stratum,
                engine.system.sys_offset,
                engine.loop_filter.frequency_ppm(),
            );
            // Emit loopstats (one line per 100 iterations)
            let loopstats_line = format!(
                "{} {:.6} {:.6} {:.3} {:.6} {:.6}",
                iteration / 100,
                iteration as f64,
                engine.system.sys_offset,
                engine.loop_filter.frequency_ppm(),
                engine.loop_filter.jitter,
                engine.loop_filter.wander,
            );
            execute_actions(
                &[DaemonAction::AppendStatistic {
                    stream: "loopstats".to_string(),
                    line: loopstats_line,
                }],
                &mut clock,
                &mut network,
                &mut store,
            );
            // Emit peerstats for each reachable peer
            for i in 0..engine.peers.len() {
                if let Some(peer) = engine.peers.get(i) {
                    if peer.reach.is_reachable() {
                        let peer_addr = ntpsec_rs_core::ntp_net::socktoa(&peer.srcaddr);
                        let peerstats_line = format!(
                            "{} {} {:.6} {:.6} {:.6} {:.6}",
                            iteration as f64,
                            peer_addr,
                            peer.offset,
                            peer.delay,
                            peer.dispersion,
                            peer.jitter,
                        );
                        execute_actions(
                            &[DaemonAction::AppendStatistic {
                                stream: "peerstats".to_string(),
                                line: peerstats_line,
                            }],
                            &mut clock,
                            &mut network,
                            &mut store,
                        );
                    }
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // ──── Graceful Shutdown ──────────────────────────────────────────
    tracing::info!("Shutting down...");

    // 1. Flush statistics (loopstats and peerstats) immediately
    engine.flush_stats();
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

    // 4. Remove PID file
    if let Some(ref pidfile) = cli.pidfile {
        let _ = std::fs::remove_file(pidfile);
        tracing::info!("Removed PID file {:?}", pidfile);
    }

    // 5. Explicit exit code
    let exit_code = {
        let guard = sig_exit_code.lock().unwrap();
        *guard
    };
    tracing::info!("ntpd-rs stopped (exit code {})", exit_code);
    std::process::exit(exit_code);
}

/// Write the given PID to the specified PID file.
fn write_pid_file(path: &std::path::Path, pid: i32) {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(path, format!("{pid}\n")) {
        Ok(()) => {
            // Best-effort: we already wrote the file
        }
        Err(e) => {
            eprintln!("Warning: cannot write PID file {:?}: {e}", path);
        }
    }
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
            DaemonAction::RefclockSample { .. } => {
                // RefclockSample actions are handled in the main loop
                // before reaching execute_actions.  If one arrives here
                // it means the caller did not pre-filter it.
                tracing::debug!("RefclockSample bypassed main-loop filter");
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

    // Record daemon start time
    engine.system.start_time = clock.now();

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

// ──── Key File Loading ──────────────────────────────────────────────────

/// Collect key file paths from configuration.
fn collect_key_paths(config: &ConfigTree) -> Vec<String> {
    config
        .options
        .iter()
        .filter_map(|opt| {
            if let ntpsec_rs_core::ntp_config::ConfigOption::Keys(p) = opt {
                Some(p.clone())
            } else {
                None
            }
        })
        .collect()
}

/// Chown a path to the given UID/GID using a proper NUL-terminated C string.
fn chown_path(path: &std::path::Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("path contains embedded NUL: {}", path.display()))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(format!(
            "chown {} failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Look up a user by name, returning (UID, GID).
fn lookup_user(user: &str) -> Option<(libc::uid_t, libc::gid_t)> {
    let cuser = std::ffi::CString::new(user).ok()?;
    let pw = unsafe { libc::getpwnam(cuser.as_ptr()) };
    if pw.is_null() {
        None
    } else {
        Some(unsafe { ((*pw).pw_uid, (*pw).pw_gid) })
    }
}

/// Load all key files referenced in the configuration.
/// Returns Err if any key file cannot be read (severe config error).
fn load_key_files(
    auth: &mut ntpsec_rs_core::ntp_auth::AuthKeyStore,
    keys_paths: &[String],
) -> Result<(), String> {
    for path in keys_paths {
        match std::fs::read_to_string(path) {
            Ok(content) => match auth.parse_keys_file(&content) {
                Ok(count) => tracing::info!("Loaded {} keys from '{}'", count, path),
                Err(e) => {
                    return Err(format!("Failed to parse keys from '{}': {}", path, e));
                }
            },
            Err(e) => {
                return Err(format!("Cannot read key file '{}': {}", path, e));
            }
        }
    }
    Ok(())
}

// ──── Privilege Dropping ────────────────────────────────────────────────

/// Drop privileges to the given username after binding privileged sockets.
/// Calls setgid() + setuid() with supplementary groups.
fn drop_privileges(user: &str) -> Result<(), String> {
    // Step 1: PR_SET_KEEPCAPS — retain bounding set through UID transition
    let ret = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(format!(
            "PR_SET_KEEPCAPS failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Step 2: Look up user by name
    let mut buf = vec![0i8; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let cuser = std::ffi::CString::new(user).map_err(|e| format!("invalid username: {e}"))?;
    let ret = unsafe {
        libc::getpwnam_r(
            cuser.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if ret != 0 || result.is_null() {
        return Err(format!("user '{}' not found", user));
    }
    let uid = pwd.pw_uid;
    let gid = pwd.pw_gid;

    // Step 3: Initialize supplementary groups
    let ret = unsafe { libc::initgroups(cuser.as_ptr(), gid) };
    if ret != 0 {
        return Err(format!(
            "initgroups failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Step 4: Change GID first, then UID (Linux capability semantics).
    // Use setresuid() instead of setuid() for glibc compatibility:
    // setuid() on glibc systems (Debian, Ubuntu, Fedora) can fail when the
    // daemon lacks CAP_SETUID in its effective set but still has it in the
    // permitted set.  setresuid() atomically sets all three UIDs (real,
    // effective, saved) and works correctly with PR_SET_KEEPCAPS.
    let ret = unsafe { libc::setgid(gid) };
    if ret != 0 {
        return Err(format!(
            "setgid failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let ret = unsafe { libc::setresuid(uid, uid, uid) };
    if ret != 0 {
        return Err(format!(
            "setresuid({}) failed: {}",
            uid,
            std::io::Error::last_os_error()
        ));
    }

    // Step 5: Retain only CAP_SYS_TIME for clock discipline.
    // CAP_SYS_TIME = 25. Linux v3 caps: caps 0-31 → data[0], caps 32-63 → data[1].
    // So cap 25 belongs in data[0], bit 25.
    #[cfg(target_os = "linux")]
    {
        const CAP_SYS_TIME_NUM: u32 = 25;
        let cap_index = (CAP_SYS_TIME_NUM / 32) as usize; // 0
        let cap_bit = 1u32 << (CAP_SYS_TIME_NUM % 32); // bit 25

        // Linux kernel cap user header (see <linux/capability.h>)
        #[repr(C)]
        struct CapUserHeader {
            version: u32,
            pid: i32,
        }
        // Linux kernel cap user data (see <linux/capability.h>)
        #[repr(C)]
        struct CapUserData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }

        let header = CapUserHeader {
            version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
            pid: 0,
        };
        // Zero out all capabilities, then set only CAP_SYS_TIME
        let mut data = [
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        data[cap_index].effective = cap_bit;
        data[cap_index].permitted = cap_bit;
        // inheritable stays 0
        let ret = unsafe {
            libc::syscall(
                libc::SYS_capset,
                &header as *const _ as *const libc::c_void,
                data.as_mut_ptr() as *mut libc::c_void,
            )
        };
        if ret != 0 {
            // capset failure leaves effective CAP_SYS_TIME unavailable,
            // which prevents clock discipline. This must hard-fail.
            unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) };
            return Err(format!(
                "capset CAP_SYS_TIME failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // Turn off PR_SET_KEEPCAPS now that caps are locked
        unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) };
        tracing::info!("Retained CAP_SYS_TIME, all other capabilities cleared");
    }

    // Step 6: Verify identity
    let actual_uid = unsafe { libc::getuid() };
    let actual_gid = unsafe { libc::getgid() };
    tracing::info!(
        "Privileges dropped to uid={} gid={} (requested {}:{})",
        actual_uid,
        actual_gid,
        uid,
        gid,
    );
    if actual_uid != uid || actual_gid != gid {
        return Err(format!(
            "UID/GID mismatch: got {}:{} expected {}:{}",
            actual_uid, actual_gid, uid, gid
        ));
    }
    Ok(())
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
    fn test_cli_production_flags() {
        let cli = Cli::parse_from([
            "ntpd-rs",
            "-p",
            "/var/run/ntpd.pid",
            "-l",
            "/var/log/ntp.log",
            "-i",
            "/var/empty",
            "-I",
            "192.168.1.1",
            "-I",
            "10.0.0.1",
            "-k",
            "/etc/ntp.keys",
            "-t",
            "1",
            "-t",
            "2",
            "-w",
            "-N",
            "-4",
        ]);
        assert_eq!(cli.pidfile, Some(PathBuf::from("/var/run/ntpd.pid")));
        assert_eq!(cli.logfile, Some(PathBuf::from("/var/log/ntp.log")));
        assert_eq!(cli.jaildir, Some(PathBuf::from("/var/empty")));
        assert_eq!(cli.interface, vec!["192.168.1.1", "10.0.0.1"]);
        assert_eq!(cli.keyfile, Some(PathBuf::from("/etc/ntp.keys")));
        assert_eq!(cli.trustedkey, vec![1, 2]);
        assert!(cli.wait_sync);
        assert!(cli.nice);
        assert!(cli.ipv4);
        assert!(!cli.ipv6);
    }

    #[test]
    fn test_resolve_listen_addresses_default() {
        let cli = Cli::parse_from(["ntpd-rs", "-n"]);
        let addrs = resolve_listen_addresses(&cli);
        assert_eq!(addrs, vec!["0.0.0.0:123"]);
    }

    #[test]
    fn test_resolve_listen_addresses_ipv6() {
        let cli = Cli::parse_from(["ntpd-rs", "-n", "-6"]);
        let addrs = resolve_listen_addresses(&cli);
        assert_eq!(addrs, vec!["[::]:123"]);
    }

    #[test]
    fn test_resolve_listen_addresses_custom() {
        let cli = Cli::parse_from(["ntpd-rs", "-n", "-I", "192.168.1.100", "-I", "10.0.0.1"]);
        let addrs = resolve_listen_addresses(&cli);
        assert_eq!(addrs, vec!["192.168.1.100:123", "10.0.0.1:123"]);
    }

    #[test]
    fn test_resolve_listen_addresses_with_port() {
        let cli = Cli::parse_from(["ntpd-rs", "-n", "-I", "192.168.1.100:456"]);
        let addrs = resolve_listen_addresses(&cli);
        assert_eq!(addrs, vec!["192.168.1.100:456"]);
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
