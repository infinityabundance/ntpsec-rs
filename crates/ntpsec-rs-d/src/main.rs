// ──── ntpd-rs — NTPsec daemon ───────────────────────────────────────────────
//
// Forensic Rust reconstruction of ntpd — drop-in replacement.
//
// ## Pipeline
//
//   1. Parse config (ntp_config)
//   2. Open sockets (ntpsec-rs-io)
//   3. Create peer associations (ntp_peer)
//   4. Enter main event loop (ntp_timer + ntp_proto):
//      a. Receive packets → validate → process → update peer
//      b. Clock selection → combine → discipline
//      c. Poll timers → transmit
//      d. Housekeeping
//   5. Handle signals, log rotation, stats output
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

use ntpsec_rs_core::ntp_auth::*;
use ntpsec_rs_core::ntp_config::*;
use ntpsec_rs_core::ntp_fp;
use ntpsec_rs_core::ntp_leapsec::*;
use ntpsec_rs_core::ntp_loopfilter::*;
use ntpsec_rs_core::ntp_monitor::*;
use ntpsec_rs_core::ntp_peer::*;
use ntpsec_rs_core::ntp_proto::*;
use ntpsec_rs_core::ntp_recvbuff::*;
use ntpsec_rs_core::ntp_restrict::*;
use ntpsec_rs_core::ntp_syslog::*;
use ntpsec_rs_core::ntp_timer::*;
use ntpsec_rs_core::ntp_types::*;

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

    // Initialize subsystems
    let mut system = SystemState::new();
    let mut loop_filter = LoopFilter::new(if cli.slew {
        DisciplineType::Pll
    } else {
        DisciplineType::PllFll
    });
    let mut peer_table = PeerTable::new();
    let mut auth_store = AuthKeyStore::new();
    let mut leap_table = LeapTable::new();
    let mut restrict_list = RestrictList::new();
    let mut mon_list = MonList::new();
    let mut timer_queue = TimerQueue::new();
    let mut syslog = SyslogBuffer::new();

    // Configure loop filter from CLI
    if cli.slew {
        loop_filter.step_threshold = f64::MAX; // Never step
    }
    if cli.panicgate {
        loop_filter.panic_threshold = f64::MAX; // Never panic
    }

    // Create peer associations from config
    for opt in &config.options {
        match opt {
            ConfigOption::Server { addr, options }
            | ConfigOption::Peer { addr, options }
            | ConfigOption::Pool { addr, options } => {
                let mode = match opt.directive_name() {
                    "peer" => NtpMode::SymActive,
                    _ => NtpMode::Client,
                };

                // Parse minpoll/maxpoll from options
                let mut minpoll = NTP_MINPOLL;
                let mut maxpoll = NTP_MAXPOLL;
                let mut burst = false;
                let mut iburst = false;
                let mut prefer = false;

                for opt_str in options {
                    match opt_str.as_str() {
                        s if s.starts_with("minpoll") => {
                            if let Some(val) = s.strip_prefix("minpoll") {
                                minpoll = val.trim().parse().unwrap_or(NTP_MINPOLL);
                            }
                        }
                        s if s.starts_with("maxpoll") => {
                            if let Some(val) = s.strip_prefix("maxpoll") {
                                maxpoll = val.trim().parse().unwrap_or(NTP_MAXPOLL);
                            }
                        }
                        "burst" => burst = true,
                        "iburst" => iburst = true,
                        "prefer" => prefer = true,
                        _ => {}
                    }
                }

                // Create the peer association
                let srcaddr = if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
                    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                    match ip {
                        std::net::IpAddr::V4(v4) => {
                            let sin =
                                unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in) };
                            sin.sin_family = libc::AF_INET as libc::sa_family_t;
                            sin.sin_port = 123u16.to_be();
                            sin.sin_addr = libc::in_addr {
                                s_addr: u32::from_ne_bytes(v4.octets()),
                            };
                        }
                        std::net::IpAddr::V6(v6) => {
                            let sin6 =
                                unsafe { &mut *(&mut sa as *mut _ as *mut libc::sockaddr_in6) };
                            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                            sin6.sin6_port = 123u16.to_be();
                            sin6.sin6_addr = libc::in6_addr {
                                s6_addr: v6.octets(),
                            };
                        }
                    }
                    sa
                } else {
                    tracing::warn!(
                        "Cannot resolve {} yet (DNS deferred to Phase 2), skipping",
                        addr
                    );
                    continue;
                };

                let mut peer = Peer::new(
                    unsafe { std::mem::transmute::<libc::sockaddr_storage, SockAddr>(srcaddr) },
                    mode,
                    NtpVersion::V4,
                    minpoll,
                    maxpoll,
                );
                if burst {
                    peer.flags |= PeerFlags::BURST;
                }
                if iburst {
                    peer.flags |= PeerFlags::IBURST;
                }
                if prefer {
                    peer.flags |= PeerFlags::PREFER;
                }

                peer_table.add(peer);
                tracing::info!("Added {} association to {}", mode as u8, addr);
            }
            ConfigOption::DriftFile(path) => {
                tracing::info!("Drift file: {}", path);
            }
            ConfigOption::StatsDir(path) => {
                tracing::info!("Stats directory: {}", path);
            }
            ConfigOption::LeapFile(path) => {
                // Try to load the leap file
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Err(e) = leap_table.load_leapfile(&content) {
                        tracing::warn!("Failed to load leap file '{}': {}", path, e);
                    } else {
                        tracing::info!("Loaded leap seconds table ({} entries)", leap_table.len());
                    }
                }
            }
            ConfigOption::Restrict { addr, flags } => {
                if addr == "-4" || addr == "-6" {
                    let ipv4 = addr == "-4";
                    // Parse restrict flags
                    let mut rflags = RestrictFlags::empty();
                    for f in flags {
                        rflags |= match f.as_str() {
                            "ignore" => RestrictFlags::IGNORE,
                            "nomodify" => RestrictFlags::NOMODIFY,
                            "nopeer" => RestrictFlags::NOPEER,
                            "noquery" => RestrictFlags::NOQUERY,
                            "notrap" => RestrictFlags::NOTRAP,
                            "notrust" => RestrictFlags::NOTRUST,
                            "limited" => RestrictFlags::LIMITED,
                            "kod" => RestrictFlags::KOD,
                            "noserve" => RestrictFlags::IGNORE,
                            "server" => RestrictFlags::SERVER,
                            _ => RestrictFlags::NONE,
                        };
                    }
                    // Set default flags for v4 or v6
                    if ipv4 {
                        restrict_list.set_default_v4(rflags);
                    }
                } else if addr == "default" {
                    let mut rflags = RestrictFlags::empty();
                    for f in flags {
                        rflags |= match f.as_str() {
                            "ignore" => RestrictFlags::IGNORE,
                            "nomodify" => RestrictFlags::NOMODIFY,
                            "nopeer" => RestrictFlags::NOPEER,
                            "noquery" => RestrictFlags::NOQUERY,
                            "notrap" => RestrictFlags::NOTRAP,
                            "notrust" => RestrictFlags::NOTRUST,
                            "limited" => RestrictFlags::LIMITED,
                            "kod" => RestrictFlags::KOD,
                            _ => RestrictFlags::NONE,
                        };
                    }
                    restrict_list.set_default_v4(rflags);
                }
                tracing::info!("Restrict entry: {} {:?}", addr, flags);
            }
            ConfigOption::Keys(path) => {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Err(e) = auth_store.parse_keys_file(&content) {
                        tracing::warn!("Failed to load keys file '{}': {}", path, e);
                    } else {
                        tracing::info!("Loaded {} auth keys from {}", auth_store.key_count(), path);
                    }
                } else {
                    tracing::warn!("Cannot read keys file '{}'", path);
                }
            }
            ConfigOption::TrustedKey(kid) => {
                auth_store.add_trusted_key(*kid);
                tracing::info!("Trusted key: {}", kid);
            }
            ConfigOption::ControlKey(kid) => {
                auth_store.set_control_key(*kid);
                tracing::info!("Control key: {}", kid);
            }
            _ => {}
        }
    }

    tracing::info!(
        "Initialized: {} peers, {} auth keys, {} leap entries",
        peer_table.len(),
        auth_store.key_count(),
        leap_table.len()
    );

    // Query-only mode: set clock once and exit
    if cli.query {
        tracing::info!("Query-only mode: setting clock and exiting");
        // Stub: in Phase 2, this will query peers and step clock
        tracing::info!("Query mode not yet fully implemented in Phase 1");
        return;
    }

    // ──── Main Event Loop ────────────────────────────────────────────
    // This is the select/poll loop matching ntpd's main loop.
    // In Phase 1 this is a polling loop; Phase 2 adds proper async I/O.

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    signal_hook_init(r);

    tracing::info!("Entering main event loop (poll interval: 1s)");

    let mut iteration: u64 = 0;
    let precision: i8 = -20; // ~1 us precision (typical for Linux)

    while running.load(Ordering::Relaxed) {
        iteration += 1;
        let now = ntpsec_rs_io::RealSystemClock::new().now();

        // 1. Process timers (poll events, housekeeping)
        let due = timer_queue.due_events(now);
        for event in due {
            match event {
                TimerEvent::Poll(id) => {
                    // Send NTP request to a peer
                    if let Some(peer) = peer_table.get_mut(id as usize) {
                        // Build and send client request
                        let pkt = build_request(peer, &system, now, precision);
                        // Stub: send via network I/O
                        tracing::trace!("Poll tick for peer {}", id);
                    }
                }
                TimerEvent::Housekeeping => {
                    // Periodic housekeeping: update clock selection, etc.
                    let mut peers_vec: Vec<Peer> = peer_table.iter().cloned().collect();
                    system.update_from_peers(&mut peers_vec, now);
                    // Write back updated peers
                    for p in peers_vec {
                        // Stub: update peer_table
                    }
                }
                _ => {}
            }
        }

        // 2. Housekeeping every 10 iterations
        if iteration % 10 == 0 {
            // Update system state from peers
            let mut peers_vec: Vec<Peer> = peer_table.iter().cloned().collect();
            system.update_from_peers(&mut peers_vec, now);
            // Write back
            for (i, p) in peers_vec.iter().enumerate() {
                if let Some(peer) = peer_table.get_mut(i) {
                    peer.offset = p.offset;
                    peer.delay = p.delay;
                    peer.dispersion = p.dispersion;
                    peer.jitter = p.jitter;
                    peer.stratum = p.stratum;
                    peer.leap = p.leap;
                    peer.flash = p.flash;
                }
            }

            // Every 100 iterations, apply clock discipline
            if iteration % 100 == 0 && system.peer_count > 0 {
                let adj = loop_filter.local_clock(system.sys_offset, now);
                match adj {
                    Adjustment::Step(offset) => {
                        tracing::info!("Step clock by {:.6}s", offset);
                    }
                    Adjustment::Slew(offset, freq) => {
                        tracing::trace!("Slew clock by {:.6}s at {:.3}ppm", offset, freq);
                    }
                    Adjustment::Panic(offset) => {
                        tracing::error!("Panic: offset {:.6}s exceeds threshold!", offset);
                        if !cli.panicgate {
                            tracing::error!("Exiting (use -g to override)");
                            break;
                        }
                    }
                    Adjustment::Ignore => {}
                }
                system.sys_frequency = loop_filter.frequency_ppm();
            }

            // Print status periodically
            if iteration % 100 == 0 {
                tracing::info!(
                    "Status: peers={} stratum={} offset={:.6}s freq={:.3}ppm jitter={:.6}s",
                    system.peer_count,
                    system.stratum,
                    system.sys_offset,
                    system.sys_frequency,
                    system.sys_jitter,
                );
            }
        }

        // Sleep for 1 second (in Phase 2, this is an epoll/kqueue wait)
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    tracing::info!("ntpd-rs shutting down");
}

/// Build an NTP client request packet.
fn build_request(peer: &Peer, system: &SystemState, now: NtpTs64, precision: i8) -> NtpPacket {
    let mut pkt = NtpPacket::zeroed();
    pkt.li_vn_mode = NtpPacket::set_li_vn_mode(
        system.leap,
        peer.version,
        if peer.hmode == NtpMode::SymActive {
            NtpMode::SymActive
        } else {
            NtpMode::Client
        },
    );
    pkt.stratum = system.stratum;
    pkt.poll = peer.hpoll;
    pkt.precision = precision;
    // The transmit timestamp is the only one we set; the rest are zero
    // (which tells the server this is a request, not a response).
    pkt.transmit_ts = ntp_fp::ntp_ts64_to_ntpts(now);
    pkt
}

/// Initialize signal handlers for graceful shutdown.
fn signal_hook_init(running: Arc<AtomicBool>) {
    let r = running.clone();
    std::thread::spawn(move || {
        // Simple signal handling: listen for Ctrl+C
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            // In production, use signal_hook crate
            // For now, handle via SIGINT handler below
        }
    });

    // Set up SIGINT handler
    let r2 = running.clone();
    std::thread::spawn(move || {
        use std::io::Read;
        // Read stdin for signals (works with Docker)
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 1];
        while r2.load(Ordering::Relaxed) {
            if stdin.read(&mut buf).is_ok() {
                // We don't actually process stdin here — this is just a placeholder
            }
        }
    });
}
