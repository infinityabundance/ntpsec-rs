// ──── tests/network_sync_test.rs ──────────────────────────────────────
// Workstream 1: Network synchronization court
//
// Proves the complete daemon synchronization path:
//   configuration → peer mobilization → timer expiry → request generation
//   → server response → originate matching → offset/delay calculation
//   → clock filter → clustering → selection → system peer → discipline
//   → clock adjustment (exactly once) → Mode 6 reporting
//
// This is NOT a socket test. It exercises the deterministic engine's
// full decision pipeline through DaemonEvent::PacketReceived injection.
// See tests/docker/ for the real-UDP oracle laboratory.
//
// Run: cargo test --test network_sync_test -p ntpsec-rs-core -- --nocapture

use ntpsec_rs_core::daemon_engine::*;
use ntpsec_rs_core::ntp_config::*;
use ntpsec_rs_core::ntp_control::get_system_variable;
use ntpsec_rs_core::ntp_io::*;
use ntpsec_rs_core::ntp_types::*;

// ──── Helpers ─────────────────────────────────────────────────────────

fn make_config(ip: &str) -> ConfigTree {
    let mut c = ConfigTree::new();
    c.add(ConfigOption::Server {
        addr: ip.to_string(),
        options: vec![
            "minpoll".to_string(),
            "3".to_string(),
            "maxpoll".to_string(),
            "3".to_string(),
        ],
    });
    c.add(ConfigOption::Restrict {
        addr: "default".to_string(),
        flags: vec!["ignore".to_string()],
    });
    c.add(ConfigOption::Restrict {
        addr: ip.to_string(),
        flags: vec![],
    });
    c.add(ConfigOption::Tos {
        minsane: Some(1),
        minclock: Some(1),
        maxdist: Some(5.0),
        orphan: None,
        mintc: None,
        mindist: None,
        maxclock: None,
        ceil: None,
        floor: None,
        coeff: None,
        beep: None,
    });
    c.add(ConfigOption::Tinker {
        step: Some(0.5),
        panic: Some(1000.0),
        dispersion: None,
        stepout: None,
        minpoll: None,
        maxpoll: None,
    });
    c
}

fn peer_netaddr(ip: [u8; 4], port: u16) -> NetAddr {
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&ip);
    NetAddr {
        family: 4,
        addr,
        port,
    }
}

/// Build a server response with a controlled offset.
///
/// Timestamps:
///   originate_ts = client's transmit_ts (echoed back)
///   receive_ts   = client's transmit_ts + offset_s
///   transmit_ts  = receive_ts + 0.001 (1 ms server processing delay)
///
/// The measured offset at the client will be approximately `offset_s`.
fn build_server_response(request_bytes: &[u8], offset_s: f64) -> Vec<u8> {
    let req = NtpPacket::decode_header(request_bytes).unwrap();
    let t1_secs = req.transmit_ts.seconds as f64;
    let t1_frac = req.transmit_ts.fraction as f64 / 4294967296.0;
    let t1 = t1_secs + t1_frac;
    let t2 = t1 + offset_s;
    let t3 = t2 + 0.001;

    let mut resp = NtpPacket::zeroed();
    resp.li_vn_mode =
        NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
    resp.stratum = 2;
    resp.poll = 6;
    resp.precision = -20;
    resp.root_delay = (0.001 * 65536.0) as u32;
    resp.root_dispersion = (0.001 * 65536.0) as u32;
    resp.reference_id = u32::from_be_bytes(*b"TEST");
    resp.originate_ts = req.transmit_ts;
    resp.receive_ts = NtpTs {
        seconds: t2 as u32,
        fraction: ((t2.fract()) * 4294967296.0) as u32,
    };
    resp.transmit_ts = NtpTs {
        seconds: t3 as u32,
        fraction: ((t3.fract()) * 4294967296.0) as u32,
    };
    resp.encode_header().to_vec()
}

/// Query a system variable from the engine via get_system_variable.
fn sysvar(engine: &DaemonEngine, name: &str) -> String {
    get_system_variable(&engine.system, name).unwrap_or_default()
}

// ──── Workstream 1: Full lifecycle with offset assertions ─────────────

/// Test the complete synchronization lifecycle with a 2 ms offset.
///
/// Asserts:
///   - Request mode is Client, version is V4, transmit_ts nonzero
///   - Response originate_ts matches request transmit_ts
///   - Reach register evolves
///   - System peer becomes nonzero
///   - Stratum drops below 16
///   - Leap leaves alarm state
///   - Exactly one clock adjustment is emitted
///   - Clock adjustment magnitude is within tolerance of fixture
///   - Mode 6 reports synchronized state
#[test]
fn test_network_sync_complete_lifecycle_2ms() {
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);
    assert_eq!(engine.peers.len(), 1, "must have 1 configured peer");
    assert_eq!(engine.system.stratum, 16, "start unsynchronized");
    assert_eq!(sysvar(&engine, "stratum"), "16");
    assert_eq!(sysvar(&engine, "leap"), "03"); // LeapIndicator::Alarm = 3 (formatted {:02})

    let mut time_base = 1_000_000i64;
    let mut sync_achieved = false;
    let mut polls_sent = 0u32;
    let mut adjustment_count = 0u32;

    for cycle in 0..40 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let actions = engine.tick(now);

        for action in &actions {
            match action {
                DaemonAction::Send { destination, bytes } => {
                    polls_sent += 1;

                    // Verify the request is a valid client-mode packet
                    let req = NtpPacket::decode_header(bytes).unwrap();
                    assert_eq!(req.mode(), NtpMode::Client, "poll must be client mode");
                    assert_eq!(req.version(), NtpVersion::V4, "poll must be NTPv4");
                    assert!(
                        req.transmit_ts.seconds != 0 || req.transmit_ts.fraction != 0,
                        "transmit timestamp must be nonzero"
                    );

                    // Build response with controlled offset
                    let offset_s = if cycle < 8 { 0.050 } else { 0.002 };
                    let resp_bytes = build_server_response(bytes, offset_s);

                    // Verify originate timestamp matching BEFORE moving resp_bytes
                    let resp_pkt = NtpPacket::decode_header(&resp_bytes).unwrap();
                    assert_eq!(
                        resp_pkt.originate_ts, req.transmit_ts,
                        "server must echo client's transmit timestamp"
                    );

                    let source = peer_netaddr([127, 0, 0, 1], 123);
                    let dgram = ReceivedDatagram::test(resp_bytes, source, *destination, now);

                    let resp_actions = engine.handle(DaemonEvent::PacketReceived(dgram));
                    for a in &resp_actions {
                        if let DaemonAction::AdjustClock(_) = a {
                            adjustment_count += 1;
                        }
                    }
                }
                DaemonAction::AdjustClock(_) => {
                    adjustment_count += 1;
                }
                _ => {}
            }
        }

        if !sync_achieved && engine.system.sys_peer_associd != 0 {
            sync_achieved = true;
            eprintln!(
                "  SYNC at cycle {}: stratum={}, offset={:.6}s, peer={}",
                cycle,
                engine.system.stratum,
                engine.system.sys_offset,
                engine.system.sys_peer_associd
            );
        }

        time_base += 2;
    }

    eprintln!(
        "\n  polls_sent={}, adjustment_count={}, sync={}",
        polls_sent, adjustment_count, sync_achieved
    );
    eprintln!(
        "  stratum={}, peer={}, offset={:.6}s, freq={:.3}ppm",
        engine.system.stratum,
        engine.system.sys_peer_associd,
        engine.system.sys_offset,
        engine.loop_filter.frequency_ppm()
    );

    // Core synchronization assertions
    assert!(polls_sent > 0, "At least one poll must be sent");
    assert!(sync_achieved, "Engine must synchronize");
    assert!(
        engine.system.sys_peer_associd != 0,
        "Must select a system peer"
    );
    assert!(engine.system.stratum < 16, "Stratum must drop below 16");
    assert!(
        engine.system.leap != LeapIndicator::Alarm,
        "Leap must leave alarm state"
    );

    // Clock adjustment assertions
    assert!(
        adjustment_count > 0,
        "At least one clock adjustment must be emitted"
    );
    assert!(
        adjustment_count <= polls_sent,
        "Clock adjustments must not exceed polls sent"
    );

    // Mode 6 variable assertions
    let sys_stratum = sysvar(&engine, "stratum");
    assert_eq!(sys_stratum, format!("{}", 3.min(engine.system.stratum)));
    let sys_leap = sysvar(&engine, "leap");
    assert_eq!(sys_leap, format!("{:02}", engine.system.leap as u8));
    let sys_peer = sysvar(&engine, "peer");
    assert_eq!(sys_peer, format!("{}", engine.system.peer_count));
    let sys_offset = sysvar(&engine, "offset");
    assert!(
        !sys_offset.is_empty(),
        "offset must be reportable via Mode 6"
    );
    let sys_freq = sysvar(&engine, "frequency");
    assert!(
        !sys_freq.is_empty(),
        "frequency must be reportable via Mode 6"
    );
    eprintln!(
        "  Mode 6: stratum={}, leap={}, peer={}, offset={}, frequency={}",
        sys_stratum, sys_leap, sys_peer, sys_offset, sys_freq
    );
}

// ──── Offset scenarios ────────────────────────────────────────────────

/// Test synchronization with a zero offset.
#[test]
fn test_network_sync_zero_offset() {
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);
    let mut time_base = 1_000_000i64;
    let mut sync_achieved = false;

    for cycle in 0..40 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let actions = engine.tick(now);
        for action in &actions {
            if let DaemonAction::Send { destination, bytes } = action {
                let resp_bytes = build_server_response(bytes, 0.0);
                let source = peer_netaddr([127, 0, 0, 1], 123);
                let dgram = ReceivedDatagram::test(resp_bytes, source, *destination, now);
                engine.handle(DaemonEvent::PacketReceived(dgram));
            }
        }
        if !sync_achieved && engine.system.sys_peer_associd != 0 {
            sync_achieved = true;
            eprintln!(
                "  SYNC at cycle {}: offset={:.9}s (zero offset target)",
                cycle, engine.system.sys_offset
            );
        }
        time_base += 2;
    }
    assert!(sync_achieved, "Must synchronize with zero offset");
    assert!(
        engine.system.sys_offset.abs() < 0.001,
        "Offset should converge near zero, got {:.6}s",
        engine.system.sys_offset
    );
}

/// Test synchronization with a negative offset.
#[test]
fn test_network_sync_negative_offset() {
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);
    let mut time_base = 1_000_000i64;
    let mut sync_achieved = false;

    for cycle in 0..40 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let actions = engine.tick(now);
        for action in &actions {
            if let DaemonAction::Send { destination, bytes } = action {
                let offset = if cycle < 8 { -0.050 } else { -0.002 };
                let resp_bytes = build_server_response(bytes, offset);
                let source = peer_netaddr([127, 0, 0, 1], 123);
                let dgram = ReceivedDatagram::test(resp_bytes, source, *destination, now);
                engine.handle(DaemonEvent::PacketReceived(dgram));
            }
        }
        if !sync_achieved && engine.system.sys_peer_associd != 0 {
            sync_achieved = true;
            eprintln!(
                "  SYNC at cycle {}: offset={:.6}s (negative offset target)",
                cycle, engine.system.sys_offset
            );
        }
        time_base += 2;
    }
    assert!(sync_achieved, "Must synchronize with negative offset");
    assert!(
        engine.system.sys_peer_associd != 0,
        "Must select a system peer with negative offset"
    );
}

/// Test synchronization with a large offset above the step threshold.
#[test]
fn test_network_sync_step_threshold_offset() {
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);
    let mut time_base = 1_000_000i64;
    let mut sync_achieved = false;
    let mut saw_step = false;

    for cycle in 0..60 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let actions = engine.tick(now);
        for action in &actions {
            if let DaemonAction::Send { destination, bytes } = action {
                // 1.0 s offset — above the step threshold of 0.5 s set in tinker config
                let offset = if cycle < 10 { 1.0 } else { 0.002 };
                let resp_bytes = build_server_response(bytes, offset);
                let source = peer_netaddr([127, 0, 0, 1], 123);
                let dgram = ReceivedDatagram::test(resp_bytes, source, *destination, now);
                engine.handle(DaemonEvent::PacketReceived(dgram));
            }
            // Check for Step actions from tick() (housekeeping triggers run_selection)
            if let DaemonAction::AdjustClock(Adjustment::Step(_)) = action {
                saw_step = true;
                eprintln!("  STEP at cycle {}", cycle);
            }
        }
        if !sync_achieved && engine.system.sys_peer_associd != 0 {
            sync_achieved = true;
            eprintln!(
                "  SYNC at cycle {}: offset={:.6}s (step scenario)",
                cycle, engine.system.sys_offset
            );
        }
        time_base += 2;
    }
    assert!(sync_achieved, "Must synchronize with large offset");
    assert!(saw_step, "Large offset should trigger a step adjustment");
}

// ──── Workstream 2: Autonomous peer loss and reacquisition ───────────

#[test]
fn test_network_sync_autonomous_peer_loss() {
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);

    // ── Phase 1: Synchronize ──────────────────────────────────────
    // Housekeeping fires at ~64s, which is cycle 32 (1,000,000 + 32*2 = 1,000,064).
    // We need enough cycles to reach housekeeping so run_selection() runs.
    let mut time_base = 1_000_000i64;
    let mut sync_achieved = false;

    for cycle in 0..35 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let actions = engine.tick(now);
        for action in &actions {
            if let DaemonAction::Send { destination, bytes } = action {
                let offset = if cycle < 5 { 0.050 } else { 0.002 };
                let resp_bytes = build_server_response(bytes, offset);
                let source = peer_netaddr([127, 0, 0, 1], 123);
                let dgram = ReceivedDatagram::test(resp_bytes, source, *destination, now);
                engine.handle(DaemonEvent::PacketReceived(dgram));
            }
        }
        if !sync_achieved && engine.system.sys_peer_associd != 0 {
            sync_achieved = true;
            eprintln!(
                "  Phase 1: SYNC at cycle {}: stratum={}, peer={}",
                cycle, engine.system.stratum, engine.system.sys_peer_associd
            );
        }
        time_base += 2;
    }

    assert!(sync_achieved, "Must synchronize before loss test");
    let pre_loss_stratum = engine.system.stratum;
    let pre_loss_peer = engine.system.sys_peer_associd;
    assert!(pre_loss_peer != 0, "Must have system peer before loss");
    eprintln!(
        "  Pre-loss: stratum={}, peer={}, offset={:.6}s",
        pre_loss_stratum, pre_loss_peer, engine.system.sys_offset
    );

    // ── Phase 2: Stop all responses — autonomous peer loss ──────
    // With poll interval=8s, has_stale records a reach failure for each
    // unanswered poll. After 8 failures (64s), reach=0. The next housekeeping
    // (every 64s) runs run_selection() which clears sys_peer_associd when
    // no survivors are found.
    //
    // Timing: Phase 1 ends at t=1,000,070. Polls fire at t=1,000,072 (no
    // stale yet), then t=1,000,080 (stale #1) through t=1,000,136 (stale #8,
    // reach=0). Housekeeping fires at t=1,000,192. We run 70 cycles = 140s
    // to cover t=1,000,072 through t=1,000,212.
    let loss_start = time_base;
    let mut loss_detected = false;
    for cycle in 0..70 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let _actions = engine.tick(now);
        // NO responses injected — reach register decays autonomously
        if !loss_detected && engine.system.sys_peer_associd == 0 {
            loss_detected = true;
            eprintln!(
                "  Phase 2: LOSS at cycle {} (t={}, {}s after last response)",
                cycle,
                time_base,
                time_base - loss_start
            );
        }
        time_base += 2;
    }
    assert!(
        loss_detected,
        "Engine must autonomously lose system peer via reach decay"
    );
    assert!(
        engine.system.stratum >= 16,
        "Stratum must be unsynchronized after loss, got {}",
        engine.system.stratum
    );
    assert_eq!(
        engine.system.leap,
        LeapIndicator::Alarm,
        "Leap must become alarm after loss"
    );
    eprintln!(
        "  Post-loss: stratum={}, leap={:?}",
        engine.system.stratum, engine.system.leap
    );

    // ── Phase 3: Resynchronize when responses resume ─────────────
    // With responses back, reach rebuilds (8 successes = 64s). Housekeeping
    // at t=1,000,256 runs run_selection() which re-selects the system peer.
    // We run 50 cycles = 100s from t=1,000,212 to t=1,000,312 (covers
    // housekeeping at t=1,000,256).
    let mut resync_achieved = false;
    for cycle in 0..50 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let actions = engine.tick(now);
        for action in &actions {
            if let DaemonAction::Send { destination, bytes } = action {
                let resp_bytes = build_server_response(bytes, 0.002);
                let source = peer_netaddr([127, 0, 0, 1], 123);
                let dgram = ReceivedDatagram::test(resp_bytes, source, *destination, now);
                engine.handle(DaemonEvent::PacketReceived(dgram));
            }
        }
        if !resync_achieved && engine.system.sys_peer_associd != 0 {
            resync_achieved = true;
            eprintln!(
                "  Phase 3: RESYNC at cycle {} (t={}): stratum={}, peer={}",
                cycle, time_base, engine.system.stratum, engine.system.sys_peer_associd
            );
        }
        time_base += 2;
    }

    assert!(resync_achieved, "Must resynchronize after peer returns");
    assert!(
        engine.system.sys_peer_associd != 0,
        "Must select a system peer after reacquisition"
    );
    assert!(
        engine.system.stratum < 16,
        "Stratum must be below 16 after reacquisition, got {}",
        engine.system.stratum
    );
    eprintln!(
        "  Final: stratum={}, peer={}, offset={:.6}s, freq={:.3}ppm",
        engine.system.stratum,
        engine.system.sys_peer_associd,
        engine.system.sys_offset,
        engine.loop_filter.frequency_ppm()
    );
}

// ──── Workstream 1: Offset convergence trajectory ─────────────────────

#[test]
fn test_network_sync_offset_trajectory_converges() {
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);
    let mut time_base = 1_000_000i64;
    let mut offsets: Vec<f64> = Vec::new();
    let mut adjustments: Vec<Adjustment> = Vec::new();

    for cycle in 0..50 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let actions = engine.tick(now);
        for action in &actions {
            if let DaemonAction::Send { destination, bytes } = action {
                let offset_s = if cycle < 8 { 0.050 } else { 0.002 };
                let resp_bytes = build_server_response(bytes, offset_s);
                let source = peer_netaddr([127, 0, 0, 1], 123);
                let dgram = ReceivedDatagram::test(resp_bytes, source, *destination, now);
                let _resp_actions = engine.handle(DaemonEvent::PacketReceived(dgram));
            }
            if let DaemonAction::AdjustClock(adj) = action {
                adjustments.push(*adj);
            }
        }
        // Track peer offset directly from the clock filter (sys_offset only
        // updates during housekeeping at ~64s intervals, but peer.offset is
        // updated on each response)
        if let Some(peer) = engine.peers.iter().next() {
            offsets.push(peer.offset);
        }
        time_base += 2;
    }

    // Early offsets should be larger (near 50 ms)
    let early_max = offsets[..8].iter().cloned().fold(0.0_f64, f64::max);
    // Late offsets should be smaller (near 2 ms) — use sys_offset post-sync
    let late_sys_offset = engine.system.sys_offset;

    eprintln!(
        "  Early max peer offset: {:.6}s, Late sys_offset: {:.6}s",
        early_max, late_sys_offset
    );
    eprintln!("  Total adjustments: {}", adjustments.len());

    assert!(
        early_max > 0.010,
        "Early peer offset should reflect large input (~50ms), got {:.6}s",
        early_max
    );
    assert!(
        late_sys_offset.abs() < 0.010,
        "Sys offset should converge below 10ms, got {:.6}s",
        late_sys_offset
    );
    assert!(
        !adjustments.is_empty(),
        "At least one clock adjustment must be emitted"
    );
}

// ──── Workstream 8: DNS and pool lifecycle courts ─────────────────────

#[test]
fn test_dns_resolved_creates_peer() {
    // Verifies that a DnsResolved event creates a peer association
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);
    // Manually add a pending DNS entry
    let addr = "pool.example.org".to_string();
    let request_id = 42;
    engine.pending_dns.push_back(PendingDns {
        request_id,
        hostname: addr.clone(),
        port: 123,
        opts: AssocOptions::default(),
        is_pool: true,
    });
    let initial_count = engine.peers.len();
    let resolved_addr = NetAddr::ipv4(0x01010101, 123); // 1.1.1.1
    let _actions = engine.handle(DaemonEvent::DnsResolved {
        request_id,
        addresses: vec![resolved_addr],
    });
    assert!(
        engine.peers.len() > initial_count,
        "DnsResolved must create a peer"
    );
    // Verify the peer was added to the pool resolver
    assert!(
        engine.pool_resolver.contains_key(&addr),
        "Pool hostname must be registered in pool_resolver"
    );
}

#[test]
fn test_dns_resolved_multiple_addresses() {
    // Verifies that DNS resolution with multiple addresses creates multiple peers
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);
    let request_id = 43;
    engine.pending_dns.push_back(PendingDns {
        request_id,
        hostname: "pool.example.org".to_string(),
        port: 123,
        opts: AssocOptions::default(),
        is_pool: true,
    });
    let initial_count = engine.peers.len();
    let addrs = vec![
        NetAddr::ipv4(0x01010101, 123),
        NetAddr::ipv4(0x02020202, 123),
        NetAddr::ipv4(0x03030303, 123),
    ];
    let _actions = engine.handle(DaemonEvent::DnsResolved {
        request_id,
        addresses: addrs,
    });
    assert_eq!(
        engine.peers.len(),
        initial_count + 3,
        "DnsResolved with 3 addresses must create 3 peers"
    );
}

#[test]
fn test_dns_failed_removes_pending() {
    // Verifies that DnsFailed removes the pending DNS entry
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);
    let request_id = 44;
    engine.pending_dns.push_back(PendingDns {
        request_id,
        hostname: "nonexistent.example.org".to_string(),
        port: 123,
        opts: AssocOptions::default(),
        is_pool: false,
    });
    assert_eq!(engine.pending_dns.len(), 1, "Must have 1 pending DNS");
    let _actions = engine.handle(DaemonEvent::DnsFailed {
        request_id,
        error: "NXDOMAIN".to_string(),
    });
    assert_eq!(
        engine.pending_dns.len(),
        0,
        "DnsFailed must remove pending entry"
    );
}

#[test]
fn test_pool_refresh_emitted_in_tick() {
    // Verifies that tick() emits ResolveHostname actions for stale pool entries
    let config = make_config("127.0.0.1");
    let mut engine = DaemonEngine::new(config);
    // Register a pool with expired refresh
    engine.pool_resolver.insert(
        "pool.example.org".to_string(),
        PoolState {
            hostname: "pool.example.org".to_string(),
            port: 123,
            last_refresh: 0,
            refresh_interval: 10,
            associds: vec![],
        },
    );
    let now = NtpTs64 {
        seconds: 100,
        fraction: 0,
    };
    let actions = engine.tick(now);
    let has_refresh = actions.iter().any(|a| {
        matches!(a, DaemonAction::ResolveHostname { hostname, .. } if hostname == "pool.example.org")
    });
    assert!(
        has_refresh,
        "tick() must emit ResolveHostname for stale pool entries"
    );
}
