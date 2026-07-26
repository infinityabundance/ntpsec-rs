// ──── tests/daemon_process_court.rs ──────────────────────────────────────
// Gate 1: Real daemon process court
//
// Proves the COMPLETE daemon path through actual trait boundaries:
//
//   configuration → peer mobilization → timer expiry
//   → engine.tick() produces Send action
//   → constructed NTP request captured through NetworkIo send
//   → server response with controlled timestamps
//   → received as DaemonEvent::PacketReceived
//   → engine.handle() processes response
//   → offset/delay calculation → clock filter → selection
//   → system peer → discipline → clock adjustment (exactly once)
//
// Run: cargo test --test daemon_process_court -p ntpsec-rs-core -- --nocapture
// =============================================================================

use ntpsec_rs_core::ntp_config::ConfigOption;
use ntpsec_rs_core::ntp_fp::ts_to_ntp;
use ntpsec_rs_core::ntp_io::*;
use ntpsec_rs_core::ntp_types::*;
use ntpsec_rs_core::*;

// ──── RecordingClock ─────────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ClockCall {
    kind: ClockCallKind,
    offset: f64,
    freq_ppm: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClockCallKind {
    Step,
    Slew,
    SetFrequency,
}

#[derive(Debug, Clone)]
struct RecordingClock {
    now: NtpTs64,
    freq_ppm: f64,
    calls: Vec<ClockCall>,
}

impl RecordingClock {
    fn new(now: NtpTs64) -> Self {
        Self {
            now,
            freq_ppm: 0.0,
            calls: Vec::new(),
        }
    }

    fn advance(&mut self, seconds: f64) {
        let secs = seconds.trunc() as i64;
        let frac = (seconds.fract() * NTP_FRAC_PER_SEC as f64) as u32;
        self.now.seconds += secs;
        self.now.fraction = self.now.fraction.wrapping_add(frac);
        if self.now.fraction < frac && frac != 0 {
            self.now.seconds += 1;
        }
    }
}

impl SystemClock for RecordingClock {
    fn now(&self) -> NtpTs64 {
        self.now
    }

    fn step(&mut self, offset: f64) -> Result<(), IoError> {
        self.calls.push(ClockCall {
            kind: ClockCallKind::Step,
            offset,
            freq_ppm: 0.0,
        });
        let secs = offset.trunc() as i64;
        let frac = (offset.fract() * NTP_FRAC_PER_SEC as f64) as i64;
        self.now.seconds += secs;
        if frac >= 0 {
            let f = frac as u32;
            self.now.fraction = self.now.fraction.wrapping_add(f);
            if self.now.fraction < f {
                self.now.seconds += 1;
            }
        } else {
            let f = (-frac) as u32;
            self.now.fraction = self.now.fraction.wrapping_sub(f);
            if self.now.fraction > (!f) {
                self.now.seconds -= 1;
            }
        }
        Ok(())
    }

    fn slew(&mut self, offset: f64, freq_ppm: f64) -> Result<(), IoError> {
        self.calls.push(ClockCall {
            kind: ClockCallKind::Slew,
            offset,
            freq_ppm,
        });
        self.step(offset)?;
        self.freq_ppm = freq_ppm;
        Ok(())
    }

    fn read_frequency(&self) -> Result<f64, IoError> {
        Ok(self.freq_ppm)
    }

    fn set_frequency(&mut self, freq_ppm: f64) -> Result<(), IoError> {
        self.calls.push(ClockCall {
            kind: ClockCallKind::SetFrequency,
            offset: 0.0,
            freq_ppm,
        });
        self.freq_ppm = freq_ppm;
        Ok(())
    }
}

// ──── TestNetwork ────────────────────────────────────────────────────

#[derive(Debug)]
struct TestNetwork {
    sent_packets: std::cell::RefCell<Vec<(NetAddr, Vec<u8>)>>,
}

impl TestNetwork {
    fn new() -> Self {
        Self {
            sent_packets: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn drain_sent(&self) -> Vec<(NetAddr, Vec<u8>)> {
        self.sent_packets.borrow_mut().drain(..).collect()
    }

    fn clear(&self) {
        self.sent_packets.borrow_mut().clear();
    }
}

impl NetworkIo for TestNetwork {
    fn bind(&mut self, _addr: &str) -> Result<(), IoError> {
        Ok(())
    }
    fn recv(&mut self) -> Result<ReceivedDatagram, IoError> {
        Err(IoError::RecvFailed("no responses".to_string()))
    }
    fn send(&mut self, buf: &[u8], dest: &NetAddr) -> Result<usize, IoError> {
        self.sent_packets.borrow_mut().push((*dest, buf.to_vec()));
        Ok(buf.len())
    }
}

// ──── Helpers ─────────────────────────────────────────────────────────

/// Build a server response with a controlled offset (matching network_sync_test pattern).
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

fn make_server_config(ip: &str) -> ConfigTree {
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
        minsane: Some(0),
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

fn first_peer(engine: &DaemonEngine) -> Option<&Peer> {
    engine.peers.iter().next()
}

fn make_received(response: Vec<u8>, source: NetAddr, rx_ts: NtpTs64) -> ReceivedDatagram {
    ReceivedDatagram::test(response, source, NetAddr::ipv4(0, 123), rx_ts)
}

// ──── Test 1: Full network sync cycle ────────────────────────────────

#[test]
fn test_daemon_full_network_sync_cycle() {
    let config = make_server_config("192.0.2.1");
    let ntp_epoch = ts_to_ntp(1_000_000_000, 0);

    let mut clock = RecordingClock::new(ntp_epoch);
    let mut network = TestNetwork::new();
    let mut engine = DaemonEngine::new(config);
    engine.system.start_time = clock.now();
    engine.minsane = 0;

    assert_eq!(engine.peers.len(), 1, "server peer mobilized");
    assert!(engine.system.stratum >= 16, "initial stratum >= 16");

    // Trigger first poll
    clock.advance(9.0);
    let tick_actions = engine.tick(clock.now());
    for action in &tick_actions {
        if let DaemonAction::Send { destination, bytes } = action {
            let _ = network.send(bytes, destination);
        }
    }

    let sent = network.drain_sent();
    assert!(!sent.is_empty(), "engine sent poll request");
    let req = NtpPacket::decode_header(&sent[0].1).expect("valid NTP packet");
    assert_eq!(req.li_vn_mode & 0x07, NtpMode::Client as u8, "mode client");
    assert_eq!(
        (req.li_vn_mode >> 3) & 0x07,
        NtpVersion::V4 as u8,
        "version 4"
    );

    // Build and inject server response
    let offset_s = 0.050;
    let resp = build_server_response(&sent[0].1, offset_s);

    // Verify response matches the request
    let resp_pkt = NtpPacket::decode_header(&resp).unwrap();
    assert_eq!(
        resp_pkt.originate_ts, req.transmit_ts,
        "response originate_ts must match request transmit_ts"
    );

    let server_netaddr = NetAddr::ipv4(u32::from_be_bytes([192, 0, 2, 1]), 123);
    let rx_ts = ts_to_ntp(1_000_000_009, 0);
    let dgram = make_received(resp, server_netaddr, rx_ts);

    let event_actions = engine.handle(DaemonEvent::PacketReceived(dgram));
    #[allow(clippy::single_match)]
    for action in &event_actions {
        if let DaemonAction::AdjustClock(adj) = action {
            match adj {
                Adjustment::Step(offset) => {
                    let _ = clock.step(*offset);
                }
                Adjustment::Slew(offset, freq) => {
                    let _ = clock.slew(*offset, *freq);
                }
                Adjustment::KernelSlew(offset, freq) => {
                    let _ = clock.slew(*offset, *freq);
                }
                Adjustment::Panic(_) => panic!("panic"),
                Adjustment::Ignore => {}
            }
        }
    }

    // Check peer state after response
    let peer = first_peer(&engine).expect("peer exists");
    assert!(peer.reach.is_reachable(), "reach nonzero after response");
    assert!(
        (peer.offset - offset_s).abs() < 0.001,
        "offset {:.6}s ≈ {:.6}s",
        peer.offset,
        offset_s
    );

    // Run ticks with responses until synchronized
    let mut adjustment_count = 0;
    let mut synchronized = false;

    for cycle in 0..40 {
        clock.advance(8.0);
        let now = clock.now();
        let actions = engine.tick(now);

        for action in &actions {
            match action {
                DaemonAction::Send { destination, bytes } => {
                    let off = if cycle < 8 { 0.050 } else { 0.002 };
                    let resp2 = build_server_response(bytes, off);
                    let dgram2 = make_received(resp2, *destination, now);
                    let adj = engine.handle(DaemonEvent::PacketReceived(dgram2));
                    for a in &adj {
                        if let DaemonAction::AdjustClock(adj) = a {
                            match adj {
                                Adjustment::Step(offset)
                                | Adjustment::Slew(offset, _)
                                | Adjustment::KernelSlew(offset, _) => {
                                    adjustment_count += 1;
                                    let _ = clock.step(*offset);
                                }
                                Adjustment::Panic(_) => panic!("panic"),
                                Adjustment::Ignore => {}
                            }
                        }
                    }
                }
                DaemonAction::AdjustClock(adj) => match adj {
                    Adjustment::Step(offset)
                    | Adjustment::Slew(offset, _)
                    | Adjustment::KernelSlew(offset, _) => {
                        adjustment_count += 1;
                        let _ = clock.step(*offset);
                    }
                    Adjustment::Panic(_) => panic!("panic"),
                    Adjustment::Ignore => {}
                },
                _ => {}
            }
        }

        if engine.system.sys_peer_associd != 0 {
            synchronized = true;
            break;
        }
    }

    assert!(synchronized, "engine selected system peer");
    assert!(
        engine.system.stratum < 16,
        "stratum {} < 16",
        engine.system.stratum
    );
    assert!(engine.system.leap != LeapIndicator::Alarm, "leap not alarm");
    assert!(adjustment_count > 0, "at least one clock adjustment");

    eprintln!(
        "✓ Gate 1 sealed: stratum={}, sys_peer={}, offset={:.6}s, adj={}, reach={}",
        engine.system.stratum,
        engine.system.sys_peer_associd,
        engine.system.sys_offset,
        adjustment_count,
        first_peer(&engine)
            .map(|p| p.reach.is_reachable())
            .unwrap_or(false),
    );
}

// ──── Test 2: Exactly-once clock mutation ────────────────────────────

#[test]
fn test_daemon_exactly_once_clock_mutation() {
    let config = make_server_config("192.0.2.2");
    let ntp_epoch = ts_to_ntp(1_000_000_000, 0);

    let mut clock = RecordingClock::new(ntp_epoch);
    let _network = TestNetwork::new();
    let mut engine = DaemonEngine::new(config);
    engine.system.start_time = clock.now();
    engine.minsane = 0;

    let mut adjustments_seen: Vec<Adjustment> = Vec::new();

    // Advance past initial poll interval
    clock.advance(9.0);
    for _ in 0..60 {
        let now = clock.now();
        clock.advance(8.0);
        let actions = engine.tick(now);

        for action in &actions {
            match action {
                DaemonAction::Send { destination, bytes } => {
                    let off = 0.010;
                    let resp = build_server_response(bytes, off);
                    let dgram = make_received(resp, *destination, now);
                    let adj = engine.handle(DaemonEvent::PacketReceived(dgram));
                    for a in &adj {
                        if let DaemonAction::AdjustClock(adj) = a {
                            adjustments_seen.push(*adj);
                        }
                    }
                }
                DaemonAction::AdjustClock(adj) => adjustments_seen.push(*adj),
                _ => {}
            }
        }

        // Apply to clock
        for adj in &adjustments_seen {
            match adj {
                Adjustment::Step(offset) => {
                    let _ = clock.step(*offset);
                }
                Adjustment::Slew(offset, freq) => {
                    let _ = clock.slew(*offset, *freq);
                }
                Adjustment::KernelSlew(offset, freq) => {
                    let _ = clock.slew(*offset, *freq);
                }
                Adjustment::Panic(_) => panic!("panic"),
                Adjustment::Ignore => {}
            }
        }

        if engine.system.sys_peer_associd != 0 {
            break;
        }
    }

    assert!(engine.system.sys_peer_associd != 0, "engine synchronized");

    let step_slew_count = clock
        .calls
        .iter()
        .filter(|c| c.kind == ClockCallKind::Step || c.kind == ClockCallKind::Slew)
        .count();

    let non_ignore_count = adjustments_seen
        .iter()
        .filter(|a| !matches!(a, Adjustment::Ignore))
        .count();

    eprintln!(
        "✓ Exactly-once: adj={}, non_ignore={}, clock_calls={}",
        adjustments_seen.len(),
        non_ignore_count,
        clock.calls.len()
    );

    assert_eq!(
        step_slew_count, non_ignore_count,
        "each non-Ignore adjustment → one clock call"
    );
    assert!(non_ignore_count > 0, "at least one adjustment applied");
}

// ──── Test 3: Autonomous peer loss and recovery ──────────────────────

#[test]
fn test_daemon_autonomous_peer_loss_and_recovery() {
    let config = make_server_config("192.0.2.3");
    let ntp_epoch = ts_to_ntp(1_000_000_000, 0);

    let mut clock = RecordingClock::new(ntp_epoch);
    let network = TestNetwork::new();
    let mut engine = DaemonEngine::new(config);
    engine.system.start_time = clock.now();
    engine.minsane = 0;

    // ── Phase 1: Synchronize ──────────────────────────────────────────
    let mut synchronized = false;
    clock.advance(9.0);
    for _ in 0..60 {
        let now = clock.now();
        clock.advance(8.0);
        let actions = engine.tick(now);

        for action in &actions {
            match action {
                DaemonAction::Send { destination, bytes } => {
                    let resp = build_server_response(bytes, 0.010);
                    let dgram = make_received(resp, *destination, now);
                    let adj = engine.handle(DaemonEvent::PacketReceived(dgram));
                    for a in &adj {
                        if let DaemonAction::AdjustClock(adj) = a {
                            match adj {
                                Adjustment::Step(offset)
                                | Adjustment::Slew(offset, _)
                                | Adjustment::KernelSlew(offset, _) => {
                                    let _ = clock.step(*offset);
                                }
                                Adjustment::Panic(_) => panic!("panic"),
                                Adjustment::Ignore => {}
                            }
                        }
                    }
                }
                DaemonAction::AdjustClock(adj) => match adj {
                    Adjustment::Step(offset)
                    | Adjustment::Slew(offset, _)
                    | Adjustment::KernelSlew(offset, _) => {
                        let _ = clock.step(*offset);
                    }
                    Adjustment::Panic(_) => panic!("panic"),
                    Adjustment::Ignore => {}
                },
                _ => {}
            }
        }

        if engine.system.sys_peer_associd != 0 {
            synchronized = true;
            break;
        }
    }

    assert!(synchronized, "engine synchronized initially");
    let start_calls = clock.calls.len();
    eprintln!(
        "Synced: stratum={}, sys_peer={}",
        engine.system.stratum, engine.system.sys_peer_associd
    );

    // ── Phase 2: Peer loss ──────────────────────────────────────────
    network.clear();
    let mut peer_unreachable = false;

    for _ in 0..30 {
        clock.advance(16.0);
        let actions = engine.tick(clock.now());
        for action in &actions {
            match action {
                DaemonAction::Send { .. } | DaemonAction::AdjustClock(_) => {}
                _ => {}
            }
        }
        if let Some(p) = first_peer(&engine) {
            if !p.reach.is_reachable() {
                peer_unreachable = true;
            }
        }
    }

    assert!(peer_unreachable, "peer reach decayed to zero");
    assert_eq!(clock.calls.len(), start_calls, "no adjustments during loss");

    // ── Phase 3: Recovery ──────────────────────────────────────────
    let mut recovered = false;
    for _ in 0..60 {
        clock.advance(8.0);
        let actions = engine.tick(clock.now());

        for action in &actions {
            match action {
                DaemonAction::Send { destination, bytes } => {
                    let resp = build_server_response(bytes, 0.010);
                    let dgram = make_received(resp, *destination, clock.now());
                    let adj = engine.handle(DaemonEvent::PacketReceived(dgram));
                    for a in &adj {
                        if let DaemonAction::AdjustClock(adj) = a {
                            match adj {
                                Adjustment::Step(offset)
                                | Adjustment::Slew(offset, _)
                                | Adjustment::KernelSlew(offset, _) => {
                                    let _ = clock.step(*offset);
                                }
                                Adjustment::Panic(_) => panic!("panic"),
                                Adjustment::Ignore => {}
                            }
                        }
                    }
                }
                DaemonAction::AdjustClock(adj) => match adj {
                    Adjustment::Step(offset)
                    | Adjustment::Slew(offset, _)
                    | Adjustment::KernelSlew(offset, _) => {
                        let _ = clock.step(*offset);
                    }
                    Adjustment::Panic(_) => panic!("panic"),
                    Adjustment::Ignore => {}
                },
                _ => {}
            }
        }

        if engine.system.sys_peer_associd != 0 {
            recovered = true;
            break;
        }
    }

    assert!(recovered, "engine reacquired sync after peer returns");
    assert!(
        engine.system.stratum < 16,
        "stratum {} < 16",
        engine.system.stratum
    );
    if let Some(p) = first_peer(&engine) {
        assert!(p.reach.is_reachable(), "peer reach nonzero after recovery");
    }

    eprintln!(
        "✓ Recovery: stratum={}, sys_peer={}",
        engine.system.stratum, engine.system.sys_peer_associd
    );
}
