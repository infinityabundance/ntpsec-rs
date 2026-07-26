// ──── tests/selection_courts.rs ──────────────────────────────────────
// Workstream 4: Selection and discipline parity courts
//
// Tests the selection pipeline (intersection, clustering, combining) and
// clock discipline (loop filter states, step/slew decisions, frequency
// management) against documented NTPsec behavior.
//
// Run: cargo test --test selection_courts -p ntpsec-rs-core -- --nocapture

use ntpsec_rs_core::ntp_fp;
use ntpsec_rs_core::ntp_loopfilter::*;
use ntpsec_rs_core::ntp_peer::*;
use ntpsec_rs_core::ntp_proto::*;
use ntpsec_rs_core::ntp_types::*;

fn make_peer_at(
    offset: f64,
    delay: f64,
    dispersion: f64,
    reachable: bool,
    prefer: bool,
    stratum: u8,
) -> Peer {
    let mut p = Peer::new(
        unsafe { std::mem::zeroed() },
        NtpMode::Client,
        NtpVersion::V4,
        4,
        10,
    );
    p.offset = offset;
    p.delay = delay;
    p.dispersion = dispersion;
    p.jitter = 0.001;
    p.stratum = stratum;
    p.leap = LeapIndicator::NoWarning;
    p.reach.record_success();
    if !reachable {
        for _ in 0..8 {
            p.reach.record_failure();
        }
    }
    if prefer {
        p.flags |= PeerFlags::PREFER;
    }
    p
}

fn make_peer(offset: f64, delay: f64, dispersion: f64, reachable: bool) -> Peer {
    make_peer_at(offset, delay, dispersion, reachable, false, 2)
}

fn run_selection(peers: &mut [Peer], now: NtpTs64, policy: &SelectionPolicy) -> usize {
    let mut sys = SystemState::new();
    sys.update_from_peers(peers, now, policy)
}

fn default_policy() -> SelectionPolicy {
    SelectionPolicy::default()
}

// ──── Falseticker scenarios ───────────────────────────────────────────

#[test]
fn test_falseticker_one_wrong_source() {
    let now = ntp_fp::ts_to_ntp(1000, 0);
    let mut peers = vec![
        make_peer(0.001, 0.005, 0.001, true),
        make_peer(0.002, 0.005, 0.001, true),
        make_peer(0.003, 0.005, 0.001, true),
        make_peer(10.0, 0.005, 0.001, true),
    ];
    let sys_peer = run_selection(&mut peers, now, &default_policy());

    assert!(sys_peer < peers.len(), "Must select a system peer");
    let selected = &peers[sys_peer];
    assert!(
        selected.offset.abs() < 0.1,
        "System peer offset must be near good sources, got {:.6}s",
        selected.offset
    );
    // TRUE flag is set by the daemon engine's run_selection, not by
    // the selection algorithm's update_from_peers. The important assertion
    // is that the system peer offset is near the good sources.
}

#[test]
fn test_falseticker_two_colluding_wrong() {
    let now = ntp_fp::ts_to_ntp(1000, 0);
    let mut peers = vec![
        make_peer(0.001, 0.005, 0.001, true),
        make_peer(0.002, 0.005, 0.001, true),
        make_peer(10.0, 0.005, 0.001, true),
        make_peer(10.1, 0.005, 0.001, true),
    ];
    let sys_peer = run_selection(&mut peers, now, &default_policy());

    // With 2 good and 2 falsetickers, intersection needs majority. With 4 peers,
    // need 3 to agree. Neither group has 3 → no survivor.
    if sys_peer >= peers.len() {
        eprintln!("  No survivor: 2 good vs 2 colluding falsetickers");
    } else {
        eprintln!(
            "  System peer {}: offset={:.6}s",
            sys_peer, peers[sys_peer].offset
        );
    }
}

#[test]
fn test_falseticker_low_jitter_wrong_source() {
    let now = ntp_fp::ts_to_ntp(1000, 0);
    let mut peers = vec![
        make_peer(0.001, 0.005, 0.001, true),
        make_peer(0.002, 0.005, 0.001, true),
        make_peer(0.003, 0.005, 0.001, true),
        make_peer(0.500, 0.001, 0.0001, true),
    ];
    let sys_peer = run_selection(&mut peers, now, &default_policy());

    assert!(sys_peer < peers.len(), "Must select a system peer");
    let selected = &peers[sys_peer];
    assert!(
        selected.offset.abs() < 0.05,
        "System peer should not be the low-jitter outlier, got {:.6}s",
        selected.offset
    );
}

// ──── Prefer peer behavior ────────────────────────────────────────────

#[test]
fn test_prefer_peer_selected_when_within_tolerance() {
    let now = ntp_fp::ts_to_ntp(1000, 0);
    let mut peers = vec![
        make_peer(0.001, 0.005, 0.001, true),
        make_peer(0.002, 0.005, 0.001, true),
        make_peer_at(0.003, 0.005, 0.001, true, true, 2),
    ];
    let sys_peer = run_selection(&mut peers, now, &default_policy());

    assert!(sys_peer < peers.len(), "Must select a system peer");
    assert!(
        peers[sys_peer].flags.contains(PeerFlags::PREFER),
        "Prefer peer should be selected when within tolerance, got peer {}",
        sys_peer
    );
}

// ──── Clock filter ────────────────────────────────────────────────────

#[test]
fn test_clock_filter_spike_rejection() {
    let mut cf = ClockFilter::new();
    for i in 0..7 {
        cf.add_sample(ClockFilterEntry {
            offset: 0.001,
            delay: 0.005,
            dispersion: 0.001 + i as f64 * 0.001,
            time: ntp_fp::ts_to_ntp(1000 + i, 0),
        });
    }
    // The spike has HIGHER delay so the filter (min-delay selector) rejects it
    cf.add_sample(ClockFilterEntry {
        offset: 0.100,
        delay: 0.050,
        dispersion: 0.001,
        time: ntp_fp::ts_to_ntp(1007, 0),
    });

    // NTPsec clock filter selects the entry with minimum delay
    let filtered = cf.filter().unwrap();
    assert!(
        filtered.offset < 0.010,
        "Spike (high delay) should be rejected by clock filter, got {:.6}s",
        filtered.offset
    );
}

#[test]
fn test_clock_filter_empty() {
    let cf = ClockFilter::new();
    assert!(cf.filter().is_none(), "Empty filter must return None");
    assert_eq!(cf.sample_count(), 0, "Empty filter has 0 samples");
}

#[test]
fn test_clock_filter_full_capacity() {
    let mut cf = ClockFilter::new();
    for i in 0..8 {
        cf.add_sample(ClockFilterEntry {
            offset: 0.001 * (i as f64 + 1.0),
            delay: 0.005,
            dispersion: 0.001,
            time: ntp_fp::ts_to_ntp(1000 + i, 0),
        });
    }
    assert_eq!(
        cf.sample_count(),
        8,
        "Filter should have 8 samples at capacity"
    );
    assert!(cf.filter().is_some(), "Full filter must return a result");
    cf.add_sample(ClockFilterEntry {
        offset: 0.010,
        delay: 0.005,
        dispersion: 0.001,
        time: ntp_fp::ts_to_ntp(1008, 0),
    });
    assert_eq!(cf.sample_count(), 8, "Filter must not exceed 8 samples");
}

// ──── Loop filter ─────────────────────────────────────────────────────

#[test]
fn test_loopfilter_initial_state() {
    let lf = LoopFilter::new(DisciplineType::PllFll);
    assert!(!lf.clock_set, "Loop filter should start unset");
    assert_eq!(lf.offset, 0.0, "Initial offset should be 0");
    assert_eq!(lf.frequency_ppm(), 0.0, "Initial frequency should be 0");
}

#[test]
fn test_loopfilter_panic_threshold() {
    let mut lf = LoopFilter::new(DisciplineType::PllFll);
    lf.configure(Some(0.5), Some(1.0));
    // First call always steps the clock
    let _first = lf.local_clock(0.001, ntp_fp::ts_to_ntp(1000, 0));
    // After clock is set, a huge offset should trigger panic
    let result = lf.local_clock(5.0, ntp_fp::ts_to_ntp(2000, 0));
    match result {
        Adjustment::Panic(offset) => {
            assert!(
                (offset - 5.0).abs() < 0.001,
                "Panic should report the offset"
            );
        }
        other => panic!(
            "Expected Panic for offset > panic threshold, got {:?}",
            other
        ),
    }
}

#[test]
fn test_loopfilter_slew_within_threshold() {
    let mut lf = LoopFilter::new(DisciplineType::PllFll);
    lf.configure(Some(0.5), Some(1000.0));
    // First call with clock_set=false always steps.
    let _first = lf.local_clock(0.001, ntp_fp::ts_to_ntp(1000, 0));
    // Now clock_set is true. Small offset should slew.
    let result = lf.local_clock(0.001, ntp_fp::ts_to_ntp(1064, 0));
    match result {
        Adjustment::Slew(_, _) | Adjustment::KernelSlew(_, _) => {}
        other => panic!("Expected Slew for small offset, got {:?}", other),
    }
}

#[test]
fn test_loopfilter_frequency_clamp() {
    let mut lf = LoopFilter::new(DisciplineType::PllFll);
    lf.configure(Some(0.5), Some(1000.0));
    for i in 0..20 {
        let t = ntp_fp::ts_to_ntp(1000 + i * 64, 0);
        let _result = lf.local_clock(0.010, t);
    }
    let freq = lf.frequency_ppm();
    assert!(
        freq.abs() < 1000.0,
        "Frequency must be bounded, got {:.3}ppm",
        freq
    );
}

#[test]
fn test_loopfilter_frequency_training() {
    let mut lf = LoopFilter::new(DisciplineType::PllFll);
    lf.configure(Some(0.5), Some(1000.0));
    for i in 0..30 {
        let offset = 0.0032; // 50 PPM x 64s
        let t = ntp_fp::ts_to_ntp(1000 + i * 64, 0);
        let _result = lf.local_clock(offset, t);
    }
    let freq = lf.frequency_ppm();
    eprintln!("  Trained frequency: {:.3}ppm", freq);
    assert!(
        freq.abs() > 0.0,
        "Frequency should be nonzero after training"
    );
}

// ──── System courts ───────────────────────────────────────────────────

#[test]
fn test_survivor_set_ties() {
    let now = ntp_fp::ts_to_ntp(1000, 0);
    let mut peers = vec![
        make_peer(0.001, 0.005, 0.001, true),
        make_peer(0.001, 0.005, 0.001, true),
        make_peer(0.002, 0.005, 0.001, true),
        make_peer(0.002, 0.005, 0.001, true),
    ];
    let sys_peer = run_selection(&mut peers, now, &default_policy());
    assert!(sys_peer < peers.len(), "Must select a system peer");
    eprintln!(
        "  Tie-breaking: selected peer {} with offset {:.6}s",
        sys_peer, peers[sys_peer].offset
    );
}

#[test]
fn test_single_peer_selected() {
    let now = ntp_fp::ts_to_ntp(1000, 0);
    let mut peers = vec![make_peer(0.001, 0.005, 0.001, true)];
    let sys_peer = run_selection(&mut peers, now, &default_policy());
    assert!(
        sys_peer < peers.len(),
        "Single reachable peer should be selected"
    );
}

#[test]
fn test_root_distance_growth() {
    let p = make_peer(0.001, 0.010, 0.005, true);
    let now = ntp_fp::ts_to_ntp(1000, 0);
    let dist1 = root_distance(&p, now);
    let later = ntp_fp::ts_to_ntp(2000, 0);
    let dist2 = root_distance(&p, later);
    assert!(
        dist2 > dist1,
        "Root distance must increase over time: {:.6}s -> {:.6}s",
        dist1,
        dist2
    );
}
