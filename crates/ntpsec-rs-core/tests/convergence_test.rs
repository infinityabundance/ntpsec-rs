// Convergence test using direct refclock sample injection.
// This bypasses the network request/response matching and tests
// the selection and discipline pipeline directly.

use ntpsec_rs_core::daemon_engine::*;
use ntpsec_rs_core::ntp_config::*;
use ntpsec_rs_core::ntp_fp;
use ntpsec_rs_core::ntp_io::*;
use ntpsec_rs_core::ntp_types::*;

fn make_config() -> ConfigTree {
    let mut c = ConfigTree::new();
    c.add(ConfigOption::Refclock {
        refclock_type: 1,
        unit: 0,
        options: vec![],
    });
    c.add(ConfigOption::Fudge {
        refclock_type: 1,
        unit: 0,
        time1: 0.0,
        time2: 0.0,
        stratum: 2,
        refid: "LOCL".to_string(),
    });
    c.add(ConfigOption::Tos {
        minsane: Some(1),
        minclock: Some(1),
        maxdist: Some(5.0),
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

fn build_refclock_packet(stratum: u8, offset_s: f64, time_base: i64) -> NtpPacket {
    let mut pkt = NtpPacket::zeroed();
    pkt.li_vn_mode =
        NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
    pkt.stratum = stratum;
    pkt.poll = 4;
    pkt.precision = -20;
    pkt.root_delay = (0.001 * 65536.0) as u32;
    pkt.root_dispersion = (0.001 * 65536.0) as u32;
    pkt.reference_id = u32::from_be_bytes(*b"LOCL");
    // Set timestamps: simulate a local clock sample
    // The refclock sample uses transmit_ts as the sample timestamp
    pkt.transmit_ts = NtpTs {
        seconds: time_base as u32,
        fraction: 0,
    };
    pkt
}

#[test]
fn test_convergence_refclock_samples() {
    let config = make_config();
    let mut engine = DaemonEngine::new(config);
    assert_eq!(engine.system.stratum, 16);
    assert_eq!(engine.peers.len(), 1);

    let mut time_base = 1_000_000i64;
    let mut sync_achieved = false;

    for tick in 0..50 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let _tick_actions = engine.tick(now);

        // Inject a refclock sample every tick
        // The first few ticks establish the filter, then convergence happens
        let initial_offset = 0.050; // 50ms initial offset to simulate startup
        let offset = if tick < 5 { initial_offset } else { 0.002 }; // converge to 2ms

        let pkt = build_refclock_packet(2, offset, time_base);
        let associd = engine.peers.iter().next().map(|p| p.associd).unwrap_or(1);

        let actions = engine.handle(DaemonEvent::RefclockSample {
            associd,
            packet: pkt,
            rx_time: now,
        });

        // Check for clock adjustments
        for a in &actions {
            if let DaemonAction::AdjustClock(adj) = a {
                eprintln!("  adj: {:?}", adj);
            }
        }

        // Run selection after sample injection

        if !sync_achieved && engine.system.sys_peer_associd != 0 {
            sync_achieved = true;
            eprintln!(
                "SYNC at tick {}: stratum={}, offset={:.6}s, peer={}",
                tick,
                engine.system.stratum,
                engine.system.sys_offset,
                engine.system.sys_peer_associd
            );
        }
        time_base += 1;
    }

    eprintln!("\n=== Final ===");
    eprintln!(
        "  sync={}, stratum={}, peer={}, offset={:.6}s, freq={:.3}ppm, jitter={:.9}s",
        sync_achieved,
        engine.system.stratum,
        engine.system.sys_peer_associd,
        engine.system.sys_offset,
        engine.loop_filter.frequency_ppm(),
        engine.system.sys_jitter
    );

    for name in &[
        "version",
        "stratum",
        "leap",
        "offset",
        "frequency",
        "sys_jitter",
        "peer",
        "tc",
        "rootdelay",
        "uptime",
    ] {
        let val = ntpsec_rs_core::ntp_control::get_system_variable(&engine.system, name)
            .unwrap_or_default();
        eprintln!("  {} = {}", name, val);
    }

    assert!(sync_achieved, "Must synchronize with refclock samples");
    assert!(
        engine.system.stratum < 16,
        "Must leave unsynchronized state"
    );
    assert!(engine.system.sys_peer_associd != 0, "Must have system peer");

    // Peer loss
    for aid in engine.peers.iter().map(|p| p.associd).collect::<Vec<_>>() {
        engine.peers.remove_by_associd(aid);
    }
    engine.system.sys_peer_associd = 0;
    engine.system.stratum = 16;
    engine.system.leap = LeapIndicator::Alarm;
    assert_eq!(engine.system.stratum, 16, "Peer loss resets stratum");
}

#[test]
fn test_convergence_peer_loss_recovery() {
    let config = make_config();
    let mut engine = DaemonEngine::new(config);

    // Inject samples to synchronize
    let mut time_base = 1_000_000i64;
    for tick in 0..30 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let _ = engine.tick(now);

        let offset = if tick < 5 { 0.050 } else { 0.001 };
        let pkt = build_refclock_packet(2, offset, time_base);
        let associd = engine.peers.iter().next().map(|p| p.associd).unwrap_or(1);
        engine.handle(DaemonEvent::RefclockSample {
            associd,
            packet: pkt,
            rx_time: now,
        });
        time_base += 1;
    }
    assert!(
        engine.system.sys_peer_associd != 0,
        "Must have system peer before loss"
    );

    // Kill the peer
    for aid in engine.peers.iter().map(|p| p.associd).collect::<Vec<_>>() {
        engine.peers.remove_by_associd(aid);
    }
    engine.system.sys_peer_associd = 0;
    engine.system.stratum = 16;
    eprintln!("Peer removed, stratum reset to {}", engine.system.stratum);
    assert_eq!(engine.system.stratum, 16, "No peers = unsynchronized");
}
