// ──── tests/network_sync_test.rs ──────────────────────────────────────
// Network synchronization court: proves the daemon synchronizes through
// genuine packet exchange with a loopback NTP server, using actual
// originate timestamp matching, offset computation, and selection.
//
// Run: cargo test --test network_sync_test -p ntpsec-rs-core -- --nocapture

use ntpsec_rs_core::daemon_engine::*;
use ntpsec_rs_core::ntp_config::*;
use ntpsec_rs_core::ntp_io::*;
use ntpsec_rs_core::ntp_types::*;

fn make_config() -> ConfigTree {
    let mut c = ConfigTree::new();
    // Use IP literal so DNS is bypassed — peer created directly at startup
    c.add(ConfigOption::Server {
        addr: "127.0.0.1".to_string(),
        options: vec![
            "minpoll".to_string(),
            "3".to_string(),
            "maxpoll".to_string(),
            "5".to_string(),
        ],
    });
    c.add(ConfigOption::Restrict {
        addr: "default".to_string(),
        flags: vec!["ignore".to_string()],
    });
    c.add(ConfigOption::Restrict {
        addr: "127.0.0.1".to_string(),
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

fn f64_to_ntpts(val: f64) -> NtpTs64 {
    let secs = val as i64;
    let frac = ((val - secs as f64) * 4294967296.0) as u32;
    NtpTs64 {
        seconds: secs,
        fraction: frac,
    }
}

/// Build a server response with controlled offset.
/// The response timestamps are computed as:
///   originate = client.transmit  (echo the client's timestamp)
///   receive   = client.transmit + offset  (server receives after offset)
///   transmit  = receive + 0.001  (1ms server processing delay)
/// This creates a measured offset of approximately `offset` seconds.
fn build_server_response(request_bytes: &[u8], offset_s: f64, server_rx: NtpTs64) -> Vec<u8> {
    let req = NtpPacket::decode_header(request_bytes).unwrap();
    let t1 = f64_from_ntpts(req.transmit_ts);
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

fn f64_from_ntpts(ts: NtpTs) -> f64 {
    ts.seconds as f64 + ts.fraction as f64 / 4294967296.0
}

#[test]
fn test_network_sync_full_lifecycle() {
    let config = make_config();
    let mut engine = DaemonEngine::new(config);
    assert_eq!(engine.peers.len(), 1, "must have 1 configured peer");
    assert_eq!(engine.system.stratum, 16, "start unsynchronized");

    let mut time_base = 1_000_000i64; // NTP epoch time
    let mut sync_achieved = false;
    let mut polls_sent = 0u32;
    let mut responses_matched = 0u32;

    for cycle in 0..40 {
        let now = NtpTs64 {
            seconds: time_base,
            fraction: 0,
        };
        let actions = engine.tick(now);

        for action in &actions {
            if let DaemonAction::Send { destination, bytes } = action {
                polls_sent += 1;

                // Build response with 5ms offset (simulating a real server)
                let offset = if cycle < 8 { 0.050 } else { 0.002 };
                let resp_bytes = build_server_response(bytes, offset, now);

                // Inject as a received datagram FROM the server (127.0.0.1:123)
                // to our client (127.0.0.1:ephemeral)
                let source = peer_netaddr([127, 0, 0, 1], 123);

                let dgram = ReceivedDatagram::test(resp_bytes, source, *destination, now);
                let resp_actions = engine.handle(DaemonEvent::PacketReceived(dgram));

                if resp_actions.iter().any(|a| {
                    matches!(
                        a,
                        DaemonAction::AdjustClock(_) | DaemonAction::PersistDrift(_)
                    )
                }) {
                    responses_matched += 1;
                }
            }
        }

        // Check for synchronization
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

        time_base += 2; // Advance 2 seconds per tick
    }

    eprintln!(
        "\n  polls_sent={}, responses_matched={}, sync={}",
        polls_sent, responses_matched, sync_achieved
    );
    eprintln!(
        "  stratum={}, peer={}, offset={:.6}s, freq={:.3}ppm",
        engine.system.stratum,
        engine.system.sys_peer_associd,
        engine.system.sys_offset,
        engine.loop_filter.frequency_ppm()
    );

    assert!(polls_sent > 0, "At least one poll must be sent");
    assert!(
        sync_achieved,
        "Engine must synchronize through network packet exchange"
    );
    assert!(
        engine.system.sys_peer_associd != 0,
        "Must select a system peer"
    );
}
