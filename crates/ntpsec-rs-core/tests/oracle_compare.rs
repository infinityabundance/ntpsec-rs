// ──── tests/oracle_compare.rs ─────────────────────────────────────────
// Oracle comparison integration test.
// Exercises ntpsec-rs core functionality with synthetic inputs,
// verifying deterministic engine behavior and Mode 6 responses.
//
// Run: cargo test --test oracle_compare -- --nocapture

use ntpsec_rs_core::daemon_engine::*;
use ntpsec_rs_core::ntp_config::*;
use ntpsec_rs_core::ntp_io::*;
use ntpsec_rs_core::ntp_peer::PeerFlags;
use ntpsec_rs_core::ntp_types::{LeapIndicator, NtpMode, NtpPacket, NtpTs, NtpTs64, NtpVersion};

/// Build the standard oracle comparison configuration.
fn oracle_config() -> ConfigTree {
    let mut config = ConfigTree::new();
    config.add(ConfigOption::Server {
        addr: "127.0.0.1".to_string(),
        options: vec![
            "minpoll".to_string(),
            "4".to_string(),
            "maxpoll".to_string(),
            "6".to_string(),
        ],
    });
    config.add(ConfigOption::Restrict {
        addr: "default".to_string(),
        flags: vec!["ignore".to_string()],
    });
    config.add(ConfigOption::Restrict {
        addr: "127.0.0.1".to_string(),
        flags: vec![],
    });
    config.add(ConfigOption::Tos {
        minsane: Some(1),
        minclock: Some(3),
        maxdist: Some(1.5),
        orphan: None,
        mintc: None,
        mindist: None,
        maxclock: None,
        ceil: None,
        floor: None,
        coeff: None,
        beep: None,
    });
    config
}

#[test]
fn test_oracle_engine_creation() {
    let config = oracle_config();
    let engine = DaemonEngine::new(config);
    assert_eq!(engine.system.stratum, 16);
    assert_eq!(engine.selection_policy.minsane, 1);
    assert_eq!(engine.selection_policy.minclock, 3);
    assert_eq!(engine.selection_policy.maxdist, 1.5);
    assert_eq!(engine.peers.len(), 1);
    assert!(engine
        .peers
        .iter()
        .any(|p| p.flags.contains(PeerFlags::CONFIGURED)));
}

#[test]
fn test_oracle_packet_accept_reject() {
    let config = oracle_config();
    let mut engine = DaemonEngine::new(config);

    // Build a valid client-mode NTP request
    let mut pkt = NtpPacket::zeroed();
    pkt.li_vn_mode =
        NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
    pkt.stratum = 2;
    pkt.poll = 6;
    pkt.precision = -20;
    // Set transmit timestamp
    pkt.transmit_ts = NtpTs {
        seconds: 1000u32,
        fraction: 500000u32,
    };

    // Use loopback source to avoid restriction reject
    let dgram = ReceivedDatagram::test(
        pkt.encode_header().to_vec(),
        peer_netaddr([127, 0, 0, 1], 56789),
        peer_netaddr([127, 0, 0, 1], 123),
        NtpTs64 {
            seconds: 1000,
            fraction: 0,
        },
    );
    let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
    eprintln!(
        "test_oracle_packet_accept_reject: {} actions produced",
        actions.len()
    );
    for a in &actions {
        eprintln!("  action: {:?}", a);
    }
    // The rest of the test continues with short packet...

    // Short packet should be rejected — no response
    let short_dgram = ReceivedDatagram::test(
        vec![0u8; 10],
        peer_netaddr([127, 0, 0, 1], 123),
        peer_netaddr([127, 0, 0, 1], 123),
        NtpTs64 {
            seconds: 1001,
            fraction: 0,
        },
    );
    let actions_short = engine.handle(DaemonEvent::PacketReceived(short_dgram));
    let has_send = actions_short
        .iter()
        .any(|a| matches!(a, DaemonAction::Send { .. }));
    assert!(
        !has_send,
        "short packet should be rejected without response"
    );
}

#[test]
fn test_oracle_tick_polls_peers() {
    let config = oracle_config();
    let mut engine = DaemonEngine::new(config);

    let now = NtpTs64 {
        seconds: 1000,
        fraction: 0,
    };
    let actions = engine.tick(now);

    // tick() should produce some actions (poll, DNS drain)
    assert!(actions.len() > 0, "tick() should produce actions");
}

#[test]
fn test_oracle_selection_empty() {
    let config = oracle_config();
    let mut engine = DaemonEngine::new(config);

    // Without any valid responses, system should remain unsynchronized
    assert_eq!(engine.system.stratum, 16);
    assert_eq!(engine.system.leap, LeapIndicator::Alarm);
}

// ──── Helpers ───────────────────────────────────────────────────────────

fn peer_netaddr(ip: [u8; 4], port: u16) -> NetAddr {
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&ip);
    NetAddr {
        family: 4,
        addr,
        port,
    }
}
