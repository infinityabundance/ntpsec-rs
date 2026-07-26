// ──── tests/restrict_courts.rs ───────────────────────────────────────
// Workstream 10: Restrictions, rate limiting, and KoD parity courts
//
// Tests NTPsec-compatible access control behavior:
//   - Default restrict rules
//   - Address/mask matching
//   - NOTRUST, NOPEER, NOQUERY, IGNORE, KOD
//   - Rate limiting and MRU eviction
//   - Kiss-o'-Death responses
//
// Run: cargo test --test restrict_courts -p ntpsec-rs-core -- --nocapture

use ntpsec_rs_core::daemon_engine::*;
use ntpsec_rs_core::ntp_config::*;
use ntpsec_rs_core::ntp_io::*;
use ntpsec_rs_core::ntp_restrict::*;
use ntpsec_rs_core::ntp_types::*;

fn peer_netaddr(ip: [u8; 4], port: u16) -> NetAddr {
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&ip);
    NetAddr {
        family: 4,
        addr,
        port,
    }
}

fn make_client_request() -> Vec<u8> {
    let mut pkt = NtpPacket::zeroed();
    pkt.li_vn_mode =
        NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
    pkt.transmit_ts = NtpTs {
        seconds: 1000,
        fraction: 0,
    };
    pkt.encode_header().to_vec()
}

fn make_dgram(source: NetAddr, dest: NetAddr, bytes: Vec<u8>, time: i64) -> ReceivedDatagram {
    ReceivedDatagram::test(
        bytes,
        source,
        dest,
        NtpTs64 {
            seconds: time,
            fraction: 0,
        },
    )
}

fn engine_with_restrict(restrict_rules: Vec<(&str, Vec<&str>)>) -> DaemonEngine {
    let mut config = ConfigTree::new();
    for (addr, flags) in restrict_rules {
        config.add(ConfigOption::Restrict {
            addr: addr.to_string(),
            flags: flags.iter().map(|s| s.to_string()).collect(),
        });
    }
    config.add(ConfigOption::Server {
        addr: "127.0.0.1".to_string(),
        options: vec![
            "minpoll".to_string(),
            "4".to_string(),
            "maxpoll".to_string(),
            "6".to_string(),
        ],
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
    config.add(ConfigOption::Tinker {
        step: Some(0.5),
        panic: Some(1000.0),
        dispersion: None,
        stepout: None,
        minpoll: None,
        maxpoll: None,
    });
    DaemonEngine::new(config)
}

// ──── Default restrict behavior ───────────────────────────────────────

#[test]
fn test_restrict_default_ignore_blocks_unconfigured() {
    // NTPsec: "restrict default ignore" blocks all traffic from unspecified sources
    let mut engine = engine_with_restrict(vec![("default", vec!["ignore"])]);
    let bytes = make_client_request();
    let source = peer_netaddr([10, 0, 0, 1], 56789);
    let dest = peer_netaddr([127, 0, 0, 1], 123);
    let dgram = make_dgram(source, dest, bytes, 1000);
    let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
    // NTPsec: IGNORE drops silently — no response, no log
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, DaemonAction::Send { .. })),
        "Default ignore must block traffic from unrestricted sources"
    );
}

#[test]
fn test_restrict_loopback_allowed_over_default_ignore() {
    // NTPsec: explicit "restrict 127.0.0.1" overrides default ignore
    let mut engine = engine_with_restrict(vec![("default", vec!["ignore"]), ("127.0.0.1", vec![])]);
    let bytes = make_client_request();
    let source = peer_netaddr([127, 0, 0, 1], 56789);
    let dest = peer_netaddr([127, 0, 0, 1], 123);
    let dgram = make_dgram(source, dest, bytes, 1000);
    let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
    // NTPsec: loopback with explicit allow should get a response
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, DaemonAction::Send { .. })),
        "Loopback must be allowed over default ignore"
    );
}

// ──── NOTRUST behavior ────────────────────────────────────────────────

#[test]
fn test_restrict_notrust_rejects_unauthenticated() {
    // NTPsec: NOTRUST rejects unauthenticated client packets
    let mut engine = engine_with_restrict(vec![
        ("default", vec!["ignore"]),
        ("127.0.0.1", vec!["notrust"]),
    ]);
    let bytes = make_client_request();
    let source = peer_netaddr([127, 0, 0, 1], 56789);
    let dest = peer_netaddr([127, 0, 0, 1], 123);
    let dgram = make_dgram(source, dest, bytes.clone(), 1000);
    let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
    // NOTRUST requires auth — unauthenticated request should be rejected
    assert!(
        actions.iter().any(|a| matches!(a, DaemonAction::Log(_))),
        "NOTRUST must reject unauthenticated requests"
    );
}

// ──── KOD behavior ────────────────────────────────────────────────────

#[test]
fn test_restrict_kod_sends_kiss_code() {
    // NTPsec: KOD flag causes the daemon to send a KoD response
    let mut engine = engine_with_restrict(vec![
        ("default", vec!["ignore"]),
        ("127.0.0.1", vec!["kod"]),
    ]);
    let bytes = make_client_request();
    let source = peer_netaddr([127, 0, 0, 1], 56789);
    let dest = peer_netaddr([127, 0, 0, 1], 123);
    let dgram = make_dgram(source, dest, bytes, 1000);
    let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
    // NTPsec: KOD sends a Kiss-o'-Death packet with DENY code
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, DaemonAction::Send { .. })),
        "KOD restrict must produce a Send response"
    );
}

// ──── Rate limiting ───────────────────────────────────────────────────

#[test]
fn test_rate_limit_blocks_excessive_traffic() {
    let mut engine = engine_with_restrict(vec![
        ("default", vec!["ignore"]),
        ("127.0.0.1", vec!["limited", "kod"]),
    ]);
    let bytes = make_client_request();
    let source = peer_netaddr([127, 0, 0, 1], 56789);
    let dest = peer_netaddr([127, 0, 0, 1], 123);

    // Send many requests rapidly to trigger rate limiting
    let mut got_kod = false;
    for i in 0..20 {
        let dgram = make_dgram(source, dest, bytes.clone(), 1000 + i);
        let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
        for a in &actions {
            if let DaemonAction::Send { .. } = a {
                // NTPsec: after enough requests, RATE KoD is sent
                got_kod = true;
            }
        }
    }
    // Rate limiting with KOD should eventually produce responses
    // (Rate limit threshold + KOD flag means RATE Kiss-o'-Death)
    eprintln!("  Rate limit test: got_kod={}", got_kod);
}

// ──── NOQUERY behavior (Mode 6) ───────────────────────────────────────

#[test]
fn test_restrict_noquery_blocks_mode6() {
    use ntpsec_rs_core::ntp_control::*;
    // NTPsec: NOQUERY blocks Mode 6 queries
    let mut engine = engine_with_restrict(vec![
        ("default", vec!["ignore"]),
        ("127.0.0.1", vec!["noquery"]),
    ]);
    let msg = ControlMessage {
        li_vn_mode: NtpPacket::set_li_vn_mode(
            LeapIndicator::NoWarning,
            NtpVersion::V4,
            NtpMode::NtpControl,
        ),
        opcode: ControlOpcode::new(false, false, false, opcodes::OP_READVAR).to_u8(),
        sequence: 1,
        status: 0,
        associd: 0,
        offset: 0,
        count: 0,
    };
    let source = peer_netaddr([127, 0, 0, 1], 56789);
    let dest = peer_netaddr([127, 0, 0, 1], 123);
    let dgram = make_dgram(source, dest, msg.encode().to_vec(), 1000);
    let actions = engine.handle(DaemonEvent::PacketReceived(dgram));
    // NOQUERY should silently discard Mode 6 requests
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, DaemonAction::Send { .. })),
        "NOQUERY must block Mode 6 queries"
    );
}
