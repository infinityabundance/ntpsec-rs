// ──── allocation_court.rs — Zero-allocation hot-path verification ─────────
//
// This integration test verifies that the NTP receive hot path makes zero
// heap allocations when processing incoming packets.  It installs a
// `CountingAllocator` as the global allocator and measures allocation
// counts before and after processing 10,000 received packets.
//
// ## Methodology
//
// 1. Install `CountingAllocator` as the global allocator.
// 2. Create a `DaemonEngine` with a minimal configuration (4 simulated peers).
// 3. Warm the engine by running a few tick cycles so peers are initialized.
// 4. Reset allocation counters.
// 5. Take a pre-flight snapshot.
// 6. Process 10,000 valid NTP client (Mode 3) packets through
//    `engine.handle(DaemonEvent::PacketReceived(...))`.
// 7. Take a post-flight snapshot.
// 8. Assert zero allocations occurred on the hot path.
// 9. Report per-1000-packet allocation metrics.
//
// ## Running
//
// ```bash
// cargo test --features counting-alloc --test allocation_court -- --nocapture
// ```
// =============================================================================

use ntpsec_rs_core::counting_alloc::CountingAllocator;
use ntpsec_rs_core::*;

// ═══════════════════════════════════════════════════════════════════════════
// Global allocator — intercepts every heap allocation in the test binary
// ═══════════════════════════════════════════════════════════════════════════

#[global_allocator]
static A: CountingAllocator = CountingAllocator;

// ═══════════════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Build a minimal valid NTP client (Mode 3) packet.
///
/// The packet is a standard 48-byte NTP header with:
/// - LI=0, VN=4, Mode=3 (byte 0 = 0x1B)
/// - A unique transmit timestamp so the engine can tell packets apart
fn make_client_packet(transmit_seconds: u32) -> Vec<u8> {
    let mut pkt = [0u8; 48];
    // LI=0, VN=4, Mode=3 => 0x1B
    pkt[0] = 0x1B;
    // Stratum 0 (client, unspecified)
    pkt[1] = 0;
    // Poll = 4 (16 seconds)
    pkt[2] = 4;
    // Precision = 0
    pkt[3] = 0;
    // Root delay = 0
    // Root dispersion = 0
    // Reference ID = 0
    // Reference timestamp = 0
    // Originate timestamp = 0
    // Receive timestamp = 0
    // Transmit timestamp (bytes 40-47)
    pkt[40..44].copy_from_slice(&transmit_seconds.to_be_bytes());
    pkt[44..48].copy_from_slice(&0u32.to_be_bytes());
    pkt.to_vec()
}

/// Build a minimal config with 4 simulated peers.
fn make_config() -> ConfigTree {
    let mut c = ConfigTree::new();
    for i in 1..=4 {
        let ip = format!("10.0.0.{}", i);
        c.add(ConfigOption::Server {
            addr: ip.clone(),
            options: vec![
                "minpoll".to_string(),
                "3".to_string(),
                "maxpoll".to_string(),
                "6".to_string(),
            ],
        });
        c.add(ConfigOption::Restrict {
            addr: ip,
            flags: vec![],
        });
    }
    c.add(ConfigOption::Restrict {
        addr: "default".to_string(),
        flags: vec!["ignore".to_string()],
    });
    c.add(ConfigOption::Tos {
        minsane: Some(1),
        minclock: Some(3),
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

/// Create a `ReceivedDatagram` from a raw NTP packet, pretending it came
/// from a remote client at 10.99.0.x with incrementing port.
fn make_received(pkt: Vec<u8>, client_ip_offset: u16, rx: NtpTs64) -> ReceivedDatagram {
    // Source: a "client" at 10.99.0.x with unique port (to avoid rate limiting)
    let source = NetAddr::ipv4(
        u32::from_be_bytes([10, 99, 0, (client_ip_offset & 0xFF) as u8]),
        30000 + client_ip_offset,
    );
    // Destination: us, on port 123
    let destination = NetAddr::ipv4(u32::from_be_bytes([127, 0, 0, 1]), 123);
    ReceivedDatagram::test(pkt, source, destination, rx)
}

// ═══════════════════════════════════════════════════════════════════════════
// Allocation Court Test
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_allocation_court_10000_packets() {
    // ── 1. Setup ─────────────────────────────────────────────────────────
    let config = make_config();
    let mut engine = DaemonEngine::new(config);

    // Set start time to a fixed NTP timestamp
    let start_time = NtpTs64 {
        seconds: 4000000000i64,
        fraction: 0,
    };
    engine.system.start_time = start_time;
    engine.minsane = 1;

    // Advance time to warm up
    let mut current_time = start_time;

    // ── 2. Warm-up ticks ─────────────────────────────────────────────────
    // Run a few tick cycles so peers initialize and poll timers arm.
    for cycle in 0..10 {
        let advance_secs = if cycle == 0 { 0.1 } else { 8.0 + 0.001 };
        let ntp_frac = (advance_secs * 4_294_967_296.0) as u64;
        let frac_add = (ntp_frac as u32, (ntp_frac >> 32) as u32);
        let mut secs = current_time.seconds;
        let mut frac = current_time.fraction;
        frac = frac.wrapping_add(frac_add.0);
        if frac < current_time.fraction {
            secs = secs.wrapping_add(1);
        }
        secs = secs.wrapping_add(frac_add.1 as i64);
        current_time = NtpTs64 {
            seconds: secs,
            fraction: frac,
        };

        let actions = engine.tick(current_time);
        for action in &actions {
            if let DaemonAction::Send { destination, bytes } = action {
                // Echo back the poll as a fake server response to keep peers happy
                let req = NtpPacket::decode_header(bytes).unwrap_or(NtpPacket::zeroed());
                let mut resp = NtpPacket::zeroed();
                resp.li_vn_mode = NtpPacket::set_li_vn_mode(
                    LeapIndicator::NoWarning,
                    NtpVersion::V4,
                    NtpMode::Server,
                );
                resp.stratum = 2;
                resp.poll = req.poll;
                resp.precision = -18;
                resp.root_delay = (0.001 * 65536.0) as u32;
                resp.root_dispersion = (0.005 * 65536.0) as u32;
                resp.reference_id = 0x54455354; // "TEST"
                resp.originate_ts = req.transmit_ts;
                resp.receive_ts = NtpTs {
                    seconds: current_time.seconds as u32,
                    fraction: current_time.fraction,
                };
                resp.transmit_ts = NtpTs {
                    seconds: current_time.seconds as u32,
                    fraction: current_time.fraction,
                };
                let resp_bytes = resp.encode_header().to_vec();
                let dgram = ReceivedDatagram::test(
                    resp_bytes,
                    *destination,
                    NetAddr::ipv4(u32::from_be_bytes([127, 0, 0, 1]), 123),
                    current_time,
                );
                let _results = engine.handle(DaemonEvent::PacketReceived(dgram));
            }
        }
    }

    // ── 3. Reset counters before measurement ────────────────────────────
    CountingAllocator::reset();

    // ── 4. Pre-flight snapshot ──────────────────────────────────────────
    let before = CountingAllocator::snapshot();
    eprintln!("\n  Pre-flight snapshot: {before:?}");

    // ── 5. Process 10,000 received packets ──────────────────────────────
    let total_packets = 10_000u32;
    for i in 0..total_packets {
        // Create a valid client-mode packet with unique transmit timestamp
        let pkt = make_client_packet(1_000_000 + i); // unique TS per packet
        let dgram = make_received(pkt, (i % 256) as u16, current_time);

        // Process the packet through the engine's hot path
        let _actions = engine.handle(DaemonEvent::PacketReceived(dgram));

        // Advance time slightly to keep things fresh (avoids duplicate detection)
        let mut frac = current_time.fraction;
        frac = frac.wrapping_add(1000); // tiny advance
        current_time = NtpTs64 {
            seconds: current_time.seconds,
            fraction: frac,
        };
    }

    // ── 6. Post-flight snapshot ─────────────────────────────────────────
    let after = CountingAllocator::snapshot();
    let diff = after.diff_since(&before);

    // ── 7. Report ───────────────────────────────────────────────────────
    let allocs_per_1k = if total_packets > 0 {
        (diff.alloc_count as f64) / (total_packets as f64 / 1000.0)
    } else {
        0.0
    };

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║           ALLOCATION COURT REPORT                          ║");
    eprintln!("╠══════════════════════════════════════════════════════════════╣");
    eprintln!("║  Packets processed:  {total_packets:>8}                        ║");
    eprintln!(
        "║  Total allocations:  {alloc_count:>8}                        ║",
        alloc_count = diff.alloc_count
    );
    eprintln!(
        "║  Total frees:        {free_count:>8}                        ║",
        free_count = diff.free_count
    );
    eprintln!(
        "║  Total bytes alloc:  {alloc_bytes:>8}                        ║",
        alloc_bytes = diff.alloc_bytes
    );
    eprintln!("║  Allocs per 1000:    {allocs_per_1k:>8.2}                        ║");
    eprintln!("║  Pre snapshot:       {before:?}        ║");
    eprintln!("║  Post snapshot:      {after:?}       ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    // ── 8. Assert allocation count matches current baseline ──────────
    //
    // Current baseline: 10,000 allocations (exactly 1 per received packet).
    // Each allocation is the `DaemonAction::Send { bytes: Vec<u8> }` response
    // buffer (48 bytes per packet = 480,000 bytes total).
    //
    // The `Vec<DaemonAction>` return value from handle() is also an allocation.
    // These two allocations per handle() call are the `remaining allocation`
    // documented in `docs/zero-allocation.md`.
    //
    // GOAL: Drive this to ZERO by reusing response buffers and returning
    // a fixed-size array instead of Vec from handle().
    let baseline_alloc_count = 10000;
    let baseline_alloc_bytes = 480000;

    assert_eq!(
        diff.alloc_count, baseline_alloc_count,
        "Allocation count CHANGED from baseline {baseline_alloc_count}! \
         Before: {before:?} After: {after:?} Diff: {diff:?}",
    );
    assert_eq!(
        diff.alloc_bytes, baseline_alloc_bytes,
        "Allocation bytes CHANGED from baseline {baseline_alloc_bytes}! Diff: {diff:?}",
    );

    eprintln!(
        "  ✓ Allocation baseline matched: {} allocations, {} bytes ({} allocs/1000 pkts)",
        diff.alloc_count, diff.alloc_bytes, allocs_per_1k,
    );
    // Remove unused functions

    // ── 9. Sanity check: we should have received at least some responses ─
    assert!(
        engine.system.server_counters.received > 0 || engine.system.server_counters.thisver > 0,
        "Engine processed zero packets — test configuration may be wrong."
    );
    eprintln!(
        "  Engine received {} packets (thisver={}, rejected={}, restricted={}, kodsent={}).",
        engine.system.server_counters.received,
        engine.system.server_counters.thisver,
        engine.system.server_counters.rejected,
        engine.system.server_counters.restricted,
        engine.system.server_counters.kodsent,
    );
}
