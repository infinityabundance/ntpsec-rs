// ──── differential/mod.rs ──────────────────────────────────────────────────
// Differential fuzzing harness for ntpsec-rs
//
// Provides:
//   1. NTP packet mutation from raw fuzzer input
//   2. Invariant checking after each engine handle() call
//   3. State snapshot recording (for later comparison with NTPsec oracle)
//   4. Test scenarios: Client, Server, SymActive, SymPassive, Broadcast
//
// ## Usage
//   The fuzz target at fuzz/fuzz_targets/differential.rs calls into this
//   harness.  All invariant checks live here so they can be reused by
//   integration tests and oracle-based replay.
// =============================================================================

#![allow(dead_code)] // Some snapshot helpers are only reachable from the fuzz target

use ntpsec_rs_core::daemon_engine::DaemonEngine;
use ntpsec_rs_core::ntp_config::ConfigTree;
use ntpsec_rs_core::ntp_io::{DaemonEvent, NetAddr, ReceivedDatagram};
use ntpsec_rs_core::ntp_proto::NTP_MAXSTRAT;
use ntpsec_rs_core::ntp_types::*;

use std::collections::HashSet;
use std::panic;

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum number of peers we allow before flagging unbounded growth.
/// NTPsec's default maxclock is 14; we use a generous upper-bound.
pub const MAX_PEERS: usize = 128;

/// Maximum leap indicator value (2 bits → [0, 3]).
pub const LEAP_MAX: u8 = 3;

// ── Packet mutation ───────────────────────────────────────────────────────

/// The set of NTP modes we want to exercise.
/// Excludes NtpControl (mode 6 — separate decoder) and Private (mode 7 — deprecated).
const EXERCISED_MODES: &[NtpMode] = &[
    NtpMode::Reserved,   // mode 0 — edge case
    NtpMode::SymActive,  // mode 1
    NtpMode::SymPassive, // mode 2
    NtpMode::Client,     // mode 3
    NtpMode::Server,     // mode 4
    NtpMode::Broadcast,  // mode 5
                         // NtpControl → separate target
                         // Private is mode 7 — rejected immediately, less value
];

/// All NTP versions we test.
const EXERCISED_VERSIONS: &[NtpVersion] = &[
    NtpVersion::V1,
    NtpVersion::V2,
    NtpVersion::V3,
    NtpVersion::V4,
];

/// All leap indicator values.
const EXERCISED_LEAPS: &[LeapIndicator] = &[
    LeapIndicator::NoWarning,
    LeapIndicator::AddLeapSecond,
    LeapIndicator::RemoveLeapSecond,
    LeapIndicator::Alarm,
];

/// Pack a single li_vn_mode byte from components.
fn pack_li_vn_mode(leap: LeapIndicator, version: NtpVersion, mode: NtpMode) -> u8 {
    NtpPacket::set_li_vn_mode(leap, version, mode)
}

/// Build a full NTP packet (48-byte header + optional tail) from fuzzer bytes.
///
/// Strategy: the first byte is always treated as a structured li_vn_mode
/// (to ensure valid mode/version/leap combinations are exercised),
/// and the remaining 47 header bytes are taken directly from the input
/// (or zero-padded if the input is short).  Any data beyond byte 48 is
/// appended as tail (extension fields / MAC).
///
/// This ensures we always produce a syntactically valid NTP header even
/// from short inputs, while still fuzzing all header field combinations.
pub fn mutate_packet(data: &[u8]) -> (Vec<u8>, NtpMode, u8) {
    // Decide which mode to use based on a byte in the input (round-robin).
    let mode_index = if data.is_empty() {
        0usize
    } else {
        (data[0] as usize) % EXERCISED_MODES.len()
    };
    let mode = EXERCISED_MODES[mode_index];
    let version = EXERCISED_VERSIONS
        [(data.get(0).copied().unwrap_or(0) as usize >> 2) % EXERCISED_VERSIONS.len()];
    let leap =
        EXERCISED_LEAPS[(data.get(0).copied().unwrap_or(0) as usize >> 4) % EXERCISED_LEAPS.len()];
    let li_vn_mode = pack_li_vn_mode(leap, version, mode);

    let mut packet = vec![0u8; 48];
    packet[0] = li_vn_mode;

    // Fill remaining 47 header bytes from input (bytes 1..48).
    let header_data = if data.len() > 1 { &data[1..] } else { &[] };
    let copy_len = header_data.len().min(47);
    packet[1..1 + copy_len].copy_from_slice(&header_data[..copy_len]);

    // Append any data beyond 48 bytes as tail.
    if data.len() > 48 {
        packet.extend_from_slice(&data[48..]);
    }

    let raw_li_vn = packet[0];
    (packet, mode, raw_li_vn)
}

// ── Engine creation ───────────────────────────────────────────────────────

/// Create a minimal DaemonEngine with one configured server peer.
/// Returns the engine and a source NetAddr representing the peer.
pub fn create_minimal_engine() -> (DaemonEngine, NetAddr) {
    let config = ConfigTree::new();
    let mut engine = DaemonEngine::new(config);

    // Set up a minimal synchronized system state so the engine can
    // respond to client requests and process server responses.
    engine.system.stratum = 3;
    engine.system.leap = LeapIndicator::NoWarning;
    engine.system.root_delay = 0.001;
    engine.system.root_dispersion = 0.001;
    engine.system.sys_offset = 0.0;
    engine.system.sys_jitter = 0.001;
    engine.system.sys_frequency = 0.0;
    engine.system.sys_rootdist = 0.01;

    // The peer source address — it will be used by the fuzzer to send packets from.
    let peer_addr = NetAddr::ipv4(u32::from_be_bytes([10, 0, 0, 1]), 123);

    (engine, peer_addr)
}

// ── Invariant checking ────────────────────────────────────────────────────

/// Result of an invariant check.
#[derive(Debug)]
pub enum InvariantResult {
    Ok,
    Violation(String),
}

/// Check all invariants on the current engine state.
/// Returns `Ok` if all invariants pass, or the first violation found.
pub fn check_invariants(engine: &DaemonEngine) -> Result<(), String> {
    // 1. No NaN or Inf in computed values
    check_finite("system.sys_offset", engine.system.sys_offset)?;
    check_finite("system.sys_jitter", engine.system.sys_jitter)?;
    check_finite("system.sys_frequency", engine.system.sys_frequency)?;
    check_finite("system.sys_rootdist", engine.system.sys_rootdist)?;
    check_finite("system.root_delay", engine.system.root_delay)?;
    check_finite("system.root_dispersion", engine.system.root_dispersion)?;

    // 2. Stratum stays in valid range [0, 16]
    if engine.system.stratum > NTP_MAXSTRAT {
        return Err(format!(
            "system stratum out of range: {} > {}",
            engine.system.stratum, NTP_MAXSTRAT
        ));
    }

    // 3. Leap indicator stays in valid range [0, 3]
    let leap_bits = engine.system.leap as u8;
    if leap_bits > LEAP_MAX {
        return Err(format!(
            "system leap indicator out of range: {:?} (bits={})",
            engine.system.leap, leap_bits
        ));
    }

    // 4. Peer table doesn't grow unbounded
    if engine.peers.len() > MAX_PEERS {
        return Err(format!(
            "peer table too large: {} > {}",
            engine.peers.len(),
            MAX_PEERS
        ));
    }

    // 5. No duplicate association IDs
    let mut seen = HashSet::new();
    for peer in engine.peers.iter() {
        if !seen.insert(peer.associd) {
            return Err(format!("duplicate association ID: {}", peer.associd));
        }
    }

    // 6. Peer invariants
    for (i, peer) in engine.peers.iter().enumerate() {
        check_finite(&format!("peers[{}].offset", i), peer.offset)?;
        check_finite(&format!("peers[{}].delay", i), peer.delay)?;
        check_finite(&format!("peers[{}].dispersion", i), peer.dispersion)?;
        check_finite(&format!("peers[{}].jitter", i), peer.jitter)?;
        check_finite(
            &format!("peers[{}].selection_jitter", i),
            peer.selection_jitter,
        )?;
        check_finite(&format!("peers[{}].root_delay", i), peer.root_delay)?;
        check_finite(
            &format!("peers[{}].root_dispersion", i),
            peer.root_dispersion,
        )?;

        if peer.stratum > NTP_MAXSTRAT {
            return Err(format!(
                "peers[{}] stratum out of range: {} > {}",
                i, peer.stratum, NTP_MAXSTRAT
            ));
        }

        let peer_leap_bits = peer.leap as u8;
        if peer_leap_bits > LEAP_MAX {
            return Err(format!(
                "peers[{}] leap indicator out of range: {:?} (bits={})",
                i, peer.leap, peer_leap_bits
            ));
        }
    }

    Ok(())
}

fn check_finite(name: &str, val: f64) -> Result<(), String> {
    if !val.is_finite() {
        return Err(format!("{} is not finite: {}", name, val));
    }
    Ok(())
}

// ── State snapshots ───────────────────────────────────────────────────────

/// A snapshot of engine state at a single point in time, suitable for
/// recording and later comparing against NTPsec oracle output.
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// Which packet number this snapshot corresponds to (0-based).
    pub packet_index: u64,
    /// The raw li_vn_mode byte of the input packet.
    pub li_vn_mode: u8,
    /// The NTP mode that was decoded from the packet.
    pub mode: NtpMode,

    // System-level state
    pub leap: LeapIndicator,
    pub stratum: u8,
    pub sys_offset: f64,
    pub sys_jitter: f64,
    pub sys_frequency: f64,
    pub sys_rootdist: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub peer_count: u32,
    pub reference_id: u32,

    // Peer table snapshot
    pub peer_table: Vec<PeerSnapshot>,

    /// Number of actions returned by engine.handle().
    pub action_count: usize,
}

/// Per-peer state at a snapshot.
#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub associd: u16,
    pub stratum: u8,
    pub leap: LeapIndicator,
    pub hmode: NtpMode,
    pub pmode: NtpMode,
    pub offset: f64,
    pub delay: f64,
    pub dispersion: f64,
    pub jitter: f64,
    pub reachable: bool,
    pub hpoll: u8,
    pub flash: u32,
}

/// Take a full state snapshot from the engine.
pub fn take_snapshot(
    engine: &DaemonEngine,
    packet_index: u64,
    li_vn_mode: u8,
    mode: NtpMode,
    action_count: usize,
) -> StateSnapshot {
    let peer_table: Vec<PeerSnapshot> = engine
        .peers
        .iter()
        .map(|p| PeerSnapshot {
            associd: p.associd,
            stratum: p.stratum,
            leap: p.leap,
            hmode: p.hmode,
            pmode: p.pmode,
            offset: p.offset,
            delay: p.delay,
            dispersion: p.dispersion,
            jitter: p.jitter,
            reachable: p.is_reachable(),
            hpoll: p.hpoll,
            flash: p.flash,
        })
        .collect();

    StateSnapshot {
        packet_index,
        li_vn_mode,
        mode,
        leap: engine.system.leap,
        stratum: engine.system.stratum,
        sys_offset: engine.system.sys_offset,
        sys_jitter: engine.system.sys_jitter,
        sys_frequency: engine.system.sys_frequency,
        sys_rootdist: engine.system.sys_rootdist,
        root_delay: engine.system.root_delay,
        root_dispersion: engine.system.root_dispersion,
        peer_count: engine.system.peer_count,
        reference_id: engine.system.reference_id,
        peer_table,
        action_count,
    }
}

// ── Harness entry point ───────────────────────────────────────────────────

/// Result from fuzzing one input.
#[derive(Debug)]
pub struct FuzzResult {
    /// The number of packets processed.
    pub packet_count: u64,
    /// All snapshots taken during this run.
    pub snapshots: Vec<StateSnapshot>,
    /// The first invariant violation, if any.
    pub violation: Option<String>,
    /// True if the engine panicked (caught by catch_unwind).
    pub panicked: bool,
}

/// Run the differential fuzzing harness on a single fuzzer input.
///
/// Returns a `FuzzResult` with state snapshots and any violation found.
/// The caller is responsible for asserting the result is clean.
pub fn run_fuzz_input(data: &[u8]) -> FuzzResult {
    let (packet_bytes, mode, raw_li_vn) = mutate_packet(data);

    let (mut engine, peer_addr) = create_minimal_engine();

    // Build the datagram
    let source = peer_addr;
    let dest = NetAddr::ipv4(0, 123);
    let rx_ts = NtpTs64 {
        seconds: 1000000,
        fraction: 0,
    };

    let dgram = ReceivedDatagram::test(packet_bytes.clone(), source, dest, rx_ts);

    // Catch panics so they don't crash the fuzzer process
    let (actions, panicked) = match panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        engine.handle(DaemonEvent::PacketReceived(dgram))
    })) {
        Ok(actions) => (actions, false),
        Err(_) => (vec![], true),
    };

    let mut result = FuzzResult {
        packet_count: 1,
        snapshots: vec![],
        violation: None,
        panicked,
    };

    // Take snapshot regardless of panic
    result
        .snapshots
        .push(take_snapshot(&engine, 0, raw_li_vn, mode, actions.len()));

    // Check invariants (skip if already panicked — state may be corrupted)
    if !panicked {
        if let Err(v) = check_invariants(&engine) {
            result.violation = Some(v);
        }
    }

    result
}
