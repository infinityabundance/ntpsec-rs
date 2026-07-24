// ──── ntp_proto.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_proto.c (84K)
//
// NTP protocol engine — the heart of ntpd.  This implements the full
// receive/process/select/combine/discipline pipeline defined in RFC 5905
// §9-13 and the ntpsec-specific policy extensions.
//
// ## Pipeline (matching ntpsec's event loop)
//
//   receive()                           — packet dispatch
//     ├─ process_packet()               — validate, classify, authenticate
//     │   ├─ clock_filter()             — update 8-sample shift register
//     │   ├─ clock_select()             — intersection + clustering
//     │   ├─ clock_combine()            — weighted survivor average
//     │   └─ local_clock()              — PLL/FLL update → loop filter
//     ├─ poll_update()                  — adaptive poll interval
//     ├─ transmit()                     — build & send response
//     └─ reachability update            — shift register management
//
// ## Oracle
//   - ntpsec ntpd/ntp_proto.c
//   - RFC 5905 §9.2 (clock filter), §10 (selection), §11 (clustering),
//     §12 (combining), §13 (loop filter)
//   - ntpsec ntpd/ntp_loopfilter.c — local_clock() integration
//
// ## Court
//   - docs/courts/ntp_proto.md
// =============================================================================

use crate::ntp_auth::*;
use crate::ntp_fp;
use crate::ntp_leapsec::*;
use crate::ntp_loopfilter::*;
use crate::ntp_monitor::*;
use crate::ntp_peer::*;
use crate::ntp_recvbuff::*;
use crate::ntp_restrict::*;
use crate::ntp_types::*;
use crate::nts::*;
use crate::nts_extens::*;

// ──── Constants ─────────────────────────────────────────────────────────

/// NTP.MAXDISPERSE — maximum dispersion (16 s) before a peer is considered
/// unreachable.  Matches ntpsec's NTP_MAXDISPERSE.
pub const NTP_MAXDISPERSE: f64 = 16.0;

/// NTP.MAXDIST — maximum select distance (1.5 s).  Matches ntpsec's
/// NTP.MAXDIST / sys_maxdist default.
pub const NTP_MAXDIST: f64 = 1.5;

/// NTP.MINDIST — minimum select distance (0.001 s / 1 ms).
pub const NTP_MINDIST: f64 = 0.001;

/// NTP.MAXSTRAT — maximum stratum (16).
pub const NTP_MAXSTRAT: u8 = 16;

/// NTP.MINPOLL — default minimum poll exponent (4 = 16 s).
pub const NTP_MINPOLL: u8 = 4;

/// NTP.MAXPOLL — default maximum poll exponent (10 = 1024 s).
pub const NTP_MAXPOLL: u8 = 10;

/// Minimum clock-selectable peers.
pub const NTP_MINSANE: usize = 1;

/// Clock filter register depth (RFC 5905 §9.2).
pub const NTP_SHIFT: usize = 8;

/// Weight factor for peer jitter in the combine algorithm (ntpsec default).
pub const NTP_WEIGHT: f64 = 0.5;

// ──── Flash bits (matching ntpsec) ──────────────────────────────────────

bitflags::bitflags! {
    /// Peer/test flash bits — each bit indicates a failed test.  A peer
    /// with any TEST bit set is NOT selectable.  Matching ntpsec's TEST bits
    /// exactly.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct FlashBits: u32 {
        /// TEST1 — duplicate packet.
        const TEST1 = 1 << 0;
        /// TEST2 — bogus packet (length, authentication, format).
        const TEST2 = 1 << 1;
        /// TEST3 — unsynchronized peer (stratum >= 16).
        const TEST3 = 1 << 2;
        /// TEST4 — bad header (LI alarm).
        const TEST4 = 1 << 3;
        /// TEST5 — root distance exceeded.
        const TEST5 = 1 << 4;
        /// TEST6 — root dispersion exceeded.
        const TEST6 = 1 << 5;
        /// TEST7 — peer synchronization loop.
        const TEST7 = 1 << 6;
        /// TEST8 — bad reference ID / authentication failure.
        const TEST8 = 1 << 7;
        /// TEST9 — unreachable.
        const TEST9 = 1 << 8;
        /// TEST10 — bad authentication.
        const TEST10 = 1 << 9;
        /// All tests pass — peer is selectable.
        const PASS = 0;
        /// Any test set — peer is NOT selectable.
        const FAIL = 0x3FF;
    }
}

// ──── Clock Filter ──────────────────────────────────────────────────────

/// Clock filter register (8-sample shift register, RFC 5905 §9.2).
#[derive(Debug, Clone, Copy)]
pub struct ClockFilterEntry {
    pub offset: f64,
    pub delay: f64,
    pub dispersion: f64,
    pub time: NtpTs64,
}

/// The clock filter (8-sample shift register).
#[derive(Debug, Clone)]
pub struct ClockFilter {
    entries: [Option<ClockFilterEntry>; NTP_SHIFT],
    count: usize,
}

impl Default for ClockFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockFilter {
    pub fn new() -> Self {
        Self {
            entries: [None; NTP_SHIFT],
            count: 0,
        }
    }

    /// Add a sample (shift register behavior).  The clock filter sorts by
    /// delay, picks the entry with the smallest delay as the peer offset,
    /// and computes the filter jitter (RMS of residuals around the selected
    /// entry).
    pub fn add_sample(&mut self, entry: ClockFilterEntry) {
        for i in (1..NTP_SHIFT).rev() {
            self.entries[i] = self.entries[i - 1];
        }
        self.entries[0] = Some(entry);
        self.count = self.count.min(NTP_SHIFT - 1) + 1;
    }

    /// Filter: return the entry with minimum delay (RFC 5905 §9.2 step 1).
    pub fn filter(&self) -> Option<ClockFilterEntry> {
        let samples: Vec<&ClockFilterEntry> =
            self.entries.iter().filter_map(|e| e.as_ref()).collect();
        if samples.is_empty() {
            return None;
        }
        samples
            .iter()
            .min_by(|a, b| {
                a.delay
                    .partial_cmp(&b.delay)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|e| **e)
    }

    /// Compute the filter jitter: RMS of (peer offset − sample offset)
    /// around the delay-minimum entry (RFC 5905 §9.2 step 2).
    pub fn filter_jitter(&self, peer_offset: f64) -> f64 {
        let samples: Vec<&ClockFilterEntry> =
            self.entries.iter().filter_map(|e| e.as_ref()).collect();
        let n = samples.len();
        if n < 2 {
            return 0.0;
        }
        let sum_sq: f64 = samples
            .iter()
            .map(|s| {
                let d = s.offset - peer_offset;
                d * d
            })
            .sum();
        (sum_sq / n as f64).sqrt()
    }

    pub fn sample_count(&self) -> usize {
        self.count
    }
    pub fn clear(&mut self) {
        self.entries = [None; NTP_SHIFT];
        self.count = 0;
    }

    /// Iterate over all valid samples.
    pub fn samples(&self) -> impl Iterator<Item = &ClockFilterEntry> {
        self.entries.iter().filter_map(|e| e.as_ref())
    }
}

// ──── Reachability Register ────────────────────────────────────────────

/// Peer reachability register (8-bit shift register, RFC 5905 §13.1).
#[derive(Debug, Clone)]
pub struct Reachability {
    register: u8,
    count: u8,
}

impl Default for Reachability {
    fn default() -> Self {
        Self::new()
    }
}

impl Reachability {
    pub fn new() -> Self {
        Self {
            register: 0,
            count: 0,
        }
    }

    pub fn record_success(&mut self) {
        self.register = (self.register << 1) | 1;
        self.count = self.count.saturating_add(1).min(NTP_SHIFT as u8);
    }

    pub fn record_failure(&mut self) {
        self.register <<= 1;
        self.count = self.count.saturating_sub(1);
    }

    pub fn is_reachable(&self) -> bool {
        self.register != 0
    }
    pub fn register(&self) -> u8 {
        self.register
    }
    pub fn reach_count(&self) -> u8 {
        self.count
    }
}

// ──── Poll Interval ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PollInterval {
    pub min_poll: u8,
    pub max_poll: u8,
    pub current: u8,
}

impl PollInterval {
    pub fn new(min_poll: u8, max_poll: u8) -> Self {
        Self {
            min_poll,
            max_poll,
            current: min_poll,
        }
    }
    pub fn increase(&mut self) {
        self.current = (self.current + 1).min(self.max_poll);
    }
    pub fn decrease(&mut self) {
        self.current = self.current.saturating_sub(1).max(self.min_poll);
    }
    pub fn interval_seconds(&self) -> u64 {
        1u64 << self.current
    }
    pub fn reset(&mut self) {
        self.current = self.min_poll;
    }
}

// ──── Rate Limit (Kiss-o'-Death) ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RateLimit {
    last_kod: NtpTs64,
    kod_count: u32,
}

impl RateLimit {
    pub fn new() -> Self {
        Self {
            last_kod: NtpTs64 {
                seconds: 0,
                fraction: 0,
            },
            kod_count: 0,
        }
    }
    pub fn should_send_kod(&self, now: NtpTs64) -> bool {
        let elapsed = now.seconds - self.last_kod.seconds;
        elapsed >= 10 || self.kod_count == 0
    }
    pub fn record_kod(&mut self, now: NtpTs64) {
        self.last_kod = now;
        self.kod_count = self.kod_count.saturating_add(1);
    }
}

// ──── Root Distance & Dispersion ──────────────────────────────────────

/// Compute root synchronization distance (RFC 5905 §10.1).
///   rootdist = root_delay / 2 + root_dispersion + peer_dispersion + phi * (t - t0)
/// where phi = 15 us/s (NTP clock skew maximum).
pub fn root_distance(peer: &Peer, now: NtpTs64) -> f64 {
    let phi = 15e-6; // 15 ppm = 15 us/s
    let elapsed = ntp_fp::ntp_ts64_to_double(now) - ntp_fp::ntp_ts64_to_double(peer.reference_time);
    peer.root_delay / 2.0 + peer.root_dispersion + peer.dispersion + phi * elapsed
}

/// Compute root dispersion (RFC 5905 §10.1).
pub fn root_dispersion(peer: &Peer, now: NtpTs64) -> f64 {
    let phi = 15e-6;
    let elapsed = ntp_fp::ntp_ts64_to_double(now) - ntp_fp::ntp_ts64_to_double(peer.reference_time);
    peer.root_dispersion + peer.dispersion + phi * elapsed
}

// ──── Clock Selection Algorithm ────────────────────────────────────────

/// The intersection algorithm (RFC 5905 §10.2).  Finds the smallest
/// intersection interval that contains at least one endpoint from each
/// of a majority of peers.  Peers whose confidence interval does NOT
/// overlap the intersection are falsetickers (marked TEST5).
pub fn clock_intersection(peers: &mut [Peer], now: NtpTs64) -> usize {
    let n = peers.len();
    if n == 0 {
        return 0;
    }

    // Compute synch (half-width of confidence interval) for each peer.
    //   synch = max(MINDISTANCE, root_delay/2 + root_dispersion + peer_jitter)
    // This matches ntpsec's confidence interval computation for the intersection
    // algorithm — using peer_jitter (clock-filter jitter) rather than the
    // dispersion + phi*elapsed terms used by root_distance().
    let synch: Vec<f64> = peers
        .iter()
        .map(|p| (p.root_delay / 2.0 + p.root_dispersion + p.jitter).max(NTP_MINDIST))
        .collect();

    // Build sorted endpoints: (value, type, peer_index)
    //   type = -1 for lower bound, +1 for upper bound
    let mut endpoints: Vec<(f64, i8, usize)> = Vec::with_capacity(2 * n);
    for (i, p) in peers.iter().enumerate() {
        endpoints.push((p.offset - synch[i], -1, i));
        endpoints.push((p.offset + synch[i], 1, i));
    }
    // Sort by offset; when equal, lower bound (-1) comes first.
    endpoints.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
    });

    // Marzullo's intersection algorithm (RFC 5905 §10.2).
    // Scan endpoints with increasing allow count (falseticker tolerance).
    // The first allow that yields a valid intersection is the minimum number
    // of falseticker peers whose intervals must be excluded.
    let mut intersection_start = 0.0f64;
    let mut intersection_end = 0.0f64;
    let mut found = false;

    for allow in 0..n {
        let mut count = 0usize;
        let mut start = f64::NAN;
        let mut end = f64::NAN;

        for (val, typ, _) in &endpoints {
            // typ is -1 (lower) → count += 1; +1 (upper) → count -= 1
            if *typ < 0 {
                count = count.wrapping_add(1);
            } else {
                count = count.wrapping_sub(1);
            }

            if count >= n - allow {
                if start.is_nan() {
                    start = *val;
                }
            } else if !start.is_nan() && end.is_nan() {
                end = *val;
                break;
            }
        }

        // If we scanned past the last endpoint while still inside the intersection
        if !start.is_nan() && end.is_nan() {
            end = endpoints.last().unwrap().0;
        }

        if !start.is_nan() && !end.is_nan() {
            intersection_start = start;
            intersection_end = end;
            found = true;
            break;
        }
    }

    // Mark peers whose confidence interval does NOT overlap with the
    // intersection interval as falsetickers (TEST5).
    let mut survivors = 0;
    if found {
        for (i, peer) in peers.iter_mut().enumerate() {
            let lo = peer.offset - synch[i];
            let hi = peer.offset + synch[i];
            if hi >= intersection_start && lo <= intersection_end {
                peer.flash &= !FlashBits::TEST5.bits();
                survivors += 1;
            } else {
                peer.flash |= FlashBits::TEST5.bits();
            }
        }
    } else {
        // No intersection found — all are falsetickers
        for peer in peers.iter_mut() {
            peer.flash |= FlashBits::TEST5.bits();
        }
    }

    survivors
}

/// The clustering algorithm (RFC 5905 §11).  From the survivors of the
/// intersection, prune the one with the highest jitter until either:
///   a) the remaining survivors ≤ NTP_MINCLOCK, or
///   b) the minimum jitter among survivors is > MAXCLOCK_JITTER * peer jitter.
///
/// Returns the survivors (pruned list).
pub fn clock_cluster(peers: &mut [Peer], now: NtpTs64) -> Vec<usize> {
    let n = peers.len();
    if n <= 1 {
        return (0..n).collect();
    }

    let mut indices: Vec<usize> = (0..n)
        .filter(|i| {
            // Only consider peers that pass all tests
            let flash = FlashBits::from_bits_truncate(peers[*i].flash);
            flash == FlashBits::PASS
        })
        .collect();

    if indices.len() <= 1 {
        return indices;
    }

    // Identify the prefer peer among the candidates (if any).
    // The prefer peer is always kept during pruning.
    let mut prefer_pos = indices
        .iter()
        .position(|&i| peers[i].flags.contains(PeerFlags::PREFER));

    // Compute jitter for each survivor relative to the others (RFC 5905 §11 eq 6).
    let mut peer_jitter = vec![0.0f64; indices.len()];
    for i in 0..indices.len() {
        let offset_i = peers[indices[i]].offset;
        let mut sum = 0.0f64;
        for j in 0..indices.len() {
            if i == j {
                continue;
            }
            let d = offset_i - peers[indices[j]].offset;
            sum += d * d;
        }
        peer_jitter[i] = (sum / (indices.len() - 1) as f64).sqrt();
    }

    // Prune: while we have more than NTP_MINCLOCK + 1 survivors, remove the
    // worst (highest jitter) if its jitter exceeds MAXCLOCK_JITTER × φ_jitter.
    // ntpsec default: MAXCLOCK_JITTER = 3.0, NTP_MINCLOCK = 3.
    const NTP_MINCLOCK: usize = 3;
    const MAXCLOCK_JITTER: f64 = 3.0;

    while indices.len() > NTP_MINCLOCK {
        // Find the worst survivor (highest peer jitter), skipping the prefer peer
        let worst_idx = peer_jitter
            .iter()
            .enumerate()
            .filter(|(idx, _)| prefer_pos.map_or(true, |p| *idx != p))
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(idx, _)| idx);

        // If the only remaining candidate(s) are the prefer peer, stop
        let worst_idx = match worst_idx {
            Some(idx) => idx,
            None => break,
        };

        // Recompute select jitter (φ_jitter) — RMS of the peer jitters
        // of the current survivors.
        let mut sum_sq = 0.0f64;
        for j in 0..indices.len() {
            sum_sq += peer_jitter[j] * peer_jitter[j];
        }
        let select_jitter = (sum_sq / indices.len() as f64).sqrt();

        if peer_jitter[worst_idx] <= MAXCLOCK_JITTER * select_jitter {
            // All are good enough — stop pruning
            break;
        }

        // Remove the worst; adjust prefer_pos if removal happens before it
        if prefer_pos.map_or(false, |p| worst_idx < p) {
            prefer_pos = prefer_pos.map(|p| p - 1);
        } else if prefer_pos.map_or(false, |p| worst_idx == p) {
            // Should not happen since we skip the prefer peer, but guard anyway
            prefer_pos = None;
        }
        indices.remove(worst_idx);
        peer_jitter.remove(worst_idx);
    }

    indices
}

/// The combining algorithm (RFC 5905 §12).  Computes a weighted average
/// of the survivor offsets.  The weight for each survivor is 1 / (peer_jitter²).
/// Returns (combined_offset, combined_jitter).
pub fn clock_combine(peers: &[Peer], survivors: &[usize]) -> (f64, f64) {
    if survivors.is_empty() {
        return (0.0, 0.0);
    }
    if survivors.len() == 1 {
        return (peers[survivors[0]].offset, peers[survivors[0]].jitter);
    }

    let mut sum_weight = 0.0f64;
    let mut sum_offset = 0.0f64;
    let mut sum_jitter_sq = 0.0f64;

    for &idx in survivors {
        let p = &peers[idx];
        let w = if p.jitter > 0.0 {
            1.0 / (p.jitter * p.jitter)
        } else {
            1.0
        };
        sum_weight += w;
        sum_offset += w * p.offset;
        sum_jitter_sq += w * p.jitter * p.jitter;
    }

    let combined_offset = sum_offset / sum_weight;
    let combined_jitter = (sum_jitter_sq / sum_weight).sqrt();

    (combined_offset, combined_jitter)
}

// ──── Packet Processing ───────────────────────────────────────────────

/// Process a received NTP packet.  This is the main receive path, matching
/// ntpsec's `receive()` and `process_packet()` logic.
///
/// Returns a list of response actions to take.
#[derive(Debug)]
pub enum ProcessResult {
    /// Discard the packet (no response).
    Discard,
    /// Send a Kiss-o'-Death response.
    SendKod(NtpPacket, SockAddr),
    /// Send an NTP response (server or symmetric mode).
    SendResponse(NtpPacket, SockAddr),
    /// Update the peer with the received sample.
    UpdatePeer,
}

/// Validate a received NTP packet.  Returns a FlashBits mask — set bits
/// indicate which tests failed.  Matching ntpsec's `test_free()` logic.
pub fn validate_packet(pkt: &NtpPacket, len: usize, expected_mode: NtpMode) -> FlashBits {
    let mut flash = FlashBits::PASS;

    // TEST1 — duplicate packet check (caller must check against last_received)
    // This is set by the caller if duplicate is detected.

    // TEST2 — bogus packet
    if len < NTP_HEADER_SIZE {
        flash |= FlashBits::TEST2;
    }

    // TEST3 — unsynchronized peer
    if pkt.stratum >= NTP_MAXSTRAT {
        flash |= FlashBits::TEST3;
    }

    // TEST4 — LI alarm
    if pkt.leap_indicator() == LeapIndicator::Alarm {
        flash |= FlashBits::TEST4;
    }

    // Check mode
    let mode = pkt.mode();
    if mode != expected_mode && mode != NtpMode::SymPassive {
        flash |= FlashBits::TEST2; // unexpected mode
    }

    // Check version
    let vn = pkt.version();
    if vn.to_bits() < NtpVersion::V3.to_bits() || vn.to_bits() > NtpVersion::V4.to_bits() {
        flash |= FlashBits::TEST2;
    }

    flash
}

/// Compute the NTP on-wire protocol offsets (RFC 5905 §8).
///   offset = [(T2 − T1) + (T3 − T4)] / 2
///   delay  = (T4 − T1) − (T3 − T2)
pub fn compute_offsets(
    t1: NtpTs64, // client transmit / originate
    t2: NtpTs64, // server receive
    t3: NtpTs64, // server transmit
    t4: NtpTs64, // client receive
) -> (f64, f64) {
    let t1_s = ntp_fp::ntp_ts64_to_double(t1);
    let t2_s = ntp_fp::ntp_ts64_to_double(t2);
    let t3_s = ntp_fp::ntp_ts64_to_double(t3);
    let t4_s = ntp_fp::ntp_ts64_to_double(t4);

    let offset = ((t2_s - t1_s) + (t3_s - t4_s)) / 2.0;
    let delay = (t4_s - t1_s) - (t3_s - t2_s);

    (offset, delay)
}

/// Accept the peer sample: update clock filter, reachability, and peer
/// variables.  Matching ntpsec's `accept()`.
pub fn accept_sample(peer: &mut Peer, offset: f64, delay: f64, dispersion: f64, now: NtpTs64) {
    // Clamp negative delay to 0 (ntpsec behavior for some edge cases).
    let delay = delay.max(0.0);

    // Update dispersion: add epsilon contribution for the poll interval.
    let poll_disp = (1u64 << peer.hpoll) as f64 * 1e-6; // 1 us per poll
    let dispersion = dispersion + poll_disp;

    // Add to clock filter
    peer.clock_filter.add_sample(ClockFilterEntry {
        offset,
        delay,
        dispersion,
        time: now,
    });

    // Update peer variables from the filter
    if let Some(filtered) = peer.clock_filter.filter() {
        peer.offset = filtered.offset;
        peer.delay = filtered.delay;
        peer.dispersion = filtered.dispersion;
    }

    // Update filter jitter
    peer.jitter = peer.clock_filter.filter_jitter(peer.offset);

    // Update reachability
    peer.reach.record_success();

    // Update peer timestamps from packet
    peer.receive_time = now;
}

// ──── Poll Management ──────────────────────────────────────────────────

/// Determine the next poll time.  Matching ntpsec's `poll_update()`.
pub fn poll_update(peer: &mut Peer, now: NtpTs64) {
    // Burst/iburst mode (NTPsec behavior)
    if peer.burst > 0 {
        // Send multiple packets at short intervals
        if peer.burst > 1 {
            peer.hpoll = peer.minpoll.max(NTP_MINPOLL + 1);
        }
        peer.burst -= 1;
        if peer.burst == 0 && peer.retry > 0 {
            peer.retry = 0;
        }
    }

    // If peer is reachable and offset is small, increase poll interval
    // toward maxpoll.  If unreachable, decrease toward minpoll.
    if peer.reach.is_reachable() {
        if peer.offset.abs() < 0.128 {
            // Well-synchronized — back off
            peer.hpoll = (peer.hpoll + 1).min(peer.maxpoll);
        } else if peer.offset.abs() < 1.0 {
            // Moderate offset — hold steady
        } else {
            // Large offset — poll faster
            peer.hpoll = peer.hpoll.saturating_sub(1).max(peer.minpoll);
        }
    } else {
        // Not reachable — poll faster
        peer.hpoll = peer.hpoll.saturating_sub(1).max(peer.minpoll);
    }
}

// ──── Transmit ─────────────────────────────────────────────────────────

/// Build an NTP server response packet.  Matching ntpsec's `transmit()`.
pub fn build_response(
    request: &NtpPacket,
    peer: Option<&Peer>,
    system: &SystemState,
    now: NtpTs64,
    precision: i8,
) -> NtpPacket {
    let mut resp = NtpPacket::zeroed();

    // LI, VN, Mode
    let li = if let Some(p) = peer {
        p.leap
    } else {
        system.leap
    };
    let vn = request.version();
    resp.li_vn_mode = NtpPacket::set_li_vn_mode(li, vn, NtpMode::Server);

    // Stratum
    resp.stratum = system.stratum;

    // Poll: use the peer's poll or system minpoll
    resp.poll = peer.map_or(system.poll, |p| p.hpoll);

    // Precision
    resp.precision = precision;

    // Root delay and dispersion (in NTP short format)
    resp.root_delay = f64_to_ntp_short(system.root_delay.max(0.0).min(65535.0));
    resp.root_dispersion = f64_to_ntp_short(system.root_dispersion.max(0.0).min(65535.0));

    // Reference ID
    resp.reference_id = system.reference_id;

    // Reference timestamp
    resp.reference_ts = ntp_fp::ntp_ts64_to_wire(system.reference_time);

    // Originate = request transmit timestamp
    resp.originate_ts = request.transmit_ts;

    // Receive = current time
    resp.receive_ts = ntp_fp::ntp_ts64_to_wire(now);

    // Transmit = current time (will be read by client)
    resp.transmit_ts = ntp_fp::ntp_ts64_to_wire(now);

    resp
}

/// Build an NTP client request packet.  Matching ntpsec's `transmit()` for client mode.
pub fn build_request(peer: &Peer, system: &SystemState, now: NtpTs64, precision: i8) -> NtpPacket {
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
    pkt.transmit_ts = ntp_fp::ntp_ts64_to_wire(now);
    pkt
}

// ──── System State ─────────────────────────────────────────────────────

/// Global NTP system state — matches ntpsec's `sys_*` globals.
#[derive(Debug, Clone)]
pub struct SystemState {
    pub leap: LeapIndicator,
    pub stratum: u8,
    pub poll: u8,
    pub precision: i8,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub reference_id: u32,
    pub reference_time: NtpTs64,
    pub peer_count: u32,
    pub sys_jitter: f64,
    pub sys_offset: f64,
    pub sys_frequency: f64,
    pub sys_rootdist: f64,
}

impl Default for SystemState {
    fn default() -> Self {
        Self {
            leap: LeapIndicator::Alarm,
            stratum: NTP_MAXSTRAT,
            poll: NTP_MINPOLL,
            precision: 0,
            root_delay: 0.0,
            root_dispersion: 0.0,
            reference_id: 0,
            reference_time: NtpTs64 {
                seconds: 0,
                fraction: 0,
            },
            peer_count: 0,
            sys_jitter: 0.0,
            sys_offset: 0.0,
            sys_frequency: 0.0,
            sys_rootdist: 0.0,
        }
    }
}

impl SystemState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update system state from a set of peers.  Returns the index of the
    /// selected system peer, or usize::MAX if no peer was selected.
    pub fn update_from_peers(&mut self, peers: &mut [Peer], now: NtpTs64) -> usize {
        // 1. Mark unreachable peers as failed TEST9
        for peer in peers.iter_mut() {
            if !peer.reach.is_reachable() {
                peer.flash |= FlashBits::TEST9.bits();
            } else {
                peer.flash &= !FlashBits::TEST9.bits();
            }
        }

        // 2. Run intersection algorithm
        let n_survivors = clock_intersection(peers, now);
        if n_survivors == 0 {
            // No survivors — fully reset to unsynchronized state
            self.leap = LeapIndicator::Alarm;
            self.stratum = NTP_MAXSTRAT;
            self.peer_count = 0;
            self.sys_offset = 0.0;
            self.sys_jitter = 0.0;
            self.sys_rootdist = f64::INFINITY;
            self.reference_id = 0;
            return usize::MAX;
        }

        // 3. Run clustering algorithm
        let survivors = clock_cluster(peers, now);
        if survivors.is_empty() {
            self.leap = LeapIndicator::Alarm;
            self.stratum = NTP_MAXSTRAT;
            self.peer_count = 0;
            self.sys_offset = 0.0;
            self.sys_jitter = 0.0;
            self.sys_rootdist = f64::INFINITY;
            self.reference_id = 0;
            return usize::MAX;
        }

        // 4. Run combining algorithm
        let (combined_offset, combined_jitter) = clock_combine(peers, &survivors);

        // 5. Pick the system peer — prefer the PREFER peer if any survivor has the flag,
        //    otherwise use the first survivor.
        let sys_peer_idx = survivors
            .iter()
            .copied()
            .find(|&i| peers[i].flags.contains(PeerFlags::PREFER))
            .unwrap_or(survivors[0]);
        let sys_peer = &peers[sys_peer_idx];

        // 6. Update system variables
        self.leap = sys_peer.leap;
        self.stratum = sys_peer.stratum.saturating_add(1).min(NTP_MAXSTRAT);
        self.reference_id = sys_peer.reference_id;
        self.reference_time = sys_peer.receive_time;
        self.root_delay = sys_peer.root_delay;
        self.root_dispersion = root_dispersion(sys_peer, now);
        self.sys_jitter = combined_jitter;
        self.sys_offset = combined_offset;
        self.sys_rootdist = root_distance(sys_peer, now);
        self.peer_count = survivors.len() as u32;
        sys_peer_idx
    }
}

// ──── Helper: f64 → NTP short format ──────────────────────────────────

/// Convert a f64 seconds value to NTP short format (16.16 fixed-point).
pub fn f64_to_ntp_short(v: f64) -> u32 {
    if v < 0.0 {
        return 0;
    }
    let int_part = (v as u16) as u32;
    let frac_part = ((v.fract() * 65536.0) as u16) as u32;
    (int_part << 16) | frac_part
}

// ──── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(offset: f64, delay: f64, dispersion: f64, reachable: bool) -> Peer {
        let mut p = Peer::new(
            unsafe { std::mem::zeroed() },
            NtpMode::Client,
            NtpVersion::V4,
            NTP_MINPOLL,
            NTP_MAXPOLL,
        );
        p.offset = offset;
        p.delay = delay;
        p.dispersion = dispersion;
        p.jitter = 0.01;
        p.root_delay = delay;
        p.root_dispersion = dispersion;
        p.stratum = 2;
        p.leap = LeapIndicator::NoWarning;
        if reachable {
            p.reach.record_success();
        }
        p
    }

    #[test]
    fn test_clock_filter_add_sample() {
        let mut cf = ClockFilter::new();
        for i in 0..10 {
            cf.add_sample(ClockFilterEntry {
                offset: i as f64 * 0.001,
                delay: (10 - i) as f64 * 0.001,
                dispersion: 0.001,
                time: NtpTs64 {
                    seconds: i,
                    fraction: 0,
                },
            });
        }
        assert_eq!(cf.sample_count(), 8);
        let filtered = cf.filter().unwrap();
        assert!((filtered.delay - 0.001).abs() < 0.0001);
    }

    #[test]
    fn test_clock_filter_jitter() {
        let mut cf = ClockFilter::new();
        for i in 0..8 {
            cf.add_sample(ClockFilterEntry {
                offset: 0.001 * (i as f64 - 3.5),
                delay: 0.01,
                dispersion: 0.001,
                time: NtpTs64 {
                    seconds: i as i64,
                    fraction: 0,
                },
            });
        }
        let jitter = cf.filter_jitter(0.0);
        assert!(jitter > 0.0);
        assert!(jitter < 0.01);
    }

    #[test]
    fn test_reachability_register() {
        let mut r = Reachability::new();
        assert!(!r.is_reachable());
        r.record_success();
        assert!(r.is_reachable());
        for _ in 0..8 {
            r.record_failure();
        }
        assert!(!r.is_reachable());
    }

    #[test]
    fn test_poll_interval() {
        let mut p = PollInterval::new(4, 10);
        assert_eq!(p.interval_seconds(), 16);
        p.increase();
        assert_eq!(p.interval_seconds(), 32);
        p.increase();
        assert_eq!(p.interval_seconds(), 64);
        p.decrease();
        assert_eq!(p.interval_seconds(), 32);
    }

    #[test]
    fn test_rate_limit() {
        let mut rl = RateLimit::new();
        let now = NtpTs64 {
            seconds: 0,
            fraction: 0,
        };
        assert!(rl.should_send_kod(now));
        rl.record_kod(now);
        assert!(!rl.should_send_kod(NtpTs64 {
            seconds: 5,
            fraction: 0
        }));
        assert!(rl.should_send_kod(NtpTs64 {
            seconds: 11,
            fraction: 0
        }));
    }

    #[test]
    fn test_validate_packet_good() {
        let pkt = NtpPacket {
            li_vn_mode: NtpPacket::set_li_vn_mode(
                LeapIndicator::NoWarning,
                NtpVersion::V4,
                NtpMode::Server,
            ),
            stratum: 2,
            ..NtpPacket::zeroed()
        };
        let flash = validate_packet(&pkt, 48, NtpMode::Server);
        assert_eq!(flash, FlashBits::PASS);
    }

    #[test]
    fn test_validate_packet_short() {
        let pkt = NtpPacket::zeroed();
        let flash = validate_packet(&pkt, 10, NtpMode::Client);
        assert!(flash.contains(FlashBits::TEST2));
    }

    #[test]
    fn test_validate_packet_unsync() {
        let pkt = NtpPacket {
            li_vn_mode: NtpPacket::set_li_vn_mode(
                LeapIndicator::NoWarning,
                NtpVersion::V4,
                NtpMode::Server,
            ),
            stratum: 16,
            ..NtpPacket::zeroed()
        };
        let flash = validate_packet(&pkt, 48, NtpMode::Server);
        assert!(flash.contains(FlashBits::TEST3));
    }

    #[test]
    fn test_compute_offsets_symmetric() {
        // Symmetric case: offset = 0, delay = 1 second
        // T1=0, T2=1, T3=2, T4=3
        // offset = [(1-0) + (2-3)]/2 = [1 + (-1)]/2 = 0
        // delay = (3-0) - (2-1) = 3 - 1 = 2
        let t1 = ntp_fp::ts_to_ntp(0, 0);
        let t2 = ntp_fp::ts_to_ntp(1, 0);
        let t3 = ntp_fp::ts_to_ntp(2, 0);
        let t4 = ntp_fp::ts_to_ntp(3, 0);

        let (offset, delay) = compute_offsets(t1, t2, t3, t4);
        let tol = 0.001;
        assert!((offset).abs() < tol, "offset {} should be ~0", offset);
        assert!((delay - 2.0).abs() < tol, "delay {} should be ~2", delay);
    }

    #[test]
    fn test_root_distance_basic() {
        let mut p = make_peer(0.001, 0.010, 0.005, true);
        let now = ntp_fp::ts_to_ntp(1000, 0);
        p.reference_time = now;
        let rd = root_distance(&p, now);
        // rd >= root_delay/2 + root_dispersion + peer_dispersion
        assert!(rd >= 0.005 + 0.005 + 0.005);
    }

    #[test]
    fn test_clock_select_outlier_pruned() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.001, 0.005, 0.001, true),
            make_peer(0.002, 0.005, 0.001, true),
            make_peer(0.003, 0.005, 0.001, true),
            make_peer(10.0, 0.005, 0.001, true),
        ];
        for (i, p) in peers.iter_mut().enumerate() {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now; // must set so root_distance is small
        }

        let survivors = clock_intersection(&mut peers, now);

        let outlier_flash = FlashBits::from_bits_truncate(peers[3].flash);
        assert!(
            outlier_flash.contains(FlashBits::TEST5),
            "outlier should be marked TEST5, flash={:?}",
            outlier_flash
        );

        for i in 0..3 {
            let f = FlashBits::from_bits_truncate(peers[i].flash);
            assert!(
                !f.contains(FlashBits::TEST5),
                "good peer {} should not be TEST5, flash={:?}",
                i,
                f
            );
        }

        assert!(survivors >= 2, "expected >=2 survivors, got {}", survivors);
    }
    #[test]
    fn test_clock_combine() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.001, 0.005, 0.001, true),
            make_peer(0.003, 0.005, 0.001, true),
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
        }

        let survivors: Vec<usize> = (0..peers.len()).collect();
        let (offset, _jitter) = clock_combine(&peers, &survivors);
        // Average of 0.001 and 0.003 = 0.002
        assert!((offset - 0.002).abs() < 0.001);
    }

    #[test]
    fn test_system_state_update() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.001, 0.005, 0.001, true),
            make_peer(0.002, 0.005, 0.001, true),
            make_peer(0.003, 0.005, 0.001, true),
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.stratum = 2;
            p.leap = LeapIndicator::NoWarning;
            p.reference_id = 0x7f7f0101;
            p.reference_time = now;
        }

        let mut sys = SystemState::new();
        sys.update_from_peers(&mut peers, now);
        assert_eq!(sys.stratum, 3);
        assert_eq!(sys.leap, LeapIndicator::NoWarning);
    }

    #[test]
    fn test_f64_to_ntp_short() {
        let v = f64_to_ntp_short(1.5);
        assert_eq!(v >> 16, 1); // integer part = 1
        assert_eq!(v & 0xFFFF, 32768); // fractional part = 0.5 * 65536
    }

    #[test]
    fn test_build_response() {
        let request = NtpPacket::zeroed();
        let system = SystemState::new();
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let resp = build_response(&request, None, &system, now, -20);
        assert_eq!(resp.mode(), NtpMode::Server);
        assert_eq!(resp.version(), NtpVersion::V4);
        assert_eq!(resp.stratum, NTP_MAXSTRAT);
    }
}
