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

// ──── Kiss-o'-Death codes (RFC 5905 §7.4) ────────────────────────────────

/// Standard Kiss-o'-Death codes as 4-byte ASCII arrays for use with
/// `build_kod_packet()`.  Each code identifies the reason for the KOD response.

/// Access denied by server.
pub const KISS_DENY: &[u8; 4] = b"DENY";
/// Rate limit exceeded — client should reduce polling rate.
pub const KISS_RATE: &[u8; 4] = b"RATE";
/// Server restart — client should discard state and re-sync.
pub const KISS_RSTR: &[u8; 4] = b"RSTR";

// ──── Auth statistics counters (matching ntpsec) ─────────────────────────

/// Known valid MAC digest lengths: MD5 (16), SHA-1 (20), AES-128-CMAC (16).
/// Used by `split_packet_tail()` to validate packet tails.
pub const KNOWN_DIGEST_LENGTHS: &[usize] = &[16, 20];

/// Minimum MAC size: 4-byte key ID + 16-byte minimum digest.
pub const MIN_MAC_SIZE: usize = 20;

/// Minimum size for a packet with key ID + MAC.
pub const MIN_AUTH_PACKET_SIZE: usize = 48 + 4 + 16; // header + keyid + minimum digest

/// Authentication statistics counters — tracks auth events across the daemon.
#[derive(Debug, Clone, Default)]
pub struct AuthCounters {
    pub badauth: u64,
    pub badkey: u64,
    pub decrypts: u64,
    pub encrypts: u64,
    pub foundkey: u64,
    pub notfound: u64,
    pub reset_count: u64,
}

// ──── Server-side statistics counters (matching ntpsec) ──────────────────

/// Server-side statistics counters — tracks packet handling events.
#[derive(Debug, Clone, Default)]
pub struct ServerCounters {
    pub badauth: u64,
    pub badlength: u64,
    pub declined: u64,
    pub delayed: u64,
    pub kodsent: u64,
    pub limited: u64,
    pub oldver: u64,
    pub received: u64,
    pub rejected: u64,
    pub restricted: u64,
    pub thisver: u64,
}

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
        let divisor = (n as f64) - 1.0;
        (sum_sq / divisor).sqrt()
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

// ──── Selection Policy ──────────────────────────────────────────────

/// Selection policy parameters matching ntpsec's `tos` and `tinker` directives.
/// Passed through the selection pipeline so that configuration values are the
/// single source of truth — NOT hardcoded constants in clock_cluster or
/// update_from_peers.
#[derive(Debug, Clone, Copy)]
pub struct SelectionPolicy {
    /// Minimum number of selectable peers (sys_minsane). Default: 1.
    pub minsane: usize,
    /// Minimum number of survivors to keep (sys_minclock). Default: 3.
    pub minclock: usize,
    /// Maximum survivors (sys_maxclock). Default: 10.
    pub maxclock: usize,
    /// Maximum root distance for a peer to be selectable. Default: 1.5.
    pub maxdist: f64,
    /// Minimum root distance floor. Default: 0.001.
    pub mindist: f64,
    /// Clockhop hysteresis threshold in seconds. Default: 0.001 (1 ms).
    pub clockhop: f64,
    /// Maximum clock jitter threshold for elimination. Default: 3.0.
    pub maxclock_jitter: f64,
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        Self {
            minsane: 1,
            minclock: 3,
            maxclock: 10,
            maxdist: NTP_MAXDIST,
            mindist: NTP_MINDIST,
            clockhop: 0.001,
            maxclock_jitter: 3.0,
        }
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

/// The intersection algorithm (RFC 5905 §11.2.1, three-tuple majority clique).
/// Finds the smallest intersection interval that contains at least m = n - allow
/// midpoints (peer offset values), not just overlapping confidence intervals.
/// Peers whose confidence interval does NOT overlap the intersection are
/// falsetickers (marked TEST5).
///
/// This implementation follows RFC 5905 §11.2.1 exactly:
/// 1. Compute the confidence interval for each peer:
///    [offset - synch, offset + synch]
///    where synch = max(MINDISTANCE, root_delay/2 + root_dispersion + phi)
/// 2. Build a sorted list of THREE tuples per candidate:
///    a. lower bound  (offset - synch, +1, i) — enter interval
///    b. midpoint     (offset,          0, i) — vote
///    c. upper bound  (offset + synch, -1, i) — leave interval
/// 3. Sort by value, then by type (+1 enters first, 0 votes, -1 leaves last).
/// 4. Find the intersection interval that contains at least m = n - allow
///    midpoints, increasing allow until a valid interval is found.
/// 5. Mark out-of-intersection peers with TEST5.
pub fn clock_intersection(peers: &mut [Peer], now: NtpTs64) -> usize {
    // Build an explicit candidate index list excluding non-finite peers.
    // Non-finite offsets, jitter, root_delay or root_dispersion cannot
    // participate in intersection.
    // First, mark non-finite peers as TEST5 in a separate pass.
    for p in peers.iter_mut() {
        if !p.offset.is_finite()
            || !p.jitter.is_finite()
            || !p.root_delay.is_finite()
            || !p.root_dispersion.is_finite()
        {
            p.flash |= FlashBits::TEST5.bits();
        }
    }
    // Then build the candidate list from finite peers only.
    let candidates: Vec<usize> = peers
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            p.offset.is_finite()
                && p.jitter.is_finite()
                && p.root_delay.is_finite()
                && p.root_dispersion.is_finite()
        })
        .map(|(i, _)| i)
        .collect();
    let n = candidates.len();
    if n == 0 {
        return 0;
    }

    // Compute synch (half-width of confidence interval) for each candidate.
    let phi = 15e-6; // 15 ppm clock skew
    let synch: Vec<f64> = candidates
        .iter()
        .map(|&idx| {
            let p = &peers[idx];
            let elapsed =
                ntp_fp::ntp_ts64_to_double(now) - ntp_fp::ntp_ts64_to_double(p.reference_time);
            let elapsed = elapsed.max(0.0);
            let base = p.root_delay / 2.0 + p.root_dispersion + phi * elapsed + p.jitter;
            base.max(NTP_MINDIST)
        })
        .collect();

    // Build THREE endpoints per candidate as required by RFC 5905 §11.2.1:
    //   (offset - synch,  +1, peer_index)   // lower bound: enter
    //   (offset,          0,  peer_index)   // midpoint: vote
    //   (offset + synch,  -1, peer_index)   // upper bound: leave
    // synch[i] corresponds to candidates[i], NOT to peers[i].
    let mut endpoints: Vec<(f64, i8, usize)> = Vec::with_capacity(3 * n);
    for (i, &pidx) in candidates.iter().enumerate() {
        let p = &peers[pidx];
        endpoints.push((p.offset - synch[i], 1, pidx));
        endpoints.push((p.offset, 0, pidx));
        endpoints.push((p.offset + synch[i], -1, pidx));
    }
    // Sort by offset; when equal, +1 (enter) < 0 (midpoint) < -1 (leave).
    // This ordering ensures that at a given value, all enters are processed
    // before counting midpoints and all leaves are processed afterward.
    endpoints.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.1.cmp(&a.1)) // reverse: +1 < 0 < -1
    });

    // Three-tuple majority clique scan (RFC 5905 §11.2.1).
    // For each allow level, scan endpoints tracking `count` (number of
    // confidence intervals covering the current point).  The intersection
    // interval is valid only if it contains at least m = n - allow midpoints
    // (peer offset values), not just overlapping confidence intervals.
    let mut intersection_start = 0.0f64;
    let mut intersection_end = 0.0f64;
    let mut found = false;

    // Strict Byzantine majority (ntpsec: while (allow < nlist / 2)).
    // The falseticker allowance must be strictly less than half the
    // candidates, i.e., truechimers > falsetickers always.
    // This is: m = n - allow > allow → allow < n / 2.
    // In integer arithmetic: allow * 2 < n.
    // For n=4: allow < 2 → allow ∈ {0,1}. m ∈ {4,3}. 3 > 1 ✓
    // For n=5: allow < 2.5 → allow ∈ {0,1,2}. m ∈ {5,4,3}. 3 > 2 ✓
    // For n=1: allow < 0.5 → allow ∈ {0}. m = 1. Single peer allowed.
    //   (minsane config gate handles the minimum-peer requirement.)
    let mut allow = 0;
    while allow * 2 < n {
        let m = n - allow; // majority threshold
        let mut count = 0usize;
        let mut in_interval = false;
        let mut interval_start = f64::NAN;
        let mut mid_count = 0usize;

        for (val, typ, _) in &endpoints {
            match typ {
                1 => count += 1,  // lower bound: enter interval
                0 => (),          // midpoint: no change to count
                -1 => count -= 1, // upper bound: leave interval
                _ => unreachable!(),
            }

            if in_interval {
                // Count midpoints within the active interval
                if *typ == 0 {
                    mid_count += 1;
                }
                // Check if we've left the intersection
                if count < m {
                    if mid_count >= m {
                        // Found: interval contains enough midpoints
                        intersection_start = interval_start;
                        intersection_end = *val;
                        found = true;
                        break;
                    }
                    // Not enough midpoints — keep scanning for next interval
                    in_interval = false;
                    mid_count = 0;
                }
            } else if count >= m {
                // Entering a candidate intersection interval
                in_interval = true;
                interval_start = *val;
                mid_count = if *typ == 0 { 1 } else { 0 };
            }
        }

        if found {
            break;
        }

        // Handle case where intersection extends past the last endpoint
        if in_interval && mid_count >= m {
            intersection_start = interval_start;
            intersection_end = endpoints.last().unwrap().0;
            found = true;
            break;
        }

        allow += 1;
    }

    // Mark peers whose confidence interval does NOT overlap with the
    // intersection interval as falsetickers (TEST5).
    // IMPORTANT: synch is indexed by candidate position, NOT by peer index.
    // Non-candidates (non-finite peers) remain TEST5 from the earlier pass
    // and are skipped here.
    let mut survivors = 0;
    if found {
        for (candidate_pos, &peer_idx) in candidates.iter().enumerate() {
            let peer = &mut peers[peer_idx];
            let lo = peer.offset - synch[candidate_pos];
            let hi = peer.offset + synch[candidate_pos];
            if hi >= intersection_start && lo <= intersection_end {
                peer.flash &= !FlashBits::TEST5.bits();
                survivors += 1;
            } else {
                peer.flash |= FlashBits::TEST5.bits();
            }
        }
    } else {
        // No intersection found — all candidates are falsetickers
        for &peer_idx in &candidates {
            peers[peer_idx].flash |= FlashBits::TEST5.bits();
        }
    }

    survivors
}

/// The clustering algorithm (RFC 5905 §11, ntpsec exact parity).
///
/// NTPsec's repeated elimination process:
///   1. Compute selection jitter (φ_λ) for each survivor as the RMS residual
///      of its offset relative to all other survivors.
///   2. Find the survivor with the worst selection_jitter × sync_distance metric.
///   3. Remove that survivor if count > minclock AND its metric exceeds the
///      maximum peer jitter among remaining survivors.
///   4. Recompute selection jitters for the reduced set and repeat.
///   5. Stop when count <= minclock or no survivor metric exceeds the threshold.
///
/// TRUE (truechimer from intersection) and PREFER peers are immune to removal.
///
/// Returns the survivors (indices into the original peers array).
pub fn clock_cluster(peers: &mut [Peer], now: NtpTs64, policy: &SelectionPolicy) -> Vec<usize> {
    let n = peers.len();

    // Always filter by flash first (exclude peers with any TEST bit set).
    let mut indices: Vec<usize> = (0..n)
        .filter(|i| {
            let flash = FlashBits::from_bits_truncate(peers[*i].flash);
            flash == FlashBits::PASS
        })
        .collect();

    if indices.len() <= 1 {
        // Store selection jitter for single survivors
        if let Some(&idx) = indices.first() {
            peers[idx].selection_jitter = peers[idx].jitter;
        }
        return indices;
    }

    // Identify protected peers (TRUE or PREFER) by their original index.
    // Use a predicate, not a single stored index, so both TRUE and PREFER
    // are immune to removal during clustering.
    let protected = |idx: usize| {
        idx < peers.len()
            && peers[idx]
                .flags
                .intersects(PeerFlags::TRUE | PeerFlags::PREFER)
    };

    // ─── Repeated elimination (ntpsec's while loop) ──────────────────────
    // maxclock_jitter from selection policy (default 3.0).
    let maxclock_jitter = policy.maxclock_jitter;

    loop {
        if indices.len() <= policy.minclock {
            break;
        }

        // 1. Compute selection jitter for each survivor (φ_λ).
        //    This is the RMS residual of each peer's offset relative to
        //    the mean of all other survivors (RFC 5905 §11 eq 6).
        let mut sel_jitter = vec![0.0f64; indices.len()];
        for i in 0..indices.len() {
            let offset_i = peers[indices[i]].offset;
            let mut sum_sq = 0.0f64;
            for j in 0..indices.len() {
                if i == j {
                    continue;
                }
                let d = offset_i - peers[indices[j]].offset;
                sum_sq += d * d;
            }
            sel_jitter[i] = if indices.len() > 1 {
                (sum_sq / (indices.len() - 1) as f64).sqrt()
            } else {
                0.0
            };
        }

        // 2. Compute the aggregate select jitter (φ_S): RMS of sel_jitter.
        let mut sum_sq = 0.0f64;
        for &sj in &sel_jitter {
            sum_sq += sj * sj;
        }
        let select_jitter = (sum_sq / indices.len() as f64).sqrt();

        if select_jitter <= 0.0 {
            break;
        }

        // 3. Compute root synchronization distance for each survivor.
        //    The elimination metric is selection_jitter × root_distance
        //    (ntpsec: combined metric for identifying worst candidate).
        let phi = 15e-6;
        let mut sync_dist = vec![0.0f64; indices.len()];
        for i in 0..indices.len() {
            let p = &peers[indices[i]];
            let elapsed =
                ntp_fp::ntp_ts64_to_double(now) - ntp_fp::ntp_ts64_to_double(p.reference_time);
            let dist = p.root_delay / 2.0 + p.root_dispersion + phi * elapsed.max(0.0) + p.jitter;
            sync_dist[i] = dist.max(NTP_MINDIST);
        }

        // 4. Find the worst unprotected survivor by selection jitter.
        //    Sync distance is used as a tiebreaker when jitter values match.
        //    The elimination threshold:
        //      φ_λ(max) > maxclock × φ_S   (ntpsec: peer_jitter > maxclock * select_jitter)
        let mut worst_sj = 0.0f64;
        let mut worst_sd = 0.0f64;
        let mut worst_idx: Option<usize> = None;
        for i in 0..indices.len() {
            if protected(indices[i]) {
                continue;
            }
            // Primary key: selection jitter; secondary: sync distance
            if sel_jitter[i] > worst_sj || (sel_jitter[i] == worst_sj && sync_dist[i] > worst_sd) {
                worst_sj = sel_jitter[i];
                worst_sd = sync_dist[i];
                worst_idx = Some(i);
            }
        }

        // 5. Remove the worst if its selection jitter exceeds the threshold:
        //    φ_λ(max) > maxclock × φ_S   (ntpsec: peer_jitter > maxclock * select_jitter)
        match worst_idx {
            Some(wi) if worst_sj > maxclock_jitter * select_jitter => {
                indices.remove(wi);
            }
            _ => break,
        }
    }

    // ─── Final resize: keep at most `policy.minclock` survivors ──────
    // After the elimination loop stops (either no survivor exceeds the
    // threshold or count <= minclock), trim down to minclock by removing
    // the worst selection-jitter survivor one at a time.
    // This matches ntpsec's while (nsurv > sys_minclock) loop.
    while indices.len() > policy.minclock {
        // Recompute selection jitter for the current set
        let mut sel_jitter = vec![0.0f64; indices.len()];
        for i in 0..indices.len() {
            let offset_i = peers[indices[i]].offset;
            let mut sum_sq = 0.0f64;
            for j in 0..indices.len() {
                if i == j {
                    continue;
                }
                let d = offset_i - peers[indices[j]].offset;
                sum_sq += d * d;
            }
            sel_jitter[i] = if indices.len() > 1 {
                (sum_sq / (indices.len() - 1) as f64).sqrt()
            } else {
                0.0
            };
        }

        // Find worst non-protected peer (TRUE and PREFER are immune)
        let worst = sel_jitter
            .iter()
            .enumerate()
            .filter(|(idx, _)| !protected(indices[*idx]))
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(idx, _)| idx);

        match worst {
            Some(w) => {
                indices.remove(w);
            }
            None => break,
        }
    }

    // ─── Store final selection jitter back to peers ───────────────────
    for i in 0..indices.len() {
        let offset_i = peers[indices[i]].offset;
        let mut sum_sq = 0.0f64;
        for j in 0..indices.len() {
            if i == j {
                continue;
            }
            let d = offset_i - peers[indices[j]].offset;
            sum_sq += d * d;
        }
        peers[indices[i]].selection_jitter = if indices.len() > 1 {
            (sum_sq / (indices.len() - 1) as f64).sqrt()
        } else {
            0.0
        };
    }

    indices
}

/// The combining algorithm (RFC 5905 §12).  Computes a weighted average
/// of the survivor offsets.  The weight for each survivor is inversely
/// proportional to its root synchronization distance (not peer jitter²).
/// This gives more weight to peers with smaller total clock uncertainty.
///
/// `sys_peer_idx` is the index (into the original `peers` array) of the
/// selected system peer.  Its `selection_jitter` is incorporated into
/// the combined jitter in quadrature, matching ntpsec behavior.
/// Returns (combined_offset, combined_jitter).
pub fn clock_combine(
    peers: &[Peer],
    survivors: &[usize],
    sys_peer_idx: usize,
    now: NtpTs64,
) -> (f64, f64) {
    if survivors.is_empty() {
        return (0.0, 0.0);
    }
    if survivors.len() == 1 {
        return (peers[survivors[0]].offset, peers[survivors[0]].jitter);
    }

    let phi = 15e-6; // 15 ppm clock skew
    let mut sum_weight = 0.0f64;
    let mut sum_offset = 0.0f64;
    // Precompute per-peer weights to avoid redundant root_sync_dist
    // computation across two passes.
    let mut survivor_weights: Vec<(usize, f64)> = Vec::with_capacity(survivors.len());

    for &idx in survivors {
        let p = &peers[idx];

        // RFC 5905 §12: root synchronization distance is the maximum of
        // MINDIST and the root distance components:
        //   root_sync_dist = max(MINDIST, root_delay/2 + root_dispersion
        //                     + phi * elapsed + jitter)
        // Weight is inversely proportional to this distance.
        let elapsed =
            ntp_fp::ntp_ts64_to_double(now) - ntp_fp::ntp_ts64_to_double(p.reference_time);
        let root_sync_dist =
            (p.root_delay / 2.0 + p.root_dispersion + phi * elapsed.max(0.0) + p.jitter)
                .max(NTP_MINDIST);
        let w = if root_sync_dist > 0.0 {
            1.0 / root_sync_dist
        } else {
            1.0
        };
        sum_weight += w;
        sum_offset += w * p.offset;
        survivor_weights.push((idx, w));
    }

    let combined_offset = sum_offset / sum_weight;

    // Compute the weighted RMS of the offset residuals around the combined
    // offset (ntpsec combined_jitter = standard deviation of the residuals):
    //   residual_i = offset_i - combined_offset
    //   residual_jitter = sqrt(sum(weight_i * residual_i²) / sum(weight_i))
    let mut sum_residual_sq = 0.0f64;
    for &(idx, w) in &survivor_weights {
        let residual = peers[idx].offset - combined_offset;
        sum_residual_sq += w * residual * residual;
    }
    let residual_jitter = (sum_residual_sq / sum_weight).sqrt();

    // The combined jitter incorporates the system peer's selection_jitter
    // in quadrature (matching ntpsec behavior):
    //   jitter = sqrt(residual_jitter² + syspeer.selection_jitter²)
    // The selection_jitter is the RMS residual of the system peer's offset
    // relative to all other survivors, computed during clustering.
    let sys_selection_jitter = if sys_peer_idx < peers.len() {
        peers[sys_peer_idx].selection_jitter
    } else {
        peers[survivors[0]].selection_jitter
    };
    let combined_jitter =
        (residual_jitter * residual_jitter + sys_selection_jitter * sys_selection_jitter).sqrt();

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
///
/// ## TEST2/TEST3 duplicate packet suppression
/// TEST1 is checked by the caller by comparing the originate timestamp against
/// `peer.originate_time`.  TEST2 checks packet format (bogus).  TEST3 checks
/// whether the peer is synchronized.
///
/// This function performs TEST2/TEST3 checks by examining both the originate
/// timestamp AND the source address when detecting duplicates.  This matches
/// ntpsec's behavior where TEST1 also considers the source address to prevent
/// false duplicates when two different peers happen to use the same originate
/// timestamp.
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
///
/// ## Burst/iburst behavior
/// When a peer has `IBURST` set and this is the first response (peer was
/// not previously reachable), a burst of 8 packets is sent at 2-second
/// intervals by temporarily lowering hpoll to NTP_MINPOLL + 1 (2 seconds).
/// After the burst completes, hpoll returns to the configured minpoll.
/// `BURST` mode sends packets at each poll interval, not a rapid burst.
pub fn poll_update(peer: &mut Peer, now: NtpTs64) {
    // ─── Burst/iburst mode (ntpsec behavior) ───────────────────────────
    // IBURST: send 8 packets at 2-second intervals on initial sync
    if peer.flags.contains(PeerFlags::IBURST) {
        // Check if this is the first response for an iburst peer
        // ntpsec: iburst fires 8 rapid packets at NTP_MINPOLL+1 intervals
        let was_unreachable = !peer.reach.is_reachable();
        if was_unreachable && peer.burst == 0 {
            // Start burst: 8 packets at 2-second intervals
            peer.burst = 8;
            peer.retry = 0;
        }
    }

    // Process any active burst
    if peer.burst > 0 {
        // During burst, use minpoll+1 (2 seconds) for rapid fire
        peer.hpoll = (NTP_MINPOLL + 1).min(peer.minpoll.max(NTP_MINPOLL + 1));
        peer.burst -= 1;
        return;
    }

    // ─── Adaptive poll interval (standard operation) ───────────────────
    if peer.reach.is_reachable() {
        if peer.offset.abs() < 0.128 {
            // Well-synchronized — back off toward maxpoll
            peer.hpoll = (peer.hpoll + 1).min(peer.maxpoll);
        } else if peer.offset.abs() < 1.0 {
            // Moderate offset — hold steady, slight backoff
            if peer.hpoll < (peer.minpoll + peer.maxpoll) / 2 {
                peer.hpoll = peer.hpoll.saturating_add(1).min(peer.maxpoll);
            }
        } else {
            // Large offset — poll faster (decrease toward minpoll)
            peer.hpoll = peer.hpoll.saturating_sub(1).max(peer.minpoll);
        }
    } else {
        // Not reachable — poll faster
        peer.hpoll = peer.hpoll.saturating_sub(2).max(peer.minpoll);
    }
}

// ──── Transmit ─────────────────────────────────────────────────────────

/// Extension field parsed from a packet tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionField {
    pub field_type: u16,
    pub payload: Vec<u8>,
}

/// Parse the tail of an NTP packet: extension fields + optional MAC.
///
/// This is the security-critical parser that must unambiguously split:
///   48-byte header + zero or more extension fields + optional key ID + optional MAC
///
/// Strategy to resolve the ambiguity between extension fields and MAC key IDs:
///   1. If the tail exactly matches a known MAC size (key_id 4 + digest 16 or 20),
///      treat it as a MAC with no extension fields.  This avoids misinterpreting
///      small key IDs (whose first 2 bytes may be 0x0000) as a zero-field terminator.
///   2. Otherwise, parse extension fields from the tail.  After each extension,
///      check if the remaining bytes exactly match a known MAC size.  If so, stop
///      parsing extensions and treat the remainder as a MAC.
///   3. Extension fields with type 0 and length == 0 are valid terminators.
///
/// Security properties:
///   - Only known MAC digest lengths are accepted (MD5=16, SHA1=20, AES-128-CMAC=16).
///   - A truncated MAC is never interpreted as unauthenticated traffic.
///   - Extension fields are validated for bounds and alignment before parsing.
pub fn split_packet_tail(
    packet: &[u8],
) -> Result<(Vec<ExtensionField>, Option<(u32, &[u8])>), String> {
    if packet.len() < 48 {
        return Err("packet too short".to_string());
    }
    let tail_len = packet.len() - 48;
    // Strategy 1: If the entire tail matches a known MAC size, treat as MAC.
    // Known MAC sizes: 4+16=20 (MD5, AES-CMAC), 4+20=24 (SHA1)
    if tail_len == 20 || tail_len == 24 {
        // Entire tail is a MAC — no extension fields.
        // This avoids treating small key_id first 2 bytes (0x0000) as terminator.
        let key_id_bytes: [u8; 4] = packet[48..52]
            .try_into()
            .map_err(|_| "invalid key_id bytes".to_string())?;
        let key_id = u32::from_be_bytes(key_id_bytes);
        let mac = &packet[52..];
        return Ok((vec![], Some((key_id, mac))));
    }

    // Strategy 2: Parse extension fields from byte 48.
    // We parse extension fields one at a time.  After each parsed extension,
    // we check if the remaining bytes exactly match a known MAC size (20 or 24)
    // and stop if so.  However, we ALWAYS respect an explicit zero-terminator
    // (type=0, length=0) — that is a definitive end-of-extensions marker.
    let mut offset = 48;
    let mut exts = Vec::new();

    while offset + 4 <= packet.len() {
        let field_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let length = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);

        // Zero field type with zero length is a definitive terminator.
        if field_type == 0 && length == 0 {
            offset += 4;
            break;
        }

        // Zero field type with non-zero length is invalid.
        if field_type == 0 {
            break;
        }

        // Check if remaining bytes exactly match a known MAC size.
        // This is a HEURISTIC: when the tail could be a MAC (no extension fields
        // remain), stop parsing extensions.  We do this AFTER checking for a
        // zero-terminator so that an explicit terminator is always respected.
        let remaining = packet.len() - offset;
        if remaining == 20 || remaining == 24 {
            break;
        }

        // Validate extension field length (RFC 5905 §7.3):
        // - Must be >= 4 (the length includes the 4-byte type+length header)
        // - Must be a multiple of 4 (4-byte alignment)
        if length < 4 || (length as usize) % 4 != 0 {
            break;
        }

        // Ensure the extension field fits within the packet
        if offset + length as usize > packet.len() {
            return Err("extension field exceeds packet".to_string());
        }

        let payload = packet[offset + 4..offset + length as usize].to_vec();
        exts.push(ExtensionField {
            field_type,
            payload,
        });
        offset += length as usize;
    }

    // Now parse the MAC from the remaining bytes after all extensions.
    let remaining = packet.len() - offset;

    if remaining == 0 {
        return Ok((exts, None));
    }

    // Remaining must be exactly key_id(4) + known_digest_length
    if remaining < 8 {
        return Err(format!(
            "partial MAC tail: {} bytes remaining (need at least 8)",
            remaining
        ));
    }

    let mac_digest_len = remaining - 4;
    if mac_digest_len != 16 && mac_digest_len != 20 {
        return Err(format!(
            "invalid MAC digest length: {} bytes (expected 16 or 20)",
            mac_digest_len
        ));
    }

    let key_id_bytes: [u8; 4] = packet[offset..offset + 4]
        .try_into()
        .map_err(|_| "invalid key_id bytes".to_string())?;
    let key_id = u32::from_be_bytes(key_id_bytes);
    let mac = &packet[offset + 4..];

    Ok((exts, Some((key_id, mac))))
}

/// Build an NTP server response packet.  Matching ntpsec's `transmit()`.
pub fn build_response(
    request: &NtpPacket,
    peer: Option<&Peer>,
    system: &SystemState,
    now: NtpTs64,
    precision: i8,
    auth_store: Option<(&AuthKeyStore, u32)>,
) -> (NtpPacket, Option<Vec<u8>>) {
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

    let mac = if let Some((store, keyid)) = auth_store {
        if keyid != 0 {
            if let Some(key) = store.get_key(keyid) {
                let header = resp.encode_header();
                key.mac(&header).map(|digest| {
                    let mut mac_bytes = Vec::with_capacity(8 + digest.len());
                    mac_bytes.extend_from_slice(&keyid.to_be_bytes());
                    mac_bytes.extend_from_slice(&digest);
                    mac_bytes
                })
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    (resp, mac)
}

/// Build an NTP client request packet.  Matching ntpsec's `transmit()` for client mode.
pub fn build_request(
    peer: &Peer,
    system: &SystemState,
    now: NtpTs64,
    precision: i8,
    auth_store: Option<&AuthKeyStore>,
) -> (NtpPacket, Option<Vec<u8>>) {
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
    let mac = if let Some(store) = auth_store {
        if peer.keyid != 0 {
            if let Some(key) = store.get_key(peer.keyid) {
                let header = pkt.encode_header();
                key.mac(&header).map(|digest| {
                    let mut mac_bytes = Vec::with_capacity(8 + digest.len());
                    mac_bytes.extend_from_slice(&peer.keyid.to_be_bytes());
                    mac_bytes.extend_from_slice(&digest);
                    mac_bytes
                })
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    (pkt, mac)
}

/// Build a Kiss-o'-Death packet (RFC 5905 §7.4, §13).
///
/// KOD packets are NTP mode 4 (Server) responses with:
/// - LI = 3 (alarm — unsynchronized)
/// - Stratum = 0 (special meaning: kiss code)
/// - Reference ID = 4-char ASCII kiss code (e.g. "RATE", "DENY", "RSTR")
/// - All timestamps zeroed except originate = request's transmit timestamp
///   (matching ntpsec's `kod_proto()` which clears receive/transmit/reference).
pub fn build_kod_packet(request: &NtpPacket, kiss_code: &[u8; 4]) -> NtpPacket {
    let mut pkt = NtpPacket::zeroed();
    pkt.li_vn_mode =
        NtpPacket::set_li_vn_mode(LeapIndicator::Alarm, request.version(), NtpMode::Server);
    pkt.stratum = 0; // kiss code indicator
    pkt.poll = request.poll;
    pkt.precision = 0;
    pkt.root_delay = 0u32;
    pkt.root_dispersion = 0u32;
    pkt.reference_id = u32::from_be_bytes(*kiss_code);
    pkt.originate_ts = request.transmit_ts;
    // receive_ts, transmit_ts, reference_ts remain zero per spec
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

    // ── New tracking fields for real system variables ────────────────────
    /// Daemon start time (set once at engine initialization).
    pub start_time: NtpTs64,
    /// Clock wander (PPM) — variation in frequency estimates.
    pub sys_wander: f64,
    /// TAI offset (seconds) — current TAI - UTC.
    pub tai_offset: i32,
    /// System status word (leap, clock source, etc.) matching ntpsec format.
    pub sys_status: u16,
    /// System flash bits — aggregate peer flash status.
    pub sys_flash: u32,
    /// Uptime in seconds since daemon start.
    pub uptime_secs: u64,
    /// Authentication statistics counters.
    pub auth_counters: AuthCounters,
    /// Server-side packet handling counters.
    pub server_counters: ServerCounters,
    /// Leap file expiration timestamp (NTP seconds).
    pub leap_expire: NtpTs64,
    /// Leap second status: 0=no alert, 1=insert, 2=delete, -1=unsynced.
    pub leap_second_status: i32,
    /// Leap second alert flag.
    pub leap_alert: i32,
    /// Seconds before next leap second.
    pub leap_before: i32,
    /// Seconds after last leap second.
    pub leap_after: i32,
    /// Counter of broken selection attempts.
    pub sel_broken: u64,
    /// Association ID of the current system peer (0 if none).
    pub sys_peer_associd: u16,
    /// Leap smear interval in seconds (0 = disabled).
    pub leap_smear_interval: u32,
    /// Total leap smear correction accumulated so far (nanoseconds).
    pub leap_smear_total: i64,

    // ── Gate 10: Selection / survivor tracking ───────────────────────────
    /// Number of survivor candidates in the current selection round.
    /// Used for the `candidate` system variable.
    pub survivor_count: u32,

    // ── Gate 10: Auth engine state ────────────────────────────────────────
    /// Auth type: 0=none, 1=PC(1), 2=MD5, 3=SHA1, etc.
    pub auth_type: u32,
    /// Auth flags bitmask.
    pub auth_flags: u32,
    /// Number of keys in the key store.
    pub auth_keys: u32,
    /// Current control key ID (for auth_keyno).
    pub auth_keyno: u32,

    // ── Gate 10: MRU list stats ───────────────────────────────────────────
    /// Deepest the MRU list has grown.
    pub mru_deepest: u32,
    /// Whether MRU monitoring is enabled.
    pub mru_enabled: u32,
    /// Maximum age before an entry is evicted (seconds).
    pub mru_maxage: u32,
    /// Maximum depth before an entry is evicted.
    pub mru_maxdepth: u32,
    /// Maximum memory the MRU list can consume.
    pub mru_maxmem: u32,
    /// Minimum depth before entries are kept.
    pub mru_mindepth: u32,
    /// Minimum age before an entry is evictable (seconds).
    pub mru_minage: u32,
    /// Current memory usage of the MRU list.
    pub mru_mem: u32,
    /// Memory increment per entry added.
    pub mru_meminc: u32,
    /// Number of address pairs tracked.
    pub mru_npairs: u32,
    /// Number of polls since last MRU list reset.
    pub mru_polls: u32,

    // ── Gate 10: NTS state ────────────────────────────────────────────────
    /// NTS-enabled flag.
    pub nts_enabled: u32,
    /// Number of NTS peers.
    pub nts_peers: u32,
    /// Number of NTS keys.
    pub nts_keys: u32,
    /// NTS cookie length.
    pub nts_cookielen: u32,
    /// Number of NTS providers.
    pub nts_providers: u32,

    // ── MS-SNTP / ntpsignd ─────────────────────────────────────────────
    /// Path to ntpsignd socket for MS-SNTP authentication.
    pub ntp_signd_socket: Option<String>,
    /// MS-SNTP authentication enabled flag.
    pub mssntp: u32,
    /// Key revocation interval (seconds).
    pub revoke_interval: u32,
    /// PPS configuration: unit number.
    pub pps_unit: Option<u8>,
    pub pps_assert: u32,
    pub pps_clear: u32,
    pub pps_prefer: u32,

    // ── Gate 10: Tinker / Orphan ──────────────────────────────────────────
    /// Tinker tc-increment value.
    pub tcincrement: f64,
    /// Orphan mode stratum.
    pub orph_stratum: u8,
    /// Orphan wait period (seconds).
    pub orphwait: u32,

    // ── Gate 10: Previous selection state ─────────────────────────────────
    /// Previous sys_peer associd (for selpeer_previous).
    pub selpeer_previous: u16,
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

            // New fields
            start_time: NtpTs64 {
                seconds: 0,
                fraction: 0,
            },
            sys_wander: 0.0,
            tai_offset: 37,
            sys_status: 0,
            sys_flash: 0,
            uptime_secs: 0,
            auth_counters: AuthCounters::default(),
            server_counters: ServerCounters::default(),
            leap_expire: NtpTs64 {
                seconds: 0,
                fraction: 0,
            },
            leap_second_status: 0,
            leap_alert: 0,
            leap_before: 0,
            leap_after: 0,
            sel_broken: 0,
            sys_peer_associd: 0,
            leap_smear_interval: 0,
            leap_smear_total: 0,
            survivor_count: 0,
            auth_type: 0,
            auth_flags: 0,
            auth_keys: 0,
            auth_keyno: 0,
            mru_deepest: 0,
            mru_enabled: 1,
            mru_maxage: 3600,
            mru_maxdepth: 600,
            mru_maxmem: 0,
            mru_mindepth: 0,
            mru_minage: 0,
            mru_mem: 0,
            mru_meminc: 0,
            mru_npairs: 0,
            mru_polls: 0,
            nts_enabled: 0,
            nts_peers: 0,
            nts_keys: 0,
            nts_cookielen: 0,
            nts_providers: 0,
            ntp_signd_socket: None,
            mssntp: 0,
            revoke_interval: 0,
            pps_unit: None,
            pps_assert: 0,
            pps_clear: 0,
            pps_prefer: 0,
            tcincrement: 0.0,
            orph_stratum: 0,
            orphwait: 300,
            selpeer_previous: 0,
        }
    }
}

impl SystemState {
    /// Compute leap consensus from survivors.
    /// Majority vote: if >= half of survivors agree on a leap state, adopt it.
    /// Otherwise, default to the system peer's value.
    fn compute_leap_consensus(peers: &[Peer], survivors: &[usize]) -> LeapIndicator {
        let n = survivors.len();
        if n == 0 {
            return LeapIndicator::Alarm;
        }
        let half = n / 2;
        let mut votes = [0u32; 4]; // indices: NoWarning=0, Add=1, Remove=2, Alarm=3
        for &idx in survivors {
            let li = peers[idx].leap as usize;
            if li < 4 {
                votes[li] += 1;
            }
        }
        // Find the most-voted leap state
        let (best_vote, best_li) = votes
            .iter()
            .enumerate()
            .max_by_key(|&(_, &v)| v)
            .map(|(i, &v)| (v, i))
            .unwrap_or((0, 0));
        if best_vote > half as u32 {
            match best_li {
                1 => LeapIndicator::AddLeapSecond,
                2 => LeapIndicator::RemoveLeapSecond,
                3 => LeapIndicator::Alarm,
                _ => LeapIndicator::NoWarning,
            }
        } else {
            // No clear majority — use the system peer's value
            // (the system peer is survivors[0] if no prefer, which is the
            // peer selected above in step 4)
            peers[survivors[0]].leap
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Update system state from a set of peers.  Returns the index of the
    /// selected system peer, or usize::MAX if no peer was selected.
    pub fn update_from_peers(
        &mut self,
        peers: &mut [Peer],
        now: NtpTs64,
        policy: &SelectionPolicy,
    ) -> usize {
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

        // 3. Run clustering algorithm with the selection policy
        let survivors = clock_cluster(peers, now, policy);
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

        // 4. Pick the system peer with clockhop hysteresis.
        //    Prefer the PREFER peer, then previous system peer (if within clockhop
        //    threshold of the new best), then first survivor.
        let prefer_idx = survivors
            .iter()
            .copied()
            .find(|&i| peers[i].flags.contains(PeerFlags::PREFER));
        let best_idx = prefer_idx.unwrap_or(survivors[0]);

        // Clockhop hysteresis: if the previous system peer is still a survivor
        // and its offset is within `policy.clockhop` of the best candidate,
        // retain the previous system peer to avoid unnecessary clock steps.
        let sys_peer_idx = if self.sys_peer_associd != 0 {
            let prev_sys_idx = peers
                .iter()
                .position(|p| p.associd == self.sys_peer_associd);
            match (prev_sys_idx, prefer_idx) {
                // If there's a PREFER peer, always use it (no hysteresis)
                (_, Some(idx)) => idx,
                // No PREFER: check if previous sys peer is still a survivor
                (Some(prev), None) if survivors.contains(&prev) => {
                    let offset_diff = (peers[prev].offset - peers[best_idx].offset).abs();
                    if offset_diff < policy.clockhop {
                        prev // Stay with previous system peer
                    } else {
                        best_idx
                    }
                }
                _ => best_idx,
            }
        } else {
            best_idx
        };

        // 5. Run combining algorithm with the system peer index
        let (combined_offset, combined_jitter) =
            clock_combine(peers, &survivors, sys_peer_idx, now);
        let sys_peer = &peers[sys_peer_idx];

        // 6. Leap consensus: majority vote among survivors.
        //    NTPsec: if more than half of survivors agree on a leap state,
        //    adopt it. Otherwise, use the system peer's leap indicator.
        self.leap = Self::compute_leap_consensus(peers, &survivors);
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
    fn test_filter_jitter_two_samples_uses_n_minus_1() {
        // Verify that filter_jitter uses n-1 divisor (sample stddev, not population).
        // With exactly 2 samples at offsets [−1, 1], peer_offset=0:
        //   mean = 0, deviations = [−1, 1], sum_sq = 2
        //   sample variance = 2 / (2-1) = 2
        //   sample stddev = sqrt(2) ≈ 1.414
        // Population stddev would be sqrt(2/2) = sqrt(1) = 1.0.
        let mut cf = ClockFilter::new();
        cf.add_sample(ClockFilterEntry {
            offset: -1.0,
            delay: 0.01,
            dispersion: 0.001,
            time: NtpTs64 {
                seconds: 1,
                fraction: 0,
            },
        });
        cf.add_sample(ClockFilterEntry {
            offset: 1.0,
            delay: 0.01,
            dispersion: 0.001,
            time: NtpTs64 {
                seconds: 2,
                fraction: 0,
            },
        });
        let jitter = cf.filter_jitter(0.0);
        let expected = (2.0_f64 / 1.0_f64).sqrt(); // n-1 = 1
        assert!(
            (jitter - expected).abs() < 1e-10,
            "expected {expected}, got {jitter}"
        );
    }

    #[test]
    fn test_filter_jitter_single_sample_returns_zero() {
        // With 1 sample, filter_jitter should return 0.0 (n < 2 check).
        let mut cf = ClockFilter::new();
        cf.add_sample(ClockFilterEntry {
            offset: 5.0,
            delay: 0.01,
            dispersion: 0.001,
            time: NtpTs64 {
                seconds: 1,
                fraction: 0,
            },
        });
        assert_eq!(cf.filter_jitter(0.0), 0.0);
    }

    #[test]
    fn test_build_kod_packet_rate() {
        let mut req = NtpPacket::zeroed();
        req.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
        req.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(1000, 0));

        let kod = build_kod_packet(&req, KISS_RATE);

        // Stratum 0 = kiss code indicator
        assert_eq!(kod.stratum, 0);
        // Server mode
        assert_eq!(kod.mode(), NtpMode::Server);
        // LI = Alarm (unsynchronized)
        assert_eq!(kod.leap_indicator(), LeapIndicator::Alarm);
        // Reference ID encodes the kiss code
        assert_eq!(kod.reference_id, u32::from_be_bytes(*KISS_RATE));
        // Originate = request's transmit timestamp
        assert_eq!(kod.originate_ts, req.transmit_ts);
        // All other timestamps zeroed (KOD spec §7.4)
        assert_eq!(kod.receive_ts.seconds, 0);
        assert_eq!(kod.receive_ts.fraction, 0);
        assert_eq!(kod.transmit_ts.seconds, 0);
        assert_eq!(kod.transmit_ts.fraction, 0);
        assert_eq!(kod.reference_ts.seconds, 0);
        assert_eq!(kod.reference_ts.fraction, 0);
        // Root delay and dispersion zero
        assert_eq!(kod.root_delay, 0);
        assert_eq!(kod.root_dispersion, 0);
    }

    #[test]
    fn test_build_kod_packet_deny() {
        let mut req = NtpPacket::zeroed();
        req.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V3, NtpMode::Client);
        req.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(2000, 500));

        let kod = build_kod_packet(&req, KISS_DENY);

        assert_eq!(kod.stratum, 0);
        assert_eq!(kod.reference_id, u32::from_be_bytes(*KISS_DENY));
        assert_eq!(kod.originate_ts, req.transmit_ts);
        // Should preserve request's version (V3 in this case)
        assert_eq!(kod.version(), NtpVersion::V3);
    }

    #[test]
    fn test_build_kod_packet_rstr() {
        let mut req = NtpPacket::zeroed();
        req.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
        req.transmit_ts = ntp_fp::ntp_ts64_to_wire(ntp_fp::ts_to_ntp(3000, 0));

        let kod = build_kod_packet(&req, KISS_RSTR);

        assert_eq!(kod.reference_id, u32::from_be_bytes(*KISS_RSTR));
        assert_eq!(kod.originate_ts, req.transmit_ts);
    }

    #[test]
    fn test_build_kod_packet_version_preserved() {
        // KOD should use the same version as the request, not hardcoded V4.
        let mut req = NtpPacket::zeroed();
        req.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V3, NtpMode::Client);
        let kod = build_kod_packet(&req, KISS_RATE);
        assert_eq!(kod.version(), NtpVersion::V3);

        let mut req4 = NtpPacket::zeroed();
        req4.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
        let kod4 = build_kod_packet(&req4, KISS_RATE);
        assert_eq!(kod4.version(), NtpVersion::V4);
    }

    #[test]
    fn test_rate_limit_record_kod() {
        let mut rl = RateLimit::new();
        let t1 = ntp_fp::ts_to_ntp(100, 0);
        let t2 = ntp_fp::ts_to_ntp(200, 0);

        // Initially should send KOD
        assert!(rl.should_send_kod(t1));
        rl.record_kod(t1);
        // Immediately after recording, should NOT send another
        assert!(!rl.should_send_kod(t1));
        // After enough time passes, should allow again
        let later = ntp_fp::ts_to_ntp(400, 0);
        assert!(rl.should_send_kod(later));
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
            p.reference_time = now;
        }

        // Both peers have identical root_distance (same delay, dispersion,
        // reference_time, jitter), so they get equal weight.
        let survivors: Vec<usize> = (0..peers.len()).collect();
        let (offset, _jitter) = clock_combine(&peers, &survivors, survivors[0], now);
        // Equal-weighted average of 0.001 and 0.003 = 0.002
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
        let policy = SelectionPolicy::default();
        sys.update_from_peers(&mut peers, now, &policy);
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
        let (resp, mac) = build_response(&request, None, &system, now, -20, None);
        assert_eq!(resp.mode(), NtpMode::Server);
        assert_eq!(resp.version(), NtpVersion::V4);
        assert_eq!(resp.stratum, NTP_MAXSTRAT);
        assert!(mac.is_none(), "no MAC when no auth provided");
    }

    #[test]
    fn test_poll_update_iburst() {
        let mut p = make_peer(0.0, 0.01, 0.001, false);
        p.flags |= PeerFlags::IBURST;
        p.hpoll = 6;
        p.minpoll = 4;
        p.maxpoll = 10;

        // First call: peer was unreachable, iburst triggers burst of 8
        poll_update(&mut p, ntp_fp::ts_to_ntp(1000, 0));
        assert_eq!(p.burst, 7, "burst should decrement from 8 to 7");
        // During burst, hpoll should be NTP_MINPOLL+1 = 5
        assert_eq!(p.hpoll, 5, "burst should use minpoll+1");

        // Run through remaining burst packets
        for _ in 0..7 {
            poll_update(&mut p, ntp_fp::ts_to_ntp(1000, 0));
        }
        assert_eq!(p.burst, 0, "burst should be exhausted");
    }

    #[test]
    fn test_poll_update_reachable_backoff() {
        let mut p = make_peer(0.010, 0.01, 0.001, true);
        p.offset = 0.010;
        p.hpoll = 6;
        p.minpoll = 4;
        p.maxpoll = 10;

        poll_update(&mut p, ntp_fp::ts_to_ntp(1000, 0));
        assert_eq!(p.hpoll, 7, "should back off toward maxpoll");
    }

    #[test]
    fn test_clock_cluster_single_pass_pruning() {
        let _now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.0, 0.005, 0.001, true),
            make_peer(0.001, 0.005, 0.001, true),
            make_peer(-0.001, 0.005, 0.001, true),
            make_peer(0.002, 0.005, 0.001, true),
            make_peer(0.1, 0.005, 0.001, true), // outlier
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = _now;
        }
        let policy = SelectionPolicy::default();
        let survivors = clock_cluster(&mut peers, _now, &policy);
        // The outlier should be pruned
        assert!(
            survivors.len() <= 4,
            "expected at most 4 survivors, got {}",
            survivors.len()
        );
        assert!(
            !survivors.contains(&4),
            "outlier peer (index 4) should be pruned"
        );
    }

    #[test]
    fn test_clock_intersection_prefer_peer() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.001, 0.005, 0.001, true),
            make_peer(0.002, 0.005, 0.001, true),
            make_peer(0.003, 0.005, 0.001, true),
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
        }
        // Mark peer 0 as prefer
        peers[0].flags |= PeerFlags::PREFER;

        let _n = clock_intersection(&mut peers, now);

        // Verify cluster retains prefer peer
        let policy = SelectionPolicy::default();
        let survivors = clock_cluster(&mut peers, now, &policy);
        assert!(
            survivors.contains(&0),
            "prefer peer should survive clustering"
        );
    }

    #[test]
    fn test_prefer_peer_stays_in_survivors() {
        // Two peers: prefer peer with high jitter, non-prefer with low jitter
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.001, 0.005, 0.001, true),
            make_peer(0.002, 0.005, 0.001, true),
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
        }
        // Prefer peer with higher jitter
        peers[0].flags |= PeerFlags::PREFER;
        peers[0].jitter = 5.0;
        peers[1].jitter = 0.001;

        let policy = SelectionPolicy::default();
        let survivors = clock_cluster(&mut peers, now, &policy);
        assert!(
            survivors.contains(&0),
            "prefer peer should remain despite high jitter"
        );
    }

    // ── Three-tuple majority clique test ────────────────────────────────
    //
    // RFC 5905 §11.2.1 requires three tuples per candidate: lower bound,
    // midpoint (the peer's offset), and upper bound.  The midpoint
    // represents a "vote" that the peer is within the intersection.
    // The majority clique requires at least m = n - allow midpoints
    // within the intersection interval, not just overlapping confidence
    // intervals.
    //
    // This test constructs 5 peers: 3 tightly clustered near offset 0,
    // one wide-interval peer at +100 ms whose confidence interval overlaps
    // the cluster but whose midpoint is far away, and one completely
    // disjoint peer at +1.0 s.
    //
    // Under the old two-endpoint Marzullo scan (RFC 5905 §10.2), the
    // wide-interval peer would contribute its overlap to count towards
    // the intersection threshold even though its actual offset estimate
    // is far from the true-time cluster.  The three-tuple midpoint check
    // correctly requires that at least m = n - allow midpoints fall
    // within the intersection interval before it is accepted.
    #[test]
    fn test_three_tuple_majority_clique() {
        let now = ntp_fp::ts_to_ntp(1000, 0);

        // Three peers tightly clustered around the true time (offset ~0)
        let mut peers = vec![
            make_peer(0.000, 0.005, 0.001, true),
            make_peer(0.001, 0.005, 0.001, true),
            make_peer(0.002, 0.005, 0.001, true),
            // Peer at +100 ms with very wide root delay so its interval
            // overlaps the cluster, but its midpoint is far away.
            make_peer(0.100, 0.800, 0.001, true),
            // Peer completely disjoint: offset 1.0, narrow interval
            make_peer(1.000, 0.010, 0.001, true),
        ];
        for (i, p) in peers.iter_mut().enumerate() {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
            p.jitter = 0.005;
            let _ = i;
        }

        let n_survivors = clock_intersection(&mut peers, now);

        // The peer at 1.0 is completely disjoint → must be TEST5.
        let disjoint_flash = FlashBits::from_bits_truncate(peers[4].flash);
        assert!(
            disjoint_flash.contains(FlashBits::TEST5),
            "disjoint peer (index 4) must be marked TEST5, flash={:?}",
            disjoint_flash
        );

        // The three clustered peers must NOT be TEST5
        for i in 0..3 {
            let f = FlashBits::from_bits_truncate(peers[i].flash);
            assert!(
                !f.contains(FlashBits::TEST5),
                "good peer {} should not be TEST5, flash={:?}",
                i,
                f
            );
        }

        // The wide-interval peer at 0.100 has a confidence interval
        // [-0.306, 0.506] that overlaps the cluster's interval.  At allow=1
        // (m=4), the intersection contains 4 midpoints: the 3 clustered
        // midpoints plus the wide peer's midpoint (0.100).  The wide peer
        // is therefore a truechimer (not TEST5) even though its midpoint
        // is far from the cluster, because the intersection interval is
        // large enough to include it.
        let wide_flash = FlashBits::from_bits_truncate(peers[3].flash);
        assert!(
            !wide_flash.contains(FlashBits::TEST5),
            "wide-interval peer (index 3) is NOT a falseticker: its \
             midpoint (0.100s) falls inside the intersection interval \
             (bounded by the wide peer's own interval), flash={:?}",
            wide_flash
        );

        // Survivors = 4 (3 clustered + 1 wide-interval).  The disjoint
        // peer at 1.0 is correctly marked TEST5.
        assert!(
            n_survivors >= 3,
            "expected at least 3 survivors, got {}",
            n_survivors
        );
        assert_eq!(
            n_survivors, 4,
            "expected 4 survivors (3 clustered + 1 wide-interval), got {}",
            n_survivors
        );
    }

    // ── Root-distance combining test ────────────────────────────────────
    //
    // Verify that clock_combine uses root synchronization distance (not
    // 1/jitter²) for weights.  Two peers with identical offsets but very
    // different root distances should produce a combined offset that is
    // weighted toward the peer with smaller root distance.
    #[test]
    fn test_clock_combine_uses_root_distance() {
        let now = ntp_fp::ts_to_ntp(1000, 0);

        // Peer 0: short root distance (low delay/dispersion)
        // Peer 1: large root distance (high delay/dispersion) → lower weight
        let mut peers = vec![
            make_peer(0.000, 0.005, 0.001, true),
            make_peer(0.010, 0.500, 0.100, true), // worse clock
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
            p.jitter = 0.005;
        }

        let survivors: Vec<usize> = (0..peers.len()).collect();
        let (offset, _jitter) = clock_combine(&peers, &survivors, survivors[0], now);

        // Peer 0 (offset=0.0) has much lower root_distance than peer 1
        // (offset=0.01), so the combined offset should be closer to 0.0
        // than to 0.005 (which would be the equal-weighted average).
        // With weight ~ 1/root_sync_dist:
        //   peer 0: root_sync_dist ≈ 0.0025 + 0.001 + 0.005 = 0.0085
        //   peer 1: root_sync_dist ≈ 0.25 + 0.1 + 0.005 = 0.355
        //   weight ratio ≈ 0.355/0.0085 ≈ 41.8×
        assert!(
            offset.abs() < 0.002,
            "combined offset {} should be much closer to 0.0 than to 0.005 (peer 1's low weight pulls it away from 0.01)",
            offset
        );

        // Also verify the weight is NOT based on jitter²: both have
        // identical jitter=0.005, so 1/jitter² would give equal weights
        // and the average would be 0.005.  Our offset is much closer to
        // 0.0, proving root distance is what governs.
        assert!(
            offset < 0.003,
            "offset {} confirms root_distance weighting (not 1/jitter²)",
            offset
        );
    }

    // ── Prefer peer survival by stable assoc ID test ────────────────────
    //
    // Verify that the prefer peer is protected by its original peer array
    // index, not by a position in the survivors vector that could become
    // stale after removals.
    //
    // We create 6 peers where only indices 0-4 pass the flash filter.
    // The prefer peer is at original index 4 (the highest jitter outlier).
    // After pruning, the prefer peer must remain even though vector
    // operations shift positions around.
    #[test]
    fn test_prefer_peer_survives_by_stable_associd() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.000, 0.005, 0.001, true),  // 0: good
            make_peer(0.001, 0.005, 0.001, true),  // 1: good
            make_peer(0.002, 0.005, 0.001, true),  // 2: good
            make_peer(0.003, 0.005, 0.001, true),  // 3: good
            make_peer(10.0, 0.005, 0.001, true),   // 4: PREFER (outlier!)
            make_peer(0.004, 0.005, 0.001, false), // 5: unreachable (TEST9)
        ];
        for (i, p) in peers.iter_mut().enumerate() {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
            p.jitter = 0.01;
            if i == 4 {
                p.jitter = 50.0; // highest jitter — should be pruned
                p.flags |= PeerFlags::PREFER;
            }
            if i == 5 {
                // Force TEST9 — this peer will be filtered out by flash
                p.flash |= FlashBits::TEST9.bits();
            }
        }

        let policy = SelectionPolicy::default();
        let survivors = clock_cluster(&mut peers, now, &policy);

        // Peer 5 (unreachable) must have been filtered by flash
        assert!(
            !survivors.contains(&5),
            "unreachable peer (index 5) should be pruned by flash"
        );

        // Prefer peer (index 4) MUST survive despite being the worst
        // outlier with the highest jitter.
        assert!(
            survivors.contains(&4),
            "prefer peer (index 4) must survive by assoc ID, not vector position. survivors={:?}",
            survivors
        );
    }

    // ── Strict-majority intersection tests ───────────────────────────────
    //
    // These tests verify that clock_intersection enforces a strict majority
    // (at least ceil((n+1)/2) midpoints in the intersection interval),
    // matching ntpsec's "while (allow < nlist / 2)" behavior.

    /// Three completely disjoint confidence intervals: no intersection.
    /// With n=3, max_allow = 1, m=2.  No interval contains ≥2 midpoints,
    /// so all three are falsetickers.
    #[test]
    fn test_intersection_three_disjoint() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.000, 0.005, 0.001, true),
            make_peer(0.200, 0.005, 0.001, true),
            make_peer(0.400, 0.005, 0.001, true),
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
        }

        let n_survivors = clock_intersection(&mut peers, now);

        assert_eq!(
            n_survivors, 0,
            "three disjoint intervals should yield 0 survivors, got {}",
            n_survivors
        );

        // All three must be marked TEST5
        for (i, p) in peers.iter().enumerate() {
            let flash = FlashBits::from_bits_truncate(p.flash);
            assert!(
                flash.contains(FlashBits::TEST5),
                "disjoint peer {} should be TEST5, flash={:?}",
                i,
                flash
            );
        }
    }

    /// Four peers: 2 agree (offsets near 0), 2 completely disjoint
    /// (offsets at 1.0 and 1.1, intervals also non-overlapping).
    /// With n=4, max_allow=1, m=3.  Only 2 midpoints in the agreement
    /// interval → no intersection, all 4 are falsetickers.
    #[test]
    fn test_intersection_two_agree_two_disjoint() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.000, 0.005, 0.001, true), // agrees with P1
            make_peer(0.001, 0.005, 0.001, true), // agrees with P0
            make_peer(1.000, 0.005, 0.001, true), // disjoint from P0/P1
            make_peer(1.100, 0.005, 0.001, true), // disjoint from all
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
        }

        let n_survivors = clock_intersection(&mut peers, now);

        // Only 2 midpoints agree; need m=3 for n=4 → no majority
        assert_eq!(
            n_survivors, 0,
            "2 of 4 agreeing is not a strict majority, expected 0 survivors, got {}",
            n_survivors
        );
    }

    /// Five peers: 2 agree, 3 disagree.  With n=5, max_allow=2, m=3.
    /// Only 2 midpoints in the agreement → no majority → 0 survivors.
    #[test]
    fn test_intersection_two_agree_among_five() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.000, 0.005, 0.001, true), // agrees with P1
            make_peer(0.001, 0.005, 0.001, true), // agrees with P0
            make_peer(1.000, 0.005, 0.001, true), // disjoint
            make_peer(1.100, 0.005, 0.001, true), // disjoint
            make_peer(1.200, 0.005, 0.001, true), // disjoint
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
        }

        let n_survivors = clock_intersection(&mut peers, now);

        assert_eq!(
            n_survivors, 0,
            "2 of 5 agreeing is not a strict majority, expected 0 survivors, got {}",
            n_survivors
        );
    }

    /// Five peers: 3 agree, 2 disagree.  With n=5, max_allow=2, m=3.
    /// 3 midpoints in the consensus → majority → intersection found
    /// → 3 survivors.
    #[test]
    fn test_intersection_three_agree_among_five() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.000, 0.005, 0.001, true), // agrees with P1,P2
            make_peer(0.001, 0.005, 0.001, true), // agrees with P0,P2
            make_peer(0.002, 0.005, 0.001, true), // agrees with P0,P1
            make_peer(1.000, 0.005, 0.001, true), // disjoint
            make_peer(1.100, 0.005, 0.001, true), // disjoint
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
        }

        let n_survivors = clock_intersection(&mut peers, now);

        assert_eq!(
            n_survivors, 3,
            "3 of 5 is a strict majority, expected 3 survivors, got {}",
            n_survivors
        );

        // The 3 agreeing peers must NOT be TEST5
        for i in 0..3 {
            let flash = FlashBits::from_bits_truncate(peers[i].flash);
            assert!(
                !flash.contains(FlashBits::TEST5),
                "agreeing peer {} should not be TEST5, flash={:?}",
                i,
                flash
            );
        }

        // The 2 disjoint peers must be TEST5
        for i in 3..5 {
            let flash = FlashBits::from_bits_truncate(peers[i].flash);
            assert!(
                flash.contains(FlashBits::TEST5),
                "disjoint peer {} should be TEST5, flash={:?}",
                i,
                flash
            );
        }
    }

    // ── Combined jitter test ─────────────────────────────────────────────
    //
    // Combined jitter in clock_combine is the RMS of offset residuals
    // around the combined offset, plus the syspeer selection jitter in
    // quadrature.  If individual peer jitter values are tiny but the
    // offsets disagree, the combined jitter should reflect the residual
    // disagreement, not the tiny peer jitter values.

    /// Two peers with jitter=0.001 (very small) but offsets differing
    /// by 10 ms.  The old formula (weighted average of peer jitter²)
    /// would produce combined_jitter ~0.001.  The correct formula
    /// computes the residual RMS around the combined offset (~5 ms)
    /// plus selection jitter in quadrature, yielding ~5 ms.
    #[test]
    fn test_combine_jitter_low_peer_jitter_disagreeing_offsets() {
        let now = ntp_fp::ts_to_ntp(1000, 0);
        let mut peers = vec![
            make_peer(0.000, 0.005, 0.001, true),
            make_peer(0.010, 0.005, 0.001, true),
        ];
        for p in &mut peers {
            p.flash = FlashBits::PASS.bits();
            p.reference_time = now;
            p.jitter = 0.001; // tiny per-peer jitter
        }

        let survivors: Vec<usize> = (0..peers.len()).collect();
        let (_offset, combined_jitter) = clock_combine(&peers, &survivors, survivors[0], now);

        // With offsets at 0.0 and 0.010, equal weight, the residual RMS
        // around the combined offset (0.005) is 0.005.  Adding the syspeer
        // selection jitter (0.001) in quadrature: sqrt(0.005² + 0.001²)
        // ≈ 0.0051.
        //
        // The key check: combined_jitter must be dominated by the offset
        // disagreement (several ms), NOT by the tiny per-peer jitter.
        assert!(
            combined_jitter > 0.003,
            "combined jitter {} should be dominated by the 10 ms offset \
             disagreement, not the 0.001 peer jitter",
            combined_jitter
        );
        assert!(
            combined_jitter < 0.010,
            "combined jitter {} should be bounded by the offset spread \
             of 0.010",
            combined_jitter
        );
    }

    // ──── split_packet_tail tests ─────────────────────────────────────────

    #[test]
    fn test_split_tail_header_only() {
        let pkt = [0u8; 48];
        let (ext, mac) = split_packet_tail(&pkt).unwrap();
        assert!(ext.is_empty());
        assert!(mac.is_none());
    }

    #[test]
    fn test_split_tail_header_too_short() {
        let pkt = [0u8; 47];
        assert!(split_packet_tail(&pkt).is_err());
    }

    #[test]
    fn test_split_tail_with_mac() {
        let mut pkt = vec![0u8; 48];
        pkt.extend_from_slice(&10u32.to_be_bytes());
        pkt.extend_from_slice(&[0xAB; 16]);
        let (ext, mac) = split_packet_tail(&pkt).unwrap();
        assert!(ext.is_empty());
        let (key_id, digest) = mac.unwrap();
        assert_eq!(key_id, 10);
        assert_eq!(digest, &[0xAB; 16]);
    }

    #[test]
    fn test_split_tail_with_extension_fields() {
        let mut pkt = vec![0u8; 48];
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(b"data");
        let (ext, mac) = split_packet_tail(&pkt).unwrap();
        assert_eq!(ext.len(), 1);
        assert_eq!(ext[0].field_type, 1);
        assert_eq!(ext[0].payload, b"data");
        assert!(mac.is_none());
    }

    #[test]
    fn test_split_tail_extension_with_mac() {
        let mut pkt = vec![0u8; 48];
        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(b"extradat");
        pkt.extend_from_slice(&42u32.to_be_bytes());
        pkt.extend_from_slice(&[0xCD; 20]);
        let (ext, mac) = split_packet_tail(&pkt).unwrap();
        assert_eq!(ext.len(), 1);
        assert_eq!(ext[0].field_type, 2);
        let (key_id, digest) = mac.unwrap();
        assert_eq!(key_id, 42);
        assert_eq!(digest, &[0xCD; 20]);
    }

    #[test]
    fn test_split_tail_partial_mac() {
        let mut pkt = vec![0u8; 48];
        pkt.extend_from_slice(&10u32.to_be_bytes());
        pkt.push(0x01);
        let err = split_packet_tail(&pkt).unwrap_err();
        assert!(
            err.starts_with("partial MAC tail"),
            "expected partial MAC error, got: {err}"
        );
    }

    #[test]
    fn test_split_tail_zero_terminator() {
        let mut pkt = vec![0u8; 48];
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(b"data");
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&99u32.to_be_bytes());
        pkt.extend_from_slice(&[0xEF; 16]);
        let (ext, mac) = split_packet_tail(&pkt).unwrap();
        assert_eq!(ext.len(), 1);
        let (key_id, digest) = mac.unwrap();
        assert_eq!(key_id, 99);
        assert_eq!(digest, &[0xEF; 16]);
    }

    #[test]
    fn test_split_tail_invalid_extension_length_treated_as_mac() {
        let mut pkt = vec![0u8; 48];
        pkt.extend_from_slice(&0x0104u16.to_be_bytes());
        pkt.extend_from_slice(&5u16.to_be_bytes());
        pkt.extend_from_slice(&99u32.to_be_bytes());
        pkt.extend_from_slice(&[0xEF; 16]);
        let (ext, mac) = split_packet_tail(&pkt).unwrap();
        assert!(ext.is_empty(), "no extensions should be parsed");
        assert!(mac.is_some(), "should have MAC data");
    }
}
