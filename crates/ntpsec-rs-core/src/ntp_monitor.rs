// ──── ntp_monitor.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_monitor.c
//
// NTP monitoring (MRU — Most Recently Used) list. Tracks client requests
// for rate limiting and statistics. Includes nonce-based query support
// matching ntpsec's protocol.
// =============================================================================

use crate::ntp_io::NetAddr;
use crate::ntp_types::*;
use getrandom::getrandom;
use std::collections::HashMap;
use std::time::Instant;

/// Nonce expiry duration (30 seconds, matching ntpsec default).
const NONCE_EXPIRY: std::time::Duration = std::time::Duration::from_secs(30);

/// A single nonce entry in the nonce cache.
#[derive(Debug, Clone)]
pub struct NonceEntry {
    /// The 32-byte nonce value.
    pub nonce: [u8; 32],
    /// When the nonce was created (for expiry).
    pub created: Instant,
}

/// Nonce cache for MRU queries.
///
/// NTPsec uses a nonce-based authentication scheme for MRU list queries:
/// the client first requests a nonce via REQ_NONCE, then uses that nonce
/// to authenticate its READ_MRU request. This prevents third parties from
/// reading the MRU list.
#[derive(Debug, Clone)]
pub struct NonceCache {
    /// Active nonces, keyed by their hex representation.
    nonces: HashMap<String, NonceEntry>,
    /// Maximum number of nonces to keep.
    max_nonces: usize,
}

impl NonceCache {
    /// Create a new nonce cache.
    pub fn new() -> Self {
        Self {
            nonces: HashMap::new(),
            max_nonces: 64,
        }
    }

    /// Create a new nonce cache with a custom maximum size.
    pub fn with_max(max_nonces: usize) -> Self {
        Self {
            nonces: HashMap::new(),
            max_nonces,
        }
    }

    /// Generate a new nonce and store it in the cache.
    /// Returns a 32-byte random nonce.
    pub fn generate_nonce(&mut self) -> [u8; 32] {
        self.purge_expired();
        let mut nonce = [0u8; 32];
        getrandom(&mut nonce).expect("getrandom failed to generate nonce");
        let key = hex::encode(nonce);
        self.nonces.insert(
            key,
            NonceEntry {
                nonce,
                created: Instant::now(),
            },
        );
        // Trim cache if over cap
        while self.nonces.len() > self.max_nonces {
            // Remove the oldest entry
            if let Some(oldest_key) = self
                .nonces
                .iter()
                .min_by_key(|(_, v)| v.created)
                .map(|(k, _)| k.clone())
            {
                self.nonces.remove(&oldest_key);
            } else {
                break;
            }
        }
        nonce
    }

    /// Verify a nonce against the cache.
    /// Returns true if the nonce is found and not expired.
    /// The nonce is consumed after verification (removed from cache),
    /// matching ntpsec's one-time-use nonce protocol.
    pub fn verify_nonce(&mut self, nonce: &[u8]) -> bool {
        self.purge_expired();
        let key = hex::encode(nonce);
        if self.nonces.remove(&key).is_some() {
            true
        } else {
            false
        }
    }

    /// Purge expired nonces from the cache.
    pub fn purge_expired(&mut self) {
        let cutoff = Instant::now()
            .checked_sub(NONCE_EXPIRY)
            .unwrap_or(Instant::now());
        self.nonces.retain(|_, entry| entry.created > cutoff);
    }

    /// Get the number of active nonces.
    pub fn len(&self) -> usize {
        self.nonces.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.nonces.is_empty()
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// A single MRU entry (matches ntpsec's `mon_entry`).
#[derive(Debug, Clone)]
pub struct MonEntry {
    pub addr: SockAddr,
    pub last_pkt: NtpTs64,
    pub first_pkt: NtpTs64,
    pub count: u32,
    pub flags: u8,
}

/// MRU list.
#[derive(Debug, Default)]
pub struct MonList {
    entries: Vec<MonEntry>,
    pub max_entries: u32,
    pub min_distance: u32,
    /// Maximum age for MRU entries in seconds. Entries older than this
    /// are pruned during periodic aging. Matching ntpsec's MRU_MAXAGE.
    pub max_age: u32,
    /// Rate limit threshold: number of packets before rate limiting kicks in.
    /// Matching ntpsec's default behavior where rate limiting applies after
    /// a configurable number of packets from the same source.
    pub rate_limit_count: u32,
    /// Nonce cache for MRU query authentication.
    pub nonce_cache: NonceCache,
}

impl MonList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 600,     // ntpsec default
            min_distance: 600,    // ntpsec default (seconds)
            max_age: 3600,        // MRU_MAX_AGE = 3600 seconds (1 hour)
            rate_limit_count: 10, // ntpsec default rate limit packet count
            nonce_cache: NonceCache::new(),
        }
    }

    /// Record a packet from a source address.
    /// Supports both AF_INET and AF_INET6 for duplicate detection.
    pub fn record(&mut self, addr: &SockAddr, now: NtpTs64) {
        // Find existing entry or create new one
        if let Some(entry) = self.entries.iter_mut().find(|e| unsafe {
            e.addr.ss_family == addr.ss_family
                && match addr.ss_family as libc::c_int {
                    libc::AF_INET => {
                        let a = &*(&e.addr as *const _ as *const libc::sockaddr_in);
                        let b = &*(addr as *const _ as *const libc::sockaddr_in);
                        a.sin_addr.s_addr == b.sin_addr.s_addr
                    }
                    libc::AF_INET6 => {
                        let a = &*(&e.addr as *const _ as *const libc::sockaddr_in6);
                        let b = &*(addr as *const _ as *const libc::sockaddr_in6);
                        a.sin6_addr.s6_addr == b.sin6_addr.s6_addr
                    }
                    _ => false,
                }
        }) {
            entry.last_pkt = now;
            entry.count += 1;
        } else {
            self.entries.push(MonEntry {
                addr: *addr,
                last_pkt: now,
                first_pkt: now,
                count: 1,
                flags: 0,
            });
            // Prune if over limit after adding
            if self.entries.len() > self.max_entries as usize {
                self.prune_over_limit();
            }
        }
    }

    /// Prune old entries: remove any entry whose last_pkt is older than
    /// `max_age` seconds from `now`. This implements MRU entry aging,
    /// matching ntpsec's periodic MRU cleanup.
    pub fn prune_aged(&mut self, now: NtpTs64) {
        let cutoff = now.seconds.saturating_sub(self.max_age as i64);
        self.entries.retain(|e| e.last_pkt.seconds >= cutoff);
    }

    /// Prune entries over the max_entries limit by removing the oldest.
    pub fn prune_over_limit(&mut self) {
        if self.entries.len() > self.max_entries as usize {
            self.entries
                .sort_by(|a, b| b.last_pkt.seconds.cmp(&a.last_pkt.seconds));
            self.entries.truncate(self.max_entries as usize);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if the MRU monitor is enabled (i.e. has a non-zero max_entries).
    pub fn is_enabled(&self) -> bool {
        self.max_entries > 0
    }

    /// Check if a source address is rate-limited (using NetAddr from daemon_engine).
    /// Returns (is_limited, packet_count).
    pub fn is_rate_limited(&self, addr: &NetAddr) -> (bool, u32) {
        // Convert NetAddr to SockAddr for matching against MRU entries
        let ss = netaddr_to_sockaddr(addr);
        if let Some(entry) = self.entries.iter().find(|e| unsafe {
            e.addr.ss_family == ss.ss_family
                && match ss.ss_family as libc::c_int {
                    libc::AF_INET => {
                        let a = &*(&e.addr as *const _ as *const libc::sockaddr_in);
                        let b = &*(&ss as *const _ as *const libc::sockaddr_in);
                        a.sin_addr.s_addr == b.sin_addr.s_addr
                    }
                    libc::AF_INET6 => {
                        let a = &*(&e.addr as *const _ as *const libc::sockaddr_in6);
                        let b = &*(&ss as *const _ as *const libc::sockaddr_in6);
                        a.sin6_addr.s6_addr == b.sin6_addr.s6_addr
                    }
                    _ => false,
                }
        }) {
            // Rate-limiting algorithm from ntpsec:
            // Compute the average interval between successive packets.
            // If it falls below MIN_INTERVAL, the source is rate-limited.
            // Also enforce that the source must exceed the configured
            // rate_limit_count before rate limiting applies (matching ntpsec
            // behavior which uses a configurable threshold, default 10).
            const MIN_INTERVAL: f64 = 0.2; // 200 ms (~5 packets/sec max)
            if entry.count > self.rate_limit_count {
                let dt = (entry.last_pkt.seconds - entry.first_pkt.seconds) as f64
                    + (entry.last_pkt.fraction as f64 - entry.first_pkt.fraction as f64)
                        / 4_294_967_296.0;
                let avg_interval = dt / (entry.count as f64 - 1.0);
                (avg_interval < MIN_INTERVAL, entry.count)
            } else {
                // Not enough packets yet for rate limiting
                (false, entry.count)
            }
        } else {
            (false, 0)
        }
    }

    /// Get a snapshot of all entries (sorted by last packet time, recent first).
    /// Used by daemon_engine for Mode 6 MRU responses.
    pub fn get_entries_snapshot(&self) -> Vec<&MonEntry> {
        let mut sorted: Vec<&MonEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| b.last_pkt.seconds.cmp(&a.last_pkt.seconds));
        sorted
    }

    /// Read MRU entries for query response, matching ntpsec's format.
    /// Returns the entries in last_pkt order (most recent first).
    pub fn read_mru(&self, limit: usize) -> Vec<&MonEntry> {
        let mut sorted: Vec<&MonEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| b.last_pkt.seconds.cmp(&a.last_pkt.seconds));
        sorted.truncate(limit);
        sorted
    }
}

/// Convert a NetAddr to a libc sockaddr_storage for MRU matching.
pub fn netaddr_to_sockaddr(addr: &NetAddr) -> SockAddr {
    let mut ss: SockAddr = unsafe { std::mem::zeroed() };
    match addr.family {
        4 => {
            let sin = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = addr.port.to_be();
            let octets = [addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3]];
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_be_bytes(octets),
            };
        }
        6 => {
            let sin6 = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = addr.port.to_be();
            sin6.sin6_addr = libc::in6_addr { s6_addr: addr.addr };
        }
        _ => {}
    }
    ss
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sockaddr_v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SockAddr {
        let mut ss: SockAddr = unsafe { std::mem::zeroed() };
        let sin = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in) };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = port.to_be();
        sin.sin_addr = libc::in_addr {
            s_addr: u32::from_be_bytes([a, b, c, d]),
        };
        ss
    }

    fn make_sockaddr_v6(port: u16) -> SockAddr {
        let mut ss: SockAddr = unsafe { std::mem::zeroed() };
        let sin6 = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6) };
        sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sin6.sin6_port = port.to_be();
        sin6.sin6_addr = libc::in6_addr {
            s6_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };
        ss
    }

    #[test]
    fn test_monitor_record_basic() {
        let mut mon = MonList::new();
        let addr = make_sockaddr_v4(192, 168, 1, 1, 123);
        let now = NtpTs64 {
            seconds: 1_000_000,
            fraction: 0,
        };
        mon.record(&addr, now);
        assert_eq!(mon.len(), 1);

        let later = NtpTs64 {
            seconds: 1_000_100,
            fraction: 0,
        };
        mon.record(&addr, later);
        assert_eq!(mon.len(), 1); // same address, updated

        // Verify count increased
        let entry = &mon.entries[0];
        assert_eq!(entry.count, 2);
        assert_eq!(entry.last_pkt.seconds, 1_000_100);
        assert_eq!(entry.first_pkt.seconds, 1_000_000);
    }

    #[test]
    fn test_monitor_record_multiple() {
        let mut mon = MonList::new();
        let addr1 = make_sockaddr_v4(192, 168, 1, 1, 123);
        let addr2 = make_sockaddr_v4(10, 0, 0, 1, 123);
        let now = NtpTs64 {
            seconds: 1_000_000,
            fraction: 0,
        };
        mon.record(&addr1, now);
        mon.record(&addr2, now);
        assert_eq!(mon.len(), 2);
    }

    #[test]
    fn test_monitor_prune_aged() {
        let mut mon = MonList::new();
        mon.max_age = 100; // 100 seconds max age
        let addr = make_sockaddr_v4(192, 168, 1, 1, 123);
        let now = NtpTs64 {
            seconds: 1_000_000,
            fraction: 0,
        };
        mon.record(&addr, now);

        // Prune at a later time past max_age
        let later = NtpTs64 {
            seconds: 1_000_200,
            fraction: 0,
        };
        mon.prune_aged(later);
        assert_eq!(mon.len(), 0);
    }

    #[test]
    fn test_monitor_prune_over_limit() {
        let mut mon = MonList::new();
        mon.max_entries = 2;
        let addr1 = make_sockaddr_v4(192, 168, 1, 1, 123);
        let addr2 = make_sockaddr_v4(10, 0, 0, 1, 123);
        let addr3 = make_sockaddr_v4(172, 16, 0, 1, 123);
        let now = NtpTs64 {
            seconds: 1_000_000,
            fraction: 0,
        };
        mon.record(&addr1, now);
        mon.record(&addr2, now);
        mon.record(&addr3, now);
        assert_eq!(mon.len(), 2); // should be pruned to 2
    }

    #[test]
    fn test_rate_limited_below_threshold() {
        let mut mon = MonList::new();
        mon.rate_limit_count = 10;
        let addr = make_sockaddr_v4(192, 168, 1, 1, 123);
        let now = NtpTs64 {
            seconds: 1_000_000,
            fraction: 0,
        };
        // Only 5 packets, below threshold of 10
        for i in 0..5 {
            mon.record(
                &addr,
                NtpTs64 {
                    seconds: 1_000_000 + i,
                    fraction: 0,
                },
            );
        }
        // Convert to NetAddr for rate limited check
        let netaddr = NetAddr::ipv4(u32::from_be_bytes([192, 168, 1, 1]), 123);
        let (limited, count) = mon.is_rate_limited(&netaddr);
        assert!(!limited);
        assert_eq!(count, 5);
    }

    #[test]
    fn test_nonce_generate_and_verify() {
        let mut cache = NonceCache::new();
        let nonce = cache.generate_nonce();
        assert_eq!(nonce.len(), 32);
        assert_eq!(cache.len(), 1);

        // Verify the nonce
        assert!(cache.verify_nonce(&nonce));
        // Nonce should be consumed
        assert!(!cache.verify_nonce(&nonce));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_nonce_invalid_rejected() {
        let mut cache = NonceCache::new();
        let bad_nonce = [0u8; 32];
        assert!(!cache.verify_nonce(&bad_nonce));
    }

    #[test]
    fn test_nonce_purge_expired() {
        let mut cache = NonceCache::new();
        let nonce = cache.generate_nonce();
        assert_eq!(cache.len(), 1);

        // Manually expire all entries
        for entry in cache.nonces.values_mut() {
            entry.created = Instant::now()
                .checked_sub(std::time::Duration::from_secs(60))
                .unwrap_or(Instant::now());
        }
        cache.purge_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_read_mru_order() {
        let mut mon = MonList::new();
        let addr1 = make_sockaddr_v4(192, 168, 1, 1, 123);
        let addr2 = make_sockaddr_v4(10, 0, 0, 1, 123);
        let now1 = NtpTs64 {
            seconds: 100,
            fraction: 0,
        };
        let now2 = NtpTs64 {
            seconds: 200,
            fraction: 0,
        };
        mon.record(&addr1, now1);
        mon.record(&addr2, now2);

        let mru = mon.read_mru(10);
        assert_eq!(mru.len(), 2);
        // Most recent first (addr2 has later time)
        assert_eq!(
            unsafe {
                (*(&mru[0].addr as *const _ as *const libc::sockaddr_in))
                    .sin_addr
                    .s_addr
            },
            u32::from_be_bytes([10, 0, 0, 1])
        );
    }

    #[test]
    fn test_read_mru_limit() {
        let mut mon = MonList::new();
        let addr1 = make_sockaddr_v4(192, 168, 1, 1, 123);
        let addr2 = make_sockaddr_v4(10, 0, 0, 1, 123);
        let addr3 = make_sockaddr_v4(172, 16, 0, 1, 123);
        let now = NtpTs64 {
            seconds: 1_000_000,
            fraction: 0,
        };
        mon.record(&addr1, now);
        mon.record(&addr2, now);
        mon.record(&addr3, now);

        let mru = mon.read_mru(2);
        assert_eq!(mru.len(), 2);
    }

    #[test]
    fn test_netaddr_to_sockaddr_ipv4() {
        let addr = NetAddr::ipv4(u32::from_be_bytes([192, 168, 1, 1]), 123);
        let ss = netaddr_to_sockaddr(&addr);
        let sin = unsafe { &*(&ss as *const _ as *const libc::sockaddr_in) };
        assert_eq!(sin.sin_family as libc::c_int, libc::AF_INET);
        assert_eq!(u16::from_be(sin.sin_port), 123);
        assert_eq!(sin.sin_addr.s_addr, u32::from_be_bytes([192, 168, 1, 1]));
    }

    #[test]
    fn test_netaddr_to_sockaddr_ipv6() {
        let addr = NetAddr::ipv6(
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            123,
        );
        let ss = netaddr_to_sockaddr(&addr);
        let sin6 = unsafe { &*(&ss as *const _ as *const libc::sockaddr_in6) };
        assert_eq!(sin6.sin6_family as libc::c_int, libc::AF_INET6);
        assert_eq!(u16::from_be(sin6.sin6_port), 123);
        assert_eq!(sin6.sin6_addr.s6_addr[0], 0x20);
        assert_eq!(sin6.sin6_addr.s6_addr[1], 0x01);
    }

    #[test]
    fn test_ipv6_duplicate_detection() {
        let mut mon = MonList::new();
        let addr = make_sockaddr_v6(123);
        let now = NtpTs64 {
            seconds: 1_000_000,
            fraction: 0,
        };
        mon.record(&addr, now);
        assert_eq!(mon.len(), 1);

        // Same address again
        let later = NtpTs64 {
            seconds: 1_000_100,
            fraction: 0,
        };
        mon.record(&addr, later);
        assert_eq!(mon.len(), 1);
        assert_eq!(mon.entries[0].count, 2);
    }

    #[test]
    fn test_read_mru_empty() {
        let mon: MonList = MonList::new();
        let mru = mon.read_mru(10);
        assert!(mru.is_empty());
    }

    #[test]
    fn test_nonce_cache_with_max() {
        let mut cache = NonceCache::with_max(2);
        cache.generate_nonce();
        cache.generate_nonce();
        cache.generate_nonce(); // Should evict oldest
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_is_enabled() {
        let mon = MonList::new();
        assert!(mon.is_enabled());
        let mon_disabled = MonList {
            max_entries: 0,
            ..MonList::new()
        };
        assert!(!mon_disabled.is_enabled());
    }
}
