// ──── ntp_peer.rs ───────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_peer.c
//
// Peer association management: creation, configuration, cleanup, and
// statistics tracking for each NTP peer/server.
//
// ## Oracle
//   - ntpsec ntpd/ntp_peer.c (19K)
//   - ntpsec include/ntp.h (peer struct)
// =============================================================================

use crate::ntp_proto::{ClockFilter, Reachability};
use crate::ntp_types::*;

/// A peer association (matches ntpsec's `struct peer`).
#[derive(Debug, Clone)]
pub struct Peer {
    pub srcaddr: SockAddr,
    pub dstadr: Option<SockAddr>,

    pub hmode: NtpMode, // host mode
    pub pmode: NtpMode, // peer mode
    pub version: NtpVersion,
    pub stratum: u8,
    pub poll_interval: u8,
    pub minpoll: u8,
    pub maxpoll: u8,

    pub clock_filter: ClockFilter,
    pub reach: Reachability,

    pub offset: f64,
    pub delay: f64,
    pub dispersion: f64,
    pub jitter: f64,

    pub hpoll: u8,  // current poll exponent
    pub ppoll: u8,  // peer's poll exponent
    pub flash: u32, // flash bits
    pub leap: LeapIndicator,
    pub precision: i8,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub reference_id: u32,
    pub reference_time: NtpTs64,
    pub originate_time: NtpTs64,
    pub receive_time: NtpTs64,
    pub transmit_time: NtpTs64,

    pub keyid: u32,
    pub flags: PeerFlags,
    pub burst: u8, // remaining burst packets
    pub retry: u8, // remaining retry attempts
    /// Stable association ID (1-based, immutable after creation).
    pub associd: u16,
}

bitflags::bitflags! {
    /// Peer flags matching ntpsec.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PeerFlags: u32 {
        const NONE      = 0;
        const AUTHENABLE = 1 << 0;  // can authenticate
        const AUTHENTIC  = 1 << 1;  // is authenticated
        const PREFER     = 1 << 2;  // prefer peer
        const BURST      = 1 << 3;  // burst mode
        const IBURST     = 1 << 4;  // initial burst
        const XLEAVE     = 1 << 5;  // interleaved mode
        const NOSYNC     = 1 << 6;  // not synchronized
        const PROBE      = 1 << 7;  // probe (manycast)
        const CONFIGURED  = 1 << 8;  // configured via config file, not ephemeral
    }
}

impl Peer {
    pub fn new(
        srcaddr: SockAddr,
        hmode: NtpMode,
        version: NtpVersion,
        minpoll: u8,
        maxpoll: u8,
    ) -> Self {
        Self {
            srcaddr,
            dstadr: None,
            hmode,
            pmode: NtpMode::Reserved,
            version,
            stratum: 16,
            poll_interval: minpoll,
            minpoll,
            maxpoll,
            clock_filter: ClockFilter::new(),
            reach: Reachability::new(),
            offset: 0.0,
            delay: 0.0,
            dispersion: 0.0,
            jitter: 0.0,
            hpoll: minpoll,
            ppoll: 0,
            flash: 0,
            leap: LeapIndicator::Alarm,
            precision: 0,
            root_delay: 0.0,
            root_dispersion: 0.0,
            reference_id: 0,
            reference_time: NtpTs64 {
                seconds: 0,
                fraction: 0,
            },
            originate_time: NtpTs64 {
                seconds: 0,
                fraction: 0,
            },
            receive_time: NtpTs64 {
                seconds: 0,
                fraction: 0,
            },
            transmit_time: NtpTs64 {
                seconds: 0,
                fraction: 0,
            },
            keyid: 0,
            flags: PeerFlags::NONE,
            burst: 0,
            retry: 0,
            associd: 0,
        }
    }

    /// Is the peer reachable?
    pub fn is_reachable(&self) -> bool {
        self.reach.is_reachable()
    }

    /// Has the peer synchronized?
    pub fn is_sync(&self) -> bool {
        self.stratum < 16 && self.is_reachable()
    }

    /// Create a minimal peer for testing with a given association ID.
    pub fn with_associd(associd: u16) -> Self {
        let mut p = Self::new(
            unsafe { std::mem::zeroed() },
            NtpMode::Client,
            NtpVersion::V4,
            4,
            10,
        );
        p.associd = associd;
        p
    }
}

/// Peer association table.
#[derive(Debug, Default)]
pub struct PeerTable {
    peers: Vec<Peer>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self { peers: Vec::new() }
    }

    pub fn add(&mut self, peer: Peer) {
        self.peers.push(peer);
    }

    pub fn remove(&mut self, index: usize) {
        if index < self.peers.len() {
            self.peers.remove(index);
        }
    }

    pub fn get(&self, index: usize) -> Option<&Peer> {
        self.peers.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Peer> {
        self.peers.get_mut(index)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.peers.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Peer> {
        self.peers.iter_mut()
    }

    /// Remove a peer by association ID.
    pub fn remove_by_associd(&mut self, associd: u16) {
        self.peers.retain(|p| p.associd != associd);
    }

    /// Find a peer by source address.
    pub fn find_by_addr(&self, addr: &SockAddr) -> Option<&Peer> {
        self.peers.iter().find(|p| unsafe {
            p.srcaddr.ss_family == addr.ss_family
                && match addr.ss_family as libc::c_int {
                    libc::AF_INET => {
                        let a = &*(&p.srcaddr as *const _ as *const libc::sockaddr_in);
                        let b = &*(addr as *const _ as *const libc::sockaddr_in);
                        a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port
                    }
                    libc::AF_INET6 => {
                        let a = &*(&p.srcaddr as *const _ as *const libc::sockaddr_in6);
                        let b = &*(addr as *const _ as *const libc::sockaddr_in6);
                        a.sin6_addr.s6_addr == b.sin6_addr.s6_addr && a.sin6_port == b.sin6_port
                    }
                    _ => false,
                }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_new() {
        let peer = Peer::with_associd(12345);
        assert_eq!(peer.associd, 12345);
        assert_eq!(peer.stratum, 16);
        assert_eq!(peer.leap, LeapIndicator::Alarm);
        assert!(!peer.reach.is_reachable());
    }

    #[test]
    fn test_peer_reachability() {
        let mut peer = Peer::with_associd(1);
        assert!(!peer.reach.is_reachable());
        peer.reach.record_success();
        assert!(peer.reach.is_reachable());
    }

    #[test]
    fn test_peer_default_params() {
        let peer = Peer::with_associd(42);
        assert_eq!(peer.minpoll, 4);
        assert_eq!(peer.maxpoll, 10);
        assert_eq!(peer.hpoll, 4);
        assert!(peer.dstadr.is_none());
        assert_eq!(peer.keyid, 0);
        assert_eq!(peer.flags, PeerFlags::NONE);
    }

    #[test]
    fn test_peer_table() {
        let mut table = PeerTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let p = Peer::with_associd(1);
        table.add(p);
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        let p2 = Peer::with_associd(2);
        table.add(p2);
        assert_eq!(table.len(), 2);

        table.remove(0);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_peer_is_sync() {
        let mut peer = Peer::with_associd(1);
        assert!(!peer.is_sync()); // stratum 16, not reachable

        peer.stratum = 4;
        assert!(!peer.is_sync()); // not reachable

        peer.reach.record_success();
        assert!(peer.is_sync()); // stratum < 16 and reachable
    }
}
