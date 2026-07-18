// ──── ntp_monitor.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_monitor.c
//
// NTP monitoring (MRU — Most Recently Used) list. Tracks client requests
// for rate limiting and statistics.
// =============================================================================

use crate::ntp_io::NetAddr;
use crate::ntp_types::*;

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
}

impl MonList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 600,  // ntpsec default
            min_distance: 600, // ntpsec default (seconds)
        }
    }

    /// Record a packet from a source address.
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
            // Prune if over limit
            if self.entries.len() > self.max_entries as usize {
                self.entries
                    .sort_by(|a, b| a.last_pkt.seconds.cmp(&b.last_pkt.seconds));
                self.entries.pop();
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
                    _ => false,
                }
        }) {
            // Basic rate limiting: if more than 10 packets in the min_distance window
            (entry.count > 10, entry.count)
        } else {
            (false, 0)
        }
    }
}

/// Convert a NetAddr to a libc sockaddr_storage for MRU matching.
fn netaddr_to_sockaddr(addr: &NetAddr) -> SockAddr {
    let mut ss: SockAddr = unsafe { std::mem::zeroed() };
    match addr.family {
        4 => {
            let sin = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = addr.port.to_be();
            let octets = [addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3]];
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(octets),
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
