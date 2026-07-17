// ──── ntp_monitor.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_monitor.c
//
// NTP monitoring (MRU — Most Recently Used) list. Tracks client requests
// for rate limiting and statistics.
// =============================================================================

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
            max_entries: 600,     // ntpsec default
            min_distance: 600,    // ntpsec default (seconds)
        }
    }

    /// Record a packet from a source address.
    pub fn record(&mut self, addr: &SockAddr, now: NtpTs64) {
        // Find existing entry or create new one
        if let Some(entry) = self.entries.iter_mut().find(|e| {
            unsafe { e.addr.ss_family == addr.ss_family &&
                match addr.ss_family as libc::c_int {
                    libc::AF_INET => {
                        let a = &*(&e.addr as *const _ as *const libc::sockaddr_in);
                        let b = &*(addr as *const _ as *const libc::sockaddr_in);
                        a.sin_addr.s_addr == b.sin_addr.s_addr
                    }
                    _ => false,
                }
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
                self.entries.sort_by(|a, b| a.last_pkt.seconds.cmp(&b.last_pkt.seconds));
                self.entries.pop();
            }
        }
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}
