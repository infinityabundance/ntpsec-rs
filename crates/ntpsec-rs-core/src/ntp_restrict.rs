// ──── ntp_restrict.rs ───────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_restrict.c
//
// NTP access restriction lists: matching incoming packets against `restrict`
// directives and applying the appropriate access controls.
//
// ## Oracle
//   - ntpsec ntpd/ntp_restrict.c (17K)
//   - ntpsec include/ntp.h (restrict flags)
// =============================================================================

use crate::ntp_types::*;

bitflags::bitflags! {
    /// Restriction flags matching ntpsec's restrict flags.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct RestrictFlags: u32 {
        /// Default entry
        const NONE      = 0;
        /// Ignore all packets
        const IGNORE    = 1 << 0;
        /// No modification (queries)
        const NOMODIFY  = 1 << 1;
        /// No mobile = limit
        const NOMOBIL   = 1 << 2;
        /// No peer
        const NOPEER    = 1 << 3;
        /// No query
        const NOQUERY   = 1 << 4;
        /// No trap
        const NOTRAP    = 1 << 5;
        /// Notrust — don't trust this host for sync
        const NOTRUST   = 1 << 6;
        /// Limited — apply rate limiting
        const LIMITED   = 1 << 7;
        /// KoD — send kiss-o'-death
        const KOD       = 1 << 8;
        /// Low-priority
        const LOWPRI    = 1 << 9;
        /// Source-is-local
        const SOURCE    = 1 << 10;
        /// Flip — flip to v4/v6
        const FLIP      = 1 << 11;
        /// Server-response
        const SERVER    = 1 << 12;
        /// All packets
        const ALL      = 1 << 13;
        /// Version (mask version)
        const VERSION   = 1 << 14;
        /// Interface (mask interface)
        const INTERFACE = 1 << 15;
    }
}

/// A single restrict entry.
#[derive(Debug, Clone)]
pub struct RestrictEntry {
    pub addr: SockAddr,
    pub mask: SockAddr,
    pub flags: RestrictFlags,
    pub mru_depth: u32,
}

/// Restriction list.
#[derive(Debug, Default)]
pub struct RestrictList {
    entries: Vec<RestrictEntry>,
    default_v4_flags: RestrictFlags,
    default_v6_flags: RestrictFlags,
}

impl RestrictList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            default_v4_flags: RestrictFlags::empty(),
            default_v6_flags: RestrictFlags::empty(),
        }
    }

    pub fn add_entry(&mut self, entry: RestrictEntry) {
        self.entries.push(entry);
    }

    /// Set default restrictions for IPv4.
    pub fn set_default_v4(&mut self, flags: RestrictFlags) {
        self.default_v4_flags = flags;
    }

    /// Set default restrictions for IPv6.
    pub fn set_default_v6(&mut self, flags: RestrictFlags) {
        self.default_v6_flags = flags;
    }

    /// Evaluate restrictions for a given source address.
    pub fn evaluate(&self, addr: &SockAddr) -> RestrictFlags {
        let mut flags = RestrictFlags::empty();
        for entry in &self.entries {
            if self.addr_matches(addr, &entry.addr, &entry.mask) {
                flags |= entry.flags;
            }
        }
        // If no default entry matched, use default
        if flags.is_empty() {
            flags = self.default_v4_flags;
        }
        flags
    }

    /// Does an address match a restrict entry with the given mask?
    fn addr_matches(&self, addr: &SockAddr, restrict_addr: &SockAddr, mask: &SockAddr) -> bool {
        unsafe {
            if addr.ss_family != restrict_addr.ss_family {
                return false;
            }
            match addr.ss_family as libc::c_int {
                libc::AF_INET => {
                    let a = &*(addr as *const _ as *const libc::sockaddr_in);
                    let r = &*(restrict_addr as *const _ as *const libc::sockaddr_in);
                    let m = &*(mask as *const _ as *const libc::sockaddr_in);
                    (a.sin_addr.s_addr & m.sin_addr.s_addr)
                        == (r.sin_addr.s_addr & m.sin_addr.s_addr)
                }
                libc::AF_INET6 => {
                    let a = &*(addr as *const _ as *const libc::sockaddr_in6);
                    let r = &*(restrict_addr as *const _ as *const libc::sockaddr_in6);
                    let m = &*(mask as *const _ as *const libc::sockaddr_in6);
                    let a_bytes = a.sin6_addr.s6_addr;
                    let r_bytes = r.sin6_addr.s6_addr;
                    let m_bytes = m.sin6_addr.s6_addr;
                    a_bytes
                        .iter()
                        .zip(r_bytes.iter().zip(m_bytes.iter()))
                        .all(|(a, (r, m))| (a & m) == (r & m))
                }
                _ => false,
            }
        }
    }
}
