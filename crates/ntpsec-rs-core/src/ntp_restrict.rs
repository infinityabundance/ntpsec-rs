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

use crate::ntp_io::NetAddr;
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

    /// Evaluate restrictions for a given source address (SockAddr).
    ///
    /// Distinguishes "matched with empty flags" from "no match at all":
    /// if a specific entry matched (even with zero flags), do NOT fall
    /// back to the family default. This ensures that:
    ///
    ///   restrict 127.0.0.1
    ///
    /// allows all traffic from loopback without inheriting default KOD.
    pub fn evaluate(&self, addr: &SockAddr) -> RestrictFlags {
        let mut flags = RestrictFlags::empty();
        let mut matched = false;
        for entry in &self.entries {
            if self.addr_matches(addr, &entry.addr, &entry.mask) {
                flags |= entry.flags;
                matched = true;
            }
        }
        // Only fall back to defaults when NO specific entry matched
        if !matched {
            flags = match addr.ss_family as libc::c_int {
                libc::AF_INET6 => self.default_v6_flags,
                _ => self.default_v4_flags,
            };
        }
        flags
    }

    /// Evaluate restrictions for a NetAddr (from daemon_engine).
    /// Returns the action to take and the matching flags.
    /// NOQUERY is applied contextually based on packet mode:
    ///   - Mode 6 (NtpControl) and Mode 7 (Private) → Discard
    ///   - All other modes (Client, Server, SymActive, etc.) → Accept
    pub fn check(&self, addr: &NetAddr, mode: NtpMode) -> (RestrictAction, RestrictFlags) {
        let flags = self.evaluate(&netaddr_to_sockaddr(addr));

        if flags.contains(RestrictFlags::IGNORE) {
            return (RestrictAction::Ignore, flags);
        }
        if flags.contains(RestrictFlags::NOQUERY)
            && matches!(mode, NtpMode::NtpControl | NtpMode::Private)
        {
            return (RestrictAction::Discard, flags);
        }
        if flags.contains(RestrictFlags::KOD) {
            return (RestrictAction::SendKod, flags);
        }
        (RestrictAction::Accept, flags)
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

/// Actions the restrict system can take on a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestrictAction {
    /// Accept the packet for normal processing.
    Accept,
    /// Silently discard the packet.
    Discard,
    /// Discard with Kiss-o'-Death response.
    SendKod,
    /// Ignore completely (no response, no log).
    Ignore,
}

/// Convert a NetAddr to a libc sockaddr_storage for restrict evaluation.
pub fn netaddr_to_sockaddr(addr: &NetAddr) -> SockAddr {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp_io::NetAddr;

    #[test]
    fn test_restrict_default_v6_ignored_ipv6_accepted() {
        // Set default-v6 to IGNORE, default-v4 to empty (accept)
        let mut list = RestrictList::new();
        list.set_default_v6(RestrictFlags::IGNORE);
        list.set_default_v4(RestrictFlags::empty());

        // IPv6 address should be IGNORE'd
        let ipv6 = NetAddr::ipv6(
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            123,
        );
        let (action, _) = list.check(&ipv6, NtpMode::Client);
        assert_eq!(
            action,
            RestrictAction::Ignore,
            "IPv6 should be ignored with default-v6"
        );

        // IPv4 should be ACCEPT'd (default-v4 is empty)
        let ipv4 = NetAddr::ipv4(0x7f000001, 123);
        let (action, _) = list.check(&ipv4, NtpMode::Client);
        assert_eq!(
            action,
            RestrictAction::Accept,
            "IPv4 should be accepted with default-v4 empty"
        );
    }

    #[test]
    fn test_restrict_default_v4_ignored_ipv4_rejected() {
        let mut list = RestrictList::new();
        list.set_default_v4(RestrictFlags::IGNORE);
        list.set_default_v6(RestrictFlags::empty());

        // IPv4 should be IGNORE'd
        let ipv4 = NetAddr::ipv4(0x7f000001, 123);
        let (action, _) = list.check(&ipv4, NtpMode::Client);
        assert_eq!(
            action,
            RestrictAction::Ignore,
            "IPv4 should be ignored with default-v4"
        );

        // IPv6 should be ACCEPT'd
        let ipv6 = NetAddr::ipv6(
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            123,
        );
        let (action, _) = list.check(&ipv6, NtpMode::Client);
        assert_eq!(
            action,
            RestrictAction::Accept,
            "IPv6 should be accepted with default-v6 empty"
        );
    }

    #[test]
    fn test_restrict_loopback_allow_not_inheriting_default_kod() {
        // The exact oracle configuration:
        //   restrict -4 default kod limited nomodify notrap nopeer
        //   restrict 127.0.0.1
        //
        // The specific 127.0.0.1 entry has NO flags. It must NOT fall
        // back to the default KOD. Mode 6 queries from 127.0.0.1
        // must be ACCEPTed.
        let mut list = RestrictList::new();
        list.set_default_v4(
            RestrictFlags::KOD
                | RestrictFlags::LIMITED
                | RestrictFlags::NOMODIFY
                | RestrictFlags::NOTRAP
                | RestrictFlags::NOPEER,
        );
        // Add a specific loopback allow rule (no flags = full access)
        let loopback = NetAddr::ipv4(0x7f000001, 123);
        let mask = NetAddr::ipv4(0xffffffff, 0);
        let entry = RestrictEntry {
            addr: netaddr_to_sockaddr(&loopback),
            mask: netaddr_to_sockaddr(&mask),
            flags: RestrictFlags::empty(),
            mru_depth: 0,
        };
        list.add_entry(entry);

        // Mode 6 NtpControl from loopback must be ACCEPTed
        let (action, _) = list.check(&loopback, NtpMode::NtpControl);
        assert_eq!(
            action,
            RestrictAction::Accept,
            "loopback Mode 6 must be accepted, not KOD'd"
        );

        // Non-loopback IPv4 (e.g. 10.0.0.1) should still get default KOD
        let external = NetAddr::ipv4(0x0a000001, 123);
        let (action, _) = list.check(&external, NtpMode::NtpControl);
        assert_eq!(
            action,
            RestrictAction::SendKod,
            "external address should still receive default KOD"
        );

        // Mode 3 (Client) from external with KOD should still send KOD
        let (action, _) = list.check(&external, NtpMode::Client);
        assert_eq!(
            action,
            RestrictAction::SendKod,
            "external client with KOD should send KOD"
        );
    }

    #[test]
    fn test_restrict_noquery_context() {
        let mut list = RestrictList::new();
        list.set_default_v4(RestrictFlags::NOQUERY);
        let addr = NetAddr::ipv4(0x7f000001, 123);

        // Mode 3 (Client) — normal time service, should be ACCEPTed
        let (action, _) = list.check(&addr, NtpMode::Client);
        assert_eq!(
            action,
            RestrictAction::Accept,
            "mode 3 Client with NOQUERY should be accepted"
        );

        // Mode 4 (Server) — normal time service, should be ACCEPTed
        let (action, _) = list.check(&addr, NtpMode::Server);
        assert_eq!(
            action,
            RestrictAction::Accept,
            "mode 4 Server with NOQUERY should be accepted"
        );

        // Mode 6 (NtpControl) — control query, should be DISCARDed
        let (action, _) = list.check(&addr, NtpMode::NtpControl);
        assert_eq!(
            action,
            RestrictAction::Discard,
            "mode 6 NtpControl with NOQUERY should be discarded"
        );

        // Mode 7 (Private) — private query, should be DISCARDed
        let (action, _) = list.check(&addr, NtpMode::Private);
        assert_eq!(
            action,
            RestrictAction::Discard,
            "mode 7 Private with NOQUERY should be discarded"
        );
    }
}
