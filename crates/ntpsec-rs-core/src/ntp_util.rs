// ──── ntp_util.rs ───────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_util.c
//
// Utility functions: daemon initialization, statistics management, and
// ancillary helpers.
// =============================================================================

use crate::ntp_types::*;

/// Statistics counters matching ntpsec.
#[derive(Debug, Clone, Default)]
pub struct NtpStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub auth_errors: u64,
    pub rate_limited: u64,
    pub kissoflife_sent: u64,
    pub leap_announcements: u32,
}

/// System event type (matches ntpsec's `sys_events`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysEvent {
    PeerEvent = 1,
    AuthEvent = 2,
    ClockEvent = 3,
    SetEvent = 4,
    SysEvent = 5,
    UserEvent = 6,
    LockEvent = 7,
}

/// Initialize NTPSEC-specific system state.
pub fn ntp_init() {
    // Stub — will initialize random seed, signal handlers, syslog
}

/// Generate a (hopefully) unique reference ID for a server.
pub fn refid_from_addr(addr: &SockAddr) -> u32 {
    unsafe {
        match addr.ss_family as libc::c_int {
            libc::AF_INET => {
                let sin = &*(addr as *const _ as *const libc::sockaddr_in);
                sin.sin_addr.s_addr
            }
            _ => 0, // Will use hash of IPv6 address
        }
    }
}
