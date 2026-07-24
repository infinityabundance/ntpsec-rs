// ──── ntp_util.rs ───────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_util.c
//
// Utility functions: daemon initialization, statistics management, and
// ancillary helpers.
// =============================================================================

use crate::ntp_types::*;
use digest::Digest;
use getrandom::getrandom;

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
    // Initialize the random seed from system entropy
    let mut seed = [0u8; 32];
    if getrandom(&mut seed).is_ok() {
        // Seed initialized
    }
    // Signal handlers are initialized by the shell (main.rs)
    // Syslog is initialized by the shell (main.rs)
}

/// Generate a (hopefully) unique reference ID for a server.
pub fn refid_from_addr(addr: &SockAddr) -> u32 {
    unsafe {
        match addr.ss_family as libc::c_int {
            libc::AF_INET => {
                let sin = &*(addr as *const _ as *const libc::sockaddr_in);
                sin.sin_addr.s_addr
            }
            6 => {
                // NTPsec uses MD5 hash of IPv6 address, first 4 bytes
                let sin6 = &*(addr as *const _ as *const libc::sockaddr_in6);
                let addr_bytes = sin6.sin6_addr.s6_addr;
                let mut hasher = md5::Md5::new();
                hasher.update(&addr_bytes[..16]);
                let result = hasher.finalize();
                u32::from_ne_bytes([result[0], result[1], result[2], result[3]])
            }
            _ => 0,
        }
    }
}
