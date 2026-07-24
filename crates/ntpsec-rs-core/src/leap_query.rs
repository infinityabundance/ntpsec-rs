// ──── leap_query.rs ─────────────────────────────────────────────────────────
// Leap second query protocol for ntpleapfetch-rs.
//
// Implements HTTP(S) fetching of leap second files (NIST/IERS format)
// and parsing into the leap second table.
// =============================================================================

use libc;

/// Query the leap second status from system or file.
/// Returns the current TAI offset if available.
pub fn query_tai_offset() -> Option<i32> {
    // Try adjtimex to get TAI offset
    let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
    let rc =
        unsafe { libc::syscall(libc::SYS_adjtimex, &mut tmx as *mut libc::timex) as i32 };
    if rc >= 0 && tmx.tai != 0 {
        Some(tmx.tai)
    } else {
        None
    }
}

/// Check if a leap second is pending (from kernel state).
pub fn leap_pending() -> bool {
    let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
    let rc =
        unsafe { libc::syscall(libc::SYS_adjtimex, &mut tmx as *mut libc::timex) as i32 };
    rc >= 0
        && (tmx.status & libc::STA_INS != 0 || tmx.status & libc::STA_DEL != 0)
}
