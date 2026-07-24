// ──── ntp_syscall.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_syscall.h
//
// System call wrapper types for clock_gettime, adjtimex, etc.
// =============================================================================

use libc;

/// Wrapper for the adjtimex/ntp_adjtime syscall.
/// Returns the current kernel time state or sets new parameters.
pub fn ntp_adjtime(buf: &mut libc::timex) -> Result<i32, String> {
    let rc = unsafe { libc::syscall(libc::SYS_adjtimex, buf as *mut libc::timex) as i32 };
    if rc < 0 {
        Err(format!(
            "adjtimex failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(rc)
    }
}

/// Get the current kernel time status via adjtimex with no changes.
pub fn ntp_gettime() -> Result<libc::timex, String> {
    let mut buf: libc::timex = unsafe { std::mem::zeroed() };
    ntp_adjtime(&mut buf)?;
    Ok(buf)
}
