// ──── refclock_pps_api.rs ───────────────────────────────────────────────────
// Forensic reconstruction of include/refclock_pps.h
//
// PPS API declarations for refclock drivers.
// =============================================================================

/// Check if the kernel PPS API is available on this system.
pub fn pps_api_available() -> bool {
    std::path::Path::new("/dev/pps0").exists()
}
