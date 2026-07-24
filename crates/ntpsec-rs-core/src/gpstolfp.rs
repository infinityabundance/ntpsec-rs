// ──── gpstolfp.rs ───────────────────────────────────────────────────────────
// Forensic reconstruction of include/gpstolfp.h, libparse/gpstolfp.c
//
// GPS-to-NTP timestamp conversion utilities.
// =============================================================================

use crate::ntp_types::NtpTs64;

/// Convert GPS time (seconds since 1980-01-06) to NTP timestamp.
/// GPS epoch offset from NTP epoch: 315964800 seconds.
const GPS_EPOCH_OFFSET: i64 = 315964800;

pub fn gps_to_ntp(gps_secs: i64, gps_nsecs: i64) -> NtpTs64 {
    let ntp_secs = gps_secs - GPS_EPOCH_OFFSET;
    let fraction = if gps_nsecs >= 0 {
        (gps_nsecs as u64 * 4_294_967_296 / 1_000_000_000) as u32
    } else {
        0
    };
    NtpTs64 {
        seconds: ntp_secs,
        fraction,
    }
}

pub fn ntp_to_gps(ntp: NtpTs64) -> (i64, i64) {
    let gps_secs = ntp.seconds + GPS_EPOCH_OFFSET;
    let gps_nsecs = (ntp.fraction as u64 * 1_000_000_000 / 4_294_967_296) as i64;
    (gps_secs, gps_nsecs)
}
