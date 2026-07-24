// ──── refclock_local.rs ─────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_local.c
//
// Local clock refclock driver (127.127.1.0). Used as a fallback when no
// external time source is available.
//
// ## Oracle
//   - ntpsec ntpd/refclock_local.c (6K)
// =============================================================================

use crate::ntp_refclock::{RefClockDriver, RefClockId, RefClockSample};
use crate::ntp_types::*;

/// Local clock driver (type 1).
#[derive(Debug)]
pub struct LocalClockDriver;

impl RefClockDriver for LocalClockDriver {
    fn name(&self) -> &'static str {
        "LOCAL"
    }
    fn type_id(&self) -> RefClockId {
        1
    }
    fn poll(&mut self) -> Option<RefClockSample> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs() as i64 - 2208988800i64; // NTP epoch offset
        let frac = ((now.as_nanos() % 1_000_000_000) as u64 * 4_294_967_296 / 1_000_000_000) as u32;
        Some(RefClockSample {
            time: crate::ntp_types::NtpTs64 {
                seconds: secs,
                fraction: frac,
            },
            offset: 0.0,
            delay: 0.0,
            dispersion: 0.001,
            leap: crate::ntp_types::LeapIndicator::NoWarning,
        })
    }
    fn timeout(&self) -> u32 {
        64
    } // poll every 64 seconds
}
