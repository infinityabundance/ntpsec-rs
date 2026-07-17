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
        // Local clock always returns zero offset
        Some(RefClockSample {
            offset: 0.0,
            delay: 0.0,
            dispersion: 0.001, // 1 ms dispersion
            time: NtpTs64 {
                seconds: 0,
                fraction: 0,
            }, // filled by caller
            leap: LeapIndicator::NoWarning,
        })
    }
    fn timeout(&self) -> u32 {
        64
    } // poll every 64 seconds
}
