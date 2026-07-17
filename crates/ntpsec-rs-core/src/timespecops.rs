// ──── timespecops.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of include/timespecops.h, libntp/timespecops.c
//
// Timespec arithmetic operations: addition, subtraction, comparison,
// conversion to/from NTP fixed-point.
// =============================================================================

use crate::ntp_types::*;

/// A timespec with ns precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpTimespec {
    pub seconds: i64,
    pub nanos: i64,
}

impl NtpTimespec {
    pub fn new(secs: i64, nanos: i64) -> Self {
        let mut ts = Self { seconds: secs, nanos };
        ts.normalize();
        ts
    }

    fn normalize(&mut self) {
        const NS_PER_SEC: i64 = 1_000_000_000;
        if self.nanos >= NS_PER_SEC || self.nanos <= -NS_PER_SEC {
            self.seconds += self.nanos / NS_PER_SEC;
            self.nanos = self.nanos % NS_PER_SEC;
        }
        if self.seconds > 0 && self.nanos < 0 {
            self.seconds -= 1;
            self.nanos += NS_PER_SEC;
        } else if self.seconds < 0 && self.nanos > 0 {
            self.seconds += 1;
            self.nanos -= NS_PER_SEC;
        }
    }

    pub fn add(&self, other: &NtpTimespec) -> Self {
        let mut ts = Self {
            seconds: self.seconds + other.seconds,
            nanos: self.nanos + other.nanos,
        };
        ts.normalize();
        ts
    }

    pub fn sub(&self, other: &NtpTimespec) -> Self {
        let mut ts = Self {
            seconds: self.seconds - other.seconds,
            nanos: self.nanos - other.nanos,
        };
        ts.normalize();
        ts
    }

    pub fn cmp(&self, other: &NtpTimespec) -> std::cmp::Ordering {
        match self.seconds.cmp(&other.seconds) {
            std::cmp::Ordering::Equal => self.nanos.cmp(&other.nanos),
            ord => ord,
        }
    }

    /// Convert to NTP l_fp.
    pub fn to_ntp(&self) -> NtpTs64 {
        crate::ntp_fp::ts_to_ntp(self.seconds, self.nanos)
    }

    /// Convert from NTP l_fp.
    pub fn from_ntp(ts: NtpTs64) -> Self {
        let (secs, nsec) = crate::ntp_fp::ntp_to_ts(ts);
        Self::new(secs, nsec)
    }
}
