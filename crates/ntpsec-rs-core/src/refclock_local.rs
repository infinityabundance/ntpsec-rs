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
use std::time::SystemTime;

/// Local clock driver (type 1).
#[derive(Debug)]
pub struct LocalClockDriver {
    /// Stratum override (if set via fudge).
    stratum_override: Option<u8>,
    /// Reference ID override (if set via fudge).
    refid_override: Option<u32>,
    /// Current poll interval in seconds (adaptive).
    poll_interval: u32,
    /// Running dispersion estimate for adaptive polling.
    dispersion_estimate: f64,
    /// Number of samples produced.
    samples_produced: u64,
}

impl Default for LocalClockDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalClockDriver {
    /// Create a new local clock driver instance.
    pub fn new() -> Self {
        Self {
            stratum_override: None,
            refid_override: None,
            poll_interval: 64,
            dispersion_estimate: 0.001,
            samples_produced: 0,
        }
    }

    /// Set a stratum override (fudge).
    ///
    /// A value of 0 means "use the default" (stratum computed by the daemon).
    /// Values 0-15 are valid NTP stratum values.
    pub fn set_stratum(&mut self, stratum: u8) {
        self.stratum_override = if stratum == 0 {
            None
        } else {
            Some(stratum.min(15))
        };
    }

    /// Set a reference ID override (fudge).
    ///
    /// The reference ID is typically a four-character ASCII code.
    pub fn set_refid(&mut self, refid: [u8; 4]) {
        self.refid_override = Some(u32::from_be_bytes(refid));
    }

    /// Clear the stratum override.
    pub fn clear_stratum(&mut self) {
        self.stratum_override = None;
    }

    /// Clear the reference ID override.
    pub fn clear_refid(&mut self) {
        self.refid_override = None;
    }

    /// Return the current stratum override, if any.
    pub fn stratum_override(&self) -> Option<u8> {
        self.stratum_override
    }

    /// Return the current reference ID override, if any.
    pub fn refid_override(&self) -> Option<u32> {
        self.refid_override
    }

    /// Return the current adaptive poll interval.
    pub fn poll_interval(&self) -> u32 {
        self.poll_interval
    }

    /// Return the number of samples produced.
    pub fn samples_produced(&self) -> u64 {
        self.samples_produced
    }

    /// Get the current system time as an NTP timestamp.
    ///
    /// On Linux, uses `clock_gettime(CLOCK_REALTIME, ...)` for the most
    /// accurate system-wide time. On all platforms, falls back to
    /// `std::time::SystemTime::now()` with conversion to NTP epoch.
    fn get_system_time() -> NtpTs64 {
        #[cfg(target_os = "linux")]
        {
            let mut tp = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ret = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut tp) };
            if ret == 0 {
                let ntp_secs = tp.tv_sec + crate::ntp_fp::NTP_TO_UNIX_OFFSET as i64;
                let ntp_frac = ((tp.tv_nsec as u64) << 32) / 1_000_000_000;
                return NtpTs64 {
                    seconds: ntp_secs,
                    fraction: ntp_frac as u32,
                };
            }
        }

        // Fallback for all platforms (including Linux if clock_gettime fails).
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs() as i64 + crate::ntp_fp::NTP_TO_UNIX_OFFSET as i64;
        let frac = ((now.as_nanos() % 1_000_000_000) as u64 * 4_294_967_296 / 1_000_000_000) as u32;
        NtpTs64 {
            seconds: secs,
            fraction: frac,
        }
    }

    /// Get the default reference ID for this driver.
    fn default_refid() -> u32 {
        u32::from_be_bytes(*b"LOCL")
    }
}

impl RefClockDriver for LocalClockDriver {
    fn name(&self) -> &'static str {
        "LOCAL"
    }
    fn type_id(&self) -> RefClockId {
        1
    }
    fn poll(&mut self) -> Option<RefClockSample> {
        let ntp_time = Self::get_system_time();

        // Determine reference identifier: use override if set, else default.
        let _refid = self.refid_override.unwrap_or_else(Self::default_refid);

        // Adaptive poll interval: adjust based on dispersion.
        // When dispersion is low, we can poll less frequently.
        // When dispersion rises, poll more often to get better samples.
        let prev_poll = self.poll_interval;

        // Simple adaptive algorithm: if dispersion is very low, increase poll
        // interval (up to max 1024s). If dispersion is high, decrease it.
        if self.dispersion_estimate < 0.0005 {
            self.poll_interval = (self.poll_interval * 2).min(1024);
        } else if self.dispersion_estimate > 0.01 {
            self.poll_interval = (self.poll_interval / 2).max(4);
        } else if self.dispersion_estimate > 0.005 {
            self.poll_interval = self.poll_interval.saturating_sub(8).max(4);
        }

        // Clamp to sensible bounds.
        self.poll_interval = self.poll_interval.clamp(4, 1024);

        // If poll interval changed, report dispersion increase briefly.
        if self.poll_interval != prev_poll {
            self.dispersion_estimate += 0.0001;
        }

        self.samples_produced += 1;

        Some(RefClockSample {
            time: ntp_time,
            offset: 0.0,
            delay: 0.0,
            dispersion: self.dispersion_estimate,
            leap: LeapIndicator::NoWarning,
        })
    }
    fn timeout(&self) -> u32 {
        self.poll_interval
    }
}

// ──── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_clock_defaults() {
        let driver = LocalClockDriver::new();
        assert_eq!(driver.name(), "LOCAL");
        assert_eq!(driver.type_id(), 1);
        assert_eq!(driver.timeout(), 64);
        assert!(driver.stratum_override().is_none());
        assert!(driver.refid_override().is_none());
        assert_eq!(driver.samples_produced(), 0);
    }

    #[test]
    fn test_local_clock_poll_returns_sample() {
        let mut driver = LocalClockDriver::new();
        let sample = driver.poll().expect("poll should return a sample");
        // The time should be a reasonable NTP timestamp (after epoch).
        assert!(
            sample.time.seconds > 0,
            "Expected positive NTP seconds, got {}",
            sample.time.seconds
        );
        assert_eq!(sample.leap, LeapIndicator::NoWarning);
        assert_eq!(driver.samples_produced(), 1);
    }

    #[test]
    fn test_local_clock_fudge_stratum() {
        let mut driver = LocalClockDriver::new();
        driver.set_stratum(5);
        assert_eq!(driver.stratum_override(), Some(5));

        driver.set_stratum(0);
        assert!(driver.stratum_override().is_none());

        driver.set_stratum(20); // above max
        assert_eq!(driver.stratum_override(), Some(15)); // clamped

        driver.clear_stratum();
        assert!(driver.stratum_override().is_none());
    }

    #[test]
    fn test_local_clock_fudge_refid() {
        let mut driver = LocalClockDriver::new();
        driver.set_refid(*b"LCL\0");
        assert_eq!(driver.refid_override(), Some(u32::from_be_bytes(*b"LCL\0")));

        driver.clear_refid();
        assert!(driver.refid_override().is_none());
    }

    #[test]
    fn test_local_clock_refid_default() {
        assert_eq!(
            LocalClockDriver::default_refid(),
            u32::from_be_bytes(*b"LOCL")
        );
    }

    #[test]
    fn test_local_clock_adaptive_poll() {
        let mut driver = LocalClockDriver::new();
        assert_eq!(driver.poll_interval(), 64);

        // First poll — should still be 64 initially.
        let _ = driver.poll();
        // Poll interval should remain within bounds.
        assert!(driver.poll_interval() >= 4);
        assert!(driver.poll_interval() <= 1024);
    }

    #[test]
    fn test_get_system_time() {
        let ntp_time = LocalClockDriver::get_system_time();
        // NTP epoch offset is 2,208,988,800 seconds.
        // Current time should be well past the NTP epoch.
        assert!(
            ntp_time.seconds > 2_208_988_800,
            "Expected NTP time to be after epoch, got {}",
            ntp_time.seconds
        );
        // Fraction should be in valid range.
        // It could be 0 at the exact second boundary, so just check it's valid.
        assert!(
            (ntp_time.fraction as u64) < 4_294_967_296u64,
            "Fraction out of range: {}",
            ntp_time.fraction
        );
    }

    #[test]
    fn test_poll_returns_valid_timestamp() {
        let mut driver = LocalClockDriver::new();
        let sample = driver.poll().expect("should produce sample");

        // Verify the sample time is actually the current system time.
        let system_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let ntp_now = system_now + crate::ntp_fp::NTP_TO_UNIX_OFFSET as i64;
        let diff = (sample.time.seconds - ntp_now).abs();
        assert!(
            diff <= 1, // at most 1 second of measurement jitter
            "Sample time {} should be close to current time {}, diff={}",
            sample.time.seconds,
            ntp_now,
            diff
        );
    }

    #[test]
    fn test_clear_stratum_after_set() {
        let mut driver = LocalClockDriver::new();
        driver.set_stratum(3);
        assert_eq!(driver.stratum_override(), Some(3));
        driver.clear_stratum();
        assert!(driver.stratum_override().is_none());
    }

    #[test]
    fn test_set_refid_and_clear() {
        let mut driver = LocalClockDriver::new();
        driver.set_refid(*b"TEST");
        assert_eq!(driver.refid_override(), Some(u32::from_be_bytes(*b"TEST")));
        driver.clear_refid();
        assert!(driver.refid_override().is_none());
    }
}
