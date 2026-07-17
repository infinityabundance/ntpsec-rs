// ──── ntp_fp.rs ─────────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_fp.h and libntp/dolfptoa.c
//
// Fixed-point NTP timestamp arithmetic: conversion between NTP time (32.32
// fixed-point), system time (timespec/timeval), and printable string forms.
//
// ## Oracle
//   - ntpsec include/ntp_fp.h, libntp/dolfptoa.c, libntp/prettydate.c
//   - RFC 5905 §6 (timestamp format), §9.2 (clock filter arithmetic)
//   - NIST SP 800-167 §6.1.1
//
// ## Court
//   - docs/courts/ntp_fp.md — conversion round-trips, ntpsec's `dolfptoa`
//     format string parity, `prettydate` output format matching.
// =============================================================================

use crate::ntp_types::*;

/// NTP-era offset in seconds from the Unix epoch.
/// This is the classic 2_208_988_800 offset (years 1900→1970).
pub const NTP_TO_UNIX_OFFSET: u32 = 2_208_988_800;

/// Convert a `timeval` (seconds + microseconds) to an NTP timestamp (l_fp).
pub fn tv_to_ntp(secs: i64, usec: i64) -> NtpTs64 {
    let ntp_secs = if secs >= 0 {
        secs + NTP_TO_UNIX_OFFSET as i64
    } else {
        secs + NTP_TO_UNIX_OFFSET as i64 - 1
    };
    // Convert microseconds to NTP fraction (2^32 per second)
    let frac = if usec >= 0 {
        ((usec as u64) << 32) / 1_000_000
    } else {
        let pos_usec = (-usec) as u64;
        ((pos_usec << 32) / 1_000_000).wrapping_neg()
    };
    NtpTs64 {
        seconds: ntp_secs,
        fraction: frac as u32,
    }
}

/// Convert a `timespec` (seconds + nanoseconds) to an NTP timestamp (l_fp).
pub fn ts_to_ntp(secs: i64, nsec: i64) -> NtpTs64 {
    let ntp_secs = if secs >= 0 {
        secs + NTP_TO_UNIX_OFFSET as i64
    } else {
        secs + NTP_TO_UNIX_OFFSET as i64 - 1
    };
    let frac = if nsec >= 0 {
        ((nsec as u64) << 32) / 1_000_000_000
    } else {
        ((nsec.unsigned_abs() << 32) / 1_000_000_000).wrapping_neg()
    };
    NtpTs64 {
        seconds: ntp_secs,
        fraction: frac as u32,
    }
}

/// Convert an NTP timestamp (l_fp) to a `timespec` (seconds + nanoseconds).
pub fn ntp_to_ts(ntp: NtpTs64) -> (i64, i64) {
    let secs = ntp.seconds - NTP_TO_UNIX_OFFSET as i64;
    let nsec = ((ntp.fraction as u64) * 1_000_000_000) >> 32;
    (secs, nsec as i64)
}

/// Convert an NTP timestamp (l_fp) to a `timeval` (seconds + microseconds).
pub fn ntp_to_tv(ntp: NtpTs64) -> (i64, i64) {
    let secs = ntp.seconds - NTP_TO_UNIX_OFFSET as i64;
    let usec = ((ntp.fraction as u64) * 1_000_000) >> 32;
    (secs, usec as i64)
}

/// Format an NTP timestamp as a string, matching ntpsec's `dolfptoa` output.
///
/// The format is: `[-]seconds.fraction` where fraction is zero-padded to
/// `frac_digits` places (default 6).
pub fn dolfptoa(ntp: NtpTs64, frac_digits: u32) -> String {
    let mut secs = ntp.seconds;
    let mut frac = ntp.fraction as u64;

    let negative = secs < 0;
    if negative {
        secs = -secs;
        if ntp.fraction != 0 {
            // Borrow from fraction
            secs -= 1;
            frac = NTP_FRAC_PER_SEC as u64 - frac;
        }
    }

    // Scale fraction to desired digits
    let divisor = 1_000_000u64.max(10u64.pow(frac_digits.min(9)));
    let scaled_frac = (frac * divisor) >> 32;

    if negative {
        format!(
            "-{}.{:0width$}",
            secs,
            scaled_frac,
            width = frac_digits as usize
        )
    } else {
        format!(
            "{}.{:0width$}",
            secs,
            scaled_frac,
            width = frac_digits as usize
        )
    }
}

/// Format an NTP timestamp as a human-readable date in ntpsec's style.
/// Matches ntpsec's `prettydate()` output format.
pub fn prettydate(ntp: NtpTs64) -> String {
    let (secs, _nsec) = ntp_to_ts(ntp);
    // Use chrono-like format (without pulling in chrono):
    // We implement a simple Gregorian calendar date breakdown.
    let (y, m, d) = unix_seconds_to_ymd(secs);
    let (hh, mm, ss) = unix_seconds_to_hms(secs);
    format!("{:04} {:02} {:02} {:02}:{:02}:{:02}", y, m, d, hh, mm, ss)
}

/// Break down Unix seconds into Gregorian year/month/day.
pub fn unix_seconds_to_ymd(secs: i64) -> (i64, u32, u32) {
    // Days since Unix epoch
    let days = if secs >= 0 {
        secs / 86400
    } else {
        (secs - 86399) / 86400
    };
    civil_from_days(days)
}

/// Break down Unix seconds into hours/minutes/seconds.
pub fn unix_seconds_to_hms(secs: i64) -> (u32, u32, u32) {
    let s = if secs >= 0 {
        secs % 86400
    } else {
        86400 - ((-secs) % 86400)
    };
    let hh = (s / 3600) as u32;
    let mm = ((s % 3600) / 60) as u32;
    let ss = (s % 60) as u32;
    (hh, mm, ss)
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day).
/// Uses the civil-from-days algorithm (Howard Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d as u32)
}

/// Convert NTP short format to double.
pub fn ntp_short_to_double(s: NtpShort) -> f64 {
    s.seconds as f64 + s.fraction as f64 / 65536.0
}

/// Convert NTP timestamp to double (seconds).
pub fn ntp_ts_to_double(ts: NtpTs) -> f64 {
    ts.seconds as f64 + ts.fraction as f64 / NTP_FRAC_PER_SEC as f64
}

/// Convert NTP 64-bit signed timestamp to double.
pub fn ntp_ts64_to_double(ts: NtpTs64) -> f64 {
    ts.seconds as f64 + ts.fraction as f64 / NTP_FRAC_PER_SEC as f64
}

/// Convert NTP 64-bit timestamp to the on-wire 32.32 NtpTs format.
pub fn ntp_ts64_to_ntpts(ts: NtpTs64) -> NtpTs {
    NtpTs {
        seconds: ts.seconds as u32,
        fraction: ts.fraction,
    }
}

// ──── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_to_unix_roundtrip() {
        let unix_secs: i64 = 1_700_000_000;
        let ntp = ts_to_ntp(unix_secs, 0);
        let (rt_secs, rt_nsec) = ntp_to_ts(ntp);
        assert_eq!(rt_secs, unix_secs);
        assert_eq!(rt_nsec, 0);
    }

    #[test]
    fn test_ntp_epoch_to_unix() {
        // NTP epoch = 1900-01-01 00:00:00 = Unix -2208988800
        let ntp = NtpTs64 {
            seconds: 0,
            fraction: 0,
        };
        let (secs, _) = ntp_to_ts(ntp);
        assert_eq!(secs, -(NTP_TO_UNIX_OFFSET as i64));
    }

    #[test]
    fn test_dolfptoa() {
        let ntp = NtpTs64 {
            seconds: 1_234_567,
            fraction: 0,
        };
        let s = dolfptoa(ntp, 6);
        assert!(s.starts_with("1234567.0"));
    }

    #[test]
    fn test_prettydate() {
        // Unix epoch = 1970-01-01 00:00:00
        let ntp = ts_to_ntp(0, 0);
        let s = prettydate(ntp);
        assert!(s.contains("1970"));
        assert!(s.contains("01 01"));
    }

    #[test]
    fn test_civil_from_days() {
        // Unix epoch day 0 = 1970-01-01
        let (y, m, d) = civil_from_days(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_readable_date() {
        let (y, m, d) = unix_seconds_to_ymd(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_tv_to_ntp() {
        let ntp = tv_to_ntp(0, 500_000);
        assert_eq!((ntp.seconds - NTP_TO_UNIX_OFFSET as i64), 0);
        assert!(ntp.fraction > 0);
    }
}
