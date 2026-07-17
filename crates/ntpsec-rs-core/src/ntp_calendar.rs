// ──── ntp_calendar.rs ───────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_calendar.h and libntp/ntp_calendar.c
//
// Gregorian calendar computations used by NTP for timestamp printing and
// leap-second table processing.
//
// ## Oracle
//   - ntpsec include/ntp_calendar.h
//   - ntpsec libntp/ntp_calendar.c
//
// ## Court
//   - docs/courts/ntp_calendar.md
// =============================================================================

use crate::ntp_types::*;

/// Days in each month (non-leap year).
pub const DAYS_PER_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Days in each month (leap year).
pub const DAYS_PER_MONTH_LEAP: [u32; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Is the given year a leap year?
pub const fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Convert month/day to day-of-year (1-based).
pub fn ymd_to_yd(y: i64, m: u32, d: u32) -> u32 {
    let month_table = if is_leap_year(y) {
        &DAYS_PER_MONTH_LEAP
    } else {
        &DAYS_PER_MONTH
    };
    let mut doy = d;
    for i in 0..(m - 1) {
        doy += month_table[i as usize];
    }
    doy
}

/// Convert day-of-year to month/day (1-based).
pub fn yd_to_ymd(y: i64, yd: u32) -> (u32, u32) {
    let month_table = if is_leap_year(y) {
        &DAYS_PER_MONTH_LEAP
    } else {
        &DAYS_PER_MONTH
    };
    let mut remaining = yd;
    for (i, &days_in_month) in month_table.iter().enumerate() {
        if remaining <= days_in_month {
            return ((i + 1) as u32, remaining);
        }
        remaining -= days_in_month;
    }
    (12, 31)
}

/// NTP calendar date structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpCalendar {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub weekday: u32,
}

impl NtpCalendar {
    /// Create from NTP timestamp.
    pub fn from_ntp(ts: NtpTs64) -> Self {
        let (secs, _) = crate::ntp_fp::ntp_to_ts(ts);
        let (y, m, d) = crate::ntp_fp::unix_seconds_to_ymd(secs);
        let (hh, mm, ss) = crate::ntp_fp::unix_seconds_to_hms(secs);

        // Weekday: 0=Sunday, 6=Saturday
        let days_since_epoch = if secs >= 0 {
            secs / 86400
        } else {
            (secs - 86399) / 86400
        };
        // Unix epoch (1970-01-01) was a Thursday
        let weekday = ((days_since_epoch + 4) % 7 + 7) % 7;

        Self {
            year: y,
            month: m,
            day: d,
            hour: hh,
            minute: mm,
            second: ss,
            weekday: weekday as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leap_year() {
        assert!(is_leap_year(2000));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn test_ymd_to_yd() {
        assert_eq!(ymd_to_yd(2023, 1, 1), 1);
        assert_eq!(ymd_to_yd(2023, 12, 31), 365);
        assert_eq!(ymd_to_yd(2024, 12, 31), 366);
    }

    #[test]
    fn test_yd_to_ymd() {
        assert_eq!(yd_to_ymd(2023, 1), (1, 1));
        assert_eq!(yd_to_ymd(2023, 365), (12, 31));
    }

    #[test]
    fn test_calendar_from_ntp() {
        let ts = crate::ntp_fp::ts_to_ntp(0, 0);
        let cal = NtpCalendar::from_ntp(ts);
        assert_eq!(cal.year, 1970);
        assert_eq!(cal.month, 1);
        assert_eq!(cal.day, 1);
        assert_eq!(cal.hour, 0);
        assert_eq!(cal.minute, 0);
        assert_eq!(cal.second, 0);
    }
}
