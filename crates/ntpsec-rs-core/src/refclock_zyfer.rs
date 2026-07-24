// ──── refclock_zyfer.rs ───────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_zyfer.c
//
// Zyfer GPStarplus GPS receiver refclock driver.
//
// ## Oracle
//   - ntpd/refclock_zyfer.c (301 lines)
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_refclock::RefClockSample;
use crate::ntp_types::LeapIndicator;

/// Zyfer GPStarplus refclock.
///
/// Drives a Zyfer GPStarplus clock via its TOD serial port. The clock
/// sends one timecode per second in the format:
/// `!TIME,YYYY,DDD,HH,MM,SS,m,T,O<CR>`
/// where `!` is the on-time character, `m` is time mode, `T` is time
/// figure of merit, and `O` is operation mode.
///
/// ## C-oracle struct
///   `struct zyferunit` in ntpd/refclock_zyfer.c
pub struct ZyferRefclock {
    pub unit: u8,
    path: String,
    reader: Option<BufReader<File>>,
    polled: u8,
    pollcnt: i32,
}

impl ZyferRefclock {
    /// Create a new Zyfer refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            path: String::new(),
            reader: None,
            polled: 0,
            pollcnt: 2,
        }
    }

    /// Open the Zyfer GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/zyfer0`).
    /// The clock runs at 9600 baud 8N1.
    ///
    /// ## C-oracle
    ///   `zyfer_start()` — opens device, configures 9600 baud 8N1.
    pub fn open(&mut self, device: &str) -> Result<(), String> {
        let file = File::open(Path::new(device))
            .map_err(|e| format!("failed to open {}: {}", device, e))?;
        self.path = device.to_string();
        self.reader = Some(BufReader::new(file));
        self.pollcnt = 2;
        self.polled = 0;
        Ok(())
    }

    /// Close the Zyfer receiver device.
    pub fn close(&mut self) {
        self.reader.take();
        self.path.clear();
    }

    /// Read and decode one time sample from the receiver.
    ///
    /// Parses the `!TIME,YYYY,DDD,HH,MM,SS,m,T,O` timecode.
    /// Validates: time mode must be 2 (UTC), operation mode should be 1 (locked).
    ///
    /// ## C-oracle
    ///   `zyfer_receive()` — parses the timecode, validates tmode and omode.
    pub fn read_sample(&mut self) -> Result<Option<RefClockSample>, String> {
        const LENZYFER: usize = 29;

        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => return Err("device not open".to_string()),
        };

        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = reader
                .read_line(&mut line)
                .map_err(|e| format!("read error: {}", e))?;

            if bytes_read == 0 {
                return Ok(None);
            }

            let trimmed = line.trim();
            if trimmed.len() < LENZYFER {
                continue;
            }

            let now = SystemTime::now();

            // Format: !TIME,YYYY,DDD,HH,MM,SS,m,T,O
            // Example: !TIME,2002,017,07,59,32,2,4,1
            let parts: Vec<&str> = trimmed.split(',').collect();
            if parts.len() != 9 || parts[0] != "!TIME" {
                continue;
            }

            let _year: i32 = parts[1].parse().map_err(|_| "bad year")?;
            let yday: i32 = parts[2].parse().map_err(|_| "bad yday")?;
            let hour: i32 = parts[3].parse().map_err(|_| "bad hour")?;
            let minute: i32 = parts[4].parse().map_err(|_| "bad minute")?;
            let second: i32 = parts[5].parse().map_err(|_| "bad second")?;
            let tmode: i32 = parts[6].parse().map_err(|_| "bad tmode")?;
            let _tfom: i32 = parts[7].parse().map_err(|_| "bad tfom")?;
            let omode: i32 = parts[8].parse().map_err(|_| "bad omode")?;

            // Time mode must be 2 (UTC)
            if tmode != 2 {
                // Not UTC, skip
                continue;
            }

            // Determine leap status based on operation mode
            // 1 = Time Locked, others are not in sync
            let leap = if omode != 1 {
                LeapIndicator::Alarm
            } else {
                LeapIndicator::NoWarning
            };

            // Convert to Unix timestamp approximately
            // We add 1900 to get a full year for the C time APIs
            // Actually the year is just the last digits, but since it's the
            // full year in the format, let's parse it that way
            let unix_secs = yday_to_unix_approx(_year, yday, hour, minute, second);

            let receive_ts = match now.duration_since(UNIX_EPOCH) {
                Ok(d) => {
                    let secs = d.as_secs() as i64;
                    let nsec = d.subsec_nanos() as i64;
                    ts_to_ntp(secs, nsec)
                }
                Err(_) => ts_to_ntp(0, 0),
            };

            let gps_time = ts_to_ntp(unix_secs as i64, 0);

            return Ok(Some(RefClockSample {
                offset: 0.0,
                delay: 0.0,
                dispersion: if omode == 1 { 0.001 } else { 1.0 },
                time: receive_ts,
                leap,
            }));
        }
    }
}

/// Convert year and day-of-year (1-based) plus time to approximate Unix timestamp.
fn yday_to_unix_approx(year: i32, yday: i32, hour: i32, min: i32, sec: i32) -> i64 {
    // Calculate days since 1970-01-01 = yday + days_in_prior_years + day_offset
    let mut days = 0i64;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    // yday is 1-based day of year
    days += (yday as i64) - 1;
    days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64)
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zyfer_open_no_such_device() {
        let mut rc = ZyferRefclock::new(1);
        let result = rc.open("/nonexistent/zyfer");
        assert!(result.is_err());
    }

    #[test]
    fn test_yday_to_unix() {
        // 2024-01-01 00:00:00 = 1704067200
        let ts = yday_to_unix_approx(2024, 1, 0, 0, 0);
        assert_eq!(ts, 1704067200);

        // 2024-12-31 23:59:59
        let ts = yday_to_unix_approx(2024, 366, 23, 59, 59);
        assert!(ts > 1704067200);
    }

    #[test]
    fn test_leap_year() {
        assert!(is_leap(2024));
        assert!(!is_leap(2023));
        assert!(!is_leap(1900));
        assert!(is_leap(2000));
    }
}
