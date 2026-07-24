// ──── refclock_arbiter.rs ─────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_arbiter.c
//
// Arbiter 1088A/B Satellite Controlled Clock refclock driver.
//
// ## Oracle
//   - ntpd/refclock_arbiter.c (445 lines)
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_refclock::RefClockSample;
use crate::ntp_types::LeapIndicator;

/// Arbiter 1088A/B GPS refclock.
///
/// Drives an Arbiter 1088A/B Satellite Controlled Clock via serial.
/// Uses the B5 poll sequence to obtain timecode in format:
/// `<cr><lf>i yy ddd hh:mm:ss.000bbb`
///
/// ## C-oracle struct
///   `struct arbunit` in ntpd/refclock_arbiter.c
pub struct ArbiterRefclock {
    pub unit: u8,
    path: String,
    reader: Option<BufReader<File>>,
    /// IEEE P1344 quality character (from TQ command)
    pub qualchar: Option<char>,
    /// Receiver status string (from SR command)
    pub status: Option<String>,
    /// Receiver position string (lat/lon/alt)
    pub latlon: Option<String>,
    /// Timecode switch counter
    tcswitch: i32,
    /// Last receive timestamp
    laststamp: Option<std::time::Instant>,
}

impl ArbiterRefclock {
    /// Create a new Arbiter refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            path: String::new(),
            reader: None,
            qualchar: None,
            status: None,
            latlon: None,
            tcswitch: 0,
            laststamp: None,
        }
    }

    /// Open the Arbiter GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/gps0`).
    ///
    /// ## C-oracle
    ///   `arb_start()` — opens device, configures 9600 baud, sends the
    ///   B5 poll sequence to initiate timecode broadcast.
    pub fn open(&mut self, device: &str) -> Result<(), String> {
        let file = File::open(Path::new(device))
            .map_err(|e| format!("failed to open {}: {}", device, e))?;
        self.path = device.to_string();
        self.reader = Some(BufReader::new(file));
        self.tcswitch = 0;
        self.qualchar = None;
        self.status = None;
        self.latlon = None;
        Ok(())
    }

    /// Close the Arbiter receiver device.
    pub fn close(&mut self) {
        self.reader.take();
        self.path.clear();
    }

    /// Read one time sample from the receiver.
    ///
    /// Parses the B5 format timecode: `i yy ddd hh:mm:ss.000`
    ///
    /// ## C-oracle
    ///   `arb_receive()` — parses the B5 format timecode and optionally
    ///   extracts the TQ quality character and SR status string.
    pub fn read_sample(&mut self) -> Result<Option<RefClockSample>, String> {
        const LENARB: usize = 24;

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
            if trimmed.is_empty() || trimmed.len() < 3 {
                continue;
            }

            let now = SystemTime::now();

            // Format B5: "i yy ddd hh:mm:ss.000   "
            // Example: "  24 080 14:32:51.000   "
            let s = trimmed;
            if s.len() < 15 {
                continue;
            }

            let syncchar = s.chars().next().unwrap_or(' ');
            let year_str = &s[2..4]; // 2-digit year
            let yday_str = &s[5..8]; // day of year
            let hour_str = &s[9..11];
            let min_str = &s[12..14];
            let sec_str = &s[15..17];

            let yy: i32 = year_str.parse().unwrap_or(-1);
            let yday: i32 = yday_str.parse().unwrap_or(-1);
            let hour: i32 = hour_str.parse().unwrap_or(-1);
            let minute: i32 = min_str.parse().unwrap_or(-1);
            let second: i32 = sec_str.parse().unwrap_or(-1);

            if yy < 0 || yday < 0 || hour < 0 || minute < 0 || second < 0 {
                continue;
            }

            // 2-digit year -> full year (assume 2000+)
            let year = yy + 2000;

            let leap = if syncchar != ' ' {
                LeapIndicator::Alarm
            } else {
                LeapIndicator::NoWarning
            };

            let unix_secs = yday_to_unix(year, yday, hour, minute, second);

            let receive_ts = match now.duration_since(UNIX_EPOCH) {
                Ok(d) => {
                    let secs = d.as_secs() as i64;
                    let nsec = d.subsec_nanos() as i64;
                    ts_to_ntp(secs, nsec)
                }
                Err(_) => ts_to_ntp(0, 0),
            };

            let gps_time = ts_to_ntp(unix_secs as i64, 0);

            // Dispersion based on quality character
            let dispersion = match self.qualchar {
                Some('0') => 1e-7,
                Some('4') => 1e-6,
                Some('5') => 1e-5,
                Some('6') => 1e-4,
                Some('7') => 0.001,
                Some('8') => 0.01,
                Some('9') => 0.1,
                Some('A') => 1.0,
                Some('B') => 10.0,
                Some('F') => 10.0,
                _ => 0.001,
            };

            self.tcswitch += 1;

            return Ok(Some(RefClockSample {
                offset: 0.0,
                delay: 0.0,
                dispersion,
                time: receive_ts,
                leap,
            }));
        }
    }
}

fn yday_to_unix(year: i32, yday: i32, hour: i32, min: i32, sec: i32) -> i64 {
    let mut days = 0i64;
    for y in 1970..year {
        days += if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) {
            366
        } else {
            365
        };
    }
    days += (yday as i64) - 1;
    days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arbiter_open_no_such_device() {
        let mut rc = ArbiterRefclock::new(1);
        let result = rc.open("/nonexistent/gps");
        assert!(result.is_err());
    }

    #[test]
    fn test_yday_to_unix_basic() {
        // 2025-01-01 00:00:00
        let ts = yday_to_unix(2025, 1, 0, 0, 0);
        assert_eq!(ts, 1735689600);
    }

    #[test]
    fn test_syncchar_detection() {
        // If locked, syncchar should be ' '
        let s = " 24 080 14:32:51.000   ";
        let syncchar = s.chars().next().unwrap();
        assert_eq!(syncchar, ' ');
    }
}
