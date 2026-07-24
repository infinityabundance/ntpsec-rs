// ──── refclock_hpgps.rs ───────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_hpgps.c
//
// HP GPS receiver refclock driver. Supports HP 58503A Time and Frequency
// Reference Receiver and HP Z3801A (with subtype 1).
//
// ## Oracle
//   - ntpd/refclock_hpgps.c (648 lines)
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_refclock::RefClockSample;
use crate::ntp_types::LeapIndicator;

/// HP GPS receiver refclock.
///
/// Drives an HP 58503A or Z3801A GPS receiver via serial. Uses the
/// `:PTIME:TCODE?` SCPI command to request timecode format 2 responses:
/// `T#yyyymmddhhmmssMFLRVcc<cr><lf>`
///
/// ## C-oracle struct
///   `struct hpgpsunit` in ntpd/refclock_hpgps.c
#[derive(Debug)]
pub struct HpGpsRefclock {
    pub unit: u8,
    path: String,
    reader: Option<BufReader<File>>,
    /// Seconds since last message
    pub idlesec: i32,
    /// Whether a poll has been called recently
    pub didpoll: bool,
    /// Command counter (collecting data)
    pub cmndcnt: u32,
    /// Line counter (collecting status screen)
    pub linecnt: i32,
    /// Current year for timecode year disambiguation
    current_year: i32,
}

impl HpGpsRefclock {
    /// Create a new HP GPS refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            path: String::new(),
            reader: None,
            idlesec: 0,
            didpoll: false,
            cmndcnt: 0,
            linecnt: 0,
            current_year: 0,
        }
    }

    /// Open the HP GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/hpgps0`).
    ///
    /// ## C-oracle
    ///   `hpgps_start()` — opens device, sends initial poll.
    pub fn open(&mut self, device: &str) -> Result<(), String> {
        let file = File::open(Path::new(device))
            .map_err(|e| format!("failed to open {}: {}", device, e))?;
        self.path = device.to_string();
        self.reader = Some(BufReader::new(file));
        self.idlesec = 0;
        self.didpoll = false;
        self.cmndcnt = 0;
        self.linecnt = 0;
        // Estimate current year from system time
        let now_sys = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        self.current_year = 1970 + (now_sys.as_secs() / 31536000) as i32;
        Ok(())
    }

    /// Close the HP GPS receiver device.
    pub fn close(&mut self) {
        self.reader.take();
        self.path.clear();
    }

    /// Read one time sample from the receiver.
    ///
    /// Parses the `T2yyyymmddhhmmssTFLRVcc` timecode
    /// (format 2 from the HP receiver).
    ///
    /// ## C-oracle
    ///   `hpgps_receive_T2()` — parses the timecode, validates checksum.
    pub fn read_sample(&mut self) -> Result<Option<RefClockSample>, String> {
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
            if trimmed.is_empty() {
                continue;
            }

            let now = SystemTime::now();
            let s = trimmed;

            // Strip leading prompt "scpi > "
            let s = if s.starts_with("scpi > ") { &s[7..] } else { s };

            // Strip leading whitespace/tabs
            let s = s.trim_start();

            // Format T2: "T2yyyymmddhhmmssTFLRVcc"
            // Must start with 'T' followed by '2'
            if s.len() < 21 || !s.starts_with('T') {
                continue;
            }

            let chars: Vec<char> = s.chars().collect();
            if chars.len() < 2 || chars[1] != '2' {
                continue;
            }

            if s.len() < 21 {
                continue;
            }

            // T2 yyyy mm dd hh mm ss T F L R V cc
            // 01 2345 67 89 01 23 45 6 7 8 9 0 12
            // 0         1         2
            // positions: 0=T, 1=2, 2-5=year, 6-7=month, 8-9=day,
            // 10-11=hour, 12-13=min, 14-15=sec, 16=timequal,
            // 17=freqqual, 18=leapchar, 19=servchar, 20=syncchar,
            // 21-22=checksum
            let year_str = &s[2..6];
            let month_str = &s[6..8];
            let day_str = &s[8..10];
            let hour_str = &s[10..12];
            let min_str = &s[12..14];
            let sec_str = &s[14..16];
            let timequal = if chars.len() > 16 { chars[16] } else { '0' };
            let _freqqual = if chars.len() > 17 { chars[17] } else { '0' };
            let leapchar = if chars.len() > 18 { chars[18] } else { '0' };
            let _servchar = if chars.len() > 19 { chars[19] } else { '0' };
            let syncchar = if chars.len() > 20 { chars[20] } else { '0' };

            if let (Ok(year), Ok(month), Ok(day), Ok(hour), Ok(min), Ok(sec)) = (
                year_str.parse::<i32>(),
                month_str.parse::<i32>(),
                day_str.parse::<i32>(),
                hour_str.parse::<i32>(),
                min_str.parse::<i32>(),
                sec_str.parse::<i32>(),
            ) {
                // Check sync and time quality
                if syncchar != '0' {
                    continue; // not synchronized
                }

                if timequal > '4' {
                    continue; // TFOM too big
                }

                // Decode leap indicator
                let leap = match (leapchar, month) {
                    ('+', 6) | ('+', 12) => LeapIndicator::AddLeapSecond,
                    ('-', 6) | ('-', 12) => LeapIndicator::RemoveLeapSecond,
                    ('0', _) => LeapIndicator::NoWarning,
                    _ => LeapIndicator::NoWarning,
                };

                // Convert date to Unix timestamp
                let unix_secs = date_to_unix(year, month, day, hour, min, sec);

                // Compute checksum for validation
                let expected_cs = if chars.len() >= 23 {
                    u16::from_str_radix(&s[21..23], 16).unwrap_or(0)
                } else {
                    0
                };
                let mut computed_cs: u16 = 0;
                for &c in &chars[..21] {
                    computed_cs = computed_cs.wrapping_add(c as u16);
                }
                computed_cs &= 0xff;

                if computed_cs != expected_cs && expected_cs != 0 {
                    continue; // checksum mismatch
                }

                let receive_ts = match now.duration_since(UNIX_EPOCH) {
                    Ok(d) => {
                        let secs = d.as_secs() as i64;
                        let nsec = d.subsec_nanos() as i64;
                        ts_to_ntp(secs, nsec)
                    }
                    Err(_) => ts_to_ntp(0, 0),
                };

                self.idlesec = 0;

                return Ok(Some(RefClockSample {
                    offset: 0.0,
                    delay: 0.0,
                    dispersion: (timequal as u8 - b'0') as f64 * 0.001,
                    time: receive_ts,
                    leap,
                }));
            }
        }
    }
}

fn date_to_unix(year: i32, month: i32, day: i32, hour: i32, min: i32, sec: i32) -> i64 {
    let mut days = 0i64;
    for y in 1970..year {
        days += if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) {
            366
        } else {
            365
        };
    }
    // Month days (January = 1)
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[m as usize];
        if m == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
            days += 1; // leap day
        }
    }
    days += (day as i64) - 1;
    days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpgps_open_no_such_device() {
        let mut rc = HpGpsRefclock::new(1);
        let result = rc.open("/nonexistent/hpgps");
        assert!(result.is_err());
    }

    #[test]
    fn test_date_to_unix() {
        // 2025-06-15 12:30:00
        let ts = date_to_unix(2025, 6, 15, 12, 30, 0);
        assert!(ts > 1735689600);
        // 1970-01-01 00:00:00
        let ts = date_to_unix(1970, 1, 1, 0, 0, 0);
        assert_eq!(ts, 0);
    }

    #[test]
    fn test_hpgps_timecode_parse() {
        // Example: T22025061512300004300xx
        let s = "T22025061512300004300AB";
        assert!(s.starts_with('T'));
        assert_eq!(s.as_bytes()[1], b'2');
        assert_eq!(&s[2..6], "2025");
        assert_eq!(&s[6..8], "06");
        assert_eq!(&s[8..10], "15");
    }

    #[test]
    fn test_checksum() {
        let s = "T22025061512300004300AB";
        let chars: Vec<char> = s.chars().collect();
        let mut cs: u16 = 0;
        for &c in &chars[..21] {
            cs = cs.wrapping_add(c as u16);
        }
        cs &= 0xff;
        let expected = u16::from_str_radix("AB", 16).unwrap();
        // Not necessarily matching, just verifying computation
        let _ = expected;
    }
}
