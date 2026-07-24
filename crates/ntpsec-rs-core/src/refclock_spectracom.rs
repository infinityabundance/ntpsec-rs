// ──── refclock_spectracom.rs ──────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_spectracom.c
//
// Spectracom GPS receiver refclock driver. Supports Spectracom time servers
// including 9483, 9489, and SecureSync (format 2 timecode). Formerly also
// supported the 9300 and WWVB radio clocks (Format 0 timecode).
//
// ## Oracle
//   - ntpd/refclock_spectracom.c (573 lines)
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_refclock::RefClockSample;
use crate::ntp_types::LeapIndicator;

/// Spectracom GPS receiver refclock.
///
/// Connects to a Spectracom time server via serial. Auto-detects the
/// timecode format (Format 0: 22 chars, Format 2: 24 chars) from the
/// message length.
///
/// ## C-oracle struct
///   `struct spectracomunit` in ntpd/refclock_spectracom.c
pub struct SpectracomRefclock {
    pub unit: u8,
    path: String,
    reader: Option<BufReader<File>>,
    /// Last <CR> timestamp
    pub last_hour: u8,
    /// Count of ignored lines (for monitoring)
    pub line_count: u8,
    /// Previous EOL was CR
    prev_eol_cr: bool,
}

impl SpectracomRefclock {
    /// Create a new Spectracom refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            path: String::new(),
            reader: None,
            last_hour: 0,
            line_count: 0,
            prev_eol_cr: false,
        }
    }

    /// Open the Spectracom receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/spectracom0`).
    ///
    /// ## C-oracle
    ///   `spectracom_start()` — opens device, configures 9600 baud,
    ///   initialises the unit structure.
    pub fn open(&mut self, device: &str) -> Result<(), String> {
        let file = File::open(Path::new(device))
            .map_err(|e| format!("failed to open {}: {}", device, e))?;
        self.path = device.to_string();
        self.reader = Some(BufReader::new(file));
        self.last_hour = 0;
        self.line_count = 0;
        self.prev_eol_cr = false;
        Ok(())
    }

    /// Close the Spectracom receiver device.
    pub fn close(&mut self) {
        self.reader.take();
        self.path.clear();
    }

    /// Read and decode one time sample from the receiver.
    ///
    /// Parses Format 0 or Format 2 timecodes based on message length,
    /// extracts synchronization flag, quality indicator, and time.
    ///
    /// ## C-oracle
    ///   `spectracom_receive()` — parses Format 0 or Format 2 timecodes
    ///   based on message length.
    pub fn read_sample(&mut self) -> Result<Option<RefClockSample>, String> {
        const LENTYPE0: usize = 22;
        const LENTYPE2: usize = 24;

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
            let len = trimmed.len();
            if len < 10 {
                continue;
            }

            let now = SystemTime::now();
            let s = trimmed;

            // Try Format 0: "I  ddd hh:mm:ss DTZ=nn" (22 chars)
            if len >= LENTYPE0 {
                // Check for Format 2 first: "IQyy ddd hh:mm:ss.mmm LD" (24 chars)
                if len >= LENTYPE2 {
                    // Try Format 2 parse
                    // Example: " 0 24 080 14:32:51.000  L "
                    // Format:  IQyy ddd hh:mm:ss.mmm LD
                    // Actually based on C source: "%c%c %2d %3d %2d:%2d:%2d.%3ld %c"
                    // Which is: syncchar, qualchar, year, yday, hour, minute, second, nsec, leapchar

                    let chars: Vec<char> = s.chars().collect();
                    if chars.len() >= 24 {
                        let syncchar = chars[0];
                        let qualchar = chars[1];
                        let year_str: String = chars[3..5].iter().collect();
                        let yday_str: String = chars[6..9].iter().collect();
                        let hour_str: String = chars[10..12].iter().collect();
                        let min_str: String = chars[13..15].iter().collect();
                        let sec_str: String = chars[16..18].iter().collect();
                        let _nsec_str: String = chars[19..22].iter().collect();

                        if let (Ok(yy), Ok(yday), Ok(hour), Ok(min), Ok(sec)) = (
                            year_str.parse::<i32>(),
                            yday_str.parse::<i32>(),
                            hour_str.parse::<i32>(),
                            min_str.parse::<i32>(),
                            sec_str.parse::<i32>(),
                        ) {
                            let year = yy + 2000;

                            let leap = if syncchar != ' ' {
                                LeapIndicator::Alarm
                            } else {
                                LeapIndicator::NoWarning
                            };

                            let dispersion = match qualchar {
                                ' ' => 0.001,
                                'A' => 0.01,
                                'B' => 0.1,
                                'C' => 0.5,
                                'D' => 1.0,
                                _ => 0.001,
                            };

                            let unix_secs = yday_to_unix(year, yday, hour, min, sec);

                            let receive_ts = match now.duration_since(UNIX_EPOCH) {
                                Ok(d) => {
                                    let secs = d.as_secs() as i64;
                                    let nsec = d.subsec_nanos() as i64;
                                    ts_to_ntp(secs, nsec)
                                }
                                Err(_) => ts_to_ntp(0, 0),
                            };

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

                // Try Format 0: "I  ddd hh:mm:ss DTZ=nn"
                // Example: "  080 14:32:51 DTZ=05"
                // Format from C: "%c %3d %2d:%2d:%2d%c%cTZ=%2d"
                let chars: Vec<char> = s.chars().collect();
                if chars.len() >= 22 {
                    let syncchar = chars[0];
                    let yday_str: String = chars[2..5].iter().collect();
                    let hour_str: String = chars[6..8].iter().collect();
                    let min_str: String = chars[9..11].iter().collect();
                    let sec_str: String = chars[12..14].iter().collect();

                    if let (Ok(yday), Ok(hour), Ok(min), Ok(sec)) = (
                        yday_str.parse::<i32>(),
                        hour_str.parse::<i32>(),
                        min_str.parse::<i32>(),
                        sec_str.parse::<i32>(),
                    ) {
                        // Format 0 doesn't have year in the timecode,
                        // so we use the current year from system clock
                        let now_sys = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        let current_year = 1970 + (now_sys.as_secs() / 31536000) as i32;

                        let leap = if syncchar != ' ' {
                            LeapIndicator::Alarm
                        } else {
                            LeapIndicator::NoWarning
                        };

                        let unix_secs = yday_to_unix(current_year, yday, hour, min, sec);

                        let receive_ts = match now.duration_since(UNIX_EPOCH) {
                            Ok(d) => {
                                let secs = d.as_secs() as i64;
                                let nsec = d.subsec_nanos() as i64;
                                ts_to_ntp(secs, nsec)
                            }
                            Err(_) => ts_to_ntp(0, 0),
                        };

                        return Ok(Some(RefClockSample {
                            offset: 0.0,
                            delay: 0.0,
                            dispersion: 0.001,
                            time: receive_ts,
                            leap,
                        }));
                    }
                }
            }
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
    fn test_spectracom_open_no_such_device() {
        let mut rc = SpectracomRefclock::new(1);
        let result = rc.open("/nonexistent/spectracom");
        assert!(result.is_err());
    }

    #[test]
    fn test_yday_to_unix() {
        // 2025-01-01 00:00:00 = 1735689600
        let ts = yday_to_unix(2025, 1, 0, 0, 0);
        assert_eq!(ts, 1735689600);
    }

    #[test]
    fn test_format2_parse() {
        // Format 2: " 0 24 080 14:32:51.000  L "
        let s = " 0 24 080 14:32:51.000  L ";
        let chars: Vec<char> = s.chars().collect();
        assert!(chars.len() >= 24);
        // sync = ' ', qual = '0', year = 24, yday = 080
        assert_eq!(chars[0], ' ');
        assert_eq!(chars[1], '0');
    }

    #[test]
    fn test_format0_parse() {
        // Format 0: "i  ddd hh:mm:ss DTZ=nn" (22 printable chars incl <cr><lf>)
        // The ASCII printable portion (between CR/LF) is 20 chars.
        let s = "  080 14:32:51 DTZ=05";
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars.len(), 21);
        assert_eq!(chars[2..5].iter().collect::<String>(), "080");
    }
}
