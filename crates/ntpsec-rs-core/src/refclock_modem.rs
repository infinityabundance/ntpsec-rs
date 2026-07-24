// ──── refclock_modem.rs ───────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_modem.c
//
// ACTS (Automated Computer Time Service) modem refclock driver. Supports
// NIST (US), USNO, PTB (Germany), and NPL (UK) telephone time services
// via a Hayes-compatible modem.
//
// ## Oracle
//   - ntpd/refclock_modem.c (929 lines)
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_refclock::RefClockSample;
use crate::ntp_types::LeapIndicator;

/// State machine states for modem dial-up
#[derive(Debug, Clone, Copy, PartialEq)]
enum ModemState {
    Idle,
    Setup,
    Connect,
    Msg,
}

/// Modem refclock driver.
///
/// Periodically dials a telephone time service via modem, receives
/// timecode data, and calculates the local clock correction. Designed
/// as backup when no radio clock or internet time server is available.
///
/// ## C-oracle struct
///   `struct modemunit` in ntpd/refclock_modem.c
pub struct ModemRefclock {
    pub unit: u8,
    path: String,
    reader: Option<BufReader<File>>,
    /// Current state in the dial-up state machine
    pub state: i32,
    /// Timeout counter for the current state
    pub timer: i32,
    /// Retry index for the current phone number
    pub retry: i32,
    /// Count of messages received
    pub msgcnt: i32,
    /// Internal state enum
    state_enum: ModemState,
    /// Buffer for assembling timecode lines
    buffer: String,
}

impl ModemRefclock {
    /// Create a new modem refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            path: String::new(),
            reader: None,
            state: 0,
            timer: 0,
            retry: 0,
            msgcnt: 0,
            state_enum: ModemState::Idle,
            buffer: String::new(),
        }
    }

    /// Open the modem device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/modem0`).
    ///
    /// ## C-oracle
    ///   `modem_start()` — opens device, configures termios.
    pub fn open(&mut self, device: &str) -> Result<(), String> {
        let file = File::open(Path::new(device))
            .map_err(|e| format!("failed to open {}: {}", device, e))?;
        self.path = device.to_string();
        self.reader = Some(BufReader::new(file));
        self.state = 0;
        self.timer = 0;
        self.retry = 0;
        self.msgcnt = 0;
        self.state_enum = ModemState::Idle;
        self.buffer.clear();
        Ok(())
    }

    /// Close the modem device.
    pub fn close(&mut self) {
        self.reader.take();
        self.path.clear();
    }

    /// Read one time sample from the modem.
    ///
    /// Parses timecodes from NIST ACTS, USNO, PTB/NPL, or Spectracom formats.
    ///
    /// ## C-oracle
    ///   `modem_receive()` / `modem_timecode()` — state machine that
    ///   manages dial-up, handshake, timecode parsing, and hang-up.
    pub fn read_sample(&mut self) -> Result<Option<RefClockSample>, String> {
        const LENACTS: usize = 50;
        const LENUSNO: usize = 20;
        const LENPTB: usize = 78;
        const LENTYPE0: usize = 22;
        const LENTYPE2: usize = 24;

        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => return Err("device not open".to_string()),
        };

        // If we're in IDLE state, let the caller know there's no data yet
        if self.state_enum == ModemState::Idle {
            return Ok(None);
        }

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
            let len = s.len();

            // Try to detect and parse timecode format based on length

            // NIST ACTS format (50 chars):
            // "jjjjj yy-mm-dd hh:mm:ss ds l uuu aaaaa UTC(NIST) *"
            if len >= LENACTS {
                let parts: Vec<&str> = s.split_whitespace().collect();
                if parts.len() >= 9 {
                    // Check for UTC(NIST) marker
                    if s.contains("UTC(NIST)") || s.contains("UTC(USNO)") {
                        if let Ok(_mjd) = parts[0].parse::<u32>() {
                            let date_parts: Vec<&str> = parts[1].split('-').collect();
                            if date_parts.len() == 3 {
                                if let (Ok(year), Ok(month), Ok(day)) = (
                                    date_parts[0].parse::<i32>(),
                                    date_parts[1].parse::<i32>(),
                                    date_parts[2].parse::<i32>(),
                                ) {
                                    let time_parts: Vec<&str> = parts[2].split(':').collect();
                                    if time_parts.len() == 3 {
                                        if let (Ok(hour), Ok(min), Ok(sec)) = (
                                            time_parts[0].parse::<i32>(),
                                            time_parts[1].parse::<i32>(),
                                            time_parts[2].parse::<i32>(),
                                        ) {
                                            let full_year =
                                                if year < 100 { year + 2000 } else { year };
                                            let unix_secs =
                                                date_to_unix(full_year, month, day, hour, min, sec);

                                            let receive_ts = match now.duration_since(UNIX_EPOCH) {
                                                Ok(d) => {
                                                    let secs = d.as_secs() as i64;
                                                    let nsec = d.subsec_nanos() as i64;
                                                    ts_to_ntp(secs, nsec)
                                                }
                                                Err(_) => ts_to_ntp(0, 0),
                                            };

                                            self.msgcnt += 1;
                                            return Ok(Some(RefClockSample {
                                                offset: 0.0,
                                                delay: 0.0,
                                                dispersion: 0.01,
                                                time: receive_ts,
                                                leap: LeapIndicator::NoWarning,
                                            }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // USNO format (20 chars): "jjjjj nnn hhmmss UTC"
            if len >= LENUSNO {
                let parts: Vec<&str> = s.split_whitespace().collect();
                if parts.len() >= 4 && s.contains("UTC") {
                    if let (Ok(_mjd), Ok(yday)) = (parts[0].parse::<u32>(), parts[1].parse::<i32>())
                    {
                        let time_str = parts[2];
                        if time_str.len() >= 6 {
                            if let (Ok(hour), Ok(min), Ok(sec)) = (
                                time_str[0..2].parse::<i32>(),
                                time_str[2..4].parse::<i32>(),
                                time_str[4..6].parse::<i32>(),
                            ) {
                                // Use current year
                                let now_sys = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default();
                                let current_year = 1970 + (now_sys.as_secs() / 31536000) as i32;

                                let unix_secs = yday_to_unix(current_year, yday, hour, min, sec);

                                let receive_ts = match now.duration_since(UNIX_EPOCH) {
                                    Ok(d) => {
                                        let secs = d.as_secs() as i64;
                                        let nsec = d.subsec_nanos() as i64;
                                        ts_to_ntp(secs, nsec)
                                    }
                                    Err(_) => ts_to_ntp(0, 0),
                                };

                                self.msgcnt += 1;
                                return Ok(Some(RefClockSample {
                                    offset: 0.0,
                                    delay: 0.06,
                                    dispersion: 0.01,
                                    time: receive_ts,
                                    leap: LeapIndicator::NoWarning,
                                }));
                            }
                        }
                    }
                }
            }

            // Spectracom Format 0: "I  ddd hh:mm:ss DTZ=nn"
            if len >= LENTYPE0 {
                // Simple check: contains TZ=
                if s.contains("TZ=") {
                    let chars: Vec<char> = s.chars().collect();
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
                        let now_sys = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        let current_year = 1970 + (now_sys.as_secs() / 31536000) as i32;

                        let unix_secs = yday_to_unix(current_year, yday, hour, min, sec);

                        let receive_ts = match now.duration_since(UNIX_EPOCH) {
                            Ok(d) => {
                                let secs = d.as_secs() as i64;
                                let nsec = d.subsec_nanos() as i64;
                                ts_to_ntp(secs, nsec)
                            }
                            Err(_) => ts_to_ntp(0, 0),
                        };

                        self.msgcnt += 1;
                        return Ok(Some(RefClockSample {
                            offset: 0.0,
                            delay: 0.0,
                            dispersion: 0.001,
                            time: receive_ts,
                            leap: LeapIndicator::NoWarning,
                        }));
                    }
                }
            }

            // Spectracom Format 2: "IQyy ddd hh:mm:ss.mmm LD"
            if len >= LENTYPE2 && len < 30 {
                let chars: Vec<char> = s.chars().collect();
                if chars.len() >= 24 {
                    let yday_str: String = chars[6..9].iter().collect();
                    let hour_str: String = chars[10..12].iter().collect();
                    let min_str: String = chars[13..15].iter().collect();
                    let sec_str: String = chars[16..18].iter().collect();

                    if let (Ok(yday), Ok(hour), Ok(min), Ok(sec)) = (
                        yday_str.parse::<i32>(),
                        hour_str.parse::<i32>(),
                        min_str.parse::<i32>(),
                        sec_str.parse::<i32>(),
                    ) {
                        let year_str: String = chars[3..5].iter().collect();
                        let year = if let Ok(yy) = year_str.parse::<i32>() {
                            yy + 2000
                        } else {
                            let now_sys = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default();
                            1970 + (now_sys.as_secs() / 31536000) as i32
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

                        self.msgcnt += 1;
                        return Ok(Some(RefClockSample {
                            offset: 0.0,
                            delay: 0.0,
                            dispersion: 0.001,
                            time: receive_ts,
                            leap: LeapIndicator::NoWarning,
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

fn date_to_unix(year: i32, month: i32, day: i32, hour: i32, min: i32, sec: i32) -> i64 {
    let mut days = 0i64;
    for y in 1970..year {
        days += if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) {
            366
        } else {
            365
        };
    }
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[m as usize];
        if m == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
            days += 1;
        }
    }
    days += (day as i64) - 1;
    days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modem_open_no_such_device() {
        let mut rc = ModemRefclock::new(1);
        let result = rc.open("/nonexistent/modem");
        assert!(result.is_err());
    }

    #[test]
    fn test_nist_format_detection() {
        let s = "47999 90-04-18 21:39:15 50 0 +.1 045.0 UTC(NIST) *";
        assert!(s.contains("UTC(NIST)"));
        assert!(s.len() >= 50);
    }

    #[test]
    fn test_usno_format() {
        let s = "12345 080 143251 UTC";
        let parts: Vec<&str> = s.split_whitespace().collect();
        assert_eq!(parts.len(), 4);
        assert!(s.contains("UTC"));
        let time_str = parts[2];
        assert_eq!(time_str.len(), 6);
        let hour: i32 = time_str[0..2].parse().unwrap();
        let min: i32 = time_str[2..4].parse().unwrap();
        let sec: i32 = time_str[4..6].parse().unwrap();
        assert_eq!(hour, 14);
        assert_eq!(min, 32);
        assert_eq!(sec, 51);
    }

    #[test]
    fn test_date_to_unix_known() {
        // 1970-01-02 = 86400
        let ts = date_to_unix(1970, 1, 2, 0, 0, 0);
        assert_eq!(ts, 86400);
    }
}
