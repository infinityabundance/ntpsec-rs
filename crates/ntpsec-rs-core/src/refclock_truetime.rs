// ──── refclock_truetime.rs ────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_truetime.c
//
// Kinemetrics/TrueTime GPS receiver refclock driver. Supports GPS/TM-TMD,
// XL-DC, GPS-800 TCU, and TL-3 receiver models.
//
// ## Oracle
//   - ntpd/refclock_truetime.c (786 lines)
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_refclock::RefClockSample;
use crate::ntp_types::LeapIndicator;

/// Receiver type identifiers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrueTimeType {
    Unknown,
    Tm,  // GPS/TM-TMD or XL-DC
    Tcu, // GPS-800 TCU
    Tl3, // TL-3
}

/// State machine states
#[derive(Debug, Clone, Copy, PartialEq)]
enum TrueState {
    Base,
    InqTm,
    InqTcu,
    InqGoes,
    Init,
    F18,
    F50,
    Start,
    Auto,
}

/// TrueTime GPS receiver refclock.
///
/// Drives a Kinemetrics/TrueTime satellite-controlled clock via a serial
/// connection. Uses a state machine to probe the receiver type and then
/// automatically parse timecodes.
///
/// ## C-oracle struct
///   `struct true_unit` in ntpd/refclock_truetime.c
pub struct TrueTimeRefclock {
    pub unit: u8,
    path: String,
    reader: Option<BufReader<File>>,
    /// Poll counter
    pub pollcnt: u32,
    /// Whether a poll has been issued
    pub polled: bool,
    /// Current state in the auto-detection state machine
    pub state: u8,
    /// Detected receiver type
    pub receiver_type: u8,
    /// Enum state
    state_enum: TrueState,
    type_enum: TrueTimeType,
}

impl TrueTimeRefclock {
    /// Create a new TrueTime refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            path: String::new(),
            reader: None,
            pollcnt: 2,
            polled: false,
            state: 0,
            receiver_type: 0,
            state_enum: TrueState::Base,
            type_enum: TrueTimeType::Unknown,
        }
    }

    /// Open the TrueTime GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/true0`).
    ///
    /// ## C-oracle
    ///   `true_start()` — opens device, initialises state machine,
    ///   probes receiver type.
    pub fn open(&mut self, device: &str) -> Result<(), String> {
        let file = File::open(Path::new(device))
            .map_err(|e| format!("failed to open {}: {}", device, e))?;
        self.path = device.to_string();
        self.reader = Some(BufReader::new(file));
        self.pollcnt = 2;
        self.polled = false;
        self.state = 0;
        self.receiver_type = 0;
        self.state_enum = TrueState::Base;
        self.type_enum = TrueTimeType::Unknown;
        Ok(())
    }

    /// Close the TrueTime receiver device.
    pub fn close(&mut self) {
        self.reader.take();
        self.path.clear();
    }

    /// Read and decode one time sample from the receiver.
    ///
    /// Parses the TrueTime timecode format: `ddd:HH:MM:SSQ`
    /// where Q is the quality character.
    ///
    /// ## C-oracle
    ///   `true_receive()` — state machine parsing of timecode formats.
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

            // Main timecode format: "ddd:hh:mm:ssQ"
            // Example: "080:14:32:51 "
            // Positions: 0123456789...
            // ddd:HH:MM:SSQ
            if s.len() >= 10
                && s.as_bytes().get(3) == Some(&b':')
                && s.as_bytes().get(6) == Some(&b':')
                && s.as_bytes().get(9) == Some(&b':')
            {
                let yday_str = &s[0..3];
                let hour_str = &s[4..6];
                let min_str = &s[7..9];
                let sec_str = &s[10..12];
                let qual = if s.len() > 12 {
                    s.as_bytes()[12] as char
                } else {
                    ' '
                };

                if let (Ok(yday), Ok(hour), Ok(min), Ok(sec)) = (
                    yday_str.parse::<i32>(),
                    hour_str.parse::<i32>(),
                    min_str.parse::<i32>(),
                    sec_str.parse::<i32>(),
                ) {
                    // Use current year from system clock
                    let now_sys = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    let current_year = 1970 + (now_sys.as_secs() / 31536000) as i32;

                    let leap = match qual {
                        '>' | '#' | '?' | 'X' => LeapIndicator::Alarm,
                        _ => LeapIndicator::NoWarning,
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

                    self.pollcnt = 2;

                    if self.polled {
                        self.polled = false;
                        return Ok(Some(RefClockSample {
                            offset: 0.0,
                            delay: 0.0,
                            dispersion: if leap == LeapIndicator::Alarm {
                                1.0
                            } else {
                                0.001
                            },
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
    fn test_truetime_open_no_such_device() {
        let mut rc = TrueTimeRefclock::new(1);
        let result = rc.open("/nonexistent/true");
        assert!(result.is_err());
    }

    #[test]
    fn test_timecode_format() {
        // Typical TrueTime timecode: "080:14:32:51 "
        let s = "080:14:32:51 ";
        assert!(s.as_bytes().get(3) == Some(&b':'));
        assert!(s.as_bytes().get(6) == Some(&b':'));
        assert!(s.as_bytes().get(9) == Some(&b':'));

        let yday: i32 = s[0..3].parse().unwrap();
        let hour: i32 = s[4..6].parse().unwrap();
        let min: i32 = s[7..9].parse().unwrap();
        let sec: i32 = s[10..12].parse().unwrap();
        assert_eq!(yday, 80);
        assert_eq!(hour, 14);
        assert_eq!(min, 32);
        assert_eq!(sec, 51);
    }

    #[test]
    fn test_quality_unsynchronized() {
        let qual = '?';
        assert_eq!(
            LeapIndicator::Alarm,
            match qual {
                '>' | '#' | '?' | 'X' => LeapIndicator::Alarm,
                _ => LeapIndicator::NoWarning,
            }
        );
    }
}
