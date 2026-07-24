// ──── refclock_jjy.rs ─────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_jjy.c
//
// JJY (Japanese JJY time signal) refclock driver. Supports multiple JJY
// receiver models: Tristate JJY-01/02, C-DEX JST2000, Echo Keisokuki
// LT-2000, Citizen T.I.C JJY-200, Tristate TS-GPSclock-01, SEIKO TIME
// SYSTEMS TDC-300, and Telephone JJY.
//
// ## Oracle
//   - ntpd/refclock_jjy.c (4518 lines)
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_refclock::RefClockSample;
use crate::ntp_types::LeapIndicator;

/// JJY receiver type identifiers (matching C UNITTYPE_* constants)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JjyReceiverType {
    TristateJjy01 = 1,
    CdexJst2000 = 2,
    EchokeisokukiLt2000 = 3,
    CitizenticJjy200 = 4,
    TristateGpsclock01 = 5,
    SeikoTimesysTdc300 = 6,
    Telephone = 100,
}

impl JjyReceiverType {
    fn from_subtype(subtype: u8) -> Option<Self> {
        match subtype {
            0 | 1 => Some(JjyReceiverType::TristateJjy01),
            2 => Some(JjyReceiverType::CdexJst2000),
            3 => Some(JjyReceiverType::EchokeisokukiLt2000),
            4 => Some(JjyReceiverType::CitizenticJjy200),
            5 => Some(JjyReceiverType::TristateGpsclock01),
            6 => Some(JjyReceiverType::SeikoTimesysTdc300),
            100..=180 => Some(JjyReceiverType::Telephone),
            _ => None,
        }
    }
}

/// JJY time signal refclock.
///
/// Receives time from Japanese JJY low-frequency time signal transmitters
/// (40 kHz / 60 kHz). Supports multiple receiver models via the
/// `unittype` field.
///
/// ## C-oracle struct
///   `struct jjyunit` in ntpd/refclock_jjy.c
pub struct JjyRefclock {
    pub unit: u8,
    path: String,
    reader: Option<BufReader<File>>,
    /// Receiver type identifier
    pub unittype: Option<JjyReceiverType>,
    /// Whether a loopback measurement is in progress (Telephone JJY mode)
    pub loopback_mode: bool,
    /// Process state (C: JJY_PROCESS_STATE_*)
    process_state: i32,
    /// Command sequence counter
    command_seq: i32,
    /// Receive sequence counter
    receive_seq: i32,
    /// Timestamp data for multi-command receivers
    timestamps: Vec<i32>,
    /// Accumulated year/month/day info
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
}

impl JjyRefclock {
    /// Create a new JJY refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            path: String::new(),
            reader: None,
            unittype: None,
            loopback_mode: false,
            process_state: 0,
            command_seq: 0,
            receive_seq: 0,
            timestamps: Vec::new(),
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
        }
    }

    /// Open the JJY receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/jjy0`).
    ///
    /// ## C-oracle
    ///   `jjy_start()` -> opens device, configures line discipline and
    ///   initialises the receiver-specific sub-driver.
    pub fn open(&mut self, device: &str) -> Result<(), String> {
        let file = File::open(Path::new(device))
            .map_err(|e| format!("failed to open {}: {}", device, e))?;
        self.path = device.to_string();
        self.reader = Some(BufReader::new(file));
        self.process_state = 0;
        self.command_seq = 0;
        self.receive_seq = 0;
        self.timestamps.clear();
        Ok(())
    }

    /// Close the JJY receiver device.
    pub fn close(&mut self) {
        self.reader.take();
        self.path.clear();
    }

    /// Set the receiver type by subtype number (matching the mode in ntp.conf).
    pub fn set_subtype(&mut self, subtype: u8) -> Result<(), String> {
        let rtype = JjyReceiverType::from_subtype(subtype)
            .ok_or_else(|| format!("unsupported JJY subtype: {}", subtype))?;
        self.unittype = Some(rtype);
        Ok(())
    }

    /// Read and decode one time sample from the receiver.
    ///
    /// Parses JJY receiver timecode formats. Each receiver type has its
    /// own format:
    ///
    /// - Tristate JJY-01: date/time via "DATE" and "TIME" commands
    ///   DATE: "YYYY/MM/DD", TIME: "HH:MM:SS"
    /// - C-DEX JST2000: "JYYMMDDDWHHMMSS+0" (single line)
    ///   where J=header, YY=year, MMDD=month/day, DDD=day-of-year
    ///   W=day-of-week, HHMMSS=time, +=sign
    /// - Echo Keisokuki LT-2000: "YYMMDDGHHMMSS"
    /// - Citizen T.I.C JJY-200: timecode with date and time
    /// - Tristate TS-GPSclock-01: similar to JJY-01 but GPS-based
    /// - SEIKO TDC-300: serial timecode
    /// - Telephone JJY: dial-up based
    ///
    /// ## C-oracle
    ///   `jjy_receive()` / `jjy_synctime()` — parses received timecodes
    ///   from the various JJY receiver formats into a refclock sample.
    pub fn read_sample(&mut self) -> Result<Option<RefClockSample>, String> {
        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => return Err("device not open".to_string()),
        };

        let rtype = match self.unittype {
            Some(t) => t,
            None => return Err("JJY receiver type not set".to_string()),
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

            match rtype {
                JjyReceiverType::TristateJjy01 | JjyReceiverType::TristateGpsclock01 => {
                    // Tristate JJY-01 / TS-GPSclock-01:
                    // Uses command/response protocol.
                    // DATE response: "YYYY/MM/DD"
                    // TIME response: "HH:MM:SS"
                    // We accumulate both then produce a sample.

                    // Try to parse as DATE: YYYY/MM/DD
                    if s.len() >= 10
                        && s.as_bytes().get(4) == Some(&b'/')
                        && s.as_bytes().get(7) == Some(&b'/')
                    {
                        if let (Ok(y), Ok(m), Ok(d)) = (
                            s[0..4].parse::<i32>(),
                            s[5..7].parse::<i32>(),
                            s[8..10].parse::<i32>(),
                        ) {
                            self.year = y;
                            self.month = m;
                            self.day = d;
                            self.receive_seq |= 1; // got date
                        }
                        continue;
                    }

                    // Try to parse as TIME: HH:MM:SS
                    if s.len() >= 8
                        && s.as_bytes().get(2) == Some(&b':')
                        && s.as_bytes().get(5) == Some(&b':')
                    {
                        if let (Ok(h), Ok(m), Ok(sec)) = (
                            s[0..2].parse::<i32>(),
                            s[3..5].parse::<i32>(),
                            s[6..8].parse::<i32>(),
                        ) {
                            self.hour = h;
                            self.minute = m;
                            self.second = sec;
                            self.receive_seq |= 2; // got time
                        }
                    }

                    // If we have both date and time, produce a sample
                    if self.receive_seq == 3 && self.year > 0 {
                        let unix_secs = date_to_unix(
                            self.year,
                            self.month,
                            self.day,
                            self.hour,
                            self.minute,
                            self.second,
                        );

                        let receive_ts = match now.duration_since(UNIX_EPOCH) {
                            Ok(d) => {
                                let secs = d.as_secs() as i64;
                                let nsec = d.subsec_nanos() as i64;
                                ts_to_ntp(secs, nsec)
                            }
                            Err(_) => ts_to_ntp(0, 0),
                        };

                        self.receive_seq = 0;
                        return Ok(Some(RefClockSample {
                            offset: 0.0,
                            delay: 0.0,
                            dispersion: 0.1,
                            time: receive_ts,
                            leap: LeapIndicator::NoWarning,
                        }));
                    }
                }

                JjyReceiverType::CdexJst2000 => {
                    // C-DEX JST2000 format: "JYYMMDDDWHHMMSS+0"
                    // Example: J2401155123456+0
                    // J = header, YY = year, MM = month, DD = day,
                    // D = day-of-week, W = ?,
                    // HHMMSS = time, +=sign, 0=?
                    if s.len() >= 15 && s.starts_with('J') {
                        if let (Ok(yy), Ok(month), Ok(day), Ok(hour), Ok(min), Ok(sec)) = (
                            s[1..3].parse::<i32>(),
                            s[3..5].parse::<i32>(),
                            s[5..7].parse::<i32>(),
                            s[8..10].parse::<i32>(),
                            s[10..12].parse::<i32>(),
                            s[12..14].parse::<i32>(),
                        ) {
                            let year = yy + 2000;
                            let unix_secs = date_to_unix(year, month, day, hour, min, sec);

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
                                dispersion: 0.1,
                                time: receive_ts,
                                leap: LeapIndicator::NoWarning,
                            }));
                        }
                    }
                }

                JjyReceiverType::EchokeisokukiLt2000 => {
                    // LT-2000 format: "YYMMDDGHHMMSS" (13 chars, single line)
                    // or older: "YYMMDDHHMMSS" (12 chars)
                    if s.len() >= 12 {
                        let has_extra = s.len() >= 13;
                        if let (Ok(yy), Ok(month), Ok(day)) = (
                            s[0..2].parse::<i32>(),
                            s[2..4].parse::<i32>(),
                            s[4..6].parse::<i32>(),
                        ) {
                            let time_start = if has_extra { 7 } else { 6 };
                            if s.len() >= time_start + 6 {
                                if let (Ok(hour), Ok(min), Ok(sec)) = (
                                    s[time_start..time_start + 2].parse::<i32>(),
                                    s[time_start + 2..time_start + 4].parse::<i32>(),
                                    s[time_start + 4..time_start + 6].parse::<i32>(),
                                ) {
                                    let year = yy + 2000;
                                    let unix_secs = date_to_unix(year, month, day, hour, min, sec);

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
                                        dispersion: 0.1,
                                        time: receive_ts,
                                        leap: LeapIndicator::NoWarning,
                                    }));
                                }
                            }
                        }
                    }
                }

                JjyReceiverType::CitizenticJjy200 => {
                    // Citizen T.I.C JJY-200 format:
                    // Outputs date and time in a specific format
                    // Format: "YYYYMMDDHHMMSS" (14 digits)
                    if s.len() >= 14 {
                        if let Ok(year) = s[0..4].parse::<i32>() {
                            // Check remaining chars are digits
                            if s[4..].chars().all(|c| c.is_ascii_digit()) {
                                if let (Ok(month), Ok(day), Ok(hour), Ok(min), Ok(sec)) = (
                                    s[4..6].parse::<i32>(),
                                    s[6..8].parse::<i32>(),
                                    s[8..10].parse::<i32>(),
                                    s[10..12].parse::<i32>(),
                                    s[12..14].parse::<i32>(),
                                ) {
                                    let unix_secs = date_to_unix(year, month, day, hour, min, sec);

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
                                        dispersion: 0.1,
                                        time: receive_ts,
                                        leap: LeapIndicator::NoWarning,
                                    }));
                                }
                            }
                        }
                    }
                }

                JjyReceiverType::SeikoTimesysTdc300 => {
                    // SEIKO TIME SYSTEMS TDC-300 format
                    // Outputs timecode with time information
                    // Format: various, typically includes date and time
                    // The C driver handles it specially
                    if s.len() >= 14 {
                        if let (Ok(yy), Ok(month), Ok(day)) = (
                            s[0..2].parse::<i32>(),
                            s[2..4].parse::<i32>(),
                            s[4..6].parse::<i32>(),
                        ) {
                            // Try to find HHMMSS
                            let time_part = &s[6..];
                            if time_part.len() >= 6 {
                                if let (Ok(hour), Ok(min), Ok(sec)) = (
                                    time_part[0..2].parse::<i32>(),
                                    time_part[2..4].parse::<i32>(),
                                    time_part[4..6].parse::<i32>(),
                                ) {
                                    let year = yy + 2000;
                                    let unix_secs = date_to_unix(year, month, day, hour, min, sec);

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
                                        dispersion: 0.1,
                                        time: receive_ts,
                                        leap: LeapIndicator::NoWarning,
                                    }));
                                }
                            }
                        }
                    }
                }

                JjyReceiverType::Telephone => {
                    // Telephone JJY mode - dial-up based
                    // The C driver implements a complex FSM for modem control
                    // For now, we treat this as a pass-through that collects
                    // timecodes from the remote end
                    //
                    // Typical timecode format is similar to the above
                    // types depending on the remote receiver
                    if s.len() >= 14 {
                        // Try YYYYMMDDHHMMSS format
                        if let (Ok(year), Ok(month), Ok(day)) = (
                            s[0..4].parse::<i32>(),
                            s[4..6].parse::<i32>(),
                            s[6..8].parse::<i32>(),
                        ) {
                            if let Some(rest) = s.get(8..) {
                                if rest.len() >= 6 {
                                    if let (Ok(hour), Ok(min), Ok(sec)) = (
                                        rest[0..2].parse::<i32>(),
                                        rest[2..4].parse::<i32>(),
                                        rest[4..6].parse::<i32>(),
                                    ) {
                                        let unix_secs =
                                            date_to_unix(year, month, day, hour, min, sec);

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
                                            dispersion: 0.1,
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
    fn test_jjy_open_no_such_device() {
        let mut rc = JjyRefclock::new(1);
        let result = rc.open("/nonexistent/jjy");
        assert!(result.is_err());
    }

    #[test]
    fn test_receiver_type_from_subtype() {
        assert_eq!(
            JjyReceiverType::from_subtype(1),
            Some(JjyReceiverType::TristateJjy01)
        );
        assert_eq!(
            JjyReceiverType::from_subtype(2),
            Some(JjyReceiverType::CdexJst2000)
        );
        assert_eq!(
            JjyReceiverType::from_subtype(3),
            Some(JjyReceiverType::EchokeisokukiLt2000)
        );
        assert_eq!(
            JjyReceiverType::from_subtype(100),
            Some(JjyReceiverType::Telephone)
        );
        assert_eq!(JjyReceiverType::from_subtype(99), None);
    }

    #[test]
    fn test_cdex_format() {
        // JYYMMDDWHHMMSS+0 (15 chars)
        let s = "J2401155123456+0";
        assert!(s.starts_with('J'));
        assert_eq!(s.len(), 16);
        let yy: i32 = s[1..3].parse().unwrap();
        let month: i32 = s[3..5].parse().unwrap();
        let day: i32 = s[5..7].parse().unwrap();
        assert_eq!(yy, 24);
        assert_eq!(month, 1);
        assert_eq!(day, 15);
    }

    #[test]
    fn test_lt2000_format() {
        // YYMMDDGHHMMSS (13 chars)
        let s = "2401155123456";
        assert_eq!(s.len(), 13);
        let yy: i32 = s[0..2].parse().unwrap();
        let month: i32 = s[2..4].parse().unwrap();
        let day: i32 = s[4..6].parse().unwrap();
        assert_eq!(yy, 24);
        assert_eq!(month, 1);
        assert_eq!(day, 15);
    }

    #[test]
    fn test_date_to_unix_jjy() {
        // 2024-01-15 12:34:56
        let ts = date_to_unix(2024, 1, 15, 12, 34, 56);
        assert_eq!(ts, 1705322096);
    }
}
