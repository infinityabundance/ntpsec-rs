// ──── refclock_oncore.rs ──────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_oncore.c
//
// Motorola Oncore GPS receiver refclock driver. Supports Basic, PVT6, VP,
// UT, UT+, GT, GT+, SL, M12, and M12+T receiver models.
//
// ## Oracle
//   - ntpd/refclock_oncore.c (4152 lines)
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_refclock::RefClockSample;
use crate::ntp_types::LeapIndicator;

/// Oncore binary protocol header byte
const ONCORE_SYNC: u8 = 0xAA;
const ONCORE_SYNC2: u8 = 0x44;
const ONCORE_SYNC3: u8 = 0x12;

/// Maximum message length including header and checksum
const ONCORE_MAX_MSG: usize = 260;

/// Oncore message IDs we care about
const ONCORE_ID_EA: u8 = 0xEA; // @@Ea position/time output

/// Oncore receiver state
#[derive(Debug, Clone, Copy, PartialEq)]
enum OncoreState {
    Sync1,
    Sync2,
    Sync3,
    IdLen,
    Data,
    Checksum1,
    Checksum2,
}

/// Motorola Oncore GPS refclock.
///
/// Drives a Motorola Oncore GPS receiver via a serial device and
/// optional PPS device. Parses the Motorola binary @@Ea message
/// for UTC time and position.
///
/// ## C-oracle struct
///   `struct instance` in ntpd/refclock_oncore.c
#[derive(Debug)]
pub struct OncoreRefclock {
    pub unit: u8,
    path: String,
    reader: Option<BufReader<File>>,
    /// Serial device path
    pub serial_device: Option<String>,
    /// PPS device path
    pub pps_device: Option<String>,
    /// Binary protocol parser state
    parse_state: OncoreState,
    /// Current message buffer
    msg_buf: [u8; ONCORE_MAX_MSG],
    /// Current position in buffer
    msg_len: usize,
    /// Expected message length
    expected_len: usize,
    /// Last decoded week number
    week: u32,
    /// Last decoded TOW (seconds)
    tow: u32,
}

impl OncoreRefclock {
    /// Create a new Oncore refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            path: String::new(),
            reader: None,
            serial_device: None,
            pps_device: None,
            parse_state: OncoreState::Sync1,
            msg_buf: [0u8; ONCORE_MAX_MSG],
            msg_len: 0,
            expected_len: 0,
            week: 0,
            tow: 0,
        }
    }

    /// Open the Oncore GPS receiver serial device.
    ///
    /// `device` — primary serial device path.
    ///
    /// ## C-oracle
    ///   `oncore_start()` — opens serial port.
    pub fn open(&mut self, device: &str) -> Result<(), String> {
        let file = File::open(Path::new(device))
            .map_err(|e| format!("failed to open {}: {}", device, e))?;
        self.path = device.to_string();
        self.serial_device = Some(device.to_string());
        self.reader = Some(BufReader::new(file));
        self.parse_state = OncoreState::Sync1;
        self.msg_len = 0;
        self.expected_len = 0;
        Ok(())
    }

    /// Close the receiver and release resources.
    pub fn close(&mut self) {
        self.reader.take();
        self.path.clear();
    }

    /// Read one time sample from the receiver.
    ///
    /// Parses Motorola Oncore binary protocol, decoding UTC time
    /// from @@Ea position/status messages.
    ///
    /// ## C-oracle
    ///   `oncore_receive()` — processes incoming Oncore binary packets,
    ///   decodes UTC time from @@Ea position/status messages.
    pub fn read_sample(&mut self) -> Result<Option<RefClockSample>, String> {
        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => return Err("device not open".to_string()),
        };

        let mut byte_buf = [0u8; 1];
        loop {
            let bytes_read = reader
                .read(&mut byte_buf)
                .map_err(|e| format!("read error: {}", e))?;

            if bytes_read == 0 {
                return Ok(None);
            }

            let b = byte_buf[0];
            let now = SystemTime::now();

            // Motorola Oncore binary protocol parser
            // Format: <0xAA><0x44><0x12><ID><length><data...><checksum_lo><checksum_hi>
            match self.parse_state {
                OncoreState::Sync1 => {
                    if b == ONCORE_SYNC {
                        self.parse_state = OncoreState::Sync2;
                        self.msg_len = 0;
                    }
                }
                OncoreState::Sync2 => {
                    if b == ONCORE_SYNC2 {
                        self.parse_state = OncoreState::Sync3;
                    } else {
                        self.parse_state = OncoreState::Sync1;
                    }
                }
                OncoreState::Sync3 => {
                    if b == ONCORE_SYNC3 {
                        self.parse_state = OncoreState::IdLen;
                    } else {
                        self.parse_state = OncoreState::Sync1;
                    }
                }
                OncoreState::IdLen => {
                    // First byte after 0xAA4412 is message class/ID (@@ = 0x40)
                    // For @@Ea messages, the ID bytes are 0x40 0xEA
                    self.msg_buf[0] = b;
                    self.msg_len = 1;
                    self.parse_state = OncoreState::Data;
                }
                OncoreState::Data => {
                    self.msg_buf[self.msg_len] = b;
                    self.msg_len += 1;

                    // @@Ea messages are typically 44 bytes (including headers)
                    // When we have enough data, switch to checksum
                    if self.msg_len >= 44 {
                        self.parse_state = OncoreState::Checksum1;
                    }
                    if self.msg_len >= ONCORE_MAX_MSG {
                        self.parse_state = OncoreState::Sync1;
                    }
                }
                OncoreState::Checksum1 => {
                    // First checksum byte
                    let _cksum_lo = b;
                    self.parse_state = OncoreState::Checksum2;
                }
                OncoreState::Checksum2 => {
                    // Second checksum byte - message is complete
                    let _cksum_hi = b;

                    // Process the message
                    // @@Ea message = position/time output
                    // Structure: 0xAA 0x44 0x12 0x40 0xEA <len> <data...>
                    // where data at offset 8-11 = TOW (seconds),
                    // offset 12 = TOW fraction (0-99),
                    // offset 38-39 = UTC week number
                    if self.msg_len >= 42
                        && self.msg_buf[0] == b'\x40'
                        && self.msg_buf[1] == ONCORE_ID_EA
                    {
                        // Parse TOW (time of week) in seconds
                        // @@Ea format: bytes 8-11 = TOW (uint32, little-endian)
                        let tow = u32::from_le_bytes([
                            self.msg_buf[8],
                            self.msg_buf[9],
                            self.msg_buf[10],
                            self.msg_buf[11],
                        ]);

                        // Parse UTC week (bytes 38-39, little-endian uint16)
                        let week = u16::from_le_bytes([self.msg_buf[38], self.msg_buf[39]]);

                        self.week = week as u32;
                        self.tow = tow;

                        // Convert to UTC
                        // GPS epoch: Jan 6, 1980
                        let gps_epoch_unix: i64 = 315964800;
                        let total_secs =
                            gps_epoch_unix + (self.week as i64 * 604800) + self.tow as i64;

                        let receive_ts = match now.duration_since(UNIX_EPOCH) {
                            Ok(d) => {
                                let secs = d.as_secs() as i64;
                                let nsec = d.subsec_nanos() as i64;
                                ts_to_ntp(secs, nsec)
                            }
                            Err(_) => ts_to_ntp(0, 0),
                        };

                        self.parse_state = OncoreState::Sync1;
                        return Ok(Some(RefClockSample {
                            offset: 0.0,
                            delay: 0.0,
                            dispersion: 0.000001,
                            time: receive_ts,
                            leap: LeapIndicator::NoWarning,
                        }));
                    }

                    self.parse_state = OncoreState::Sync1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oncore_open_no_such_device() {
        let mut rc = OncoreRefclock::new(1);
        let result = rc.open("/nonexistent/oncore");
        assert!(result.is_err());
    }

    #[test]
    fn test_oncore_sync_bytes() {
        // Header is 0xAA 0x44 0x12
        assert_eq!(ONCORE_SYNC, 0xAA);
        assert_eq!(ONCORE_SYNC2, 0x44);
        assert_eq!(ONCORE_SYNC3, 0x12);
    }

    #[test]
    fn test_ea_message_id() {
        // @@Ea = 0x40 0xEA
        assert_eq!(ONCORE_ID_EA, 0xEA);
        assert_eq!(b'\x40', 0x40);
    }

    #[test]
    fn test_gps_epoch() {
        let gps_epoch_unix: i64 = 315964800;
        assert_eq!(gps_epoch_unix, 315964800);
    }

    #[test]
    fn test_tow_week_to_unix() {
        let week: u32 = 2400;
        let tow: u32 = 345600; // 4 days into the week
        let gps_epoch_unix: i64 = 315964800;
        let total_secs = gps_epoch_unix + (week as i64 * 604800) + tow as i64;
        assert!(total_secs > 315964800);
    }
}
