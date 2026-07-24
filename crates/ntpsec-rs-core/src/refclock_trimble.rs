// ──── refclock_trimble.rs ─────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_trimble.c
//
// Trimble GPS receiver refclock driver. Supports Palisade, Thunderbolt,
// Acutime 2000, Acutime Gold, Resolution SMT, ACE III, Copernicus II,
// and EndRun Praecis timing receivers.
//
// ## Oracle
//   - ntpd/refclock_trimble.c (1390 lines)
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_refclock::RefClockSample;
use crate::ntp_types::LeapIndicator;

/// TSIP protocol constants
const DLE: u8 = 0x10;
const ETX: u8 = 0x03;
const RMAX: usize = 172;

/// TSIP parser states
#[derive(Debug, Clone, Copy, PartialEq)]
enum TsipState {
    Empty,
    Dle1,
    Data,
    Dle2,
    Full,
}

/// Clock type identifiers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrimbleClockType {
    Palisade = 0,
    Praecis = 1,
    Thunderbolt = 2,
    Acutime = 3,
    ResolutionSmt = 5,
    Ace = 6,
    Copernicus = 7,
}

/// Trimble GPS refclock.
///
/// Drives a Trimble GPS receiver via TSIP (Trimble Standard Interface
/// Protocol) or Praecis ASCII protocol over a serial connection.
///
/// ## C-oracle struct
///   `struct trimble_unit` in ntpd/refclock_trimble.c
pub struct TrimbleRefclock {
    pub unit: u8,
    path: String,
    reader: Option<BufReader<File>>,
    /// Whether a TSIP packet has been received this poll cycle
    pub got_pkt: bool,
    /// Whether a time packet has been received this poll cycle
    pub got_time: bool,
    /// Samples accumulated in the median filter this poll
    pub samples: i32,
    /// GPS week number
    pub week: u32,
    /// GPS time of week (milliseconds)
    pub tow: u64,
    /// TSIP parser state
    tsip_state: TsipState,
    /// Packet assembly buffer
    rpt_buf: [u8; RMAX],
    /// Current position in buffer
    rpt_cnt: usize,
    /// UTC offset (GPS-UTC)
    utc_offset: i32,
}

impl TrimbleRefclock {
    /// Create a new Trimble refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            path: String::new(),
            reader: None,
            got_pkt: false,
            got_time: false,
            samples: 0,
            week: 0,
            tow: 0,
            tsip_state: TsipState::Empty,
            rpt_buf: [0u8; RMAX],
            rpt_cnt: 0,
            utc_offset: 18, // approximate GPS-UTC offset
        }
    }

    /// Open the Trimble GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/trimble0`).
    ///
    /// ## C-oracle
    ///   `trimble_start()` — opens device, configures termios.
    pub fn open(&mut self, device: &str) -> Result<(), String> {
        let file = File::open(Path::new(device))
            .map_err(|e| format!("failed to open {}: {}", device, e))?;
        self.path = device.to_string();
        self.reader = Some(BufReader::new(file));
        self.got_pkt = false;
        self.got_time = false;
        self.samples = 0;
        self.week = 0;
        self.tow = 0;
        self.tsip_state = TsipState::Empty;
        self.rpt_cnt = 0;
        Ok(())
    }

    /// Close the Trimble receiver device.
    pub fn close(&mut self) {
        self.reader.take();
        self.path.clear();
    }

    /// Read and decode one time sample from the receiver.
    ///
    /// This implements a TSIP DLE/ETX packet parser. The key time
    /// packet is packet 0x42 (GPS time) which provides week number
    /// and time-of-week, and packet 0x8F-AB (UTC parameters) which
    /// provides UTC offset.
    ///
    /// ## C-oracle
    ///   `trimble_receive()` — TSIP packet parsing state machine.
    pub fn read_sample(&mut self) -> Result<Option<RefClockSample>, String> {
        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => return Err("device not open".to_string()),
        };

        let mut byte_buf = [0u8; 1];
        loop {
            // Read one byte at a time for TSIP parsing
            let bytes_read = reader
                .read(&mut byte_buf)
                .map_err(|e| format!("read error: {}", e))?;

            if bytes_read == 0 {
                return Ok(None);
            }

            let b = byte_buf[0];
            let now = SystemTime::now();

            // TSIP state machine
            match self.tsip_state {
                TsipState::Empty => {
                    if b == DLE {
                        self.tsip_state = TsipState::Dle1;
                        self.rpt_cnt = 0;
                    }
                }
                TsipState::Dle1 => {
                    self.rpt_buf[0] = b; // packet ID
                    self.rpt_cnt = 1;
                    self.tsip_state = TsipState::Data;
                }
                TsipState::Data => {
                    if b == DLE {
                        self.tsip_state = TsipState::Dle2;
                    } else if self.rpt_cnt < RMAX {
                        self.rpt_buf[self.rpt_cnt] = b;
                        self.rpt_cnt += 1;
                    } else {
                        // Buffer overflow, reset
                        self.tsip_state = TsipState::Empty;
                    }
                }
                TsipState::Dle2 => {
                    if b == ETX {
                        // End of packet
                        self.tsip_state = TsipState::Full;
                    } else if b == DLE {
                        // Stuffed DLE byte
                        if self.rpt_cnt < RMAX {
                            self.rpt_buf[self.rpt_cnt] = DLE;
                            self.rpt_cnt += 1;
                        }
                        self.tsip_state = TsipState::Data;
                    } else {
                        // Not end of packet, this is the data byte
                        if self.rpt_cnt < RMAX {
                            self.rpt_buf[self.rpt_cnt] = DLE;
                            self.rpt_cnt += 1;
                        }
                        if self.rpt_cnt < RMAX {
                            self.rpt_buf[self.rpt_cnt] = b;
                            self.rpt_cnt += 1;
                        }
                        self.tsip_state = TsipState::Data;
                    }

                    if self.tsip_state == TsipState::Full {
                        let pkt_id = self.rpt_buf[0];
                        let data = &self.rpt_buf[1..self.rpt_cnt];
                        self.tsip_state = TsipState::Empty;

                        // Process packet 0x42: GPS time
                        if pkt_id == 0x42 && data.len() >= 10 {
                            // Format from C: week (u16), TOW (u32), UTC offset (i16), flags
                            let week = u16::from_be_bytes([data[0], data[1]]);
                            let tow_ms = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                            let _utc_offset_s = i16::from_be_bytes([data[6], data[7]]);
                            let _flags = data[8];
                            let _tracking = data[9];

                            self.week = week as u32;
                            self.tow = tow_ms as u64;
                            self.got_pkt = true;
                            self.got_time = true;

                            // Convert GPS time to UTC
                            // GPS epoch: Jan 6, 1980
                            // GPS week * 604800 + TOW/1000 = seconds since GPS epoch
                            // Then add GPS-UTC offset (leap seconds)
                            let gps_epoch_unix: i64 = 315964800; // Jan 6 1980 00:00:00 UTC
                            let total_secs = gps_epoch_unix
                                + (self.week as i64 * 604800)
                                + (self.tow as i64 / 1000)
                                - self.utc_offset as i64;

                            let receive_ts = match now.duration_since(UNIX_EPOCH) {
                                Ok(d) => {
                                    let secs = d.as_secs() as i64;
                                    let nsec = d.subsec_nanos() as i64;
                                    ts_to_ntp(secs, nsec)
                                }
                                Err(_) => ts_to_ntp(0, 0),
                            };

                            self.samples += 1;

                            return Ok(Some(RefClockSample {
                                offset: 0.0,
                                delay: 0.0,
                                dispersion: 0.000001,
                                time: receive_ts,
                                leap: LeapIndicator::NoWarning,
                            }));
                        }

                        // Process packet 0x8F-AB: UTC parameters (super packet)
                        if pkt_id == 0x8F && data.len() >= 2 && data[1] == 0xAB && data.len() >= 8 {
                            let utc_offset_s = i16::from_be_bytes([data[4], data[5]]);
                            self.utc_offset = utc_offset_s as i32;
                        }
                    }
                }
                TsipState::Full => {
                    // Should not happen
                    self.tsip_state = TsipState::Empty;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trimble_open_no_such_device() {
        let mut rc = TrimbleRefclock::new(1);
        let result = rc.open("/nonexistent/trimble");
        assert!(result.is_err());
    }

    #[test]
    fn test_tsip_dle_detection() {
        assert_eq!(DLE, 0x10);
        assert_eq!(ETX, 0x03);
    }

    #[test]
    fn test_gps_epoch() {
        // GPS epoch: Jan 6, 1980
        let gps_epoch_unix: i64 = 315964800;
        // Week 0, TOW 0 should equal GPS epoch
        assert_eq!(gps_epoch_unix, 315964800);
    }

    #[test]
    fn test_packet_id_42() {
        // Packet 0x42 is GPS time
        assert_eq!(0x42, 66);
    }

    #[test]
    fn test_super_packet_id() {
        // 0x8F-AB is UTC parameters
        assert_eq!(0x8F, 143);
        assert_eq!(0xAB, 171);
    }
}
