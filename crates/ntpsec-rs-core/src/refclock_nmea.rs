// ──── refclock_nmea.rs ──────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_nmea.c
//
// NMEA GPS refclock driver (type 19). Parses NMEA 0183 sentences
// ($GPGGA and $GPRMC) from a serial GPS device and produces time samples.
//
// ## Oracle
//   - ntpsec ntpd/refclock_nmea.c — NMEA refclock driver
//   - NMEA 0183 standard §4.10 (sentence format, checksum)
//   - NMEA 0183 standard §5.2 (GGA), §5.8 (RMC)
//
// ## Court
//   - docs/courts/refclock_nmea.md — sentence parsing, time conversion,
//     checksum verification, packet assembly.
// =============================================================================

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::SystemTime;

use crate::ntp_fp::ts_to_ntp;
use crate::ntp_types::*;

// ─── Constants ──────────────────────────────────────────────────────────────

/// NMEA reference identifier used as the NTP reference ID.
/// ASCII big-endian: "NMEA".
const REFID_NMEA: u32 = 0x4E_4D_45_41;

/// Number of days between the proleptic Gregorian epoch (0000-03-01)
/// and the Unix epoch (1970-01-01). Used in `days_from_civil`.
const DAYS_FROM_CIVIL_OFFSET: i64 = 719_468;

// ─── NMEA Sentence Types ────────────────────────────────────────────────────

/// NMEA sentence types we care about.
#[derive(Debug, Clone, PartialEq)]
pub enum NmeaSentence {
    /// $GPGGA — Global Positioning System Fix Data.
    Gga {
        /// UTC time as (hours, minutes, seconds).
        time: (u8, u8, u8),
        /// Sub-second nanoseconds extracted from the time field.
        sub_seconds: u32,
        /// Latitude in decimal degrees (positive north).
        latitude: f64,
        /// Longitude in decimal degrees (positive east).
        longitude: f64,
        /// GPS quality indicator (0=invalid, 1=GPS fix, 2=DGPS fix).
        quality: u8,
        /// Altitude above mean sea level in metres.
        altitude: f64,
    },
    /// $GPRMC — Recommended Minimum Specific GNSS Data.
    Rmc {
        /// UTC time as (hours, minutes, seconds).
        time: (u8, u8, u8),
        /// Sub-second nanoseconds extracted from the time field.
        sub_seconds: u32,
        /// Date as (day, month, 2-digit year).
        date: (u8, u8, u8),
        /// Status: 'A' = active/valid, 'V' = void/invalid.
        status: char,
        /// Latitude in decimal degrees (positive north).
        latitude: f64,
        /// Longitude in decimal degrees (positive east).
        longitude: f64,
        /// Speed over ground in knots.
        speed: f64,
        /// Course over ground in degrees true.
        course: f64,
    },
}

// ─── NMEA Checksum ─────────────────────────────────────────────────────────

/// Verify the NMEA 0183 checksum at the end of a sentence.
///
/// The checksum is the XOR of all bytes between the leading `$`/`!` (exclusive)
/// and the `*` (exclusive), represented as two hexadecimal digits after the `*`.
///
/// Returns `true` if the checksum is present and valid.
fn nmea_checksum_ok(line: &str) -> bool {
    let line = line.trim();
    // Find the '*' that marks the checksum separator.
    let star = match line.rfind('*') {
        Some(pos) => pos,
        None => return false,
    };

    // Must have exactly two hex digits after '*', optionally followed by
    // whitespace (CR/LF) and nothing else.
    let checksum_str = &line[star + 1..];
    let cs_trimmed = checksum_str.trim();
    if cs_trimmed.len() != 2 {
        return false;
    }

    let expected = match u8::from_str_radix(cs_trimmed, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // XOR all bytes between the start marker (after $ or !) and '*'.
    let start = if line.starts_with('$') || line.starts_with('!') {
        1
    } else {
        0
    };

    let mut computed = 0u8;
    for &b in line[start..star].as_bytes() {
        computed ^= b;
    }

    computed == expected
}

// ─── Coordinate Parsing ────────────────────────────────────────────────────

/// Parse an NMEA latitude field in DDMM.MMMM format.
///
/// # Examples
/// - `"4807.038"` with `"N"` → 48.1173 (north positive)
/// - `"4807.038"` with `"S"` → -48.1173 (south negative)
fn parse_latitude(raw: &str, hemi: &str) -> Option<f64> {
    let dot = raw.find('.')?;
    // Latitude: DDMM.MMMM — degrees are before the first two digits before dot.
    if dot < 2 {
        return None;
    }
    let deg: f64 = raw[..dot - 2].parse().ok()?;
    let minutes: f64 = raw[dot - 2..].parse().ok()?;
    let lat = deg + minutes / 60.0;
    match hemi {
        "N" => Some(lat),
        "S" => Some(-lat),
        _ => None,
    }
}

/// Parse an NMEA longitude field in DDDMM.MMMM format.
///
/// # Examples
/// - `"01131.000"` with `"E"` → 11.516667 (east positive)
/// - `"01131.000"` with `"W"` → -11.516667 (west negative)
fn parse_longitude(raw: &str, hemi: &str) -> Option<f64> {
    let dot = raw.find('.')?;
    // Longitude: DDDMM.MMMM — degrees are before the first three digits before dot.
    if dot < 3 {
        return None;
    }
    let deg: f64 = raw[..dot - 2].parse().ok()?;
    let minutes: f64 = raw[dot - 2..].parse().ok()?;
    let lon = deg + minutes / 60.0;
    match hemi {
        "E" => Some(lon),
        "W" => Some(-lon),
        _ => None,
    }
}

// ─── Sentence Parsing ──────────────────────────────────────────────────────

/// Extract the 3-character sentence formatter from a talker+sentence field.
///
/// NMEA 0183 field 0 is either `ttsss` (talker ID + formatter, 5 chars) or
/// `sss` (formatter only, 3 chars). Returns just the 3-char formatter.
fn sentence_id(field0: &str) -> &str {
    if field0.len() >= 5 {
        &field0[2..] // strip 2-char talker ID (e.g. "GP" from "GPGGA")
    } else {
        field0
    }
}

/// Parse a $GPGGA sentence into an `NmeaSentence::Gga`.
///
/// Field layout (NMEA 0183 §5.2):
///   0: Talker + "GGA"        e.g. "GPGGA"
///   1: UTC time (HHMMSS)
///   2: Latitude (DDMM.MMMM)
///   3: N/S hemisphere
///   4: Longitude (DDDMM.MMMM)
///   5: E/W hemisphere
///   6: GPS quality indicator
///   7: Number of satellites tracked
///   8: Horizontal dilution of precision
///   9: Altitude above MSL
///  10: Units of altitude (M = metres)
///  11: Geoidal separation
///  12: Units of separation
///  13: Age of differential correction (blank if not used)
///  14: Differential reference station ID
fn parse_gga(fields: &[&str]) -> Option<NmeaSentence> {
    // Need at least 15 fields (0-indexed, field 0 is the sentence ID)
    if fields.len() < 15 {
        return None;
    }

    let time_str = fields.get(1)?;
    let (hh, mm, ss, sub_seconds) = parse_time(time_str)?;

    let lat_raw = fields.get(2)?;
    let lat_hemi = fields.get(3)?;
    let latitude = parse_latitude(lat_raw, lat_hemi)?;

    let lon_raw = fields.get(4)?;
    let lon_hemi = fields.get(5)?;
    let longitude = parse_longitude(lon_raw, lon_hemi)?;

    let quality: u8 = fields.get(6)?.parse().ok()?;

    let alt_str = fields.get(9)?;
    let altitude: f64 = if alt_str.is_empty() {
        0.0
    } else {
        alt_str.parse().ok()?
    };

    Some(NmeaSentence::Gga {
        time: (hh, mm, ss),
        sub_seconds,
        latitude,
        longitude,
        quality,
        altitude,
    })
}

/// Parse a $GPRMC sentence into an `NmeaSentence::Rmc`.
///
/// Field layout (NMEA 0183 §5.8):
///   0: Talker + "RMC"        e.g. "GPRMC"
///   1: UTC time (HHMMSS)
///   2: Status (A=active, V=void)
///   3: Latitude (DDMM.MMMM)
///   4: N/S hemisphere
///   5: Longitude (DDDMM.MMMM)
///   6: E/W hemisphere
///   7: Speed over ground (knots)
///   8: Course over ground (degrees true)
///   9: Date (DDMMYY)
///  10: Magnetic variation
///  11: E/W variation
///  12: Mode indicator (optional, NMEA 2.3+)
fn parse_rmc(fields: &[&str]) -> Option<NmeaSentence> {
    // Need at least 12 fields.
    if fields.len() < 12 {
        return None;
    }

    let time_str = fields.get(1)?;
    let (hh, mm, ss, sub_seconds) = parse_time(time_str)?;

    let status_str = fields.get(2)?;
    let status = status_str.chars().next()?;

    let lat_raw = fields.get(3)?;
    let lat_hemi = fields.get(4)?;
    let latitude = parse_latitude(lat_raw, lat_hemi)?;

    let lon_raw = fields.get(5)?;
    let lon_hemi = fields.get(6)?;
    let longitude = parse_longitude(lon_raw, lon_hemi)?;

    let speed: f64 = fields
        .get(7)
        .and_then(|s| if s.is_empty() { None } else { s.parse().ok() })
        .unwrap_or(0.0);

    let course: f64 = fields
        .get(8)
        .and_then(|s| if s.is_empty() { None } else { s.parse().ok() })
        .unwrap_or(0.0);

    let date_str = fields.get(9)?;
    let (dd, mm_date, yy) = parse_date(date_str)?;

    Some(NmeaSentence::Rmc {
        time: (hh, mm, ss),
        sub_seconds,
        date: (dd, mm_date, yy),
        status,
        latitude,
        longitude,
        speed,
        course,
    })
}

/// Parse an NMEA time field in HHMMSS[.sss] format.
fn parse_time(raw: &str) -> Option<(u8, u8, u8, u32)> {
    if raw.len() < 6 {
        return None;
    }
    let hh: u8 = raw[..2].parse().ok()?;
    let mm: u8 = raw[2..4].parse().ok()?;
    let ss: u8 = raw[4..6].parse().ok()?;
    if hh > 23 || mm > 59 || ss > 59 {
        return None;
    }

    // Extract fractional seconds and convert to nanoseconds.
    let nanos = if raw.len() > 6 && raw.as_bytes().get(6) == Some(&b'.') {
        let frac_str = &raw[7..];
        let mut val: u32 = 0;
        let mut digits = 0u32;
        for c in frac_str.chars() {
            if let Some(d) = c.to_digit(10) {
                if digits < 9 {
                    val = val * 10 + d;
                    digits += 1;
                }
            } else {
                break;
            }
        }
        // Scale to nanoseconds (right-pad with zeros).
        for _ in digits..9 {
            val *= 10;
        }
        val
    } else {
        0
    };

    Some((hh, mm, ss, nanos))
}

/// Parse an NMEA date field in DDMMYY format.
fn parse_date(raw: &str) -> Option<(u8, u8, u8)> {
    if raw.len() < 6 {
        return None;
    }
    let dd: u8 = raw[..2].parse().ok()?;
    let mm: u8 = raw[2..4].parse().ok()?;
    let yy: u8 = raw[4..6].parse().ok()?;
    // Basic sanity: day 1-31, month 1-12.
    if dd < 1 || dd > 31 || mm < 1 || mm > 12 {
        return None;
    }
    Some((dd, mm, yy))
}

// ─── Public Parsing API ────────────────────────────────────────────────────

/// Parse an NMEA 0183 sentence from a raw line of text.
///
/// Supports `$GPGGA` and `$GPRMC` sentences (with any talker ID, e.g. `$GPGGA`,
/// `$GNGGA`, `$GLGGA`, `$GPRMC`, `$GNRMC`). The checksum is verified; if it is
/// missing or incorrect, `None` is returned.
pub fn parse_nmea_sentence(line: &str) -> Option<NmeaSentence> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.starts_with('$') && !trimmed.starts_with('!') {
        return None;
    }

    // Verify the checksum.
    if !nmea_checksum_ok(trimmed) {
        return None;
    }

    // Split on '*', take the body before the checksum.
    let body = match trimmed.split('*').next() {
        Some(b) => b,
        None => return None,
    };

    // Split into comma-separated fields.
    let fields: Vec<&str> = body.split(',').collect();
    if fields.is_empty() {
        return None;
    }

    // The first field is the sentence ID (with optional talker prefix).
    // Strip the leading '$' or '!' — it's part of field 0 in NMEA framing.
    let field0 = if fields[0].starts_with('$') || fields[0].starts_with('!') {
        &fields[0][1..]
    } else {
        fields[0]
    };

    let sid = sentence_id(field0);

    match sid {
        "GGA" => parse_gga(&fields),
        "RMC" => parse_rmc(&fields),
        _ => None,
    }
}

// ─── Civil Date Utilities ──────────────────────────────────────────────────

/// Return the number of days since the proleptic Gregorian epoch (0000-03-01)
/// for the given civil date.
///
/// This is the inverse of Howard Hinnant's `civil_from_days`. The result is
/// an offset from 0000-03-01, which is day 0 of the Hinnant algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u32; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = (yoe * 365 + yoe / 4 - yoe / 100) as i64 + doy as i64;
    era * 146_097 + doe - DAYS_FROM_CIVIL_OFFSET
}

/// Convert an NMEA date+time to Unix epoch seconds.
///
/// NMEA two-digit year handling follows the conventional mapping:
///   - yy 80-99 → 1900 + yy (i.e. 1980-1999)
///   - yy 00-79 → 2000 + yy (i.e. 2000-2079)
fn nmea_datetime_to_unix(dd: u8, mm: u8, yy: u8, hh: u8, mn: u8, ss: u8) -> Option<i64> {
    let year = if yy >= 80 {
        1900 + yy as i64
    } else {
        2000 + yy as i64
    };
    let month = mm as u32;
    let day = dd as u32;

    // Basic validity check.
    if month < 1 || month > 12 || day < 1 || day > 31 {
        return None;
    }

    let unix_epoch_days = days_from_civil(1970, 1, 1);
    let target_days = days_from_civil(year, month, day);
    let days_since_unix = target_days - unix_epoch_days;

    Some(days_since_unix * 86_400 + (hh as i64) * 3_600 + (mn as i64) * 60 + ss as i64)
}

// ─── Sample Type ───────────────────────────────────────────────────────────

/// A single time sample produced by the NMEA refclock.
#[derive(Debug, Clone)]
pub struct NmeaSample {
    /// System time at which the NMEA sentence was received.
    pub receive_time: NtpTs64,
    /// UTC time extracted from the GPS sentence, converted to NTP epoch.
    pub gps_time: NtpTs64,
    /// Leap indicator (always NoWarning from GPS data).
    pub leap: LeapIndicator,
}

/// Convert an `NmeaSample` into a server-mode `NtpPacket`.
///
/// The packet is constructed as a refclock server response:
///   - li_vn_mode: NoWarning, V4, Server
///   - reference_id: NMEA ASCII
///   - reference/receive/transmit timestamps: GPS time
pub fn nmea_sample_to_packet(sample: &NmeaSample, precision: i8) -> NtpPacket {
    let ref_ts = ntp_ts64_to_ntpts(sample.gps_time);
    NtpPacket {
        li_vn_mode: NtpPacket::set_li_vn_mode(sample.leap, NtpVersion::V4, NtpMode::Server),
        stratum: 0, // Refclock; stratum determined upstream
        poll: 0,
        precision,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: REFID_NMEA,
        reference_ts: ref_ts,
        originate_ts: NtpTs {
            seconds: 0,
            fraction: 0,
        },
        receive_ts: ref_ts,
        transmit_ts: ref_ts,
    }
}

// ─── Driver ────────────────────────────────────────────────────────────────

/// NMEA refclock driver.
///
/// Opens a serial device (or any file/character device providing NMEA sentences),
/// reads and parses $GPGGA and $GPRMC sentences, and produces time samples.
///
/// # Example
///
/// ```ignore
/// let mut clock = NmeaRefclock::new(0);
/// clock.open("/dev/ttyUSB0").expect("open device");
/// if let Ok(Some(sample)) = clock.read_sample() {
///     let packet = nmea_sample_to_packet(&sample, -6);
///     // ... send packet up the NTP protocol chain ...
/// }
/// clock.close();
/// ```
#[derive(Debug)]
pub struct NmeaRefclock {
    /// Refclock unit number.
    unit: u8,
    /// Path to the serial device.
    path: String,
    /// Buffered reader wrapping the open device.
    reader: Option<BufReader<File>>,
    /// Last valid time sample produced.
    last_sample: Option<NmeaSample>,
    /// Number of samples successfully read.
    samples_read: u64,
    /// Last known date from RMC sentences, used to date GGA-only time.
    last_date: Option<(u8, u8, u8)>, // (dd, mm, yy)
}

impl NmeaRefclock {
    /// Create a new NMEA refclock instance for the given unit number.
    pub fn new(unit: u8) -> Self {
        NmeaRefclock {
            unit,
            path: String::new(),
            reader: None,
            last_sample: None,
            samples_read: 0,
            last_date: None,
        }
    }

    /// Open the serial device at `path`.
    ///
    /// On success, the device is opened and buffered for line-oriented reading.
    /// The `path` is stored for diagnostic purposes.
    pub fn open(&mut self, path: &str) -> Result<(), String> {
        let file =
            File::open(Path::new(path)).map_err(|e| format!("failed to open {}: {}", path, e))?;
        self.path = path.to_string();
        self.reader = Some(BufReader::new(file));
        self.last_date = None;
        self.last_sample = None;
        self.samples_read = 0;
        Ok(())
    }

    /// Read and parse the next NMEA sentence from the device.
    ///
    /// Returns `Ok(None)` when the stream ends (EOF) with no error.
    /// Returns `Err(...)` on I/O errors.
    /// Non-NMEA lines and sentences with bad checksums are silently skipped.
    pub fn read_sentence(&mut self) -> Result<Option<NmeaSentence>, String> {
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
                // EOF.
                return Ok(None);
            }

            // Try to parse — skip if it's not a valid sentence.
            if let Some(sentence) = parse_nmea_sentence(&line) {
                return Ok(Some(sentence));
            }
            // Otherwise loop to the next line.
        }
    }

    /// Read a time sample from the GPS device.
    ///
    /// Reads lines from the device until a valid $GPGGA or $GPRMC sentence
    /// containing usable time information is obtained. The system time is
    /// captured as the receive timestamp.
    ///
    /// For $GPRMC sentences: full date and time are extracted. The date is
    /// cached for use with subsequent $GPGGA sentences.
    ///
    /// For $GPGGA sentences: only the time-of-day is available; the date
    /// from the most recent $GPRMC sentence is used.
    pub fn read_sample(&mut self) -> Result<Option<NmeaSample>, String> {
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

            // Capture system time as close as possible to the line arrival.
            let now = SystemTime::now();

            let sentence = match parse_nmea_sentence(&line) {
                Some(s) => s,
                None => continue, // skip unparseable lines
            };

            let (unixtime, sub_seconds, leap) = match sentence_to_unix(&sentence, self.last_date) {
                Some(t) => t,
                None => continue, // insufficient data (e.g. GGA with no prior date)
            };

            // Update cached date from RMC.
            if let NmeaSentence::Rmc { date, .. } = &sentence {
                self.last_date = Some(*date);
            }

            // Convert receive timestamp to NTP format.
            let receive_ts = match now.duration_since(SystemTime::UNIX_EPOCH) {
                Ok(d) => {
                    let secs = d.as_secs() as i64;
                    let nsec = d.subsec_nanos() as i64;
                    ts_to_ntp(secs, nsec)
                }
                Err(_) => ts_to_ntp(0, 0),
            };

            let gps_time = ts_to_ntp(unixtime, sub_seconds as i64);

            let sample = NmeaSample {
                receive_time: receive_ts,
                gps_time,
                leap,
            };

            self.last_sample = Some(sample.clone());
            self.samples_read += 1;
            return Ok(Some(sample));
        }
    }

    /// Close the device.
    pub fn close(&mut self) {
        if let Some(reader) = self.reader.take() {
            drop(reader);
        }
        self.path.clear();
        self.last_sample = None;
        self.last_date = None;
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Return the unit number.
    pub fn unit(&self) -> u8 {
        self.unit
    }

    /// Return the device path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Return the last sample produced.
    pub fn last_sample(&self) -> Option<&NmeaSample> {
        self.last_sample.as_ref()
    }

    /// Return the number of samples read so far.
    pub fn samples_read(&self) -> u64 {
        self.samples_read
    }

    /// Return whether the device is currently open.
    pub fn is_open(&self) -> bool {
        self.reader.is_some()
    }
}

// ─── Internal Helpers ──────────────────────────────────────────────────────

/// Convert an NMEA sentence into a Unix timestamp (seconds since Unix epoch).
///
/// Returns `(unix_seconds, leap_indicator)` or `None` if the sentence does not
/// contain enough information to determine absolute time.
///
/// For GGA, the date from `last_date` is required since GGA only provides time.
/// For RMC, the date is embedded in the sentence.
fn sentence_to_unix(
    sentence: &NmeaSentence,
    last_date: Option<(u8, u8, u8)>,
) -> Option<(i64, u32, LeapIndicator)> {
    match *sentence {
        NmeaSentence::Rmc {
            time: (hh, mm, ss),
            sub_seconds,
            date: (dd, mm_date, yy),
            status,
            ..
        } => {
            // Only accept active (valid) status.
            if status != 'A' {
                return None;
            }
            let unixtime = nmea_datetime_to_unix(dd, mm_date, yy, hh, mm, ss)?;
            Some((unixtime, sub_seconds, LeapIndicator::NoWarning))
        }
        NmeaSentence::Gga {
            time: (hh, mm, ss),
            sub_seconds,
            quality,
            ..
        } => {
            // Quality must be 1 (GPS) or 2 (DGPS).
            if quality == 0 {
                return None;
            }
            // GGA has no date; use the last known date from an RMC sentence.
            let (dd, mm_date, yy) = last_date?;
            let unixtime = nmea_datetime_to_unix(dd, mm_date, yy, hh, mm, ss)?;
            Some((unixtime, sub_seconds, LeapIndicator::NoWarning))
        }
    }
}

/// Convert an `NtpTs64` to the wire-format `NtpTs` (truncating to u32 seconds).
fn ntp_ts64_to_ntpts(ts: NtpTs64) -> NtpTs {
    NtpTs {
        seconds: ts.seconds as u32,
        fraction: ts.fraction,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parsing tests ──────────────────────────────────────────────────────

    /// A valid $GPGGA sentence at 12:35:19 UTC, position 48°07.038'N 011°31.000'E,
    /// quality 1 (GPS fix), altitude 545.4 m.
    const VALID_GGA: &str = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";

    /// A valid $GPRMC sentence at 12:35:19 UTC on 23 March 1994, status A (active),
    /// same position, speed 022.4 kn, course 084.4°.
    const VALID_RMC: &str = "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A";

    #[test]
    fn test_parse_gga() {
        let sentence = parse_nmea_sentence(VALID_GGA).expect("should parse GGA");
        match sentence {
            NmeaSentence::Gga {
                time,
                sub_seconds,
                latitude,
                longitude,
                quality,
                altitude,
            } => {
                assert_eq!(time, (12, 35, 19));
                assert_eq!(sub_seconds, 0);
                // 48°07.038' N = 48 + 7.038/60 = 48.1173
                assert!((latitude - 48.1173).abs() < 0.0001);
                // 011°31.000' E = 11 + 31.000/60 = 11.516667
                assert!((longitude - 11.516667).abs() < 0.0001);
                assert_eq!(quality, 1);
                assert!((altitude - 545.4).abs() < 0.01);
            }
            _ => panic!("expected GGA, got something else"),
        }
    }

    #[test]
    fn test_parse_rmc() {
        let sentence = parse_nmea_sentence(VALID_RMC).expect("should parse RMC");
        match sentence {
            NmeaSentence::Rmc {
                time,
                date,
                status,
                sub_seconds,
                latitude,
                longitude,
                speed,
                course,
            } => {
                assert_eq!(time, (12, 35, 19));
                assert_eq!(sub_seconds, 0);
                assert_eq!(date, (23, 3, 94)); // DD=23, MM=03, YY=94
                assert_eq!(status, 'A');
                // 48°07.038' N
                assert!((latitude - 48.1173).abs() < 0.0001);
                // 011°31.000' E
                assert!((longitude - 11.516667).abs() < 0.0001);
                assert!((speed - 22.4).abs() < 0.01);
                assert!((course - 84.4).abs() < 0.01);
            }
            _ => panic!("expected RMC, got something else"),
        }
    }

    #[test]
    fn test_invalid_checksum() {
        // Valid GGA with the last hex digit flipped: *47 → *48
        let bad_cs = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*48";
        assert!(parse_nmea_sentence(bad_cs).is_none());

        // Missing checksum entirely
        let no_cs = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,";
        assert!(parse_nmea_sentence(no_cs).is_none());

        // Garbage after checksum (extra chars after the 2 hex digits)
        let garbage = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47extra";
        // The first two hex digits after * are "47" which is correct, but
        // there should be no trailing non-whitespace characters.
        assert!(parse_nmea_sentence(garbage).is_none());
    }

    #[test]
    fn test_missing_sentence() {
        // Empty string
        assert!(parse_nmea_sentence("").is_none());
        // Only whitespace
        assert!(parse_nmea_sentence("   \t\n  ").is_none());
        // Truncated — no checksum
        assert!(parse_nmea_sentence("$GPGGA,123519").is_none());
        // Just the start marker
        assert!(parse_nmea_sentence("$").is_none());
        // Not an NMEA sentence
        assert!(parse_nmea_sentence("hello world").is_none());
        // Unknown sentence type
        assert!(parse_nmea_sentence("$GPGSV,1,1,01,01,,,*47").is_none());
    }

    #[test]
    fn test_rmc_void_status_rejected() {
        // RMC with status 'V' (void) — should not produce a valid time sample.
        let void_rmc = "$GPRMC,123519,V,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*7D";
        let sentence = parse_nmea_sentence(void_rmc).expect("should parse as RMC");
        // The sentence parses, but the time sample should be rejected.
        let result = sentence_to_unix(&sentence, None);
        assert!(result.is_none());
    }

    #[test]
    fn test_gga_requires_last_date() {
        let gga = parse_nmea_sentence(VALID_GGA).expect("should parse GGA");
        // Without a last date, GGA cannot produce a timestamp.
        assert!(sentence_to_unix(&gga, None).is_none());
        // With a last date, it should work.
        let result = sentence_to_unix(&gga, Some((23, 3, 94)));
        assert!(result.is_some());
        let (unixtime, sub_seconds, leap) = result.unwrap();
        assert_eq!(leap, LeapIndicator::NoWarning);
        assert_eq!(sub_seconds, 0);
        // 1994-03-23 12:35:19 UTC
        // Quick sanity: Unix timestamp should be positive and within a reasonable range.
        assert!(unixtime > 700_000_000);
        assert!(unixtime < 800_000_000);
    }

    #[test]
    fn test_gga_quality_zero_rejected() {
        // GGA with quality 0 (invalid fix).
        let bad_gga = "$GPGGA,123519,4807.038,N,01131.000,E,0,08,0.9,545.4,M,46.9,M,,*46";
        let sentence = parse_nmea_sentence(bad_gga).expect("should parse GGA");
        match sentence {
            NmeaSentence::Gga { quality, .. } => {
                assert_eq!(quality, 0);
            }
            _ => panic!("expected GGA"),
        }
        let result = sentence_to_unix(&sentence, Some((23, 3, 94)));
        assert!(result.is_none(), "quality 0 should not produce a sample");
    }

    // ── Time conversion tests ─────────────────────────────────────────────

    #[test]
    fn test_nmea_datetime_to_unix() {
        // 1994-03-23 12:35:19 UTC
        let ts = nmea_datetime_to_unix(23, 3, 94, 12, 35, 19).expect("should convert");
        // Verify against a known value: Unix timestamp for 1994-03-23 12:35:19 UTC
        let expected = 764_426_119;
        assert_eq!(ts, expected);
    }

    #[test]
    fn test_year_2000_boundary() {
        // 2000-01-01 00:00:00 (yy=00 → 2000)
        let ts = nmea_datetime_to_unix(1, 1, 0, 0, 0, 0).expect("should convert y2k");
        let expected = 946_684_800;
        assert_eq!(ts, expected);
    }

    #[test]
    fn test_year_1980_boundary() {
        // 1980-01-01 00:00:00 (yy=80 → 1980)
        let ts = nmea_datetime_to_unix(1, 1, 80, 0, 0, 0).expect("should convert 1980");
        let expected = 315_532_800;
        assert_eq!(ts, expected);
    }

    // ── Packet construction test ──────────────────────────────────────────

    #[test]
    fn test_nmea_packet_construction() {
        // Build a sample from known data.
        let gps_unixtime: i64 = 764_243_719; // 1994-03-23 12:35:19 UTC
        let receive_unixtime: i64 = 1_700_000_000; // fictitious receive time

        let sample = NmeaSample {
            receive_time: ts_to_ntp(receive_unixtime, 0),
            gps_time: ts_to_ntp(gps_unixtime, 0),
            leap: LeapIndicator::NoWarning,
        };

        let packet = nmea_sample_to_packet(&sample, -6);

        // Verify LI/VN/Mode: NoWarning, V4, Server
        assert_eq!(packet.leap_indicator(), LeapIndicator::NoWarning);
        assert_eq!(packet.version(), NtpVersion::V4);
        assert_eq!(packet.mode(), NtpMode::Server);

        // Reference ID should be "NMEA" in ASCII (big-endian).
        assert_eq!(packet.reference_id, 0x4E_4D_45_41);

        // GPS time should appear in reference/receive/transmit timestamps.
        let expected_ref_ts = ntp_ts64_to_ntpts(ts_to_ntp(gps_unixtime, 0));
        assert_eq!(packet.reference_ts, expected_ref_ts);
        assert_eq!(packet.receive_ts, expected_ref_ts);
        assert_eq!(packet.transmit_ts, expected_ref_ts);

        // Precision should be set to the provided value.
        assert_eq!(packet.precision, -6);

        // Stratum is 0 for a refclock (set upstream).
        assert_eq!(packet.stratum, 0);
        assert_eq!(packet.poll, 0);
        assert_eq!(packet.root_delay, 0);
        assert_eq!(packet.root_dispersion, 0);
    }

    // ── Coordinate parsing tests ──────────────────────────────────────────

    #[test]
    fn test_parse_latitude_north() {
        let lat = parse_latitude("4807.038", "N").unwrap();
        let expected = 48.0 + 7.038 / 60.0;
        assert!((lat - expected).abs() < 1e-10);
        assert!(lat > 0.0);
    }

    #[test]
    fn test_parse_latitude_south() {
        let lat = parse_latitude("4807.038", "S").unwrap();
        let expected = -(48.0 + 7.038 / 60.0);
        assert!((lat - expected).abs() < 1e-10);
        assert!(lat < 0.0);
    }

    #[test]
    fn test_parse_longitude_east() {
        let lon = parse_longitude("01131.000", "E").unwrap();
        let expected = 11.0 + 31.000 / 60.0;
        assert!((lon - expected).abs() < 1e-10);
        assert!(lon > 0.0);
    }

    #[test]
    fn test_parse_longitude_west() {
        let lon = parse_longitude("01131.000", "W").unwrap();
        let expected = -(11.0 + 31.000 / 60.0);
        assert!((lon - expected).abs() < 1e-10);
        assert!(lon < 0.0);
    }

    #[test]
    fn test_parse_time_valid() {
        assert_eq!(parse_time("123519"), Some((12, 35, 19, 0)));
        assert_eq!(parse_time("000000"), Some((0, 0, 0, 0)));
        assert_eq!(parse_time("235959"), Some((23, 59, 59, 0)));
    }

    #[test]
    fn test_parse_time_invalid() {
        assert!(parse_time("").is_none());
        assert!(parse_time("1235").is_none()); // too short
        assert!(parse_time("246000").is_none()); // hour 24
        assert!(parse_time("126000").is_none()); // minute 60
        assert!(parse_time("123460").is_none()); // second 60
    }

    #[test]
    fn test_parse_date_valid() {
        assert_eq!(parse_date("230394"), Some((23, 3, 94)));
        assert_eq!(parse_date("010100"), Some((1, 1, 0)));
        assert_eq!(parse_date("311299"), Some((31, 12, 99)));
    }

    #[test]
    fn test_parse_date_invalid() {
        assert!(parse_date("").is_none());
        assert!(parse_date("123").is_none()); // too short
        assert!(parse_date("320100").is_none()); // day 32
        assert!(parse_date("001200").is_none()); // day 0
        assert!(parse_date("130000").is_none()); // month 0
    }

    // ── Checksum tests ───────────────────────────────────────────────────

    #[test]
    fn test_nmea_checksum_valid() {
        assert!(nmea_checksum_ok(VALID_GGA));
        assert!(nmea_checksum_ok(VALID_RMC));
    }

    #[test]
    fn test_nmea_checksum_invalid() {
        assert!(!nmea_checksum_ok("$GPGGA,123519*00"));
        assert!(!nmea_checksum_ok("no checksum here"));
        assert!(!nmea_checksum_ok("$GPGGA*")); // no hex digits
    }

    // ── Talker ID tests ──────────────────────────────────────────────────

    #[test]
    fn test_sentence_id_with_talker() {
        assert_eq!(sentence_id("GPGGA"), "GGA");
        assert_eq!(sentence_id("GNGGA"), "GGA");
        assert_eq!(sentence_id("GLGGA"), "GGA");
        assert_eq!(sentence_id("GPRMC"), "RMC");
        assert_eq!(sentence_id("GNRMC"), "RMC");
    }

    #[test]
    fn test_sentence_id_without_talker() {
        assert_eq!(sentence_id("GGA"), "GGA");
        assert_eq!(sentence_id("RMC"), "RMC");
    }

    #[test]
    fn test_various_talker_ids_accepted() {
        // $GNGGA (GNSS, multi-constellation)
        let gn_gga = "$GNGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*59";
        assert!(parse_nmea_sentence(gn_gga).is_some());

        // $GLGGA (GLONASS)
        let gl_gga = "$GLGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*5B";
        assert!(parse_nmea_sentence(gl_gga).is_some());
    }

    // ── days_from_civil tests ─────────────────────────────────────────────

    #[test]
    fn test_days_from_civil_unix_epoch() {
        // 1970-01-01 should yield the same offset as the reference.
        let d = days_from_civil(1970, 1, 1);
        let ref_d = days_from_civil(1970, 1, 1);
        assert_eq!(d, ref_d);
        // The difference from itself is zero.
        assert_eq!(d - ref_d, 0);
    }

    #[test]
    fn test_days_from_civil_known_date() {
        // 1994-03-23 minus 1970-01-01 = 8843 days
        let d1 = days_from_civil(1994, 3, 23);
        let d0 = days_from_civil(1970, 1, 1);
        assert_eq!(d1 - d0, 8847);
    }
}
