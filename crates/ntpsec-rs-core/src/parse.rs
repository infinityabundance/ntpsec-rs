// ──── parse.rs ──────────────────────────────────────────────────────────────
// Forensic reconstruction of include/parse.h, libparse/parse.c,
// libparse/parse_conf.c
//
// Reference clock timecode parsing engine.
//
// ## Supported timecode formats
//
// 1. Fixed-width numeric formats: YYMMDDHHMMSS, YYYYMMDDHHMMSS, HHMMSS, etc.
// 2. NMEA 0183 sentences: $GPGGA, $GPRMC, $GPZDA (and with any talker ID).
//
// =============================================================================

use crate::ntp_types::{LeapIndicator, NtpTs64};

// ──── Error Type ────────────────────────────────────────────────────────────

/// Error returned when a timecode string cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The sentence type is unknown / not supported.
    UnknownSentenceType(String),
    /// The checksum (if applicable) is missing or incorrect.
    ChecksumError,
    /// A required field is missing or invalid.
    MissingField(String),
    /// A field value is out of the valid range.
    InvalidValue(String),
    /// The string does not match any configured format.
    FormatMismatch(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSentenceType(s) => write!(f, "unknown sentence type: {s}"),
            Self::ChecksumError => write!(f, "checksum error"),
            Self::MissingField(s) => write!(f, "missing field: {s}"),
            Self::InvalidValue(s) => write!(f, "invalid value: {s}"),
            Self::FormatMismatch(s) => write!(f, "format mismatch: {s}"),
        }
    }
}

impl std::error::Error for ParseError {}

// ──── Parsed Timecode ───────────────────────────────────────────────────────

/// A parsed timecode result.
///
/// This represents the fully decomposed date/time components extracted from
/// a serial reference-clock timecode string (NMEA, IRIG, WWVB, etc.).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedTimecode {
    /// Year (e.g. 2024).
    pub year: i32,
    /// Month (1–12).
    pub month: u8,
    /// Day (1–31).
    pub day: u8,
    /// Hour (0–23).
    pub hour: u8,
    /// Minute (0–59).
    pub minute: u8,
    /// Second (0–60 — may be 60 during a leap second).
    pub second: u8,
    /// Sub-second nanoseconds (0..999_999_999).
    pub subsecond_ns: u32,
    /// UTC offset in hours (e.g. +5 = UTC+5).
    pub utc_offset: i32,
    /// Whether daylight saving time is active.
    pub dst: bool,
    /// Whether this second is a leap second event.
    pub leap_second: bool,
}

impl Default for ParsedTimecode {
    fn default() -> Self {
        Self {
            year: 0,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            subsecond_ns: 0,
            utc_offset: 0,
            dst: false,
            leap_second: false,
        }
    }
}

// ──── Leap Indicator ────────────────────────────────────────────────────────

/// The parsed timecode with an associated NTP leap indicator.
///
/// Leap indicators are computed from the timecode content (e.g. leap-second
/// markers in NMEA $GPZDA, or special day-of-year values).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedTimecodeWithLeap {
    /// The parsed time components.
    pub timecode: ParsedTimecode,
    /// The leap indicator derived from the timecode.
    pub leap: LeapIndicator,
}

impl ParsedTimecodeWithLeap {
    /// Create a new timecode result with NoWarning leap.
    pub fn new(tc: ParsedTimecode) -> Self {
        Self {
            leap: LeapIndicator::NoWarning,
            timecode: tc,
        }
    }

    /// Create a timecode result with an explicit leap indicator.
    pub fn with_leap(tc: ParsedTimecode, leap: LeapIndicator) -> Self {
        Self { timecode: tc, leap }
    }
}

// ──── Timecode Source ───────────────────────────────────────────────────────

/// Metadata identifying the source format of a parsed timecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimecodeSource {
    /// NMEA GGA sentence.
    NmeaGga,
    /// NMEA RMC sentence.
    NmeaRmc,
    /// NMEA ZDA sentence (UTC time + date with local zone).
    NmeaZda,
    /// Fixed-width numeric format (e.g. YYMMDDHHMMSS).
    FixedWidth,
    /// Unrecognised format.
    Unknown,
}

// ──── TimecodeParser Trait ──────────────────────────────────────────────────

/// A parser that converts a raw timecode string from a reference clock into
/// an NTP timestamp and leap-indicator pair.
///
/// Implementations handle specific timecode formats (NMEA, IRIG, WWVB, etc.)
pub trait TimecodeParser {
    /// Parse a raw timecode string into a parsed timecode.
    ///
    /// Returns the parsed components on success, or a `ParseError` describing
    /// the failure.
    fn parse(&self, line: &str) -> Result<ParsedTimecodeWithLeap, ParseError>;

    /// Parse a raw timecode string into an NTP timestamp directly.
    ///
    /// The default implementation calls `parse()` and converts the result
    /// into an `NtpTs64` using the timecode's date-time components.
    ///
    /// # Errors
    ///
    /// Delegates to `parse()`.
    fn parse_to_ntp(&self, line: &str) -> Result<(NtpTs64, LeapIndicator), ParseError> {
        let parsed = self.parse(line)?;
        let ntp = datetime_to_ntp(&parsed.timecode).ok_or_else(|| {
            ParseError::InvalidValue("cannot convert date to NTP timestamp".into())
        })?;
        Ok((ntp, parsed.leap))
    }

    /// Return the source format identifier for this parser.
    fn source(&self) -> TimecodeSource;
}

// ──── Default Parser: Fixed-Width Numeric Formats ──────────────────────────

/// A parser for fixed-width numeric timecode strings.
///
/// Supports formats like `YYMMDDHHMMSS`, `YYYYMMDDHHMMSS`, `HHMMSS`, etc.
/// The format string uses:
///   * `Y` — 4-digit year
///   * `y` — 2-digit year (70-99→19xx, 00-69→20xx)
///   * `M` — 2-digit month (01-12)
///   * `D` — 2-digit day (01-31)
///   * `h` — 2-digit hour (00-23)
///   * `m` — 2-digit minute (00-59)
///   * `s` — 2-digit second (00-60)
pub struct FixedWidthParser<'a> {
    /// List of format strings to try, in order.
    pub formats: &'a [&'a str],
}

impl<'a> FixedWidthParser<'a> {
    /// Create a new parser with the given format strings.
    pub fn new(formats: &'a [&'a str]) -> Self {
        Self { formats }
    }
}

impl TimecodeParser for FixedWidthParser<'_> {
    fn parse(&self, line: &str) -> Result<ParsedTimecodeWithLeap, ParseError> {
        let tc = parse_fixed_width_timecode(line, self.formats).ok_or_else(|| {
            ParseError::FormatMismatch(format!(
                "line '{}' does not match any format in {:?}",
                line, self.formats
            ))
        })?;
        Ok(ParsedTimecodeWithLeap::new(tc))
    }

    fn source(&self) -> TimecodeSource {
        TimecodeSource::FixedWidth
    }
}

// ──── NMEA Parser ───────────────────────────────────────────────────────────

/// A parser for NMEA 0183 timecode sentences: `$GPGGA`, `$GPRMC`, `$GPZDA`
/// (and with any talker ID, e.g. `$GNGGA`, `$GNRMC`, `$GNZDA`).
pub struct NmeaParser;

impl NmeaParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NmeaParser {
    fn default() -> Self {
        Self::new()
    }
}

impl TimecodeParser for NmeaParser {
    fn parse(&self, line: &str) -> Result<ParsedTimecodeWithLeap, ParseError> {
        parse_nmea_timecode(line)
    }

    fn source(&self) -> TimecodeSource {
        TimecodeSource::Unknown // determined per-sentence
    }
}

// ──── Composite Parser ──────────────────────────────────────────────────────

/// A composite parser that tries multiple parsers in order.
///
/// The first parser to succeed wins.  Useful for refclock drivers that accept
/// multiple timecode formats (e.g. NMEA + fixed-width fallback).
pub struct CompositeParser<'a> {
    parsers: Vec<Box<dyn TimecodeParser + 'a>>,
}

impl<'a> CompositeParser<'a> {
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
        }
    }

    /// Add a parser to the end of the try-order.
    pub fn add<P: TimecodeParser + 'a>(&mut self, parser: P) {
        self.parsers.push(Box::new(parser));
    }

    /// Create a CompositeParser from an iterator of parsers.
    pub fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Box<dyn TimecodeParser + 'a>>,
    {
        Self {
            parsers: iter.into_iter().collect(),
        }
    }
}

impl TimecodeParser for CompositeParser<'_> {
    fn parse(&self, line: &str) -> Result<ParsedTimecodeWithLeap, ParseError> {
        let mut last_err = ParseError::FormatMismatch("no parsers configured".into());
        for parser in &self.parsers {
            match parser.parse(line) {
                Ok(result) => return Ok(result),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn source(&self) -> TimecodeSource {
        // Return the source of the first parser, or Unknown.
        self.parsers
            .first()
            .map(|p| p.source())
            .unwrap_or(TimecodeSource::Unknown)
    }
}

// ──── Fixed-Width Timecode Parsing ──────────────────────────────────────────

/// Parse a numeric-only timecode string (fixed-width fields).
///
/// Supports formats like: YYMMDDHHMMSS, YYYYMMDDHHMMSS, HHMMSS, etc.
///
/// Each format string uses single-letter field specifiers:
///   * `Y` — exactly 4 digit positions (year)
///   * `y` — exactly 2 digit positions (year, ambiguous century)
///   * `M` — exactly 2 digit positions (month)
///   * `D` — exactly 2 digit positions (day)
///   * `h` — exactly 2 digit positions (hour)
///   * `m` — exactly 2 digit positions (minute)
///   * `s` — exactly 2 digit positions (second)
///
/// Unknown format characters cause the format to be skipped.
pub fn parse_fixed_width_timecode(s: &str, formats: &[&str]) -> Option<ParsedTimecode> {
    for fmt in formats {
        let chars = fmt.chars().filter(|c| *c != ' ').collect::<Vec<_>>();
        if s.len() < chars.len() {
            continue;
        }
        // Try to extract fields based on format specifiers
        let mut tc = ParsedTimecode::default();
        let mut pos = 0;
        let mut matched = true;
        let mut i = 0;
        while i < chars.len() {
            if pos >= s.len() {
                matched = false;
                break;
            }
            let c = chars[i];
            // Count consecutive identical format chars as one field
            let mut count = 0;
            for j in i..chars.len() {
                if chars[j] == c {
                    count += 1;
                } else {
                    break;
                }
            }
            match c {
                'Y' => {
                    /* 4-digit year */
                    if pos + 4 <= s.len() {
                        tc.year = s[pos..pos + 4].parse().ok()?;
                        pos += 4;
                    } else {
                        matched = false;
                        break;
                    }
                }
                'y' => {
                    /* 2-digit year */
                    if pos + 2 <= s.len() {
                        let yy: i32 = s[pos..pos + 2].parse().ok()?;
                        tc.year = if yy >= 70 { 1900 + yy } else { 2000 + yy };
                        pos += 2;
                    } else {
                        matched = false;
                        break;
                    }
                }
                'M' => {
                    /* 2-digit month */
                    if pos + 2 <= s.len() {
                        tc.month = s[pos..pos + 2].parse().ok()?;
                        pos += 2;
                    } else {
                        matched = false;
                        break;
                    }
                }
                'D' => {
                    /* 2-digit day */
                    if pos + 2 <= s.len() {
                        tc.day = s[pos..pos + 2].parse().ok()?;
                        pos += 2;
                    } else {
                        matched = false;
                        break;
                    }
                }
                'h' => {
                    if pos + 2 <= s.len() {
                        tc.hour = s[pos..pos + 2].parse().ok()?;
                        pos += 2;
                    } else {
                        matched = false;
                        break;
                    }
                }
                'm' => {
                    if pos + 2 <= s.len() {
                        tc.minute = s[pos..pos + 2].parse().ok()?;
                        pos += 2;
                    } else {
                        matched = false;
                        break;
                    }
                }
                's' => {
                    if pos + 2 <= s.len() {
                        tc.second = s[pos..pos + 2].parse().ok()?;
                        pos += 2;
                    } else {
                        matched = false;
                        break;
                    }
                }
                _ => {
                    matched = false;
                    break;
                } // Unknown format char
            }
            // Skip past consecutive identical format characters
            i += count;
        }
        if matched
            && tc.month >= 1
            && tc.month <= 12
            && tc.day >= 1
            && tc.day <= 31
            && tc.hour <= 23
            && tc.minute <= 59
            && tc.second <= 60
        {
            return Some(tc);
        }
    }
    None
}

// ──── NMEA Timecode Parsing ─────────────────────────────────────────────────

/// Parse an NMEA 0183 timecode sentence and return the parsed components
/// together with a leap indicator.
///
/// Supported sentences:
///   * `$GPGGA` / `$GNGGA` — UTC time only (no date), leap = NoWarning
///   * `$GPRMC` / `$GNRMC` — UTC time + date, leap = NoWarning
///   * `$GPZDA` / `$GNZDA` — UTC time + date + local zone, leap = NoWarning
///
/// When only time (no date) is available, the date fields remain at their
/// defaults (year=0, month=1, day=1) — the caller is expected to fill in
/// the date from context.
pub fn parse_nmea_timecode(line: &str) -> Result<ParsedTimecodeWithLeap, ParseError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(ParseError::MissingField("empty line".into()));
    }
    if !trimmed.starts_with('$') && !trimmed.starts_with('!') {
        return Err(ParseError::UnknownSentenceType(format!(
            "line does not start with $ or !: {trimmed}"
        )));
    }

    // Verify the NMEA checksum.
    if !nmea_checksum_ok(trimmed) {
        return Err(ParseError::ChecksumError);
    }

    // Split on '*', take the body before the checksum.
    let body = trimmed.split('*').next().ok_or(ParseError::ChecksumError)?;

    let fields: Vec<&str> = body.split(',').collect();
    if fields.is_empty() {
        return Err(ParseError::MissingField("no fields".into()));
    }

    // Strip leading '$' or '!' from field 0.
    let field0 = if fields[0].starts_with('$') || fields[0].starts_with('!') {
        &fields[0][1..]
    } else {
        fields[0]
    };

    let sid = sentence_id(field0);

    match sid {
        "GGA" => parse_nmea_gga_timecode(&fields),
        "RMC" => parse_nmea_rmc_timecode(&fields),
        "ZDA" => parse_nmea_zda_timecode(&fields),
        _ => Err(ParseError::UnknownSentenceType(format!(
            "unsupported NMEA sentence: {sid}"
        ))),
    }
}

/// Extract the 3-character sentence formatter from a talker+sentence field.
///
/// NMEA 0183 field 0 is either `ttsss` (talker ID + formatter, 5 chars) or
/// `sss` (formatter only, 3 chars). Returns just the 3-char formatter.
fn sentence_id(field0: &str) -> &str {
    if field0.len() >= 5 {
        &field0[2..] // strip 2-char talker ID
    } else {
        field0
    }
}

/// Verify the NMEA 0183 checksum.
fn nmea_checksum_ok(line: &str) -> bool {
    let line = line.trim();
    let star = match line.rfind('*') {
        Some(pos) => pos,
        None => return false,
    };

    let checksum_str = &line[star + 1..];
    let cs_trimmed = checksum_str.trim();
    if cs_trimmed.len() != 2 {
        return false;
    }

    let expected = match u8::from_str_radix(cs_trimmed, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };

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

/// Parse an NMEA time field in HHMMSS[.sss] format.
fn parse_nmea_time(raw: &str) -> Option<(u8, u8, u8, u32)> {
    if raw.len() < 6 {
        return None;
    }
    let hh: u8 = raw[..2].parse().ok()?;
    let mm: u8 = raw[2..4].parse().ok()?;
    let ss: u8 = raw[4..6].parse().ok()?;
    if hh > 23 || mm > 59 || ss > 59 {
        return None;
    }

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
fn parse_nmea_date(raw: &str) -> Option<(u8, u8, u8)> {
    if raw.len() < 6 {
        return None;
    }
    let dd: u8 = raw[..2].parse().ok()?;
    let mm: u8 = raw[2..4].parse().ok()?;
    let yy: u8 = raw[4..6].parse().ok()?;
    if dd < 1 || dd > 31 || mm < 1 || mm > 12 {
        return None;
    }
    Some((dd, mm, yy))
}

/// Parse a $GPGGA / $GNGGA sentence into a ParsedTimecode.
///
/// GGA provides UTC time but no date.  The date fields remain at their
/// defaults.
///
/// Fields: talker+GGA, time, lat, NS, lon, EW, quality, numSats, HDOP,
///         alt, altUnit, geoidSep, geoidUnit, age, refStation
fn parse_nmea_gga_timecode(fields: &[&str]) -> Result<ParsedTimecodeWithLeap, ParseError> {
    // Need at least 6 fields for the time; full GGA has 15.
    if fields.len() < 6 {
        return Err(ParseError::MissingField(format!(
            "GGA requires at least 6 fields, got {}",
            fields.len()
        )));
    }

    let time_str = fields
        .get(1)
        .ok_or(ParseError::MissingField("GGA time".into()))?;
    if time_str.is_empty() {
        return Err(ParseError::MissingField("GGA time is empty".into()));
    }

    let (hh, mm, ss, nanos) = parse_nmea_time(time_str).ok_or(ParseError::InvalidValue(
        format!("GGA invalid time: {time_str}"),
    ))?;

    Ok(ParsedTimecodeWithLeap::new(ParsedTimecode {
        hour: hh,
        minute: mm,
        second: ss,
        subsecond_ns: nanos,
        ..ParsedTimecode::default()
    }))
}

/// Parse a $GPRMC / $GNRMC sentence into a ParsedTimecode.
///
/// RMC provides UTC time + date.
///
/// Fields: talker+RMC, time, status, lat, NS, lon, EW, speed, course, date,
///         magVar, magVarDir, mode
fn parse_nmea_rmc_timecode(fields: &[&str]) -> Result<ParsedTimecodeWithLeap, ParseError> {
    if fields.len() < 10 {
        return Err(ParseError::MissingField(format!(
            "RMC requires at least 10 fields, got {}",
            fields.len()
        )));
    }

    let time_str = fields
        .get(1)
        .ok_or(ParseError::MissingField("RMC time".into()))?;
    if time_str.is_empty() {
        return Err(ParseError::MissingField("RMC time is empty".into()));
    }
    let (hh, mm, ss, nanos) = parse_nmea_time(time_str).ok_or(ParseError::InvalidValue(
        format!("RMC invalid time: {time_str}"),
    ))?;

    // Status field: 'A' = active/valid, 'V' = void/invalid.
    let status: &str = fields
        .get(2)
        .copied()
        .ok_or(ParseError::MissingField("RMC status".into()))?;
    if status != "A" {
        return Err(ParseError::InvalidValue(format!(
            "RMC status is '{status}', expected 'A' (active)"
        )));
    }

    let date_str = fields
        .get(9)
        .ok_or(ParseError::MissingField("RMC date".into()))?;
    if date_str.is_empty() {
        return Err(ParseError::MissingField("RMC date is empty".into()));
    }
    let (dd, mm_date, yy) = parse_nmea_date(date_str).ok_or(ParseError::InvalidValue(format!(
        "RMC invalid date: {date_str}"
    )))?;

    // Convert 2-digit year to full year.
    let year = if yy >= 80 {
        1900 + yy as i32
    } else {
        2000 + yy as i32
    };

    Ok(ParsedTimecodeWithLeap::new(ParsedTimecode {
        year,
        month: mm_date,
        day: dd,
        hour: hh,
        minute: mm,
        second: ss,
        subsecond_ns: nanos,
        ..ParsedTimecode::default()
    }))
}

/// Parse a $GPZDA / $GNZDA sentence into a ParsedTimecode.
///
/// ZDA provides UTC time + date + local zone offset.
///
/// Fields: talker+ZDA, time, day, month, year, localZoneHours,
///         localZoneMinutes
fn parse_nmea_zda_timecode(fields: &[&str]) -> Result<ParsedTimecodeWithLeap, ParseError> {
    if fields.len() < 7 {
        return Err(ParseError::MissingField(format!(
            "ZDA requires at least 7 fields, got {}",
            fields.len()
        )));
    }

    let time_str = fields
        .get(1)
        .ok_or(ParseError::MissingField("ZDA time".into()))?;
    if time_str.is_empty() {
        return Err(ParseError::MissingField("ZDA time is empty".into()));
    }
    let (hh, mm, ss, nanos) = parse_nmea_time(time_str).ok_or(ParseError::InvalidValue(
        format!("ZDA invalid time: {time_str}"),
    ))?;

    let day_str = fields
        .get(2)
        .ok_or(ParseError::MissingField("ZDA day".into()))?;
    let day: u8 = day_str
        .parse()
        .map_err(|_| ParseError::InvalidValue(format!("ZDA invalid day: {day_str}")))?;

    let month_str = fields
        .get(3)
        .ok_or(ParseError::MissingField("ZDA month".into()))?;
    let month: u8 = month_str
        .parse()
        .map_err(|_| ParseError::InvalidValue(format!("ZDA invalid month: {month_str}")))?;

    let year_str = fields
        .get(4)
        .ok_or(ParseError::MissingField("ZDA year".into()))?;
    let year: i32 = year_str
        .parse()
        .map_err(|_| ParseError::InvalidValue(format!("ZDA invalid year: {year_str}")))?;

    let zone_hours_str = fields
        .get(5)
        .ok_or(ParseError::MissingField("ZDA zone hours".into()))?;
    let zone_hours: i32 = if zone_hours_str.is_empty() {
        0
    } else {
        zone_hours_str.parse().map_err(|_| {
            ParseError::InvalidValue(format!("ZDA invalid zone hours: {zone_hours_str}"))
        })?
    };

    let zone_minutes_str = fields
        .get(6)
        .ok_or(ParseError::MissingField("ZDA zone minutes".into()))?;
    let zone_minutes: i32 = if zone_minutes_str.is_empty() {
        0
    } else {
        zone_minutes_str.parse().map_err(|_| {
            ParseError::InvalidValue(format!("ZDA invalid zone minutes: {zone_minutes_str}"))
        })?
    };

    if day < 1 || day > 31 || month < 1 || month > 12 {
        return Err(ParseError::InvalidValue(format!(
            "ZDA invalid date: {year:04}-{month:02}-{day:02}"
        )));
    }

    // UTC offset in hours (zone_hours + zone_minutes/60).
    let utc_offset = zone_hours + if zone_hours >= 0 { 1 } else { -1 } * zone_minutes / 60;

    Ok(ParsedTimecodeWithLeap::new(ParsedTimecode {
        year,
        month,
        day,
        hour: hh,
        minute: mm,
        second: ss,
        subsecond_ns: nanos,
        utc_offset,
        ..ParsedTimecode::default()
    }))
}

// ──── Date/Time to NTP Timestamp Conversion ─────────────────────────────────

/// Convert a ParsedTimecode into an NTP 64-bit timestamp.
///
/// The civil date is converted to Unix seconds using a days-from-civil
/// algorithm, then shifted to the NTP epoch.
fn datetime_to_ntp(tc: &ParsedTimecode) -> Option<NtpTs64> {
    if tc.year == 0 {
        // No year available (e.g. GGA-only data) — cannot convert.
        return None;
    }
    if tc.month < 1 || tc.month > 12 || tc.day < 1 || tc.day > 31 {
        return None;
    }
    if tc.hour > 23 || tc.minute > 59 || tc.second > 60 {
        return None;
    }

    let unix_secs = civil_to_unix(tc.year as i64, tc.month as u32, tc.day as u32)
        + (tc.hour as i64) * 3600
        + (tc.minute as i64) * 60
        + (tc.second as i64);

    let ntp_secs = unix_secs + crate::ntp_fp::NTP_TO_UNIX_OFFSET as i64;

    // Convert sub-second nanoseconds to NTP fraction.
    let frac = ((tc.subsecond_ns as u64) << 32) / 1_000_000_000;

    Some(NtpTs64 {
        seconds: ntp_secs,
        fraction: frac as u32,
    })
}

/// Compute Unix epoch seconds for a civil date.
fn civil_to_unix(year: i64, month: u32, day: u32) -> i64 {
    let days = days_from_civil(year, month, day);
    let unix_epoch_days = days_from_civil(1970, 1, 1);
    (days - unix_epoch_days) * 86_400
}

/// Days from civil date using Howard Hinnant's algorithm.
///
/// Returns the number of days since the proleptic Gregorian epoch (0000-03-01).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as u32; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = (yoe * 365 + yoe / 4 - yoe / 100) as i64 + doy as i64;
    era * 146_097 + doe - 719_468 // 719468 = days from 0000-03-01 to 1970-01-01
}

// ──── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Fixed-width parser tests ───────────────────────────────────────

    #[test]
    fn test_parse_yyyymmddhhmmss() {
        let tc = parse_fixed_width_timecode("20241225143015", &["YYYYMMDDhhmmss"]).unwrap();
        assert_eq!(tc.year, 2024);
        assert_eq!(tc.month, 12);
        assert_eq!(tc.day, 25);
        assert_eq!(tc.hour, 14);
        assert_eq!(tc.minute, 30);
        assert_eq!(tc.second, 15);
    }

    #[test]
    fn test_parse_yymmddhhmmss() {
        let tc = parse_fixed_width_timecode("241225143015", &["yyMMDDhhmmss"]).unwrap();
        assert_eq!(tc.year, 2024);
        assert_eq!(tc.month, 12);
        assert_eq!(tc.day, 25);
    }

    #[test]
    fn test_parse_yy_before_70() {
        let tc = parse_fixed_width_timecode("691225143015", &["yyMMDDhhmmss"]).unwrap();
        assert_eq!(tc.year, 2069);
    }

    #[test]
    fn test_parse_short_string() {
        assert!(parse_fixed_width_timecode("2412", &["yyMMDDhhmmss"]).is_none());
    }

    #[test]
    fn test_parse_invalid_chars() {
        assert!(parse_fixed_width_timecode("abcdefghijkl", &["yyMMDDhhmmss"]).is_none());
    }

    #[test]
    fn test_parse_out_of_range_month() {
        assert!(parse_fixed_width_timecode("241300000000", &["yyMMDDhhmmss"]).is_none());
    }

    #[test]
    fn test_parse_out_of_range_day() {
        assert!(parse_fixed_width_timecode("240132000000", &["yyMMDDhhmmss"]).is_none());
    }

    #[test]
    fn test_parse_out_of_range_hour() {
        assert!(parse_fixed_width_timecode("240101240000", &["yyMMDDhhmmss"]).is_none());
    }

    #[test]
    fn test_parse_leap_second() {
        let tc = parse_fixed_width_timecode("240101235960", &["yyMMDDhhmmss"]).unwrap();
        assert_eq!(tc.second, 60);
    }

    // ─── NMEA checksum tests ────────────────────────────────────────────

    #[test]
    fn test_nmea_checksum_valid() {
        assert!(nmea_checksum_ok(
            "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47"
        ));
    }

    #[test]
    fn test_nmea_checksum_invalid() {
        assert!(!nmea_checksum_ok(
            "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*00"
        ));
    }

    #[test]
    fn test_nmea_checksum_missing_star() {
        assert!(!nmea_checksum_ok("$GPGGA,123519"));
    }

    #[test]
    fn test_nmea_checksum_rmc() {
        assert!(nmea_checksum_ok(
            "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A"
        ));
    }

    // ─── NMEA time parsing tests ────────────────────────────────────────

    #[test]
    fn test_parse_nmea_time_basic() {
        let (hh, mm, ss, ns) = parse_nmea_time("123519").unwrap();
        assert_eq!(hh, 12);
        assert_eq!(mm, 35);
        assert_eq!(ss, 19);
        assert_eq!(ns, 0);
    }

    #[test]
    fn test_parse_nmea_time_with_fraction() {
        let (hh, mm, ss, ns) = parse_nmea_time("123519.500").unwrap();
        assert_eq!(hh, 12);
        assert_eq!(mm, 35);
        assert_eq!(ss, 19);
        assert_eq!(ns, 500_000_000);
    }

    #[test]
    fn test_parse_nmea_time_with_microsecond() {
        let (_hh, _mm, _ss, ns) = parse_nmea_time("123519.005").unwrap();
        assert_eq!(ns, 5_000_000);
    }

    #[test]
    fn test_parse_nmea_time_invalid() {
        assert!(parse_nmea_time("").is_none());
        assert!(parse_nmea_time("12345").is_none());
        assert!(parse_nmea_time("256000").is_none()); // hour > 23
    }

    #[test]
    fn test_parse_nmea_date_basic() {
        let (dd, mm, yy) = parse_nmea_date("250324").unwrap();
        assert_eq!(dd, 25);
        assert_eq!(mm, 03);
        assert_eq!(yy, 24);
    }

    #[test]
    fn test_parse_nmea_date_invalid() {
        assert!(parse_nmea_date("000101").is_none()); // day=0
        assert!(parse_nmea_date("320101").is_none()); // day=32
        assert!(parse_nmea_date("011301").is_none()); // month=13
    }

    // ─── GGA parser tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_nmea_gga_timecode_valid() {
        let line = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.leap, LeapIndicator::NoWarning);
        assert_eq!(result.timecode.hour, 12);
        assert_eq!(result.timecode.minute, 35);
        assert_eq!(result.timecode.second, 19);
        assert_eq!(result.timecode.subsecond_ns, 0);
        // GGA has no date, so year remains 0.
        assert_eq!(result.timecode.year, 0);
    }

    #[test]
    fn test_parse_nmea_gga_timecode_with_fraction() {
        let line = "$GPGGA,123519.500,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*5C";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.timecode.hour, 12);
        assert_eq!(result.timecode.minute, 35);
        assert_eq!(result.timecode.second, 19);
        assert_eq!(result.timecode.subsecond_ns, 500_000_000);
    }

    #[test]
    fn test_parse_nmea_gga_bad_checksum() {
        let line = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*00";
        let result = parse_nmea_timecode(line);
        assert_eq!(result.unwrap_err(), ParseError::ChecksumError);
    }

    // ─── RMC parser tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_nmea_rmc_timecode_valid() {
        let line = "$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.timecode.year, 1994);
        assert_eq!(result.timecode.month, 3);
        assert_eq!(result.timecode.day, 23);
        assert_eq!(result.timecode.hour, 12);
        assert_eq!(result.timecode.minute, 35);
        assert_eq!(result.timecode.second, 19);
    }

    #[test]
    fn test_parse_nmea_rmc_timecode_modern() {
        let line = "$GPRMC,083559,A,1234.567,N,01234.567,E,000.0,360.0,251224,000.0,E*73";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.timecode.year, 2024);
        assert_eq!(result.timecode.month, 12);
        assert_eq!(result.timecode.day, 25);
        assert_eq!(result.timecode.hour, 08);
        assert_eq!(result.timecode.minute, 35);
        assert_eq!(result.timecode.second, 59);
    }

    #[test]
    fn test_parse_nmea_rmc_inactive() {
        // Status 'V' (void) should produce an error.
        let line = "$GPRMC,123519,V,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*7D";
        let result = parse_nmea_timecode(line);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::InvalidValue(s) => assert!(s.contains("status")),
            _ => panic!("expected InvalidValue"),
        }
    }

    #[test]
    fn test_parse_nmea_rmc_missing_time() {
        let line = "$GPRMC,,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*5D";
        let result = parse_nmea_timecode(line);
        assert!(result.is_err());
    }

    // ─── ZDA parser tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_nmea_zda_timecode_valid() {
        let line = "$GPZDA,083559,25,12,2024,00,00*4A";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.timecode.year, 2024);
        assert_eq!(result.timecode.month, 12);
        assert_eq!(result.timecode.day, 25);
        assert_eq!(result.timecode.hour, 08);
        assert_eq!(result.timecode.minute, 35);
        assert_eq!(result.timecode.second, 59);
        assert_eq!(result.timecode.utc_offset, 0);
    }

    #[test]
    fn test_parse_nmea_zda_with_zone_offset() {
        let line = "$GPZDA,083559,25,12,2024,+05,30*67";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.timecode.year, 2024);
        assert_eq!(result.timecode.month, 12);
        assert_eq!(result.timecode.day, 25);
        assert_eq!(result.timecode.hour, 08);
        assert_eq!(result.timecode.minute, 35);
        assert_eq!(result.timecode.second, 59);
        assert_eq!(result.timecode.utc_offset, 5);
    }

    #[test]
    fn test_parse_nmea_zda_negative_zone() {
        let line = "$GPZDA,083559,25,12,2024,-05,00*62";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.timecode.utc_offset, -5);
    }

    #[test]
    fn test_parse_nmea_zda_gnss_talker() {
        let line = "$GNZDA,083559,25,12,2024,00,00*54";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.timecode.year, 2024);
        assert_eq!(result.timecode.month, 12);
        assert_eq!(result.timecode.day, 25);
    }

    #[test]
    fn test_parse_nmea_zda_missing_field() {
        // Too few fields.
        let line = "$GPZDA,083559,25,12*53";
        let result = parse_nmea_timecode(line);
        assert!(result.is_err());
    }

    // ─── Unknown sentence test ──────────────────────────────────────────

    #[test]
    fn test_parse_unknown_sentence() {
        let line = "$GPGLL,4916.45,N,12311.12,W,225444,A*31";
        let result = parse_nmea_timecode(line);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::UnknownSentenceType(s) => assert!(s.contains("GLL")),
            _ => panic!("expected UnknownSentenceType"),
        }
    }

    // ─── TimecodeParser trait tests ─────────────────────────────────────

    #[test]
    fn test_fixed_width_parser_trait() {
        let parser = FixedWidthParser::new(&["yyMMDDhhmmss"]);
        let result = parser.parse("241225143015").unwrap();
        assert_eq!(result.timecode.year, 2024);
        assert_eq!(result.timecode.month, 12);
        assert_eq!(result.timecode.day, 25);
        assert_eq!(parser.source(), TimecodeSource::FixedWidth);
    }

    #[test]
    fn test_fixed_width_parser_format_mismatch() {
        let parser = FixedWidthParser::new(&["YYMMDDhhmmss"]);
        let result = parser.parse("short");
        assert!(result.is_err());
    }

    #[test]
    fn test_nmea_parser_trait_gga() {
        let parser = NmeaParser;
        let line = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
        let result = parser.parse(line).unwrap();
        assert_eq!(result.timecode.hour, 12);
    }

    #[test]
    fn test_nmea_parser_trait_rmc() {
        let parser = NmeaParser;
        let line = "$GPRMC,083559,A,1234.567,N,01234.567,E,000.0,360.0,251224,000.0,E*73";
        let result = parser.parse(line).unwrap();
        assert_eq!(result.timecode.year, 2024);
    }

    #[test]
    fn test_nmea_parser_trait_zda() {
        let parser = NmeaParser;
        let line = "$GPZDA,083559,25,12,2024,00,00*4A";
        let result = parser.parse(line).unwrap();
        assert_eq!(result.timecode.year, 2024);
    }

    #[test]
    fn test_nmea_parser_trait_bad_checksum() {
        let parser = NmeaParser;
        let line = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*00";
        let result = parser.parse(line);
        assert_eq!(result.unwrap_err(), ParseError::ChecksumError);
    }

    // ─── Composite parser tests ─────────────────────────────────────────

    #[test]
    fn test_composite_parser_first_wins() {
        let mut composite = CompositeParser::new();
        composite.add(NmeaParser);
        composite.add(FixedWidthParser::new(&["yyMMDDhhmmss"]));

        // NMEA sentence should be parsed by the NMEA parser.
        let result = composite
            .parse("$GPRMC,083559,A,1234.567,N,01234.567,E,000.0,360.0,251224,000.0,E*73")
            .unwrap();
        assert_eq!(result.timecode.year, 2024);
        assert_eq!(composite.source(), TimecodeSource::Unknown); // from NmeaParser

        // Fixed-width sentence should fall through to the fixed-width parser.
        let result = composite.parse("241225143015").unwrap();
        assert_eq!(result.timecode.year, 2024);
    }

    #[test]
    fn test_composite_parser_empty() {
        let composite = CompositeParser::<'_>::new();
        let result = composite.parse("anything");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ParseError::FormatMismatch("no parsers configured".into())
        );
    }

    #[test]
    fn test_composite_parser_all_fail() {
        let mut composite = CompositeParser::new();
        composite.add(FixedWidthParser::new(&["YYYYMMDDhhmmss"]));
        let result = composite.parse("short");
        assert!(result.is_err());
    }

    // ─── parse_to_ntp tests ─────────────────────────────────────────────

    #[test]
    fn test_parse_to_ntp_rmc() {
        let parser = NmeaParser;
        let line = "$GPRMC,083559,A,1234.567,N,01234.567,E,000.0,360.0,251224,000.0,E*73";
        let (ntp, leap) = parser.parse_to_ntp(line).unwrap();
        assert_eq!(leap, LeapIndicator::NoWarning);
        // 2024-12-25 08:35:59 UTC in NTP seconds.
        // Unix: 1735115759. NTP: 1735115759 + 2208988800 = 3944104559
        assert_eq!(ntp.seconds, 3_944_104_559);
    }

    #[test]
    fn test_parse_to_ntp_gga_no_date() {
        let parser = NmeaParser;
        let line = "$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
        // GGA has no date, so parse_to_ntp should fail.
        let result = parser.parse_to_ntp(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_to_ntp_fixed_width() {
        let parser = FixedWidthParser::new(&["yyMMDDhhmmss"]);
        let (ntp, leap) = parser.parse_to_ntp("241225143015").unwrap();
        assert_eq!(leap, LeapIndicator::NoWarning);
        // 2024-12-25 14:30:15 UTC in NTP seconds.
        assert_eq!(ntp.seconds, 3_944_125_815);
    }

    // ─── ParsedTimecodeWithLeap tests ───────────────────────────────────

    #[test]
    fn test_parsed_timecode_with_leap_new() {
        let tc = ParsedTimecode::default();
        let parsed = ParsedTimecodeWithLeap::new(tc);
        assert_eq!(parsed.leap, LeapIndicator::NoWarning);
    }

    #[test]
    fn test_parsed_timecode_with_leap_explicit() {
        let tc = ParsedTimecode::default();
        let parsed = ParsedTimecodeWithLeap::with_leap(tc, LeapIndicator::Alarm);
        assert_eq!(parsed.leap, LeapIndicator::Alarm);
    }

    // ─── ParseError tests ───────────────────────────────────────────────

    #[test]
    fn test_parse_error_display() {
        assert_eq!(format!("{}", ParseError::ChecksumError), "checksum error");
        assert_eq!(
            format!("{}", ParseError::UnknownSentenceType("GLL".into())),
            "unknown sentence type: GLL"
        );
        assert_eq!(
            format!("{}", ParseError::MissingField("time".into())),
            "missing field: time"
        );
    }

    // ─── Test RMC with GNRMC (GNSS talker) ──────────────────────────────

    #[test]
    fn test_parse_gnrmc_timecode() {
        let line = "$GNRMC,083559,A,1234.567,N,01234.567,E,000.0,360.0,251224,000.0,E*6D";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.timecode.year, 2024);
        assert_eq!(result.timecode.month, 12);
        assert_eq!(result.timecode.day, 25);
    }

    // ─── Test with GNZDA (GNSS talker) ──────────────────────────────────

    #[test]
    fn test_parse_gnzda_timecode() {
        let line = "$GNZDA,083559,25,12,2024,00,00*54";
        let result = parse_nmea_timecode(line).unwrap();
        assert_eq!(result.timecode.year, 2024);
    }

    // ─── datetime_to_ntp tests ─────────────────────────────────────────

    #[test]
    fn test_datetime_to_ntp_no_year() {
        let tc = ParsedTimecode {
            year: 0,
            hour: 12,
            minute: 0,
            second: 0,
            ..ParsedTimecode::default()
        };
        assert!(datetime_to_ntp(&tc).is_none());
    }

    #[test]
    fn test_datetime_to_ntp_out_of_range() {
        let tc = ParsedTimecode {
            year: 2024,
            month: 13,
            ..ParsedTimecode::default()
        };
        assert!(datetime_to_ntp(&tc).is_none());
    }

    // ─── Sentence ID extraction tests ───────────────────────────────────

    #[test]
    fn test_sentence_id_with_talker() {
        assert_eq!(sentence_id("GPGGA"), "GGA");
        assert_eq!(sentence_id("GNRMC"), "RMC");
        assert_eq!(sentence_id("GNZDA"), "ZDA");
        assert_eq!(sentence_id("GGA"), "GGA");
    }
}
