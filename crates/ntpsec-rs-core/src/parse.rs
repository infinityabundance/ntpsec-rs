// ──── parse.rs ──────────────────────────────────────────────────────────────
// Forensic reconstruction of include/parse.h, libparse/parse.c,
// libparse/parse_conf.c
//
// Reference clock timecode parsing engine.
// =============================================================================

/// Timecode parsing engine for refclock drivers.
/// Parses structured time information from serial timecode strings.

/// A parsed timecode result.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedTimecode {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub subsecond_ns: u32,
    pub utc_offset: i32,
    pub dst: bool,
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

/// Parse a numeric-only timecode string (fixed-width fields).
/// Supports formats like: YYMMDDHHMMSS, YYYYMMDDHHMMSS, HHMMSS, etc.
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
            // Consume consecutive identical format chars as one field
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
                    /* 4-digit year — consume exactly 4 digits */
                    if pos + 4 <= s.len() {
                        tc.year = s[pos..pos + 4].parse().ok()?;
                        pos += 4;
                    } else {
                        matched = false;
                        break;
                    }
                }
                'y' => {
                    /* 2-digit year — consume exactly 2 digits */
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
        if matched {
            return Some(tc);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
