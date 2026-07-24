// ──── ntp_leapsec.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_leapsec.c, ntpd/ntp_leapsec.h
//
// Leap second table management: loading, querying, and applying leap second
// corrections. Supports both historic leap table and leap smear.
//
// ## Oracle
//   - ntpsec ntpd/ntp_leapsec.c (25K)
//   - ntpsec ntpd/ntp_leapsec.h (9K)
//   - RFC 5905 §12.4 (leap indicators)
// =============================================================================

use crate::ntp_types::*;
use sha1::{Digest, Sha1};

/// Default smear interval in seconds (narrow = 2h, wide = 24h).
pub const LEAP_SMEAR_DEFAULT: u32 = 86400; // 24 hours, matching ntpsec default

/// A single leap second entry.
#[derive(Debug, Clone, Copy)]
pub struct LeapEntry {
    /// NTP timestamp of the leap event.
    pub ntp_time: NtpTs64,
    /// Leap offset (+1 or -1 seconds).
    pub offset: i8,
    /// Expiration time (when this entry is no longer valid).
    pub expires: NtpTs64,
}

/// Leap info structure returned when loading a leap file.
/// Used by daemon_engine to pass loaded leap data to the LeapTable.
#[derive(Debug, Clone)]
pub struct LeapInfo {
    pub entries: Vec<LeapEntry>,
    pub expires: Option<NtpTs64>,
    pub tai_offset: i8,
}

/// Load a leapfile from disk and return parsed LeapInfo.
impl LeapInfo {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read leapfile '{}': {}", path, e))?;
        let mut table = LeapTable::new();
        table.load_leapfile(&content)?;
        Ok(LeapInfo {
            entries: table.entries.clone(),
            expires: table.file_expires,
            tai_offset: table.tai_offset,
        })
    }
}

/// Leap second table.
#[derive(Debug, Default)]
pub struct LeapTable {
    pub entries: Vec<LeapEntry>,
    /// Leap smear interval in seconds (0 = no smear).
    pub smear_interval: u32,
    /// Expiration of the most recently loaded leapfile.
    file_expires: Option<NtpTs64>,
    /// TAI offset (TAI - UTC) derived from cumulative leap seconds.
    tai_offset: i8,
}

impl LeapTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            smear_interval: 0,
            file_expires: None,
            tai_offset: 0,
        }
    }

    /// Add a leap second entry.
    pub fn add_entry(&mut self, entry: LeapEntry) {
        // Update TAI offset based on the cumulative leap seconds
        self.tai_offset += entry.offset;
        self.entries.push(entry);
        self.entries
            .sort_by(|a, b| a.ntp_time.seconds.cmp(&b.ntp_time.seconds));
    }

    /// Parse header lines from a NIST/IERS leapfile.
    /// Returns (expiration_ntp_ts, sha1_hash_string) if present.
    fn parse_leapfile_header(content: &str) -> (Option<NtpTs64>, Option<String>) {
        let mut expiration: Option<NtpTs64> = None;
        let mut hash: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("#@") {
                // #@ expiration_timestamp (NTP timestamp of file expiry)
                let rest = line[2..].trim();
                if let Ok(secs) = rest.parse::<i64>() {
                    expiration = Some(NtpTs64 {
                        seconds: secs,
                        fraction: 0,
                    });
                }
            } else if line.starts_with("#$") {
                // #$ sha1_hash_value
                let rest = line[2..].trim();
                if !rest.is_empty() {
                    hash = Some(rest.to_string());
                }
            } else if !line.starts_with('#') && !line.is_empty() {
                // First data line — headers are done
                break;
            }
        }

        // If no explicit expiration was found, scan forward: the expiration
        // is commonly the last comment line before the data.
        if expiration.is_none() {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("#@") {
                    let rest = line[2..].trim();
                    if let Ok(secs) = rest.parse::<i64>() {
                        expiration = Some(NtpTs64 {
                            seconds: secs,
                            fraction: 0,
                        });
                    }
                } else if !line.starts_with('#') && !line.is_empty() {
                    break;
                }
            }
        }

        (expiration, hash)
    }

    /// Validate the SHA-1 hash of the leapfile content.
    /// The hash in `#$` covers the data body (all lines from the first
    /// non-header line through end-of-file). Returns true if valid or
    /// if no hash was specified.
    pub fn validate_hash(content: &str, expected_hash: &str) -> bool {
        // Hash covers the body: all non-#@, non-#$ lines
        let mut hasher = Sha1::new();
        let mut in_body = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if !in_body {
                if !trimmed.starts_with('#') && !trimmed.is_empty() {
                    in_body = true;
                    // This line is part of the body
                    hasher.update(line.as_bytes());
                    hasher.update(b"\n");
                }
                // Skip header lines (#@, #$, #, empty)
                continue;
            }
            // Body lines
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }

        let computed = hex::encode(hasher.finalize());
        computed.to_uppercase() == expected_hash.trim().to_uppercase()
    }

    /// Load from a leapseconds file (NIST/IERS format).
    /// File format:
    ///   #@ expiry_timestamp
    ///   #$ sha1_hash (optional)
    ///   timestamp offset ...
    pub fn load_leapfile(&mut self, content: &str) -> Result<(), String> {
        self.entries.clear();
        self.file_expires = None;
        self.tai_offset = 0;

        // Parse headers
        let (expiration, hash) = Self::parse_leapfile_header(content);

        // Validate hash if present
        if let Some(ref expected) = hash {
            if !Self::validate_hash(content, expected) {
                return Err("leapfile SHA-1 hash mismatch: file may be corrupt or tampered".into());
            }
        }

        // Parse entries
        let mut parsed_entries: Vec<LeapEntry> = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let timestamp: i64 = parts[0]
                .parse()
                .map_err(|_| format!("invalid timestamp: {}", parts[0]))?;
            let offset: i8 = parts[1]
                .parse()
                .map_err(|_| format!("invalid offset: {}", parts[1]))?;

            let expires = expiration.unwrap_or(NtpTs64 {
                seconds: timestamp + 86400 * 365,
                fraction: 0,
            });

            parsed_entries.push(LeapEntry {
                ntp_time: NtpTs64 {
                    seconds: timestamp,
                    fraction: 0,
                },
                offset,
                expires,
            });

            self.tai_offset += offset;
        }

        // Sort entries by time
        parsed_entries.sort_by(|a, b| a.ntp_time.seconds.cmp(&b.ntp_time.seconds));
        self.entries = parsed_entries;
        self.file_expires = expiration;

        Ok(())
    }

    /// Check if the loaded leapfile has expired relative to `now`.
    /// Returns true if the file has an expiration date and `now` is past it.
    pub fn is_expired(&self, now: NtpTs64) -> bool {
        match self.file_expires {
            Some(exp) => now.seconds >= exp.seconds,
            None => false,
        }
    }

    /// Get the file expiration timestamp, if one was loaded.
    pub fn file_expiration(&self) -> Option<NtpTs64> {
        self.file_expires
    }

    /// Get the current TAI offset (TAI - UTC) derived from cumulative
    /// leap seconds in the loaded leapfile.
    pub fn tai_offset(&self) -> i8 {
        self.tai_offset
    }

    /// Query the leap status at a given NTP timestamp.
    /// Returns None if no leap event is pending.
    pub fn query(&self, now: NtpTs64) -> Option<LeapIndicator> {
        for entry in &self.entries {
            if entry.expires.seconds > now.seconds && now.seconds >= entry.ntp_time.seconds - 86400
            {
                if entry.offset > 0 {
                    return Some(LeapIndicator::AddLeapSecond);
                } else {
                    return Some(LeapIndicator::RemoveLeapSecond);
                }
            }
        }
        None
    }

    /// Apply leap smear adjustment at a given time.
    /// Returns the smear adjustment in seconds.
    /// This is the "to be applied" offset at the given time.
    pub fn smear_adjustment(&self, now: NtpTs64, _ref_time: NtpTs64) -> f64 {
        if self.smear_interval == 0 {
            return 0.0;
        }

        for entry in &self.entries {
            if now.seconds >= entry.ntp_time.seconds
                && now.seconds < entry.ntp_time.seconds + self.smear_interval as i64
            {
                let elapsed = now.seconds - entry.ntp_time.seconds;
                let fraction = elapsed as f64 / self.smear_interval as f64;
                // ntpsec's exact smear: linear interpolation
                // offset goes from full value to 0 over the smear window
                return entry.offset as f64 * (1.0 - fraction);
            }
        }
        0.0
    }

    /// Compute the smear offset at a given NTP timestamp.
    /// This is a convenience wrapper around smear_adjustment that
    /// derives the reference time from the leap table itself.
    pub fn smear_offset(&self, now: NtpTs64) -> f64 {
        if self.smear_interval == 0 || self.entries.is_empty() {
            return 0.0;
        }

        // Find the nearest leap second event
        // If we're within a smear window, return the adjustment
        for entry in &self.entries {
            let window_start = entry.ntp_time.seconds;
            let window_end = window_start + self.smear_interval as i64;
            if now.seconds >= window_start && now.seconds < window_end {
                let elapsed = now.seconds - window_start;
                let fraction = elapsed as f64 / self.smear_interval as f64;
                return entry.offset as f64 * (1.0 - fraction);
            }
        }

        // If exactly at the leap boundary (after smear), return 0
        0.0
    }

    /// Update the table from a LeapInfo (e.g., from a file reload).
    pub fn update(&mut self, info: LeapInfo) {
        self.entries = info.entries;
        self.file_expires = info.expires;
        self.tai_offset = info.tai_offset;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries as a slice.
    pub fn entries(&self) -> &[LeapEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAPFILE_SAMPLE: &str = "\
#@ 3890592000
#$ 672b7c6a8a5c6b3f0e1d2c3a4b5f6e7d8c9a0b1c
# $Updated: 2024-01-01 00:00:00 UTC
#
#  NIST Leap Second File
#  Lines starting with #$ define SHA-1 hash
#
#@ 3890592000
#
3692217600	1	0	0	0	0
3710966400	1	0	0	0	0
3730752000	1	0	0	0	0
3750624000	1	0	0	0	0
3770481600	1	0	0	0	0
3790339200	1	0	0	0	0
3810096000	1	0	0	0	0
3829944000	1	0	0	0	0
3849696000	1	0	0	0	0
3869544000	1	0	0	0	0
3889296000	1	0	0	0	0
";

    fn make_sample_leapfile() -> String {
        // Generate the SHA-1 hash for the sample data
        let body_lines = [
            "3692217600\t1\t0\t0\t0\t0",
            "3710966400\t1\t0\t0\t0\t0",
            "3730752000\t1\t0\t0\t0\t0",
            "3750624000\t1\t0\t0\t0\t0",
            "3770481600\t1\t0\t0\t0\t0",
            "3790339200\t1\t0\t0\t0\t0",
            "3810096000\t1\t0\t0\t0\t0",
            "3829944000\t1\t0\t0\t0\t0",
            "3849696000\t1\t0\t0\t0\t0",
            "3869544000\t1\t0\t0\t0\t0",
            "3889296000\t1\t0\t0\t0\t0",
        ];
        let mut hasher = Sha1::new();
        for (i, line) in body_lines.iter().enumerate() {
            hasher.update(line.as_bytes());
            if i < body_lines.len() - 1 || !line.is_empty() {
                hasher.update(b"\n");
            }
        }
        let hash = hex::encode(hasher.finalize());

        format!(
            "\
#@ 3890592000
#$ {}
# $Updated: 2024-01-01 00:00:00 UTC
#
#  NIST Leap Second File
#
#@ 3890592000
#
3692217600\t1\t0\t0\t0\t0
3710966400\t1\t0\t0\t0\t0
3730752000\t1\t0\t0\t0\t0
3750624000\t1\t0\t0\t0\t0
3770481600\t1\t0\t0\t0\t0
3790339200\t1\t0\t0\t0\t0
3810096000\t1\t0\t0\t0\t0
3829944000\t1\t0\t0\t0\t0
3849696000\t1\t0\t0\t0\t0
3869544000\t1\t0\t0\t0\t0
3889296000\t1\t0\t0\t0\t0
",
            hash.to_uppercase()
        )
    }

    #[test]
    fn test_leap_table_add() {
        let mut table = LeapTable::new();
        table.add_entry(LeapEntry {
            ntp_time: NtpTs64 {
                seconds: 3_892_073_600,
                fraction: 0,
            },
            offset: 1,
            expires: NtpTs64 {
                seconds: 3_892_073_600 + 86400 * 365,
                fraction: 0,
            },
        });
        assert_eq!(table.len(), 1);
        assert_eq!(table.tai_offset(), 1);
    }

    #[test]
    fn test_leap_table_query() {
        let mut table = LeapTable::new();
        let leap_time = NtpTs64 {
            seconds: 3_892_073_600,
            fraction: 0,
        };
        table.add_entry(LeapEntry {
            ntp_time: leap_time,
            offset: 1,
            expires: NtpTs64 {
                seconds: 3_892_073_600 + 86400 * 365,
                fraction: 0,
            },
        });
        // Query the day before the leap
        let before = NtpTs64 {
            seconds: leap_time.seconds - 3600,
            fraction: 0,
        };
        assert!(table.query(before).is_some());
    }

    #[test]
    fn test_smear_adjustment_correct_formula() {
        let mut table = LeapTable::new();
        table.smear_interval = 7200; // 2-hour smear
        let leap_time = NtpTs64 {
            seconds: 3_892_073_600,
            fraction: 0,
        };
        table.add_entry(LeapEntry {
            ntp_time: leap_time,
            offset: 1,
            expires: NtpTs64 {
                seconds: 3_892_073_600 + 86400 * 365,
                fraction: 0,
            },
        });
        // At the start of smear (elapsed=0): offset = 1 * (1 - 0) = 1.0
        let start = NtpTs64 {
            seconds: leap_time.seconds,
            fraction: 0,
        };
        assert!((table.smear_adjustment(start, leap_time) - 1.0).abs() < 0.001);

        // Mid-smear (elapsed=3600, fraction=0.5): offset = 1 * (1 - 0.5) = 0.5
        let mid = NtpTs64 {
            seconds: leap_time.seconds + 3600,
            fraction: 0,
        };
        let adj = table.smear_adjustment(mid, leap_time);
        assert!((adj - 0.5).abs() < 0.01);

        // End of smear (elapsed=7200, fraction=1.0): offset = 1 * (1 - 1) = 0.0
        let end = NtpTs64 {
            seconds: leap_time.seconds + 7200,
            fraction: 0,
        };
        assert!((table.smear_adjustment(end, leap_time)).abs() < 0.001);
    }

    #[test]
    fn test_smear_offset_convenience() {
        let mut table = LeapTable::new();
        table.smear_interval = 3600;
        let leap_time = NtpTs64 {
            seconds: 3_892_073_600,
            fraction: 0,
        };
        table.add_entry(LeapEntry {
            ntp_time: leap_time,
            offset: -1, // negative leap second
            expires: NtpTs64 {
                seconds: 3_892_073_600 + 86400 * 365,
                fraction: 0,
            },
        });

        // At start: offset = -1 * (1 - 0) = -1.0
        let start = NtpTs64 {
            seconds: leap_time.seconds,
            fraction: 0,
        };
        assert!((table.smear_offset(start) - (-1.0)).abs() < 0.001);

        // Halfway: offset = -1 * (1 - 0.5) = -0.5
        let mid = NtpTs64 {
            seconds: leap_time.seconds + 1800,
            fraction: 0,
        };
        assert!((table.smear_offset(mid) - (-0.5)).abs() < 0.01);

        // Well past smear: 0
        let past = NtpTs64 {
            seconds: leap_time.seconds + 7200,
            fraction: 0,
        };
        assert!((table.smear_offset(past)).abs() < 0.001);

        // Before smear: 0
        let before = NtpTs64 {
            seconds: leap_time.seconds - 3600,
            fraction: 0,
        };
        assert!((table.smear_offset(before)).abs() < 0.001);
    }

    #[test]
    fn test_no_smear_when_interval_zero() {
        let table = LeapTable::new();
        let now = NtpTs64 {
            seconds: 3_892_073_600,
            fraction: 0,
        };
        assert!((table.smear_offset(now)).abs() < 0.001);
    }

    #[test]
    fn test_parse_leapfile_header() {
        let content = "#@ 3890592000\n#$ ABCDEF1234567890ABCDEF1234567890ABCDEF12\n# comment\n3692217600\t1\n";
        let (expiration, hash) = LeapTable::parse_leapfile_header(content);
        assert!(expiration.is_some());
        assert_eq!(expiration.unwrap().seconds, 3_890_592_000);
        assert_eq!(hash.unwrap(), "ABCDEF1234567890ABCDEF1234567890ABCDEF12");
    }

    #[test]
    fn test_load_leapfile_with_hash_validation() {
        let leapfile = make_sample_leapfile();
        let mut table = LeapTable::new();
        let result = table.load_leapfile(&leapfile);
        assert!(result.is_ok(), "load failed: {:?}", result.err());
        assert_eq!(table.len(), 11);
        assert_eq!(table.tai_offset(), 11); // all +1 offsets
        assert!(table.file_expiration().is_some());
        assert_eq!(table.file_expiration().unwrap().seconds, 3_890_592_000);
    }

    #[test]
    fn test_is_expired() {
        let leapfile = make_sample_leapfile();
        let mut table = LeapTable::new();
        table.load_leapfile(&leapfile).unwrap();

        // Before expiration
        let before = NtpTs64 {
            seconds: 3_890_591_999,
            fraction: 0,
        };
        assert!(!table.is_expired(before));

        // At expiration
        let at = NtpTs64 {
            seconds: 3_890_592_000,
            fraction: 0,
        };
        assert!(table.is_expired(at));

        // After expiration
        let after = NtpTs64 {
            seconds: 3_890_592_001,
            fraction: 0,
        };
        assert!(table.is_expired(after));
    }

    #[test]
    fn test_tai_offset_cumulative() {
        let mut table = LeapTable::new();
        assert_eq!(table.tai_offset(), 0);

        table.add_entry(LeapEntry {
            ntp_time: NtpTs64 {
                seconds: 3_692_217_600,
                fraction: 0,
            },
            offset: 1,
            expires: NtpTs64 {
                seconds: 3_692_217_600 + 86400 * 365,
                fraction: 0,
            },
        });
        assert_eq!(table.tai_offset(), 1);

        table.add_entry(LeapEntry {
            ntp_time: NtpTs64 {
                seconds: 3_710_966_400,
                fraction: 0,
            },
            offset: 1,
            expires: NtpTs64 {
                seconds: 3_710_966_400 + 86400 * 365,
                fraction: 0,
            },
        });
        assert_eq!(table.tai_offset(), 2);

        // Negative leap second
        table.add_entry(LeapEntry {
            ntp_time: NtpTs64 {
                seconds: 3_730_752_000,
                fraction: 0,
            },
            offset: -1,
            expires: NtpTs64 {
                seconds: 3_730_752_000 + 86400 * 365,
                fraction: 0,
            },
        });
        assert_eq!(table.tai_offset(), 1);
    }

    #[test]
    fn test_hash_validation_correct() {
        let leapfile = make_sample_leapfile();
        // Extract the expected hash from the file itself
        let expected = leapfile
            .lines()
            .find(|l| l.trim().starts_with("#$"))
            .map(|l| l[2..].trim().to_string())
            .unwrap_or_default();
        assert!(!expected.is_empty(), "no hash found in leapfile");
        assert!(LeapTable::validate_hash(&leapfile, &expected));
    }

    #[test]
    fn test_hash_validation_wrong() {
        let leapfile = make_sample_leapfile();
        assert!(!LeapTable::validate_hash(
            &leapfile,
            "0000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_load_without_hash_still_works() {
        let content = "#@ 3890592000\n# no hash line\n3692217600\t1\n3710966400\t-1\n";
        let mut table = LeapTable::new();
        let result = table.load_leapfile(content);
        assert!(result.is_ok());
        assert_eq!(table.len(), 2);
        assert_eq!(table.tai_offset(), 0); // +1 + -1 = 0
    }

    #[test]
    fn test_load_empty_file() {
        let mut table = LeapTable::new();
        let result = table.load_leapfile("");
        assert!(result.is_ok());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_load_invalid_timestamp() {
        let mut table = LeapTable::new();
        let result = table.load_leapfile("notanumber 1");
        assert!(result.is_err());
    }

    #[test]
    fn test_entries_sorted_by_time() {
        let mut table = LeapTable::new();
        table.add_entry(LeapEntry {
            ntp_time: NtpTs64 {
                seconds: 3_892_073_600,
                fraction: 0,
            },
            offset: 1,
            expires: NtpTs64 {
                seconds: 3_892_073_600 + 86400 * 365,
                fraction: 0,
            },
        });
        table.add_entry(LeapEntry {
            ntp_time: NtpTs64 {
                seconds: 3_692_217_600,
                fraction: 0,
            },
            offset: 1,
            expires: NtpTs64 {
                seconds: 3_692_217_600 + 86400 * 365,
                fraction: 0,
            },
        });
        let entries = table.entries();
        assert_eq!(entries[0].ntp_time.seconds, 3_692_217_600);
        assert_eq!(entries[1].ntp_time.seconds, 3_892_073_600);
    }

    #[test]
    fn test_query_outside_range() {
        let mut table = LeapTable::new();
        let leap_time = NtpTs64 {
            seconds: 3_892_073_600,
            fraction: 0,
        };
        table.add_entry(LeapEntry {
            ntp_time: leap_time,
            offset: 1,
            expires: NtpTs64 {
                seconds: 3_892_073_600 + 86400 * 365,
                fraction: 0,
            },
        });
        // Too far before
        let too_early = NtpTs64 {
            seconds: leap_time.seconds - 86401,
            fraction: 0,
        };
        assert!(table.query(too_early).is_none());

        // Past expiration
        let too_late = NtpTs64 {
            seconds: leap_time.seconds + 86400 * 365 + 1,
            fraction: 0,
        };
        assert!(table.query(too_late).is_none());
    }

    #[test]
    fn test_negative_leap_second_query() {
        let mut table = LeapTable::new();
        let leap_time = NtpTs64 {
            seconds: 3_892_073_600,
            fraction: 0,
        };
        table.add_entry(LeapEntry {
            ntp_time: leap_time,
            offset: -1,
            expires: NtpTs64 {
                seconds: 3_892_073_600 + 86400 * 365,
                fraction: 0,
            },
        });
        let before = NtpTs64 {
            seconds: leap_time.seconds - 3600,
            fraction: 0,
        };
        assert_eq!(table.query(before), Some(LeapIndicator::RemoveLeapSecond));
    }

    #[test]
    fn test_smear_negative_leap() {
        let mut table = LeapTable::new();
        table.smear_interval = 3600;
        let leap_time = NtpTs64 {
            seconds: 3_892_073_600,
            fraction: 0,
        };
        table.add_entry(LeapEntry {
            ntp_time: leap_time,
            offset: -1,
            expires: NtpTs64 {
                seconds: 3_892_073_600 + 86400 * 365,
                fraction: 0,
            },
        });
        // Quarter smear: -1 * (1 - 0.25) = -0.75
        let qtr = NtpTs64 {
            seconds: leap_time.seconds + 900,
            fraction: 0,
        };
        assert!((table.smear_offset(qtr) - (-0.75)).abs() < 0.01);
    }

    #[test]
    fn test_file_expiration_none() {
        let mut table = LeapTable::new();
        let result = table.load_leapfile("3692217600\t1\n");
        assert!(result.is_ok());
        assert!(table.file_expiration().is_none());
        assert!(!table.is_expired(NtpTs64 {
            seconds: i64::MAX,
            fraction: 0,
        }));
    }

    #[test]
    fn test_parse_header_fields() {
        let content = "\
#@ 4000000000
#$ DEADBEEF0123456789ABCDEF0123456789ABCDEF
# comment
# another comment
3692217600	1	0	0	0	0
";
        let (exp, hash) = LeapTable::parse_leapfile_header(content);
        assert!(exp.is_some());
        assert_eq!(exp.unwrap().seconds, 4_000_000_000);
        assert!(hash.is_some());
        assert_eq!(hash.unwrap(), "DEADBEEF0123456789ABCDEF0123456789ABCDEF");
    }

    #[test]
    fn test_smear_no_entries() {
        let table = LeapTable::new();
        let now = NtpTs64 {
            seconds: 3_892_073_600,
            fraction: 0,
        };
        assert_eq!(table.smear_offset(now), 0.0);
    }
}
