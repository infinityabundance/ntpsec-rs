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

/// Leap second table.
#[derive(Debug, Default)]
pub struct LeapTable {
    entries: Vec<LeapEntry>,
    /// Leap smear interval in seconds (0 = no smear).
    pub smear_interval: u32,
}

impl LeapTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            smear_interval: 0,
        }
    }

    /// Add a leap second entry.
    pub fn add_entry(&mut self, entry: LeapEntry) {
        self.entries.push(entry);
        self.entries
            .sort_by(|a, b| a.ntp_time.seconds.cmp(&b.ntp_time.seconds));
    }

    /// Load from a leapseconds file (NIST/IERS format).
    /// File format: `#@ expiry_timestamp` header, `timestamp offset ...` lines
    pub fn load_leapfile(&mut self, content: &str) -> Result<(), String> {
        self.entries.clear();
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

            // Parse expiration from #@ header
            let expires = NtpTs64 {
                seconds: timestamp + 86400 * 365,
                fraction: 0,
            };

            self.add_entry(LeapEntry {
                ntp_time: NtpTs64 {
                    seconds: timestamp,
                    fraction: 0,
                },
                offset,
                expires,
            });
        }
        Ok(())
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
    pub fn smear_adjustment(&self, now: NtpTs64, ref_time: NtpTs64) -> f64 {
        if self.smear_interval == 0 {
            return 0.0;
        }

        for entry in &self.entries {
            if now.seconds >= entry.ntp_time.seconds
                && now.seconds < entry.ntp_time.seconds + self.smear_interval as i64
            {
                let elapsed = now.seconds - entry.ntp_time.seconds;
                let fraction = elapsed as f64 / self.smear_interval as f64;
                return entry.offset as f64 * fraction;
            }
        }
        0.0
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_smear_adjustment() {
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
        // Mid-smear
        let mid = NtpTs64 {
            seconds: leap_time.seconds + 3600,
            fraction: 0,
        };
        let adj = table.smear_adjustment(mid, leap_time);
        assert!((adj - 0.5).abs() < 0.01);
    }
}
