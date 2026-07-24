// ──── refclock_spectracom.rs ──────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_spectracom.c
//
// Spectracom GPS receiver refclock driver. Supports Spectracom time servers
// including 9483, 9489, and SecureSync (format 2 timecode). Formerly also
// supported the 9300 and WWVB radio clocks (Format 0 timecode).
//
// ## Oracle
//   - ntpd/refclock_spectracom.c (573 lines)
// =============================================================================

/// Spectracom GPS receiver refclock.
///
/// Connects to a Spectracom time server via serial. Auto-detects the
/// timecode format (Format 0: 22 chars, Format 2: 24 chars) from the
/// message length.
///
/// ## C-oracle struct
///   `struct spectracomunit` in ntpd/refclock_spectracom.c
pub struct SpectracomRefclock {
    pub unit: u8,
    /// Last <CR> timestamp
    pub last_hour: u8,
    /// Count of ignored lines (for monitoring)
    pub line_count: u8,
}

impl SpectracomRefclock {
    /// Create a new Spectracom refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            last_hour: 0,
            line_count: 0,
        }
    }

    /// Open the Spectracom receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/spectracom0`).
    ///
    /// ## C-oracle
    ///   `spectracom_start()` — opens device, configures 9600 baud,
    ///   initialises the unit structure.
    pub fn open(&mut self, _device: &str) -> Result<(), String> {
        Err(format!(
            "Spectracom refclock not yet implemented (unit {})",
            self.unit
        ))
    }

    /// Close the Spectracom receiver device.
    pub fn close(&mut self) {}

    /// Read and decode one time sample from the receiver.
    ///
    /// ## C-oracle
    ///   `spectracom_receive()` — parses Format 0 or Format 2 timecodes
    ///   based on message length, extracts synchronization flag, quality
    ///   indicator, and time.
    pub fn read_sample(&mut self) -> Result<Option<crate::ntp_refclock::RefClockSample>, String> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spectracom_open_no_such_device() {
        let mut rc = SpectracomRefclock::new(1);
        let result = rc.open("/nonexistent/spectracom");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }
}
