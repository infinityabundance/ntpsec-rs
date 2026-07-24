// ──── refclock_arbiter.rs ─────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_arbiter.c
//
// Arbiter 1088A/B Satellite Controlled Clock refclock driver.
//
// ## Oracle
//   - ntpd/refclock_arbiter.c (445 lines)
// =============================================================================

/// Arbiter 1088A/B GPS refclock.
///
/// Drives an Arbiter 1088A/B Satellite Controlled Clock via serial.
/// Uses the B5 poll sequence to obtain timecode in format:
/// `<cr><lf>i yy ddd hh:mm:ss.000bbb`
///
/// ## C-oracle struct
///   `struct arbunit` in ntpd/refclock_arbiter.c
pub struct ArbiterRefclock {
    pub unit: u8,
    /// IEEE P1344 quality character (from TQ command)
    pub qualchar: Option<char>,
    /// Receiver status string (from SR command)
    pub status: Option<String>,
    /// Receiver position string (lat/lon/alt)
    pub latlon: Option<String>,
}

impl ArbiterRefclock {
    /// Create a new Arbiter refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            qualchar: None,
            status: None,
            latlon: None,
        }
    }

    /// Open the Arbiter GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/gps0`).
    ///
    /// ## C-oracle
    ///   `arb_start()` — opens device, configures 9600 baud, sends the
    ///   B5 poll sequence to initiate timecode broadcast.
    pub fn open(&mut self, _device: &str) -> Result<(), String> {
        Err(format!(
            "Arbiter refclock not yet implemented (unit {})",
            self.unit
        ))
    }

    /// Close the Arbiter receiver device.
    pub fn close(&mut self) {}

    /// Read one time sample from the receiver.
    ///
    /// ## C-oracle
    ///   `arb_receive()` — parses the B5 format timecode and optionally
    ///   extracts the TQ quality character and SR status string.
    pub fn read_sample(&mut self) -> Result<Option<crate::ntp_refclock::RefClockSample>, String> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arbiter_open_no_such_device() {
        let mut rc = ArbiterRefclock::new(1);
        let result = rc.open("/nonexistent/gps");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }
}
