// ──── refclock_hpgps.rs ───────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_hpgps.c
//
// HP GPS receiver refclock driver. Supports HP 58503A Time and Frequency
// Reference Receiver and HP Z3801A (with subtype 1).
//
// ## Oracle
//   - ntpd/refclock_hpgps.c (648 lines)
// =============================================================================

/// HP GPS receiver refclock.
///
/// Drives an HP 58503A or Z3801A GPS receiver via serial. Uses the
/// `:PTIME:CODE?` SCPI command to request timecode format 2 responses:
/// `T#yyyymmddhhmmssMFLRVcc<cr><lf>`
///
/// ## C-oracle struct
///   `struct hpgpsunit` in ntpd/refclock_hpgps.c
pub struct HpGpsRefclock {
    pub unit: u8,
    /// Seconds since last message
    pub idlesec: i32,
    /// Whether a poll has been called recently
    pub didpoll: bool,
    /// Command counter (collecting data)
    pub cmndcnt: u32,
    /// Line counter (collecting status screen)
    pub linecnt: i32,
}

impl HpGpsRefclock {
    /// Create a new HP GPS refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            idlesec: 0,
            didpoll: false,
            cmndcnt: 0,
            linecnt: 0,
        }
    }

    /// Open the HP GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/hpgps0`).
    ///
    /// ## C-oracle
    ///   `hpgps_start()` — opens device, configures termios (9600 baud
    ///   8N1 for 58503A, 19200 7O1 for Z3801A), sends initial poll.
    pub fn open(&mut self, _device: &str) -> Result<(), String> {
        Err(format!(
            "HP GPS refclock not yet implemented (unit {})",
            self.unit
        ))
    }

    /// Close the HP GPS receiver device.
    pub fn close(&mut self) {}

    /// Read one time sample from the receiver.
    ///
    /// ## C-oracle
    ///   `hpgps_receive()` — parses the `T#yyyymmddhhmmssMFLRVcc` timecode
    ///   format, extracts time and quality indicators.
    pub fn read_sample(&mut self) -> Result<Option<crate::ntp_refclock::RefClockSample>, String> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpgps_open_no_such_device() {
        let mut rc = HpGpsRefclock::new(1);
        let result = rc.open("/nonexistent/hpgps");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }
}
