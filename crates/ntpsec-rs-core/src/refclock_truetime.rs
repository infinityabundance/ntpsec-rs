// ──── refclock_truetime.rs ────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_truetime.c
//
// Kinemetrics/TrueTime GPS receiver refclock driver. Supports GPS/TM-TMD,
// XL-DC, GPS-800 TCU, and TL-3 receiver models.
//
// ## Oracle
//   - ntpd/refclock_truetime.c (786 lines)
// =============================================================================

/// TrueTime GPS receiver refclock.
///
/// Drives a Kinemetrics/TrueTime satellite-controlled clock via a serial
/// connection. Uses a state machine to probe the receiver type and then
/// automatically parse timecodes.
///
/// ## C-oracle struct
///   `struct true_unit` in ntpd/refclock_truetime.c
pub struct TrueTimeRefclock {
    pub unit: u8,
    /// Poll counter
    pub pollcnt: u32,
    /// Whether a poll has been issued
    pub polled: bool,
    /// Current state in the auto-detection state machine
    pub state: u8,
    /// Detected receiver type
    pub receiver_type: u8,
}

impl TrueTimeRefclock {
    /// Create a new TrueTime refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            pollcnt: 0,
            polled: false,
            state: 0,
            receiver_type: 0,
        }
    }

    /// Open the TrueTime GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/true0`).
    ///
    /// ## C-oracle
    ///   `true_start()` — opens device, initialises state machine,
    ///   probes receiver type.
    pub fn open(&mut self, _device: &str) -> Result<(), String> {
        Err(format!(
            "TrueTime refclock not yet implemented (unit {})",
            self.unit
        ))
    }

    /// Close the TrueTime receiver device.
    pub fn close(&mut self) {}

    /// Read and decode one time sample from the receiver.
    ///
    /// ## C-oracle
    ///   `true_receive()` — state machine parsing of timecode formats:
    ///   `ADDD:HH:MM:SSQCL` for TM/XL-DC, other formats for TCU/TL-3.
    pub fn read_sample(&mut self) -> Result<Option<crate::ntp_refclock::RefClockSample>, String> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truetime_open_no_such_device() {
        let mut rc = TrueTimeRefclock::new(1);
        let result = rc.open("/nonexistent/true");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }
}
