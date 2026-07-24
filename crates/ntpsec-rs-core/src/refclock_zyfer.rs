// ──── refclock_zyfer.rs ───────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_zyfer.c
//
// Zyfer GPStarplus GPS receiver refclock driver.
//
// ## Oracle
//   - ntpd/refclock_zyfer.c (301 lines)
// =============================================================================

/// Zyfer GPStarplus refclock.
///
/// Drives a Zyfer GPStarplus clock via its TOD serial port. The clock
/// sends one timecode per second in the format:
/// `!TIME,YYYY,DDD,HH,MM,SS,m,T,O<CR>`
/// where `!` is the on-time character, `m` is time mode, `T` is time
/// figure of merit, and `O` is operation mode.
///
/// ## C-oracle struct
///   `struct zyferunit` in ntpd/refclock_zyfer.c
pub struct ZyferRefclock {
    pub unit: u8,
    /// Poll message flag
    pub polled: u8,
    /// Poll counter
    pub pollcnt: i32,
    /// Receive buffer pointer
    pub rcvptr: i32,
}

impl ZyferRefclock {
    /// Create a new Zyfer refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            polled: 0,
            pollcnt: 0,
            rcvptr: 0,
        }
    }

    /// Open the Zyfer GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/zyfer0`).
    ///
    /// ## C-oracle
    ///   `zyfer_start()` — opens device, configures 9600 baud 8N1.
    pub fn open(&mut self, _device: &str) -> Result<(), String> {
        Err(format!(
            "Zyfer refclock not yet implemented (unit {})",
            self.unit
        ))
    }

    /// Close the Zyfer receiver device.
    pub fn close(&mut self) {}

    /// Read one time sample from the receiver.
    ///
    /// ## C-oracle
    ///   `zyfer_receive()` — parses the `!TIME,YYYY,DDD,HH,MM,SS,m,T,O`
    ///   timecode, validates time mode (must be UTC=2) and TFOM.
    pub fn read_sample(&mut self) -> Result<Option<crate::ntp_refclock::RefClockSample>, String> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zyfer_open_no_such_device() {
        let mut rc = ZyferRefclock::new(1);
        let result = rc.open("/nonexistent/zyfer");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }
}
