// ──── refclock_oncore.rs ──────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_oncore.c
//
// Motorola Oncore GPS receiver refclock driver. Supports Basic, PVT6, VP,
// UT, UT+, GT, GT+, SL, M12, and M12+T receiver models.
//
// ## Oracle
//   - ntpd/refclock_oncore.c (4152 lines)
// =============================================================================

/// Motorola Oncore GPS refclock.
///
/// Drives a Motorola Oncore GPS receiver via a serial device and
/// optional PPS device. May also use shared memory for status
/// data.
///
/// ## C-oracle struct
///   `struct instance` in ntpd/refclock_oncore.c
pub struct OncoreRefclock {
    pub unit: u8,
    /// Serial device path (/dev/oncore.serial.N)
    pub serial_device: Option<String>,
    /// PPS device path (/dev/oncore.pps.N)
    pub pps_device: Option<String>,
}

impl OncoreRefclock {
    /// Create a new Oncore refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            serial_device: None,
            pps_device: None,
        }
    }

    /// Open the Oncore GPS receiver serial and PPS devices.
    ///
    /// `device` — primary serial device path.
    ///
    /// ## C-oracle
    ///   `oncore_start()` — opens serial port, optionally configures
    ///   PPSAPI, reads config file, initialises shared memory.
    pub fn open(&mut self, _device: &str) -> Result<(), String> {
        Err(format!(
            "Oncore refclock not yet implemented (unit {})",
            self.unit
        ))
    }

    /// Close the receiver and release resources.
    pub fn close(&mut self) {}

    /// Read one time sample from the receiver.
    ///
    /// ## C-oracle
    ///   `oncore_receive()` — processes incoming Oncore binary packets,
    ///   decodes UTC time from @@Ea position/status messages.
    pub fn read_sample(&mut self) -> Result<Option<crate::ntp_refclock::RefClockSample>, String> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oncore_open_no_such_device() {
        let mut rc = OncoreRefclock::new(1);
        let result = rc.open("/nonexistent/oncore");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }
}
