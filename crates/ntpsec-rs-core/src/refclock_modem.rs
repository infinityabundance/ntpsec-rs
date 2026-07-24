// ──── refclock_modem.rs ───────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_modem.c
//
// ACTS (Automated Computer Time Service) modem refclock driver. Supports
// NIST (US), USNO, PTB (Germany), and NPL (UK) telephone time services
// via a Hayes-compatible modem.
//
// ## Oracle
//   - ntpd/refclock_modem.c (929 lines)
// =============================================================================

/// ACTS modem dial-up refclock.
///
/// Periodically dials a telephone time service via modem, receives
/// timecode data, and calculates the local clock correction. Designed
/// as backup when no radio clock or internet time server is available.
///
/// ## C-oracle struct
///   `struct modemunit` in ntpd/refclock_modem.c
pub struct ModemRefclock {
    pub unit: u8,
    /// Current state in the dial-up state machine
    pub state: i32,
    /// Timeout counter for the current state
    pub timer: i32,
    /// Retry index for the current phone number
    pub retry: i32,
    /// Count of messages received
    pub msgcnt: i32,
}

impl ModemRefclock {
    /// Create a new modem refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            state: 0,
            timer: 0,
            retry: 0,
            msgcnt: 0,
        }
    }

    /// Open the modem device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/modem0` or
    /// `/dev/acts0`).
    ///
    /// ## C-oracle
    ///   `modem_start()` — opens device, configures termios, sends
    ///   initialisation string to modem.
    pub fn open(&mut self, _device: &str) -> Result<(), String> {
        Err(format!(
            "modem refclock not yet implemented (unit {})",
            self.unit
        ))
    }

    /// Close the modem device.
    pub fn close(&mut self) {}

    /// Read one time sample from the modem.
    ///
    /// ## C-oracle
    ///   `modem_receive()` / `modem_timecode()` — state machine that
    ///   manages dial-up, handshake, timecode parsing, and hang-up.
    ///   Supports NIST, USNO, PTB, and NPL timecode formats.
    pub fn read_sample(&mut self) -> Result<Option<crate::ntp_refclock::RefClockSample>, String> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modem_open_no_such_device() {
        let mut rc = ModemRefclock::new(1);
        let result = rc.open("/nonexistent/modem");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }
}
