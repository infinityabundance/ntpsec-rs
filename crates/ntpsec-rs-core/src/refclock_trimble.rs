// ──── refclock_trimble.rs ─────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_trimble.c
//
// Trimble GPS receiver refclock driver. Supports Palisade, Thunderbolt,
// Acutime 2000, Acutime Gold, Resolution SMT, ACE III, Copernicus II,
// and EndRun Praecis timing receivers.
//
// ## Oracle
//   - ntpd/refclock_trimble.c (1390 lines)
// =============================================================================

/// Trimble GPS refclock.
///
/// Drives a Trimble GPS receiver via TSIP (Trimble Standard Interface
/// Protocol) or Praecis ASCII protocol over a serial connection.
///
/// ## C-oracle struct
///   `struct trimble_unit` in ntpd/refclock_trimble.c
pub struct TrimbleRefclock {
    pub unit: u8,
    /// Whether a TSIP packet has been received this poll cycle
    pub got_pkt: bool,
    /// Whether a time packet has been received this poll cycle
    pub got_time: bool,
    /// Samples accumulated in the median filter this poll
    pub samples: i32,
    /// GPS week number
    pub week: u32,
    /// GPS time of week (milliseconds)
    pub tow: u64,
}

impl TrimbleRefclock {
    /// Create a new Trimble refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            got_pkt: false,
            got_time: false,
            samples: 0,
            week: 0,
            tow: 0,
        }
    }

    /// Open the Trimble GPS receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/trimble0` or
    /// `/dev/palisade0` in classic mode).
    ///
    /// ## C-oracle
    ///   `trimble_start()` — opens device, configures termios, sets
    ///   DTR/RTS, initialises parser state.
    pub fn open(&mut self, _device: &str) -> Result<(), String> {
        Err(format!(
            "Trimble refclock not yet implemented (unit {})",
            self.unit
        ))
    }

    /// Close the Trimble receiver device.
    pub fn close(&mut self) {}

    /// Read and decode one time sample from the receiver.
    ///
    /// ## C-oracle
    ///   `trimble_receive()` — TSIP packet parsing state machine that
    ///   extracts UTC time from packet 0x42 (GPS time) and optional
    ///   event input packets.
    pub fn read_sample(&mut self) -> Result<Option<crate::ntp_refclock::RefClockSample>, String> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trimble_open_no_such_device() {
        let mut rc = TrimbleRefclock::new(1);
        let result = rc.open("/nonexistent/trimble");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }
}
