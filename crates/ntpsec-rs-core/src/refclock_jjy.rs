// ──── refclock_jjy.rs ─────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_jjy.c
//
// JJY (Japanese JJY time signal) refclock driver. Supports multiple JJY
// receiver models: Tristate JJY-01/02, C-DEX JST2000, Echo Keisokuki
// LT-2000, Citizen T.I.C JJY-200, Tristate TS-GPSclock-01, SEIKO TIME
// SYSTEMS TDC-300, and Telephone JJY.
//
// ## Oracle
//   - ntpd/refclock_jjy.c (4518 lines)
// =============================================================================

/// JJY time signal refclock.
///
/// Receives time from Japanese JJY low-frequency time signal transmitters
/// (40 kHz / 60 kHz). Supports multiple receiver models via the
/// `unittype` field.
///
/// ## C-oracle struct
///   `struct jjyunit` in ntpd/refclock_jjy.c
pub struct JjyRefclock {
    pub unit: u8,
    /// Receiver type identifier (UNITTYPE_* constants from the C source)
    pub unittype: Option<char>,
    /// Line speed (baud rate)
    pub linespeed: Option<i32>,
    /// Whether a loopback measurement is in progress (Telephone JJY mode)
    pub loopback_mode: bool,
}

impl JjyRefclock {
    /// Create a new JJY refclock instance.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            unittype: None,
            linespeed: None,
            loopback_mode: false,
        }
    }

    /// Open the JJY receiver device.
    ///
    /// `device` — path to the serial device (e.g. `/dev/jjy0`).
    ///
    /// ## C-oracle
    ///   `jjy_start()` -> opens device, configures line discipline and
    ///   initialises the receiver-specific sub-driver.
    pub fn open(&mut self, _device: &str) -> Result<(), String> {
        Err(format!(
            "JJY refclock not yet implemented (unit {})",
            self.unit
        ))
    }

    /// Close the JJY receiver device.
    pub fn close(&mut self) {}

    /// Read and decode one time sample from the receiver.
    ///
    /// ## C-oracle
    ///   `jjy_receive()` / `jjy_synctime()` — parses received timecodes
    ///   from the various JJY receiver formats into a refclock sample.
    pub fn read_sample(&mut self) -> Result<Option<crate::ntp_refclock::RefClockSample>, String> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jjy_open_no_such_device() {
        let mut rc = JjyRefclock::new(1);
        let result = rc.open("/nonexistent/jjy");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet implemented"));
    }
}
