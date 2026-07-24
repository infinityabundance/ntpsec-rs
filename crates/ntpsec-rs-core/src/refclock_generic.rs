// ──── refclock_generic.rs ───────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_generic.c
//
// Generic refclock driver framework (type G). Implements the parsing
// infrastructure for serial time reference devices.
// =============================================================================

use crate::parse::ParsedTimecode;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// A generic refclock that uses the parse engine to interpret timecodes.
#[derive(Debug)]
pub struct GenericRefclock {
    reader: Option<BufReader<std::fs::File>>,
    unit: u8,
    format: &'static str,
}

impl GenericRefclock {
    /// Open a serial timecode device.
    ///
    /// `unit` — refclock unit number (1–255).
    /// `device` — path to the serial device (e.g. `/dev/gps0`).
    /// `format` — format string passed to `parse_fixed_width_timecode`.
    pub fn new(unit: u8, device: &str, format: &'static str) -> Result<Self, String> {
        let path = Path::new(device);
        let file =
            std::fs::File::open(path).map_err(|e| format!("cannot open {}: {}", device, e))?;
        Ok(Self {
            reader: Some(BufReader::new(file)),
            unit,
            format,
        })
    }

    /// Read and parse one timecode line from the device.
    ///
    /// Returns `Ok(None)` if the line was empty (EOF).
    pub fn read_timecode(&mut self) -> Result<Option<ParsedTimecode>, String> {
        let reader = self.reader.as_mut().ok_or("generic refclock not open")?;
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read error: {}", e))?;
        if line.trim().is_empty() {
            return Ok(None);
        }
        let formats = &[self.format];
        let tc = crate::parse::parse_fixed_width_timecode(line.trim(), formats);
        Ok(tc)
    }

    /// Close the device.
    pub fn close(&mut self) {
        self.reader.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_refclock_new_no_such_device() {
        let rc = GenericRefclock::new(1, "/nonexistent/device/xxxx", "%H%M%S");
        assert!(rc.is_err());
        assert!(rc.unwrap_err().contains("cannot open"));
    }
}
