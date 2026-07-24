// ──── refclock_gpsd.rs — GPSD refclock driver (type 16) ───────────────
//
// Reads time-position data from gpsd (GPS service daemon) via its TCP
// JSON protocol.  Produces synthetic NTP packets for the daemon engine.
//
// ## Oracle
//   - ntpsec ntpd/refclock_gpsd.c (6K)
//   - gpsd JSON protocol specification (gpsd.io)
// =============================================================================

use crate::ntp_types::*;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Default gpsd port.
pub const GPSD_DEFAULT_PORT: u16 = 2947;

/// GPSD refclock driver instance.
#[derive(Debug)]
pub struct GpsdRefclock {
    unit: u8,
    host: String,
    port: u16,
    stream: Option<TcpStream>,
    reader: Option<BufReader<TcpStream>>,
    last_fix: Option<GpsdFix>,
    samples_read: u64,
}

/// A GPS time fix from gpsd.
#[derive(Debug, Clone)]
pub struct GpsdFix {
    pub time: NtpTs64,
    pub mode: u8, // 0=none, 1=2D, 2=3D, 3=RTK
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: Option<f64>,
    pub precision: i8,
}

impl GpsdRefclock {
    /// Create a new GPSD refclock instance for the given unit number.
    pub fn new(unit: u8) -> Self {
        GpsdRefclock {
            unit,
            host: String::new(),
            port: GPSD_DEFAULT_PORT,
            stream: None,
            reader: None,
            last_fix: None,
            samples_read: 0,
        }
    }

    /// Connect to gpsd at `host:port`.
    ///
    /// On success, a TCP connection is established and a buffered reader is
    /// initialized for line-oriented JSON reading.
    pub fn connect(&mut self, host: &str, port: u16) -> Result<(), String> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| format!("invalid address '{}': {}", addr, e))?,
            Duration::from_secs(5),
        )
        .map_err(|e| format!("connection to {} failed: {}", addr, e))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| format!("set_read_timeout failed: {}", e))?;

        self.host = host.to_string();
        self.port = port;
        self.stream = Some(
            stream
                .try_clone()
                .map_err(|e| format!("clone failed: {}", e))?,
        );
        self.reader = Some(BufReader::new(stream));
        self.last_fix = None;
        self.samples_read = 0;

        Ok(())
    }

    /// Send a ?WATCH command to enable TIME JSON objects.
    ///
    /// gpsd protocol: `?WATCH={"enable":true,"json":byte};`
    pub fn watch(&mut self) -> Result<(), String> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| "not connected".to_string())?;

        let cmd = b"?WATCH={\"enable\":true,\"json\":true};";
        stream
            .write_all(cmd)
            .map_err(|e| format!("write WATCH failed: {}", e))?;

        Ok(())
    }

    /// Read and parse the next JSON object from gpsd.
    ///
    /// Returns `Ok(None)` on EOF with no error.
    /// Returns `Err(...)` on I/O errors.
    /// Non-TIME objects are silently skipped.
    pub fn read_object(&mut self) -> Result<Option<GpsdFix>, String> {
        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => return Err("not connected".to_string()),
        };

        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = reader
                .read_line(&mut line)
                .map_err(|e| format!("read error: {}", e))?;

            if bytes_read == 0 {
                return Ok(None);
            }

            // Parse JSON line using serde_json. The gpsd TIME object looks like:
            //
            //   {"class":"TIME","device":"...","time":1234567890.123456,
            //    "leap":0,"precision":-6,...}
            if let Some(fix) = parse_time_object(&line) {
                return Ok(Some(fix));
            }
            // Skip non-TIME objects silently.
        }
    }

    /// Read a time sample from gpsd.
    ///
    /// Alias for `read_object` — reads the next TIME object from the stream.
    pub fn read_sample(&mut self) -> Result<Option<GpsdFix>, String> {
        let fix = self.read_object()?;

        if let Some(f) = &fix {
            self.last_fix = Some(f.clone());
            self.samples_read += 1;
        }

        Ok(fix)
    }

    /// Disconnect from gpsd.
    pub fn disconnect(&mut self) {
        self.reader = None;
        self.stream = None;
        self.host.clear();
        self.port = GPSD_DEFAULT_PORT;
        self.last_fix = None;
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Return the unit number.
    pub fn unit(&self) -> u8 {
        self.unit
    }

    /// Return the gpsd host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Return the gpsd port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Return the last fix produced.
    pub fn last_fix(&self) -> Option<&GpsdFix> {
        self.last_fix.as_ref()
    }

    /// Return the number of samples read so far.
    pub fn samples_read(&self) -> u64 {
        self.samples_read
    }

    /// Return whether the device is currently connected.
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

// ──── JSON parsing helpers ────────────────────────────────────────────

/// Parse a gpsd TIME object from a JSON line using serde_json.
///
/// Expects a JSON object with `"class":"TIME"` and extracts `"time"`,
/// `"precision"`, and optionally `"mode"`, `"lat"`, `"lon"`, `"alt"`.
fn parse_time_object(line: &str) -> Option<GpsdFix> {
    let v: Value = serde_json::from_str(line).ok()?;

    // Must be a TIME object.
    if v.get("class")?.as_str()? != "TIME" {
        return None;
    }

    // Parse the time field: Unix seconds as f64.
    let unix_time = v.get("time")?.as_f64()?;

    // Parse precision (optional, defaults to 0).
    let precision = v.get("precision").and_then(|x| x.as_i64()).unwrap_or(0) as i8;

    // Convert Unix time to NTP timestamp.
    let ntp_time = unix_to_ntp_ts64(unix_time);

    // Optional fields
    let mode = v.get("mode").and_then(|x| x.as_i64()).unwrap_or(0) as u8;
    let latitude = v.get("lat").and_then(|x| x.as_f64()).unwrap_or(0.0);
    let longitude = v.get("lon").and_then(|x| x.as_f64()).unwrap_or(0.0);
    let altitude = v.get("alt").and_then(|x| x.as_f64());

    Some(GpsdFix {
        time: ntp_time,
        mode,
        latitude,
        longitude,
        altitude,
        precision,
    })
}

/// Convert a Unix timestamp (seconds as f64, with fractional part) to NtpTs64.
fn unix_to_ntp_ts64(unix_secs: f64) -> NtpTs64 {
    let secs = unix_secs as i64;
    let frac = (unix_secs.fract().abs() * 4_294_967_296.0) as u32;

    NtpTs64 {
        seconds: secs + NTP_EPOCH_OFFSET as i64,
        fraction: frac,
    }
}

/// Convert a Unix timestamp (seconds, nanoseconds) to NtpTs64.
fn ts_to_ntp(secs: i64, nsecs: i64) -> NtpTs64 {
    let ntp_secs = secs + NTP_EPOCH_OFFSET as i64;

    // Normalize nanoseconds to the [0, 10^9) range.
    let (sec_adj, nsec_norm) = if nsecs < 0 {
        // The reference uses nsecs in the range [0, 1e9) after a
        // checked_sub or similar.  For safety we floor-divide.
        let adj = (-nsecs + 999_999_999) / 1_000_000_000;
        (-adj, nsecs + adj * 1_000_000_000)
    } else {
        (0i64, nsecs)
    };

    let ntp_secs = ntp_secs + sec_adj;
    // 2^32 / 10^9 ≈ 4.294967296
    let frac =
        ((nsec_norm as u64).wrapping_mul(4_294_967_296u64 / 1_000_000_000u64) & 0xFFFF_FFFF) as u32;

    NtpTs64 {
        seconds: ntp_secs,
        fraction: frac,
    }
}

/// Construct a synthetic NTP packet from a GPSD fix and a receive timestamp.
///
/// Returns a 48-byte NTP packet suitable for the refclock engine.
pub fn gpsd_fix_to_packet(fix: &GpsdFix, receive_time: NtpTs64) -> NtpPacket {
    let mut pkt = NtpPacket::zeroed();

    // LI = 0 (no leap warning), VN = 4, Mode = 4 (server)
    pkt.li_vn_mode =
        NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);

    // Stratum 0 means unspecified; 1 is primary reference.
    // GPSD refclocks typically report as stratum 0 so the daemon
    // assigns the correct stratum based on its own configuration.
    pkt.stratum = 0;

    // Poll interval: 16 seconds (log2 16 = 4).
    pkt.poll = 4;

    // Precision from the GPSD fix; default to -6 if none reported.
    pkt.precision = fix.precision;

    // Root delay and dispersion: zero for a refclock (filled by daemon).
    pkt.root_delay = 0;
    pkt.root_dispersion = 0;

    // Reference timestamp: the GPS fix time.
    pkt.reference_ts = crate::ntp_fp::ntp_ts64_to_wire(fix.time);

    // Reference identifier: "GPSD" in ASCII.
    pkt.reference_id = u32::from_be_bytes(*b"GPSD");

    // Transmit timestamp: the GPS time from the fix.
    pkt.transmit_ts = crate::ntp_fp::ntp_ts64_to_wire(fix.time);

    // Receive timestamp: when we got the data from gpsd.
    pkt.receive_ts = crate::ntp_fp::ntp_ts64_to_wire(receive_time);

    pkt
}

// ──── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpsd_refclock_new() {
        let rc = GpsdRefclock::new(1);
        assert_eq!(rc.unit(), 1);
        assert!(!rc.is_connected());
        assert!(rc.last_fix().is_none());
        assert_eq!(rc.samples_read(), 0);
        assert_eq!(rc.host(), "");
        assert_eq!(rc.port(), GPSD_DEFAULT_PORT);
    }

    #[test]
    fn test_connect_refused() {
        // Trying to connect to a closed port should fail.
        let mut rc = GpsdRefclock::new(2);
        let result = rc.connect("127.0.0.1", 1); // port 1 is typically closed
        assert!(
            result.is_err(),
            "expected connection refused, got {:?}",
            result
        );
        assert!(!rc.is_connected());
    }

    #[test]
    fn test_gpsd_packet_construction() {
        // Build a fix and verify the resulting NTP packet.
        let fix = GpsdFix {
            time: NtpTs64 {
                seconds: 2_208_988_800 + 1_000_000_000, // ~2001-09-09
                fraction: 0,
            },
            mode: 3,
            latitude: 48.8566,
            longitude: 2.3522,
            altitude: Some(35.0),
            precision: -7,
        };

        let receive_time = NtpTs64 {
            seconds: 2_208_988_800 + 1_000_000_001,
            fraction: 0,
        };

        let pkt = gpsd_fix_to_packet(&fix, receive_time);

        assert_eq!(pkt.stratum, 0);
        assert_eq!(pkt.precision, -7);
        assert_eq!(
            pkt.reference_id,
            u32::from_be_bytes(*b"GPSD"),
            "reference ID should be 'GPSD'"
        );

        // Verify transmit timestamp matches fix time.
        assert_eq!(pkt.transmit_ts.seconds, fix.time.seconds as u32);
        assert_eq!(pkt.transmit_ts.fraction, fix.time.fraction);

        // Verify receive timestamp.
        assert_eq!(pkt.receive_ts.seconds, receive_time.seconds as u32);
    }

    #[test]
    fn test_parse_time_object_invalid() {
        // Non-TIME objects should be rejected.
        let line =
            r#"{"class":"DEVICE","path":"/dev/ttyUSB0","activated":"2023-01-01T00:00:00.000Z"}"#;
        assert!(parse_time_object(line).is_none());

        // Garbage input.
        assert!(parse_time_object("not json at all").is_none());
        assert!(parse_time_object("").is_none());
    }

    #[test]
    fn test_parse_time_object_valid() {
        // A minimal TIME object.
        let line = r#"{"class":"TIME","device":"/dev/gps0","time":1234567890.123456,"leap":0,"precision":-6}"#;
        let fix = parse_time_object(line).expect("should parse valid TIME object");

        // Unix time 1234567890.123456 → NTP time = 1234567890 + NTP_EPOCH_OFFSET
        let expected_ntp_secs = 1234567890i64 + NTP_EPOCH_OFFSET as i64;
        assert_eq!(fix.time.seconds, expected_ntp_secs);
        // Fractional part: 0.123456 * 2^32 ≈ 530242915
        assert!(fix.time.fraction > 0);
        assert_eq!(fix.precision, -6);
        assert_eq!(fix.mode, 0); // not present, defaults to 0
    }

    #[test]
    fn test_parse_time_object_with_position() {
        let line = r#"{"class":"TIME","device":"/dev/gps0","time":1700000000.5,"mode":3,"lat":48.8566,"lon":2.3522,"alt":35.0,"precision":-8}"#;
        let fix = parse_time_object(line).expect("should parse TIME with position");

        let expected_ntp_secs = 1700000000i64 + NTP_EPOCH_OFFSET as i64;
        assert_eq!(fix.time.seconds, expected_ntp_secs);
        assert_eq!(fix.mode, 3);
        assert!((fix.latitude - 48.8566).abs() < 0.0001);
        assert!((fix.longitude - 2.3522).abs() < 0.0001);
        assert_eq!(fix.altitude, Some(35.0));
        assert_eq!(fix.precision, -8);
    }

    #[test]
    fn test_unix_to_ntp_roundtrip() {
        // Unix epoch 0 → NTP epoch.
        let ntp = unix_to_ntp_ts64(0.0);
        assert_eq!(ntp.seconds, NTP_EPOCH_OFFSET as i64);
        assert_eq!(ntp.fraction, 0);

        // 1 Jan 2000 00:00:00 UTC = 946684800 Unix.
        let ntp = unix_to_ntp_ts64(946684800.0);
        let expected = 946684800i64 + NTP_EPOCH_OFFSET as i64;
        assert_eq!(ntp.seconds, expected);
        assert_eq!(ntp.fraction, 0);

        // With fractional seconds.
        let ntp = unix_to_ntp_ts64(946684800.5);
        assert_eq!(ntp.seconds, expected);
        assert!(ntp.fraction > 0);
        // 0.5 * 2^32 = 2147483648
        assert_eq!(ntp.fraction, 2_147_483_648);
    }

    #[test]
    fn test_parse_time_object_rejects_non_time_class() {
        // A valid JSON object that is not a TIME class should be rejected.
        let non_time = r#"{"class":"DEVICE","time":1234.5}"#;
        assert!(parse_time_object(non_time).is_none());

        // Garbage should be rejected.
        assert!(parse_time_object("not json").is_none());
    }

    #[test]
    fn test_parse_time_object_partial_fields() {
        // TIME object with only required fields should still parse.
        let minimal = r#"{"class":"TIME","time":1000000.0}"#;
        let fix = parse_time_object(minimal).expect("should parse minimal TIME");
        let expected_secs = 1_000_000i64 + NTP_EPOCH_OFFSET as i64;
        assert_eq!(fix.time.seconds, expected_secs);
        assert_eq!(fix.precision, 0);
        assert_eq!(fix.mode, 0);
        assert!((fix.latitude - 0.0).abs() < 0.0001);
        assert!((fix.longitude - 0.0).abs() < 0.0001);
        assert!(fix.altitude.is_none());
    }

    #[test]
    fn test_gpsd_packet_leap_and_mode() {
        let fix = GpsdFix {
            time: NtpTs64 {
                seconds: 2_208_988_800 + 946684800,
                fraction: 0,
            },
            mode: 2,
            latitude: 0.0,
            longitude: 0.0,
            altitude: None,
            precision: -5,
        };
        let recv = NtpTs64 {
            seconds: 2_208_988_800 + 946684801,
            fraction: 0,
        };
        let pkt = gpsd_fix_to_packet(&fix, recv);

        // LI=0, VN=4, Mode=4 (server)
        assert_eq!(pkt.li_vn_mode >> 6, 0); // LI
        assert_eq!((pkt.li_vn_mode >> 3) & 0x07, 4); // VN
        assert_eq!(pkt.li_vn_mode & 0x07, 4); // Mode
    }

    #[test]
    fn test_disconnect_idempotent() {
        let mut rc = GpsdRefclock::new(4);
        rc.disconnect(); // safe even when not connected
        assert!(!rc.is_connected());
        assert_eq!(rc.host(), "");
    }

    #[test]
    fn test_read_object_without_connect_errors() {
        let mut rc = GpsdRefclock::new(5);
        let result = rc.read_object();
        assert!(result.is_err(), "should error when not connected");
        assert_eq!(result.unwrap_err(), "not connected");
    }
}
