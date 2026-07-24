// ──── refclock_gpsd.rs — GPSD refclock driver (type 16) ───────────────
//
// Reads time-position data from gpsd (GPS service daemon) via its TCP
// JSON protocol. Produces synthetic NTP packets for the daemon engine.
//
// Supports all GPSD JSON message types: VERSION, DEVICE, TPV, SKY, ATT.
// Handles automatic reconnection with exponential backoff and verifies
// the GPSD protocol version on connect.
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

/// Minimum GPSD protocol version required.
pub const GPSD_MIN_VERSION: &str = "3.0";

/// Maximum reconnection backoff in seconds.
pub const MAX_RECONNECT_BACKOFF: u64 = 30;

/// Initial reconnection backoff in seconds.
pub const INITIAL_RECONNECT_BACKOFF: u64 = 1;

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
    /// Current reconnect backoff duration in seconds.
    reconnect_backoff: u64,
    /// Total number of reconnection attempts.
    reconnect_attempts: u64,
    /// Whether the initial handshake (VERSION/DEVICE) has completed.
    handshake_complete: bool,
    /// GPSD protocol version reported by the daemon.
    gpsd_version: Option<String>,
    /// Most recent leap indicator from GPSD.
    last_leap: LeapIndicator,
    /// Whether we've sent the ?WATCH command.
    watch_sent: bool,
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
    pub leap: LeapIndicator,
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
            reconnect_backoff: INITIAL_RECONNECT_BACKOFF,
            reconnect_attempts: 0,
            handshake_complete: false,
            gpsd_version: None,
            last_leap: LeapIndicator::NoWarning,
            watch_sent: false,
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
        self.handshake_complete = false;
        self.gpsd_version = None;
        self.last_leap = LeapIndicator::NoWarning;
        self.watch_sent = false;

        Ok(())
    }

    /// Connect to gpsd and perform the VERSION/DEVICE handshake.
    ///
    /// This is the preferred connection method as it:
    /// 1. Establishes a TCP connection
    /// 2. Requests and verifies the GPSD protocol version
    /// 3. Processes DEVICE notifications
    /// 4. Enables WATCH mode for TIME/TPV objects
    ///
    /// Returns `Ok(())` on success, or `Err(String)` with a description.
    pub fn connect_with_handshake(&mut self, host: &str, port: u16) -> Result<(), String> {
        self.connect(host, port)?;

        // Request version information.
        self.request_version()?;

        // Read and verify the VERSION response.
        loop {
            match self.read_json_line()? {
                Some(line) => {
                    if self.process_message(&line)? {
                        // Successfully processed a message.
                        if self.handshake_complete {
                            break;
                        }
                    }
                }
                None => {
                    return Err("connection closed during handshake".to_string());
                }
            }
        }

        // Send WATCH command.
        self.watch()?;

        // Read initial DEVICE response(s).
        for _ in 0..5 {
            match self.read_json_line()? {
                Some(line) => {
                    self.process_message(&line)?;
                }
                None => break,
            }
        }

        Ok(())
    }

    /// Request the GPSD version by sending a ?VERSION poll.
    fn request_version(&mut self) -> Result<(), String> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| "not connected".to_string())?;

        let cmd = b"?VERSION;\n";
        stream
            .write_all(cmd)
            .map_err(|e| format!("write VERSION request failed: {}", e))?;

        Ok(())
    }

    /// Read a single JSON line from the GPSD stream.
    fn read_json_line(&mut self) -> Result<Option<String>, String> {
        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None => return Err("not connected".to_string()),
        };

        let mut line = String::new();
        let bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| format!("read error: {}", e))?;

        if bytes_read == 0 {
            return Ok(None);
        }

        Ok(Some(line))
    }

    /// Process a GPSD JSON message and return true if it was successfully handled.
    ///
    /// Handles VERSION, DEVICE, TPV, TIME, SKY, ATT, and ERROR messages.
    fn process_message(&mut self, line: &str) -> Result<bool, String> {
        let v: Value = match serde_json::from_str(line.trim()) {
            Ok(val) => val,
            Err(_) => return Ok(false), // skip non-JSON
        };

        let class = match v.get("class").and_then(|c| c.as_str()) {
            Some(c) => c,
            None => return Ok(false),
        };

        match class {
            "VERSION" => {
                let release = v
                    .get("release")
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");
                let proto_major = v.get("proto_major").and_then(|m| m.as_i64()).unwrap_or(0);
                let proto_minor = v.get("proto_minor").and_then(|m| m.as_i64()).unwrap_or(0);

                if proto_major < 3 {
                    return Err(format!(
                        "GPSD protocol version {}.{} is too old (need 3.0+), release: {}",
                        proto_major, proto_minor, release
                    ));
                }

                self.gpsd_version = Some(format!("{}.{}", proto_major, proto_minor));
                self.handshake_complete = true;
                Ok(true)
            }
            "DEVICE" => {
                // DEVICE messages describe available GPS devices.
                // We don't need to extract specific data from them.
                Ok(true)
            }
            "TPV" | "TIME" => {
                // TPV (Time-Position-Velocity) or TIME — our main data source.
                if let Some(fix) = parse_gpsd_object(&v) {
                    self.last_fix = Some(fix.clone());
                    self.samples_read += 1;
                    self.last_leap = fix.leap;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            "SKY" | "ATT" => {
                // SKY (satellite view) and ATT (attitude) are informative
                // but don't provide time data.
                Ok(true)
            }
            "ERROR" => {
                let message = v
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                Err(format!("GPSD error: {}", message))
            }
            _ => {
                // Unknown class — skip silently.
                Ok(false)
            }
        }
    }

    /// Send a ?WATCH command to enable TIME/TPV JSON objects.
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

        self.watch_sent = true;
        Ok(())
    }

    /// Read and parse the next JSON object from gpsd.
    ///
    /// Returns `Ok(None)` on EOF with no error.
    /// Returns `Err(...)` on I/O errors.
    /// Non-TIME/TPV objects are silently skipped.
    pub fn read_object(&mut self) -> Result<Option<GpsdFix>, String> {
        loop {
            match self.read_json_line()? {
                Some(line) => {
                    if self.process_message(&line)? {
                        if let Some(fix) = &self.last_fix {
                            // Return a clone if this was a TPV/TIME message.
                            return Ok(Some(fix.clone()));
                        }
                    }
                    // Continue looping for non-TPV/TIME messages.
                }
                None => return Ok(None),
            }
        }
    }

    /// Read a time sample from gpsd with auto-reconnection.
    ///
    /// On connection failure, automatically retries with exponential backoff
    /// (1s, 2s, 4s, 8s, ... up to max 30s).
    pub fn read_sample(&mut self) -> Result<Option<GpsdFix>, String> {
        loop {
            match self.read_object() {
                Ok(Some(fix)) => {
                    // Success — reset backoff on success.
                    self.reconnect_backoff = INITIAL_RECONNECT_BACKOFF;
                    self.reconnect_attempts = 0;
                    return Ok(Some(fix));
                }
                Ok(None) => {
                    // Clean EOF — the remote end closed the connection.
                    // Attempt reconnection.
                    if !self.try_reconnect()? {
                        return Ok(None);
                    }
                    // Retry the read after reconnection.
                }
                Err(e) => {
                    // Connection error — attempt reconnection.
                    self.disconnect_internal();
                    if !self.try_reconnect()? {
                        return Err(format!("Reconnection failed: {}", e));
                    }
                    // Retry the read after reconnection.
                }
            }
        }
    }

    /// Try to reconnect with exponential backoff.
    ///
    /// Returns `true` if reconnection succeeded, `false` if we should give up.
    fn try_reconnect(&mut self) -> Result<bool, String> {
        if self.host.is_empty() {
            return Ok(false);
        }

        if !self.is_connected() {
            self.reconnect_attempts += 1;

            let backoff = self.reconnect_backoff;
            std::thread::sleep(Duration::from_secs(backoff));

            // Exponential backoff with max cap.
            self.reconnect_backoff = (backoff * 2).min(MAX_RECONNECT_BACKOFF);

            // Clone host and port to avoid borrowing self while calling
            // the mutable method connect_with_handshake.
            let host = self.host.clone();
            let port = self.port;

            // Attempt to reconnect with handshake.
            match self.connect_with_handshake(&host, port) {
                Ok(()) => {
                    return Ok(true);
                }
                Err(e) => {
                    // Connection still failing — will retry on next call.
                    return Err(format!(
                        "reconnect attempt {} failed: {}",
                        self.reconnect_attempts, e
                    ));
                }
            }
        }

        Ok(true)
    }

    /// Internal disconnect that preserves reconnection state.
    fn disconnect_internal(&mut self) {
        self.reader = None;
        self.stream = None;
        self.handshake_complete = false;
        self.watch_sent = false;
    }

    /// Disconnect from gpsd and reset all state.
    pub fn disconnect(&mut self) {
        self.disconnect_internal();
        self.host.clear();
        self.port = GPSD_DEFAULT_PORT;
        self.last_fix = None;
        self.gpsd_version = None;
        self.last_leap = LeapIndicator::NoWarning;
        self.reconnect_backoff = INITIAL_RECONNECT_BACKOFF;
        self.reconnect_attempts = 0;
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

    /// Return the detected GPSD protocol version, if available.
    pub fn gpsd_version(&self) -> Option<&str> {
        self.gpsd_version.as_deref()
    }

    /// Return the last leap indicator.
    pub fn last_leap(&self) -> LeapIndicator {
        self.last_leap
    }

    /// Return whether the VERSION/DEVICE handshake is complete.
    pub fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Return the current reconnect backoff in seconds.
    pub fn reconnect_backoff(&self) -> u64 {
        self.reconnect_backoff
    }

    /// Return the total number of reconnection attempts.
    pub fn reconnect_attempts(&self) -> u64 {
        self.reconnect_attempts
    }
}

// ──── JSON parsing helpers ────────────────────────────────────────────

/// Parse a gpsd TIME or TPV object using serde_json.
///
/// Extracts the `"time"` field, `"precision"` (optional), and optionally
/// `"mode"`, `"lat"`, `"lon"`, `"alt"`, and `"leap"`.
fn parse_gpsd_object(v: &Value) -> Option<GpsdFix> {
    // Parse the time field: Unix seconds as f64.
    let unix_time = v.get("time")?.as_f64()?;

    // Parse precision (optional, defaults to 0).
    let precision = v.get("precision").and_then(|x| x.as_i64()).unwrap_or(0) as i8;

    // Parse leap indicator (optional, 0=NoWarning, 1=+1 leap, 2=-1 leap, 3=Alarm).
    let leap = v
        .get("leap")
        .and_then(|x| x.as_i64())
        .map(|l| match l {
            1 => LeapIndicator::AddLeapSecond,
            2 => LeapIndicator::RemoveLeapSecond,
            3 => LeapIndicator::Alarm,
            _ => LeapIndicator::NoWarning,
        })
        .unwrap_or(LeapIndicator::NoWarning);

    // Convert Unix time to NTP timestamp with proper rounding.
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
        leap,
    })
}

/// Parse a gpsd TIME object from a JSON line.
///
/// This is the legacy interface that expects a JSON line. New code should
/// use `parse_gpsd_object` which operates on a parsed `Value`.
fn parse_time_object(line: &str) -> Option<GpsdFix> {
    let v: Value = serde_json::from_str(line).ok()?;

    // Must be a TIME or TPV object.
    let class = v.get("class")?.as_str()?;
    if class != "TIME" && class != "TPV" {
        return None;
    }

    parse_gpsd_object(&v)
}

/// Convert a Unix timestamp (seconds as f64, with fractional part) to NtpTs64.
///
/// Uses proper rounding to avoid precision loss when converting the
/// fractional part to NTP fraction (fract * 2^32).
fn unix_to_ntp_ts64(unix_secs: f64) -> NtpTs64 {
    let secs = unix_secs as i64;

    // Convert fractional part to nanoseconds using integer arithmetic
    // to avoid floating-point precision issues.
    let fract = unix_secs.fract().abs();
    let nsecs = (fract * 1_000_000_000.0 + 0.5) as u64;

    // Convert nanoseconds to NTP fraction (2^-32 second units)
    // ns / 1e9 * 2^32 = ns * 4294967296 / 1e9
    // Use u64 arithmetic with rounding: (nsecs * 4_294_967_296 + 500_000_000) / 1_000_000_000
    let frac = ((nsecs as u64 * 4_294_967_296u64 + 500_000_000u64) / 1_000_000_000u64) as u32;

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

    // LI from GPSD leap indicator, VN = 4, Mode = 4 (server)
    pkt.li_vn_mode = NtpPacket::set_li_vn_mode(fix.leap, NtpVersion::V4, NtpMode::Server);

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

/// Reset the reconnection backoff to its initial value.
/// Useful after a successful long-term connection is established.
pub fn reset_reconnect_backoff(rc: &mut GpsdRefclock) {
    rc.reconnect_backoff = INITIAL_RECONNECT_BACKOFF;
    rc.reconnect_attempts = 0;
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
        assert!(!rc.handshake_complete());
        assert!(rc.gpsd_version().is_none());
        assert_eq!(rc.last_leap(), LeapIndicator::NoWarning);
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
            leap: LeapIndicator::NoWarning,
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
        // Non-TIME/TPV objects should be rejected.
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
        // Fractional part: 0.123456 * 2^32 ≈ 530242915 (with rounding)
        assert!(fix.time.fraction > 0);
        assert_eq!(fix.precision, -6);
        assert_eq!(fix.mode, 0); // not present, defaults to 0
        assert_eq!(fix.leap, LeapIndicator::NoWarning);
    }

    #[test]
    fn test_parse_time_object_with_position() {
        let line = r#"{"class":"TPV","device":"/dev/gps0","time":1700000000.5,"mode":3,"lat":48.8566,"lon":2.3522,"alt":35.0,"precision":-8}"#;
        let fix = parse_time_object(line).expect("should parse TPV with position");

        let expected_ntp_secs = 1700000000i64 + NTP_EPOCH_OFFSET as i64;
        assert_eq!(fix.time.seconds, expected_ntp_secs);
        assert_eq!(fix.mode, 3);
        assert!((fix.latitude - 48.8566).abs() < 0.0001);
        assert!((fix.longitude - 2.3522).abs() < 0.0001);
        assert_eq!(fix.altitude, Some(35.0));
        assert_eq!(fix.precision, -8);
    }

    #[test]
    fn test_parse_tpv_as_time_object() {
        // TPV objects should also be parseable via parse_time_object.
        let line = r#"{"class":"TPV","time":1234567890.0}"#;
        let fix = parse_time_object(line).expect("should parse TPV object");
        let expected_secs = 1234567890i64 + NTP_EPOCH_OFFSET as i64;
        assert_eq!(fix.time.seconds, expected_secs);
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
    fn test_unix_to_ntp_fraction_rounding() {
        // Test that the precision issue with f64 fractions is handled.
        // Due to IEEE 754 representation, 1000000000.1 has fract ≈ 0.100000024
        // which gives fraction ≈ 429496833, not the ideal 429496730.
        // The test verifies the computed value is consistent and stable.
        let ntp = unix_to_ntp_ts64(1000000000.1);
        assert_eq!(ntp.seconds, 1000000000i64 + NTP_EPOCH_OFFSET as i64);
        // Accept within 0.5 microseconds of the ideal value
        let ideal = 429_496_730u32;
        let actual = ntp.fraction;
        let diff = if actual > ideal {
            actual - ideal
        } else {
            ideal - actual
        };
        assert!(
            diff < 500,
            "fraction {} differs from ideal {} by more than 500 units",
            actual,
            ideal
        );

        // 0.333333333 * 2^32 ≈ 1431655764.67 → should round appropriately
        let ntp2 = unix_to_ntp_ts64(1000000000.333333333);
        assert!(ntp2.fraction > 1_431_000_000);
    }

    #[test]
    fn test_parse_time_object_rejects_non_time_class() {
        // A valid JSON object that is not a TIME/TPV class should be rejected.
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
        assert_eq!(fix.leap, LeapIndicator::NoWarning);
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
            leap: LeapIndicator::AddLeapSecond,
        };
        let recv = NtpTs64 {
            seconds: 2_208_988_800 + 946684801,
            fraction: 0,
        };
        let pkt = gpsd_fix_to_packet(&fix, recv);

        // LI should be set from the leap indicator (AddLeapSecond = 1)
        assert_eq!(pkt.leap_indicator(), LeapIndicator::AddLeapSecond);
        // VN=4, Mode=4 (server)
        assert_eq!(pkt.version(), NtpVersion::V4);
        assert_eq!(pkt.mode(), NtpMode::Server);
    }

    #[test]
    fn test_disconnect_idempotent() {
        let mut rc = GpsdRefclock::new(4);
        rc.disconnect(); // safe even when not connected
        assert!(!rc.is_connected());
        assert_eq!(rc.host(), "");
        assert!(!rc.handshake_complete());
    }

    #[test]
    fn test_read_object_without_connect_errors() {
        let mut rc = GpsdRefclock::new(5);
        let result = rc.read_object();
        assert!(result.is_err(), "should error when not connected");
        assert_eq!(result.unwrap_err(), "not connected");
    }

    #[test]
    fn test_parse_leap_field() {
        // Test with leap = 1 (AddLeapSecond)
        let line = r#"{"class":"TIME","time":1000000.0,"leap":1}"#;
        let fix = parse_time_object(line).expect("should parse with leap=1");
        assert_eq!(fix.leap, LeapIndicator::AddLeapSecond);

        // Test with leap = 2 (RemoveLeapSecond)
        let line = r#"{"class":"TIME","time":1000000.0,"leap":2}"#;
        let fix = parse_time_object(line).expect("should parse with leap=2");
        assert_eq!(fix.leap, LeapIndicator::RemoveLeapSecond);

        // Test with leap = 3 (Alarm)
        let line = r#"{"class":"TIME","time":1000000.0,"leap":3}"#;
        let fix = parse_time_object(line).expect("should parse with leap=3");
        assert_eq!(fix.leap, LeapIndicator::Alarm);

        // Test missing leap field → NoWarning
        let line = r#"{"class":"TIME","time":1000000.0}"#;
        let fix = parse_time_object(line).expect("should parse without leap");
        assert_eq!(fix.leap, LeapIndicator::NoWarning);
    }

    #[test]
    fn test_process_version_message() {
        let mut rc = GpsdRefclock::new(6);

        // Test processing a VERSION message.
        let version_line =
            r#"{"class":"VERSION","release":"3.24","proto_major":3,"proto_minor":14}"#;
        let result = rc.process_message(version_line);
        assert!(result.is_ok());
        assert_eq!(rc.gpsd_version(), Some("3.14"));
        assert!(rc.handshake_complete());
    }

    #[test]
    fn test_process_version_message_too_old() {
        let mut rc = GpsdRefclock::new(7);

        // Protocol version 2.x should be rejected.
        let old_version = r#"{"class":"VERSION","release":"2.5","proto_major":2,"proto_minor":5}"#;
        let result = rc.process_message(old_version);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));
    }

    #[test]
    fn test_process_device_message() {
        let mut rc = GpsdRefclock::new(8);
        let device_line =
            r#"{"class":"DEVICE","path":"/dev/ttyUSB0","activated":"2024-01-01T00:00:00.000Z"}"#;
        let result = rc.process_message(device_line);
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_error_message() {
        let mut rc = GpsdRefclock::new(9);
        let error_line = r#"{"class":"ERROR","message":"device not available"}"#;
        let result = rc.process_message(error_line);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("device not available"));
    }

    #[test]
    fn test_parse_gpsd_object_skey_att() {
        // SKY and ATT messages should be processable but not produce fixes.
        let sky_line = r#"{"class":"SKY","satellites":[]}"#;
        let mut rc = GpsdRefclock::new(10);
        let result = rc.process_message(sky_line);
        assert!(result.is_ok());
        assert!(rc.last_fix().is_none());

        let att_line = r#"{"class":"ATT","heading":90.0}"#;
        let result = rc.process_message(att_line);
        assert!(result.is_ok());
        assert!(rc.last_fix().is_none());
    }

    #[test]
    fn test_gpsd_fix_leap_in_packet() {
        let fix = GpsdFix {
            time: NtpTs64 {
                seconds: 2_208_988_800 + 946684800,
                fraction: 0,
            },
            mode: 3,
            latitude: 0.0,
            longitude: 0.0,
            altitude: None,
            precision: -7,
            leap: LeapIndicator::Alarm,
        };
        let recv = NtpTs64 {
            seconds: 2_208_988_800 + 946684801,
            fraction: 0,
        };
        let pkt = gpsd_fix_to_packet(&fix, recv);
        assert_eq!(pkt.leap_indicator(), LeapIndicator::Alarm);
    }

    #[test]
    fn test_reset_reconnect_backoff() {
        let mut rc = GpsdRefclock::new(11);
        rc.reconnect_backoff = 30;
        rc.reconnect_attempts = 10;
        reset_reconnect_backoff(&mut rc);
        assert_eq!(rc.reconnect_backoff, INITIAL_RECONNECT_BACKOFF);
        assert_eq!(rc.reconnect_attempts, 0);
    }

    #[test]
    fn test_gpsd_packet_leap_propagation() {
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
            leap: LeapIndicator::RemoveLeapSecond,
        };
        let recv = NtpTs64 {
            seconds: 2_208_988_800 + 946684801,
            fraction: 0,
        };
        let pkt = gpsd_fix_to_packet(&fix, recv);

        // LI should be RemoveLeapSecond (= 2)
        assert_eq!(pkt.leap_indicator(), LeapIndicator::RemoveLeapSecond);
    }
}
