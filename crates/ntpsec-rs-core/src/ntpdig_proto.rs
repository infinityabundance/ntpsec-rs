// ──── ntpdig_proto.rs ───────────────────────────────────────────────────────
// ntpdig NTP query implementation.
//
// Implements the ntpdig client for querying NTP servers and displaying
// the time.
//
// ## Oracle
//   - RFC 5905 §6–§8 (NTP packet header, on-wire protocol, clock-filter)
//   - ntpdig from ntpclients/ntpdig.py
//
// ## Protocol summary
//   The client sends a Mode 3 (Client) NTPv4 packet with a transmit
//   timestamp (T1). The server responds with Mode 4 (Server) or Mode 2
//   (SymPassive) containing:
//     T1 = originate timestamp (copied from request)
//     T2 = receive timestamp (server arrival)
//     T3 = transmit timestamp (server departure)
//   The client records T4 = client receive timestamp.
//
//   offset = ((T2 - T1) + (T3 - T4)) / 2
//   delay  = (T4 - T1) - (T3 - T2)
// =============================================================================

use std::fmt;
use std::net::ToSocketAddrs;
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::ntp_fp::{ntp_ts64_to_wire, ntp_ts_to_ntpts};
use crate::ntp_types::*;

// ──── Constants ─────────────────────────────────────────────────────────────

/// NTP fraction per second (2^32).
const NTP_FRAC_PER_SEC_F64: f64 = 4_294_967_296.0;

// ──── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during an NTP query.
#[derive(Debug, Clone)]
pub enum NtpDigError {
    /// Network-level error (connect, send, recv).
    Network(String),
    /// Response failed protocol validation.
    BadResponse(String),
    /// Query timed out.
    Timeout,
    /// Server returned a kiss-of-death code.
    InvalidKissCode(String),
}

impl fmt::Display for NtpDigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NtpDigError::Network(msg) => write!(f, "network error: {msg}"),
            NtpDigError::BadResponse(msg) => write!(f, "bad response: {msg}"),
            NtpDigError::Timeout => write!(f, "query timed out"),
            NtpDigError::InvalidKissCode(code) => write!(f, "invalid kiss code: {code}"),
        }
    }
}

impl std::error::Error for NtpDigError {}

// ──── Query result ──────────────────────────────────────────────────────────

/// Result of a single NTP query.
#[derive(Debug, Clone)]
pub struct NtpQueryResult {
    /// Target server hostname or address.
    pub remote: String,
    /// NTP stratum of the server (0 = kiss-o'-death, 1 = primary).
    pub stratum: u8,
    /// Reference identifier as raw u32.
    pub refid: u32,
    /// Reference identifier as display string.
    pub refid_string: String,
    /// Clock precision as a signed exponent of 2 (log2 seconds).
    pub precision: i8,
    /// Root delay in seconds (round-trip to the ultimate time source).
    pub root_delay: f64,
    /// Root dispersion in seconds (maximum error of the ultimate source).
    pub root_dispersion: f64,
    /// Computed clock offset in seconds (positive = local clock is behind).
    pub offset: f64,
    /// Round-trip delay in seconds.
    pub delay: f64,
    /// Root dispersion (same as root_dispersion).
    pub dispersion: f64,
    /// ISO 8601 timestamp of the measurement (client wall-clock time).
    pub when: String,
    /// Leap indicator from the server.
    pub leap: LeapIndicator,
}

// ──── NTP query client ──────────────────────────────────────────────────────

/// A simple NTP client that queries servers using the on-wire protocol.
///
/// # Example
///
/// ```ignore
/// let mut client = NtpDigClient::new(Duration::from_secs(5), 1);
/// match client.query("pool.ntp.org", 123) {
///     Ok(result) => println!("offset={} delay={}", result.offset, result.delay),
///     Err(e) => eprintln!("{e}"),
/// }
/// ```
#[derive(Debug, Clone)]
pub struct NtpDigClient {
    /// Maximum time to wait for a response.
    timeout: Duration,
    /// Number of queries to perform; the best result (lowest delay) is returned.
    samples: u32,
}

impl NtpDigClient {
    /// Create a new NTP dig client.
    ///
    /// * `timeout` — per-query timeout.
    /// * `samples` — number of queries to perform per `query()` call.
    pub fn new(timeout: Duration, samples: u32) -> Self {
        NtpDigClient { timeout, samples }
    }

    /// Query a single NTP server, performing `samples` queries.
    ///
    /// Returns the best result (the one with the lowest delay).
    pub fn query(&mut self, host: &str, port: u16) -> Result<NtpQueryResult, NtpDigError> {
        let mut best: Option<NtpQueryResult> = None;

        for _ in 0..self.samples.max(1) {
            let result = self.query_once(host, port)?;
            let is_better = match &best {
                None => true,
                Some(current) => result.delay < current.delay,
            };
            if is_better {
                best = Some(result);
            }
        }

        best.ok_or_else(|| NtpDigError::Network("no results".to_string()))
    }

    /// Perform a single NTP query and return the raw result.
    fn query_once(&mut self, host: &str, port: u16) -> Result<NtpQueryResult, NtpDigError> {
        // --- Resolve and connect ---
        let addr = format!("{host}:{port}");
        let socket_addrs: Vec<std::net::SocketAddr> = addr
            .to_socket_addrs()
            .map_err(|e| NtpDigError::Network(format!("DNS resolution failed: {e}")))?
            .collect();

        if socket_addrs.is_empty() {
            return Err(NtpDigError::Network("no addresses resolved".to_string()));
        }
        let server_addr = socket_addrs[0];

        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| NtpDigError::Network(format!("bind failed: {e}")))?;

        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| NtpDigError::Network(format!("set timeout failed: {e}")))?;

        socket
            .connect(server_addr)
            .map_err(|e| NtpDigError::Network(format!("connect failed: {e}")))?;

        // --- Build the request packet ---
        let mut pkt = NtpPacket::zeroed();
        pkt.li_vn_mode =
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Client);
        pkt.transmit_ts = ntp_ts64_to_wire(Self::get_ntp_time());

        // T1: the transmit timestamp we are sending.
        let t1 = Self::get_ntp_time();

        let request_bytes = pkt.encode_header();

        socket
            .send(&request_bytes)
            .map_err(|e| NtpDigError::Network(format!("send failed: {e}")))?;

        // --- Receive the response ---
        let mut buf = [0u8; NTP_MAX_PACKET_SIZE];
        let recv_len = socket.recv(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
            {
                NtpDigError::Timeout
            } else {
                NtpDigError::Network(format!("recv failed: {e}"))
            }
        })?;

        // T4: client receive timestamp (wall-clock time right after recv).
        let t4 = Self::get_ntp_time();

        if recv_len < NTP_HEADER_SIZE {
            return Err(NtpDigError::BadResponse(format!(
                "response too short: {recv_len} bytes"
            )));
        }

        // --- Decode and validate ---
        let response = NtpPacket::decode_header(&buf[..recv_len])
            .map_err(|e| NtpDigError::BadResponse(format!("decode failed: {e}")))?;

        let version = response.version();
        let mode = response.mode();

        if version != NtpVersion::V4 {
            return Err(NtpDigError::BadResponse(format!(
                "unexpected version: {:?}",
                version
            )));
        }

        if mode != NtpMode::Server && mode != NtpMode::SymPassive {
            return Err(NtpDigError::BadResponse(format!(
                "unexpected mode: {:?}",
                mode
            )));
        }

        // Kiss-o'-death check: stratum 0.
        if response.stratum == 0 {
            let kiss = refid_to_string(response.reference_id, 0);
            return Err(NtpDigError::InvalidKissCode(kiss));
        }

        // --- Extract timestamps ---
        // T2 = receive timestamp (server received our request)
        let t2 = ntp_ts_to_ntpts(response.receive_ts);
        // T3 = transmit timestamp (server sent the response)
        let t3 = ntp_ts_to_ntpts(response.transmit_ts);

        // --- Compute offset and delay (all in f64 seconds from NTP epoch) ---
        let t1_f = ntp_ts_to_f64(&t1);
        let t2_f = ntp_ts_to_f64(&t2);
        let t3_f = ntp_ts_to_f64(&t3);
        let t4_f = ntp_ts_to_f64(&t4);

        let offset = ((t2_f - t1_f) + (t3_f - t4_f)) / 2.0;
        let delay = (t4_f - t1_f) - (t3_f - t2_f);

        // --- Convert root delay and dispersion ---
        let root_delay = ntp_short_to_f64(response.root_delay);
        let root_dispersion = ntp_short_to_f64(response.root_dispersion);

        // --- Compute the wall-clock time (ISO 8601) ---
        let when = unix_to_iso_string(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        );

        // --- Stratum/refid display ---
        let refid_string = refid_to_string(response.reference_id, response.stratum);

        Ok(NtpQueryResult {
            remote: host.to_string(),
            stratum: response.stratum,
            refid: response.reference_id,
            refid_string,
            precision: response.precision,
            root_delay,
            root_dispersion,
            offset,
            delay,
            dispersion: root_dispersion,
            when,
            leap: response.leap_indicator(),
        })
    }

    /// Get the current system time as an NTP timestamp (NtpTs64).
    fn get_ntp_time() -> NtpTs64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let total_secs = now.as_secs() as i64 + NTP_EPOCH_OFFSET as i64;
        // Convert sub-second nanoseconds to NTP fraction (2^32 per second).
        let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;

        NtpTs64 {
            seconds: total_secs,
            fraction: frac as u32,
        }
    }
}

// ──── Utility functions ─────────────────────────────────────────────────────

/// Convert a `u32` NTP short-format value (16.16 fixed-point) to `f64`.
fn ntp_short_to_f64(val: u32) -> f64 {
    let secs = (val >> 16) as f64;
    let frac = (val & 0xFFFF) as f64 / 65536.0;
    secs + frac
}

/// Convert an `NtpTs64` to `f64` seconds relative to the NTP epoch.
///
/// The NTP epoch begins at 1900-01-01 00:00:00 UTC.
pub fn ntp_ts_to_f64(ts: &NtpTs64) -> f64 {
    ts.seconds as f64 + ts.fraction as f64 / NTP_FRAC_PER_SEC_F64
}

/// Convert `f64` seconds relative to the NTP epoch to an `NtpTs64`.
///
/// The NTP epoch begins at 1900-01-01 00:00:00 UTC.
pub fn f64_to_ntp_ts(secs: f64) -> NtpTs64 {
    let secs_i = secs.floor() as i64;
    let frac_f = secs - secs.floor();
    let fraction = (frac_f * NTP_FRAC_PER_SEC_F64) as u32;
    NtpTs64 {
        seconds: secs_i,
        fraction,
    }
}

/// Convert a reference identifier (`refid: u32`) to a display string.
///
/// * Stratum 0 — kiss-o'-death code (4 ASCII characters).
/// * Stratum 1 — reference clock identifier (4 ASCII characters).
/// * Stratum > 1 — formatted as a dotted-quad IPv4 address.
pub fn refid_to_string(refid: u32, stratum: u8) -> String {
    if stratum <= 1 {
        // Interpret as 4-character ASCII.
        let bytes = refid.to_be_bytes();
        let printable: String = bytes.iter().map(|&b| b as char).collect();
        // Ensure we don't include trailing nulls in display.
        printable.trim_end_matches('\0').to_string()
    } else {
        // Format as IPv4 dotted-quad.
        let bytes = refid.to_be_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// Convert a Unix timestamp (seconds since epoch) to a simple ISO 8601 string.
///
/// Format: `YYYY-MM-DDTHH:MM:SS`
fn unix_to_iso_string(unix_secs: i64) -> String {
    // Break down into date/time components.
    let (y, m, d) = unix_seconds_to_ymd(unix_secs);
    let (hh, mm, ss) = unix_seconds_to_hms(unix_secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}")
}

/// Break down Unix seconds into year, month, day.
fn unix_seconds_to_ymd(secs: i64) -> (i64, u32, u32) {
    let days = if secs >= 0 {
        secs / 86400
    } else {
        (secs - 86399) / 86400
    };
    civil_from_days(days)
}

/// Break down Unix seconds into hours, minutes, seconds.
fn unix_seconds_to_hms(secs: i64) -> (u32, u32, u32) {
    let s = if secs >= 0 {
        secs % 86400
    } else {
        86400 - ((-secs) % 86400)
    };
    let hh = (s / 3600) as u32;
    let mm = ((s % 3600) / 60) as u32;
    let ss = (s % 60) as u32;
    (hh, mm, ss)
}

/// Convert days since Unix epoch to (year, month, day) using
/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d as u32)
}

// ──── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify round-trip conversion between NtpTs64 and f64.
    #[test]
    fn test_ntp_ts_to_f64_roundtrip() {
        // NTP epoch = 0.0
        let ts = NtpTs64 {
            seconds: 0,
            fraction: 0,
        };
        let f = ntp_ts_to_f64(&ts);
        assert!((f - 0.0).abs() < 1e-9);
        let back = f64_to_ntp_ts(f);
        assert_eq!(back.seconds, 0);
        assert_eq!(back.fraction, 0);

        // A known time: 2024-01-01 00:00:00 UTC
        // Unix = 1_704_067_200, NTP = 1_704_067_200 + 2_208_988_800 = 3_913_056_000
        let ntp_secs = 1_704_067_200i64 + NTP_EPOCH_OFFSET as i64;
        let ts = NtpTs64 {
            seconds: ntp_secs,
            fraction: 0,
        };
        let f = ntp_ts_to_f64(&ts);
        let back = f64_to_ntp_ts(f);
        assert_eq!(back.seconds, ntp_secs);
        assert_eq!(back.fraction, 0);

        // Fractional: half a second
        let half_frac = (NTP_FRAC_PER_SEC_F64 / 2.0) as u32;
        let ts = NtpTs64 {
            seconds: ntp_secs,
            fraction: half_frac,
        };
        let f = ntp_ts_to_f64(&ts);
        assert!((f - (ntp_secs as f64 + 0.5)).abs() < 1e-9);
        let back = f64_to_ntp_ts(f);
        assert_eq!(back.seconds, ntp_secs);
        // Fraction may lose a little precision in the round-trip, but should be very close.
        let diff = (back.fraction as i64 - half_frac as i64).abs();
        assert!(diff <= 1, "fraction diff = {diff}");

        // Negative NTP timestamps (before NTP epoch — should not happen in practice but test anyway)
        let ts = NtpTs64 {
            seconds: -1,
            fraction: 0,
        };
        let f = ntp_ts_to_f64(&ts);
        assert!((f - (-1.0)).abs() < 1e-9);
    }

    /// Refid for stratum 0 should produce a kiss-code string.
    #[test]
    fn test_refid_to_string_stratum0() {
        // "DENY" as u32
        let deny = u32::from_be_bytes(*b"DENY");
        assert_eq!(refid_to_string(deny, 0), "DENY");

        // "RATE" as u32
        let rate = u32::from_be_bytes(*b"RATE");
        assert_eq!(refid_to_string(rate, 0), "RATE");

        // "RSTR" as u32
        let rstr = u32::from_be_bytes(*b"RSTR");
        assert_eq!(refid_to_string(rstr, 0), "RSTR");

        // "STEP" as u32
        let step = u32::from_be_bytes(*b"STEP");
        assert_eq!(refid_to_string(step, 0), "STEP");

        // Stratum 1 also yields ASCII
        let gps = u32::from_be_bytes(*b"GPS\0");
        let result = refid_to_string(gps, 1);
        assert_eq!(result, "GPS");

        // All zeros
        assert_eq!(refid_to_string(0, 0), "");
    }

    /// Refid for stratum > 1 should produce a dotted-quad IP address.
    #[test]
    fn test_refid_to_string_ip() {
        // 127.0.0.1
        let refid = u32::from_be_bytes([127, 0, 0, 1]);
        assert_eq!(refid_to_string(refid, 2), "127.0.0.1");

        // 192.168.1.1
        let refid = u32::from_be_bytes([192, 168, 1, 1]);
        assert_eq!(refid_to_string(refid, 3), "192.168.1.1");

        // 0.0.0.0
        assert_eq!(refid_to_string(0, 2), "0.0.0.0");
    }

    /// Verify the offset and delay formulas with known values.
    ///
    /// Using a simple scenario:
    ///   T1 = 100.0   (client sent)
    ///   T2 = 101.0   (server received)
    ///   T3 = 101.5   (server sent)
    ///   T4 = 102.5   (client received)
    ///
    ///   offset = ((101.0 - 100.0) + (101.5 - 102.5)) / 2
    ///          = (1.0 + (-1.0)) / 2 = 0.0
    ///
    ///   delay  = (102.5 - 100.0) - (101.5 - 101.0)
    ///          = 2.5 - 0.5 = 2.0
    #[test]
    fn test_query_times() {
        let t1 = NtpTs64 {
            seconds: 100,
            fraction: 0,
        };
        let t2 = NtpTs64 {
            seconds: 101,
            fraction: 0,
        };
        let t3 = NtpTs64 {
            seconds: 101,
            fraction: NTP_FRAC_PER_SEC_F64 as u32 / 2, // 0.5 sec
        };
        let t4 = NtpTs64 {
            seconds: 102,
            fraction: NTP_FRAC_PER_SEC_F64 as u32 / 2, // 0.5 sec
        };

        let t1_f = ntp_ts_to_f64(&t1);
        let t2_f = ntp_ts_to_f64(&t2);
        let t3_f = ntp_ts_to_f64(&t3);
        let t4_f = ntp_ts_to_f64(&t4);

        assert!((t1_f - 100.0).abs() < 1e-9);
        assert!((t2_f - 101.0).abs() < 1e-9);
        assert!((t3_f - 101.5).abs() < 1e-9);
        assert!((t4_f - 102.5).abs() < 1e-9);

        let offset = ((t2_f - t1_f) + (t3_f - t4_f)) / 2.0;
        let delay = (t4_f - t1_f) - (t3_f - t2_f);

        assert!(
            (offset - 0.0).abs() < 1e-9,
            "expected offset 0.0, got {offset}"
        );
        assert!(
            (delay - 2.0).abs() < 1e-9,
            "expected delay 2.0, got {delay}"
        );

        // Asymmetric path test:
        //   T1 = 100.0, T2 = 101.5, T3 = 102.0, T4 = 103.0
        //   offset = ((101.5 - 100.0) + (102.0 - 103.0)) / 2
        //          = (1.5 + (-1.0)) / 2 = 0.25
        //   delay  = (103.0 - 100.0) - (102.0 - 101.5)
        //          = 3.0 - 0.5 = 2.5
        let t1 = NtpTs64 {
            seconds: 100,
            fraction: 0,
        };
        let t2 = NtpTs64 {
            seconds: 101,
            fraction: NTP_FRAC_PER_SEC_F64 as u32 / 2, // 0.5
        };
        let t3 = NtpTs64 {
            seconds: 102,
            fraction: 0,
        };
        let t4 = NtpTs64 {
            seconds: 103,
            fraction: 0,
        };

        let t1_f = ntp_ts_to_f64(&t1);
        let t2_f = ntp_ts_to_f64(&t2);
        let t3_f = ntp_ts_to_f64(&t3);
        let t4_f = ntp_ts_to_f64(&t4);

        let offset = ((t2_f - t1_f) + (t3_f - t4_f)) / 2.0;
        let delay = (t4_f - t1_f) - (t3_f - t2_f);

        assert!(
            (offset - 0.25).abs() < 1e-9,
            "expected offset 0.25, got {offset}"
        );
        assert!(
            (delay - 2.5).abs() < 1e-9,
            "expected delay 2.5, got {delay}"
        );
    }

    /// Verify the ntp_short_to_f64 conversion.
    #[test]
    fn test_ntp_short_to_f64() {
        // 1.5 seconds: seconds = 1, fraction = 0x8000 (32768/65536 = 0.5)
        let val: u32 = (1 << 16) | 0x8000;
        let result = ntp_short_to_f64(val);
        assert!((result - 1.5).abs() < 1e-9);

        // 0.0
        assert!((ntp_short_to_f64(0) - 0.0).abs() < 1e-9);
    }

    /// Verify the ISO 8601 formatting for known timestamps.
    #[test]
    fn test_unix_to_iso_string() {
        // Unix epoch: 1970-01-01T00:00:00
        assert_eq!(unix_to_iso_string(0), "1970-01-01T00:00:00");

        // A known date: 2024-06-15T12:30:45
        // Unix timestamp for 2024-06-15 12:30:45 UTC
        // We'll verify the format, the exact number requires calculation
        let s = unix_to_iso_string(1_718_454_645);
        assert_eq!(s, "2024-06-15T12:30:45");
    }

    /// Verify that NtpDigClient can be constructed.
    #[test]
    fn test_client_construction() {
        let client = NtpDigClient::new(Duration::from_secs(5), 3);
        assert_eq!(client.timeout, Duration::from_secs(5));
        assert_eq!(client.samples, 3);
    }

    /// Verify error Display implementations.
    #[test]
    fn test_error_display() {
        let err = NtpDigError::Network("connection refused".to_string());
        assert_eq!(format!("{err}"), "network error: connection refused");

        let err = NtpDigError::BadResponse("invalid mode".to_string());
        assert_eq!(format!("{err}"), "bad response: invalid mode");

        let err = NtpDigError::Timeout;
        assert_eq!(format!("{err}"), "query timed out");

        let err = NtpDigError::InvalidKissCode("DENY".to_string());
        assert_eq!(format!("{err}"), "invalid kiss code: DENY");
    }
}
