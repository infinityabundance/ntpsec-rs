// ──── refclock_pps.rs ───────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_pps.c
//
// Pulse-Per-Second refclock driver (type 22).
//
// Uses the Linux kernel PPS API (RFC 2783) via ioctl on /dev/ppsN to capture
// precise pulse-per-second timestamps from a serial-line DCD signal or
// dedicated PPS device.
//
// ## Oracle
//   - ntpsec: ntpd/refclock_pps.c
//   - RFC 2783 — Pulse-Per-Second API for Unix-like Operating Systems
//   - Linux: include/uapi/linux/pps.h (PPS_FETCH ioctl, struct pps_kinfo)
//
// ## Court
//   - docs/courts/refclock_pps.md — ioctl parameter layout, sequence-number
//     deduplication, packet-field mapping.
// =============================================================================

use crate::ntp_fp::{ntp_ts64_to_ntpts, ts_to_ntp};
use crate::ntp_types::*;

// ──── PPS kernel API constants and structures ───────────────────────────────

/// The `PPS_FETCH` ioctl command number.
///
/// Encoded via `_IOWR('n', 4, struct pps_fetch_params)`.
/// On x86_64 Linux this produces `0xc050a004` (dir=3, size=80, type='n'=0x6e...).
///
/// We define it as a `c_ulong` since `libc::ioctl` accepts that type.
#[cfg(target_os = "linux")]
const PPS_FETCH: libc::c_ulong = 0xc050a004;

/// Kernel PPS time-stamp structure (struct pps_kinfo in `<linux/pps.h>`).
///
/// Layout (x86_64 Linux):
/// ```text
/// offset  size  field
///  0       4    assert_sequence
///  4       4    clear_sequence
///  8      16    assert_timestamp (timespec: tv_sec + tv_nsec, 8+8)
/// 24      16    clear_timestamp
/// 40       4    current_mode
/// 44       4    <padding to 8-byte alignment>
/// total   48
/// ```
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PpsKInfo {
    assert_sequence: u32,
    clear_sequence: u32,
    assert_timestamp: libc::timespec,
    clear_timestamp: libc::timespec,
    current_mode: i32,
}

/// Fetch-parameter wrapper required by the `PPS_FETCH` ioctl.
///
/// The kernel expects a `struct pps_fetch_params` containing the timestamp
/// format flag, an optional timeout, and the `pps_kinfo` result buffer.
///
/// Layout (x86_64 Linux):
/// ```text
/// offset  size  field
///  0       4    tsformat       (0 = timespec)
///  4       4    timeout_sec    (0 = return immediately)
///  8       4    timeout_nsec
/// 12       4    <padding>
/// 16      48    info (PpsKInfo)
/// total   64
/// ```
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PpsFetchParams {
    tsformat: i32,
    timeout_sec: i32,
    timeout_nsec: i32,
    __pad: i32,
    info: PpsKInfo,
}

// ──── PPS refclock driver ───────────────────────────────────────────────────

/// PPS refclock driver instance.
///
/// Opens the kernel PPS device (`/dev/ppsN`) and reads precise assert
/// timestamps.  On non-Linux platforms `open()` returns an error.
#[derive(Debug)]
pub struct PpsRefclock {
    /// Refclock unit number (determines the device path, e.g. unit 0 → `/dev/pps0`).
    unit: u8,
    /// Open file descriptor, or `None` when closed.
    fd: Option<i32>,
    /// Device path (e.g. `/dev/pps0`).
    device: String,
    /// Last seen assert-sequence number, used to detect duplicate reads.
    last_assert_sequence: u32,
    /// Total number of successful samples read.
    samples_read: u64,
}

impl PpsRefclock {
    /// Create a new PPS refclock instance for the given unit number.
    ///
    /// The device is not opened until [`open()`](Self::open) is called.
    pub fn new(unit: u8) -> Self {
        let device = format!("/dev/pps{}", unit);
        Self {
            unit,
            fd: None,
            device,
            last_assert_sequence: 0,
            samples_read: 0,
        }
    }

    /// Open the PPS device (e.g., `/dev/pps0` for unit 0).
    ///
    /// Returns `Ok(())` on success, or `Err(String)` with a description of
    /// the failure.
    pub fn open(&mut self) -> Result<(), String> {
        self._open()
    }

    #[cfg(target_os = "linux")]
    fn _open(&mut self) -> Result<(), String> {
        if self.fd.is_some() {
            return Err("PPS device already open".to_string());
        }

        let path_c = std::ffi::CString::new(self.device.as_str())
            .map_err(|e| format!("Invalid device path: {}", e))?;

        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };

        if fd < 0 {
            let errno = std::io::Error::last_os_error();
            return Err(format!("Failed to open {}: {}", self.device, errno));
        }

        self.fd = Some(fd);
        self.last_assert_sequence = 0;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn _open(&mut self) -> Result<(), String> {
        Err(format!(
            "PPS refclock requires Linux; cannot open {}",
            self.device
        ))
    }

    /// Close the PPS device.
    pub fn close(&mut self) {
        if let Some(fd) = self.fd.take() {
            unsafe {
                libc::close(fd);
            }
        }
        self.last_assert_sequence = 0;
    }

    /// Read a PPS timestamp.
    ///
    /// Returns the precise kernel timestamp of the most recent pulse.
    /// Uses the `PPS_FETCH` ioctl to retrieve the latest assert timestamp
    /// from the kernel PPS device.
    ///
    /// Returns:
    /// - `Ok(Some(stamp))` — a new (or first) PPS timestamp was captured.
    /// - `Ok(None)` — no new assert event since the last read
    ///   (sequence number did not advance).
    /// - `Err(msg)` — the ioctl failed (device not open, I/O error, etc.).
    pub fn read_timestamp(&mut self) -> Result<Option<PpsStamp>, String> {
        self._read_timestamp()
    }

    #[cfg(target_os = "linux")]
    fn _read_timestamp(&mut self) -> Result<Option<PpsStamp>, String> {
        let fd = self.fd.ok_or_else(|| "PPS device not open".to_string())?;

        let mut params = PpsFetchParams {
            tsformat: 0,    // default (struct timespec)
            timeout_sec: 0, // no timeout — return immediately
            timeout_nsec: 0,
            __pad: 0,
            info: PpsKInfo {
                assert_sequence: 0,
                clear_sequence: 0,
                assert_timestamp: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                clear_timestamp: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                current_mode: 0,
            },
        };

        let ret = unsafe { libc::ioctl(fd, PPS_FETCH, &mut params as *mut PpsFetchParams) };

        if ret < 0 {
            let errno = std::io::Error::last_os_error();
            // EAGAIN / EWOULDBLOCK means no PPS event yet
            if errno.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(format!("PPS_FETCH ioctl failed: {}", errno));
        }

        let seq = params.info.assert_sequence;
        if seq != 0 && seq == self.last_assert_sequence {
            // No new assert event since last read.
            return Ok(None);
        }
        self.last_assert_sequence = seq;
        self.samples_read += 1;

        let ts = params.info.assert_timestamp;
        let ntp_time = ts_to_ntp(ts.tv_sec, ts.tv_nsec);

        Ok(Some(PpsStamp {
            assert_time: ntp_time,
            sequence: seq,
        }))
    }

    #[cfg(not(target_os = "linux"))]
    fn _read_timestamp(&mut self) -> Result<Option<PpsStamp>, String> {
        let _ = self
            .fd
            .as_ref()
            .ok_or_else(|| "PPS device not open".to_string())?;
        Err("PPS timestamp read is only supported on Linux".to_string())
    }

    /// Returns the number of successful samples read.
    pub fn samples_read(&self) -> u64 {
        self.samples_read
    }

    /// Returns the unit number of this refclock instance.
    pub fn unit(&self) -> u8 {
        self.unit
    }

    /// Returns the device path.
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Returns `true` if the device is currently open.
    pub fn is_open(&self) -> bool {
        self.fd.is_some()
    }
}

impl Drop for PpsRefclock {
    fn drop(&mut self) {
        self.close();
    }
}

// ──── PPS timestamp ─────────────────────────────────────────────────────────

/// A PPS timestamp with both raw and corrected times.
///
/// Captured from the kernel via the `PPS_FETCH` ioctl on a PPS device node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpsStamp {
    /// The PPS assert timestamp in NTP time (CLOCK_REALTIME).
    pub assert_time: NtpTs64,
    /// Sequence number of the PPS assert event.
    pub sequence: u32,
}

// ──── Packet construction ───────────────────────────────────────────────────

/// Build a synthetic NTP packet from a PPS timestamp.
///
/// The returned packet is suitable for injection into the NTP clock-filter
/// pipeline as if it were received from a stratum-0 reference clock.  All
/// timestamp fields are set to the PPS assert time; the precision reflects
/// approximately 1 ns granularity.
pub fn pps_stamp_to_packet(stamp: &PpsStamp) -> NtpPacket {
    let mut pkt = NtpPacket::zeroed();
    pkt.li_vn_mode =
        NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server);
    pkt.precision = -30; // ~1 ns precision for PPS
    pkt.reference_id = u32::from_be_bytes(*b"PPS\0");

    // Convert from the 64-bit NtpTs64 used internally to the
    // 32.32 on-wire NtpTs format.
    let wire_ts = ntp_ts64_to_ntpts(stamp.assert_time);
    pkt.reference_ts = wire_ts;
    pkt.receive_ts = wire_ts;
    pkt.transmit_ts = wire_ts;
    pkt
}

// ──── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pps_refclock_new() {
        let pps = PpsRefclock::new(0);
        assert_eq!(pps.unit(), 0);
        assert_eq!(pps.device(), "/dev/pps0");
        assert!(!pps.is_open());
        assert_eq!(pps.samples_read(), 0);

        let pps3 = PpsRefclock::new(3);
        assert_eq!(pps3.unit(), 3);
        assert_eq!(pps3.device(), "/dev/pps3");
    }

    #[test]
    fn test_pps_device_not_found() {
        // Without a real /dev/pps device (typical in CI/containers),
        // open() should return an error.  The exact message varies
        // by platform, but it must be an Err.
        let mut pps = PpsRefclock::new(99);
        let result = pps.open();
        assert!(
            result.is_err(),
            "Expected open to fail on nonexistent device"
        );

        #[cfg(not(target_os = "linux"))]
        assert!(
            result.unwrap_err().contains("requires Linux"),
            "Non-Linux should report platform limitation"
        );
    }

    #[test]
    fn test_pps_packet_construction() {
        // Build a synthetic PPS stamp at a known time.
        let stamp = PpsStamp {
            assert_time: NtpTs64 {
                seconds: 4_000_000_000i64, // well into NTP era 0
                fraction: 0x8000_0000,     // exactly 0.5 seconds
            },
            sequence: 42,
        };

        let pkt = pps_stamp_to_packet(&stamp);

        // Verify LI/VN/Mode encoding.
        assert_eq!(
            pkt.li_vn_mode,
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server)
        );
        assert_eq!(pkt.leap_indicator(), LeapIndicator::NoWarning);
        assert_eq!(pkt.version(), NtpVersion::V4);
        assert_eq!(pkt.mode(), NtpMode::Server);

        // Verify precision (PPS ≈ 1 ns → log2(1e-9) ≈ -30).
        assert_eq!(pkt.precision, -30);

        // Verify reference ID.
        assert_eq!(pkt.reference_id, u32::from_be_bytes(*b"PPS\0"));

        // Verify timestamp conversion: NtpTs64 -> on-wire NtpTs.
        let expected_wire = ntp_ts64_to_ntpts(stamp.assert_time);
        assert_eq!(pkt.reference_ts, expected_wire);
        assert_eq!(pkt.receive_ts, expected_wire);
        assert_eq!(pkt.transmit_ts, expected_wire);

        // Originate timestamp should remain zeroed (unused for refclock).
        assert_eq!(
            pkt.originate_ts,
            NtpTs {
                seconds: 0,
                fraction: 0
            }
        );
    }

    #[test]
    fn test_pps_stamp_sequence() {
        let stamp = PpsStamp {
            assert_time: ts_to_ntp(1_700_000_000, 123_456_789),
            sequence: 1,
        };
        assert_eq!(stamp.sequence, 1);

        let stamp2 = PpsStamp {
            assert_time: ts_to_ntp(1_700_000_001, 0),
            sequence: 2,
        };
        assert!(stamp2.sequence > stamp.sequence);
    }

    #[test]
    fn test_pps_refclock_close_twice() {
        // Calling close on an already-closed instance should be safe.
        let mut pps = PpsRefclock::new(0);
        pps.close(); // no-op (was never opened)
        pps.close(); // second close — should also be safe
        assert!(!pps.is_open());
    }

    #[test]
    fn test_pps_refclock_double_open() {
        // Calling open twice without an intervening close should fail.
        let mut pps = PpsRefclock::new(0);
        // First open will likely fail (no real device),
        // but if it succeeds, second open must fail.
        let _ = pps.open();
        if pps.is_open() {
            let result = pps.open();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("already open"));
        }
    }

    #[test]
    fn test_pps_read_timestamp_not_open() {
        // Reading without opening should produce an error.
        let mut pps = PpsRefclock::new(0);
        let result = pps.read_timestamp();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not open"));
    }
}
