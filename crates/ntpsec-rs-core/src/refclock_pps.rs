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

use crate::ntp_fp::{ntp_ts64_to_wire, ts_to_ntp};
use crate::ntp_types::*;

// ──── PPS kernel API constants and structures ───────────────────────────────

/// Kernel PPS time-stamp structure (struct pps_ktime in `<linux/pps.h>`).
///
/// This is NOT `struct timespec` — it is a 16-byte structure on all architectures:
/// ```text
/// offset  size  field
///   0      8    sec   (s64)
///   8      4    nsec  (s32)
///  12      4    flags (u32)
/// total: 16
/// ```
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PpsKTime {
    sec: i64,
    nsec: i32,
    flags: u32,
}

impl PpsKTime {
    fn zero() -> Self {
        PpsKTime {
            sec: 0,
            nsec: 0,
            flags: 0,
        }
    }
}

/// Kernel PPS info structure (struct pps_kinfo in `<linux/pps.h>`).
///
/// ```text
/// offset  size  field
///   0      4     assert_sequence
///   4      4     clear_sequence
///   8     16     assert_tu   (pps_ktime)
///  24     16     clear_tu    (pps_ktime)
///  40      4     current_mode
///  44      4     <padding to 8-byte boundary>
/// total: 48
/// ```
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PpsKInfo {
    assert_sequence: u32,
    clear_sequence: u32,
    assert_tu: PpsKTime,
    clear_tu: PpsKTime,
    current_mode: i32,
}

/// Fetch data structure (struct pps_fdata in `<linux/pps.h>`).
///
/// ```text
/// offset  size  field
///   0     48     info   (pps_kinfo)
///  48     16     timeout (pps_ktime)
/// total: 64
/// ```
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PpsFData {
    info: PpsKInfo,
    timeout: PpsKTime,
}

/// Kernel PPS parameters (struct pps_kparams in `<linux/pps.h>`).
///
/// Used by the PPS_GETPARAMS ioctl for version detection.
/// ```text
/// offset  size  field
///   0      4     api_version
///   4      4     mode
///   8     16     assert_off_tu (pps_ktime)
///  24     16     clear_off_tu  (pps_ktime)
/// total: 40
/// ```
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PpsKParams {
    api_version: i32,
    mode: i32,
    assert_off_tu: PpsKTime,
    clear_off_tu: PpsKTime,
}

/// Compute a Linux ioctl command number.
///
/// On x86_64 (and most 64-bit platforms): sizeof(void*) = 8.
/// On ARM32 (and most 32-bit platforms): sizeof(void*) = 4.
/// The kernel PPS ioctl commands pass structs by pointer, so the size
/// field in the ioctl encoding is always sizeof(void*).
const fn ioctl_cmd(dir: u32, typ: u8, nr: u32, size: u32) -> u32 {
    (dir << 30) | ((size & 0x3FFF) << 16) | ((typ as u32) << 8) | nr
}

/// The `PPS_FETCH` ioctl command number.
///
/// Defined as `_IOWR('p', 0xa4, struct pps_fdata *)` in `<linux/pps.h>`.
/// The ioctl encoding uses sizeof(pointer) as the size field:
///   - 64-bit: dir=3, size=8, type='p'=0x70, nr=0xa4 → 0xc00870a4
///   - 32-bit: dir=3, size=4, type='p'=0x70, nr=0xa4 → 0xc00470a4
#[cfg(target_os = "linux")]
fn pps_fetch_cmd() -> u32 {
    let ptr_size = std::mem::size_of::<*const ()>() as u32;
    ioctl_cmd(3, b'p', 0xa4, ptr_size)
}

/// The `PPS_GETPARAMS` ioctl command number.
///
/// Defined as `_IOR('p', 0xa1, struct pps_kparams *)` in `<linux/pps.h>`.
#[cfg(target_os = "linux")]
fn pps_getparams_cmd() -> u32 {
    let ptr_size = std::mem::size_of::<*const ()>() as u32;
    ioctl_cmd(1, b'p', 0xa1, ptr_size)
}

/// The `PPS_SETPARAMS` ioctl command number.
///
/// Defined as `_IOW('p', 0xa2, struct pps_kparams *)` in `<linux/pps.h>`.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn pps_setparams_cmd() -> u32 {
    let ptr_size = std::mem::size_of::<*const ()>() as u32;
    ioctl_cmd(2, b'p', 0xa2, ptr_size)
}

// ──── PPS version information ───────────────────────────────────────────────

/// PPS kernel API version information.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpsVersion {
    /// API version number (from `pps_kparams.api_version`).
    pub api_version: i32,
    /// Current mode flags (from `pps_kparams.mode`).
    pub mode: i32,
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
    /// Last seen clear-sequence number, used for `clear_timestamp()` deduplication.
    last_clear_sequence: u32,
    /// Total number of successful samples read.
    samples_read: u64,
    /// Kernel PPS API version (detected on open, if available).
    kernel_version: Option<PpsVersion>,
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
            last_clear_sequence: 0,
            samples_read: 0,
            kernel_version: None,
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
        self.last_clear_sequence = 0;

        // Detect kernel PPS API version via PPS_GETPARAMS.
        let mut kparams = PpsKParams {
            api_version: 0,
            mode: 0,
            assert_off_tu: PpsKTime::zero(),
            clear_off_tu: PpsKTime::zero(),
        };

        let cmd = pps_getparams_cmd();
        let ret = unsafe { libc::ioctl(fd, cmd as _, &mut kparams as *mut PpsKParams) };

        if ret >= 0 {
            self.kernel_version = Some(PpsVersion {
                api_version: kparams.api_version,
                mode: kparams.mode,
            });
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn _open(&mut self) -> Result<(), String> {
        Err(format!(
            "PPS refclock requires Linux; cannot open {}",
            self.device
        ))
    }

    /// Detect the kernel PPS API version via `PPS_GETPARAMS` ioctl.
    ///
    /// Returns the API version and current mode flags.
    #[cfg(target_os = "linux")]
    pub fn detect_version(&self) -> Result<PpsVersion, String> {
        let fd = self.fd.ok_or_else(|| "PPS device not open".to_string())?;

        let mut kparams = PpsKParams {
            api_version: 0,
            mode: 0,
            assert_off_tu: PpsKTime::zero(),
            clear_off_tu: PpsKTime::zero(),
        };

        let cmd = pps_getparams_cmd();
        let ret = unsafe { libc::ioctl(fd, cmd as _, &mut kparams as *mut PpsKParams) };

        if ret < 0 {
            let errno = std::io::Error::last_os_error();
            return Err(format!("PPS_GETPARAMS ioctl failed: {}", errno));
        }

        Ok(PpsVersion {
            api_version: kparams.api_version,
            mode: kparams.mode,
        })
    }

    /// Return the detected kernel PPS API version, if available.
    pub fn kernel_version(&self) -> Option<PpsVersion> {
        self.kernel_version
    }

    /// Close the PPS device.
    pub fn close(&mut self) {
        if let Some(fd) = self.fd.take() {
            unsafe {
                libc::close(fd);
            }
        }
        self.last_assert_sequence = 0;
        self.last_clear_sequence = 0;
        self.kernel_version = None;
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

        let mut fdata = PpsFData {
            info: PpsKInfo {
                assert_sequence: 0,
                clear_sequence: 0,
                assert_tu: PpsKTime::zero(),
                clear_tu: PpsKTime::zero(),
                current_mode: 0,
            },
            timeout: PpsKTime::zero(),
        };

        let cmd = pps_fetch_cmd();
        let ret = unsafe { libc::ioctl(fd, cmd as _, &mut fdata as *mut PpsFData) };

        if ret < 0 {
            let errno = std::io::Error::last_os_error();
            // EAGAIN / EWOULDBLOCK means no PPS event yet
            if errno.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(format!("PPS_FETCH ioctl failed: {}", errno));
        }

        let seq = fdata.info.assert_sequence;
        if seq != 0 && seq == self.last_assert_sequence {
            // No new assert event since last read.
            return Ok(None);
        }
        self.last_assert_sequence = seq;
        self.last_clear_sequence = fdata.info.clear_sequence;
        self.samples_read += 1;

        let ts = fdata.info.assert_tu;
        let ntp_time = ts_to_ntp(ts.sec, ts.nsec as i64);

        Ok(Some(PpsStamp {
            assert_time: ntp_time,
            sequence: seq,
            clear_sequence: fdata.info.clear_sequence,
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

    /// Read and clear the PPS clear (falling-edge) timestamp.
    ///
    /// Some PPS devices provide both assert (rising edge) and clear (falling
    /// edge) timestamps. This method reads the clear timestamp, then clears
    /// it to avoid re-reading the same event.
    ///
    /// Returns:
    /// - `Ok(Some(stamp))` — a new clear timestamp was captured.
    /// - `Ok(None)` — no new clear event since the last read.
    /// - `Err(msg)` — the ioctl failed.
    pub fn read_clear_timestamp(&mut self) -> Result<Option<PpsStamp>, String> {
        self._read_clear_timestamp()
    }

    #[cfg(target_os = "linux")]
    fn _read_clear_timestamp(&mut self) -> Result<Option<PpsStamp>, String> {
        let fd = self.fd.ok_or_else(|| "PPS device not open".to_string())?;

        let mut fdata = PpsFData {
            info: PpsKInfo {
                assert_sequence: 0,
                clear_sequence: 0,
                assert_tu: PpsKTime::zero(),
                clear_tu: PpsKTime::zero(),
                current_mode: 0,
            },
            timeout: PpsKTime::zero(),
        };

        let cmd = pps_fetch_cmd();
        let ret = unsafe { libc::ioctl(fd, cmd as _, &mut fdata as *mut PpsFData) };

        if ret < 0 {
            let errno = std::io::Error::last_os_error();
            if errno.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(format!("PPS_FETCH ioctl failed: {}", errno));
        }

        let seq = fdata.info.clear_sequence;
        if seq != 0 && seq == self.last_clear_sequence {
            return Ok(None);
        }
        self.last_clear_sequence = seq;
        self.last_assert_sequence = fdata.info.assert_sequence;
        self.samples_read += 1;

        let ts = fdata.info.clear_tu;
        let ntp_time = ts_to_ntp(ts.sec, ts.nsec as i64);

        Ok(Some(PpsStamp {
            assert_time: ntp_time,
            sequence: seq,
            clear_sequence: seq,
        }))
    }

    #[cfg(not(target_os = "linux"))]
    fn _read_clear_timestamp(&mut self) -> Result<Option<PpsStamp>, String> {
        let _ = self
            .fd
            .as_ref()
            .ok_or_else(|| "PPS device not open".to_string())?;
        Err("PPS clear timestamp read is only supported on Linux".to_string())
    }

    /// Clear the captured PPS timestamp from the kernel device.
    ///
    /// This reads the PPS_FETCH ioctl and discards the result, effectively
    /// resetting the sequence number so the next read will see fresh data.
    /// Useful after a timeout or when edge transitions need to be discarded.
    pub fn clear_timestamp(&mut self) -> Result<(), String> {
        self._clear_timestamp()
    }

    #[cfg(target_os = "linux")]
    fn _clear_timestamp(&mut self) -> Result<(), String> {
        // Reading the ioctl and discarding is the standard way to clear
        // the captured timestamp from the kernel PPS device.
        let _ = self.read_timestamp()?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn _clear_timestamp(&mut self) -> Result<(), String> {
        Err("PPS clear timestamp is only supported on Linux".to_string())
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
    /// The PPS assert (or clear) timestamp in NTP time (CLOCK_REALTIME).
    pub assert_time: NtpTs64,
    /// Sequence number of the PPS event.
    pub sequence: u32,
    /// Clear sequence number from the same fetch.
    pub clear_sequence: u32,
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
    pkt.stratum = 0; // primary refclock
    pkt.precision = -30; // ~1 ns precision for PPS
    pkt.root_delay = 0;
    pkt.root_dispersion = 0;
    pkt.reference_id = u32::from_be_bytes(*b"PPS\0");

    // Convert from the 64-bit NtpTs64 used internally to the
    // 32.32 on-wire NtpTs format.
    let wire_ts = ntp_ts64_to_wire(stamp.assert_time);
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
        assert!(pps.kernel_version().is_none());

        let pps3 = PpsRefclock::new(3);
        assert_eq!(pps3.unit(), 3);
        assert_eq!(pps3.device(), "/dev/pps3");
    }

    #[test]
    fn test_pps_device_not_found() {
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
        let stamp = PpsStamp {
            assert_time: NtpTs64 {
                seconds: 4_000_000_000i64,
                fraction: 0x8000_0000,
            },
            sequence: 42,
            clear_sequence: 43,
        };

        let pkt = pps_stamp_to_packet(&stamp);

        assert_eq!(
            pkt.li_vn_mode,
            NtpPacket::set_li_vn_mode(LeapIndicator::NoWarning, NtpVersion::V4, NtpMode::Server)
        );
        assert_eq!(pkt.leap_indicator(), LeapIndicator::NoWarning);
        assert_eq!(pkt.version(), NtpVersion::V4);
        assert_eq!(pkt.mode(), NtpMode::Server);
        assert_eq!(pkt.precision, -30);
        assert_eq!(pkt.reference_id, u32::from_be_bytes(*b"PPS\0"));

        let expected_wire = ntp_ts64_to_wire(stamp.assert_time);
        assert_eq!(pkt.reference_ts, expected_wire);
        assert_eq!(pkt.receive_ts, expected_wire);
        assert_eq!(pkt.transmit_ts, expected_wire);

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
            clear_sequence: 0,
        };
        assert_eq!(stamp.sequence, 1);

        let stamp2 = PpsStamp {
            assert_time: ts_to_ntp(1_700_000_001, 0),
            sequence: 2,
            clear_sequence: 1,
        };
        assert!(stamp2.sequence > stamp.sequence);
    }

    #[test]
    fn test_pps_refclock_close_twice() {
        let mut pps = PpsRefclock::new(0);
        pps.close();
        pps.close();
        assert!(!pps.is_open());
    }

    #[test]
    fn test_pps_refclock_double_open() {
        let mut pps = PpsRefclock::new(0);
        let _ = pps.open();
        if pps.is_open() {
            let result = pps.open();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("already open"));
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_pps_unavailable_on_non_linux() {
        let mut pps = PpsRefclock::new(0);
        assert!(pps.open().is_err());
    }

    #[test]
    fn test_pps_read_timestamp_not_open() {
        let mut pps = PpsRefclock::new(0);
        let result = pps.read_timestamp();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not open"));
    }

    #[test]
    fn test_pps_clear_timestamp_not_open() {
        let mut pps = PpsRefclock::new(0);
        let result = pps.clear_timestamp();
        assert!(result.is_err());
    }

    #[test]
    fn test_pps_read_clear_timestamp_not_open() {
        let mut pps = PpsRefclock::new(0);
        let result = pps.read_clear_timestamp();
        assert!(result.is_err());
    }

    #[test]
    fn test_pps_kernel_struct_sizes() {
        #[cfg(target_os = "linux")]
        {
            // PpsKTime is always 16 bytes (sec: i64=8, nsec: i32=4, flags: u32=4)
            assert_eq!(
                std::mem::size_of::<PpsKTime>(),
                16,
                "PpsKTime must be 16 bytes"
            );

            // PpsKInfo: 4 + 4 + 16 + 16 + 4 = 44, padded to 8 = 48
            let kinfo_size = std::mem::size_of::<PpsKInfo>();
            assert!(
                kinfo_size == 44 || kinfo_size == 48,
                "PpsKInfo size should be 44 (32-bit) or 48 (64-bit), got {}",
                kinfo_size
            );

            // PpsFData = PpsKInfo + PpsKTime
            let fdata_size = std::mem::size_of::<PpsFData>();
            assert!(
                fdata_size == 60 || fdata_size == 64,
                "PpsFData size should be 60 (32-bit) or 64 (64-bit), got {}",
                fdata_size
            );

            // PpsKParams: 4 + 4 + 16 + 16 = 40
            assert_eq!(
                std::mem::size_of::<PpsKParams>(),
                40,
                "PpsKParams must be 40 bytes"
            );
        }
    }

    #[test]
    fn test_pps_ioctl_cmd_encoding() {
        #[cfg(target_os = "linux")]
        {
            // Verify ioctl encoding.
            // PPS_FETCH = _IOWR('p', 0xa4, struct pps_fdata *) with pointer size.
            let fetch_cmd = pps_fetch_cmd();

            // Direction should be _IOWR = 3 (top 2 bits = 11)
            assert_eq!(fetch_cmd >> 30, 3, "PPS_FETCH should be _IOWR");

            // Type should be 'p' = 0x70
            assert_eq!(
                (fetch_cmd >> 8) & 0xFF,
                0x70,
                "PPS_FETCH type should be 'p'"
            );

            // Number should be 0xa4
            assert_eq!(fetch_cmd & 0xFF, 0xa4, "PPS_FETCH nr should be 0xa4");

            // PPS_GETPARAMS = _IOR('p', 0xa1, ...)
            let get_cmd = pps_getparams_cmd();
            assert_eq!(get_cmd >> 30, 1, "PPS_GETPARAMS should be _IOR");
            assert_eq!(
                (get_cmd >> 8) & 0xFF,
                0x70,
                "PPS_GETPARAMS type should be 'p'"
            );
            assert_eq!(get_cmd & 0xFF, 0xa1, "PPS_GETPARAMS nr should be 0xa1");
        }
    }

    #[test]
    fn test_pps_ioctl_arch_aware() {
        #[cfg(target_os = "linux")]
        {
            let ptr_size = std::mem::size_of::<*const ()>();
            let fetch_cmd = pps_fetch_cmd();
            let size_field = (fetch_cmd >> 16) & 0x3FFF;
            assert_eq!(
                size_field as usize, ptr_size,
                "PPS_FETCH size field should match pointer size"
            );

            let get_cmd = pps_getparams_cmd();
            let size_field = (get_cmd >> 16) & 0x3FFF;
            assert_eq!(
                size_field as usize, ptr_size,
                "PPS_GETPARAMS size field should match pointer size"
            );
        }
    }

    #[test]
    fn test_pps_ktime_layout() {
        #[cfg(target_os = "linux")]
        {
            let ktime = PpsKTime::zero();
            assert_eq!(ktime.sec, 0);
            assert_eq!(ktime.nsec, 0);
            assert_eq!(ktime.flags, 0);
        }
    }
}
