// ──── refclock_shm.rs ───────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/refclock_shm.c
//
// Shared Memory refclock driver (type 28). Reads time samples from POSIX
// shared memory segments and produces synthetic NTP packets for the
// daemon engine to process as server responses.
//
// ## Oracle
//   - ntpsec ntpd/refclock_shm.c (14K)
//   - ntpsec include/ntp_shm.h
// =============================================================================

use crate::ntp_fp::{self, ts_to_ntp};
use crate::ntp_types::*;

/// SHM refclock unit number maximum (0-3, matching ntpsec default).
pub const SHM_UNITS: usize = 4;

/// Size of the shared memory segment (struct shmTime + padding).
/// Must match the layout used by ntpsec's time providers.
pub const SHM_SIZE: usize = 200;

/// NTP_SHM_MODE values — how the time provider writes samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShmMode {
    /// Mode 0: write all fields, set count = count + 1, then set valid = 1.
    Uninterpolated,
    /// Mode 1: write count = count + 1, then set valid = 1;
    /// reading side interpolates between raw samples.
    Interpolated,
}

impl ShmMode {
    pub fn from_i32(mode: i32) -> Self {
        match mode {
            0 => ShmMode::Uninterpolated,
            _ => ShmMode::Interpolated,
        }
    }

    pub fn to_i32(self) -> i32 {
        match self {
            ShmMode::Uninterpolated => 0,
            ShmMode::Interpolated => 1,
        }
    }
}

/// The shared memory structure, matching ntpsec's `struct shmTime`.
///
/// Fields are allocated as individual i32 values rather than a packed struct
/// to avoid undefined behavior from reinterpreting raw shared-memory bytes.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ShmTime {
    pub mode: i32,                    // 0=uninterpolated, 1=interpolated
    pub count: i32,                   // sequence counter
    pub valid: i32,                   // set to 1 by writer when sample is ready
    pub nsec: i32,                    // sub-second time (nanoseconds or microseconds)
    pub clock_time_stamp_sec: i32,    // seconds from time source
    pub clock_time_stamp_usec: i32,   // sub-seconds from time source
    pub receive_time_stamp_sec: i32,  // seconds when writer received time
    pub receive_time_stamp_usec: i32, // sub-seconds of receive time
    pub leap: i32,                    // leap indicator
    pub precision: i32,               // clock precision (log2 seconds)
    pub nsamples: i32,                // number of valid samples
    pub valid2: i32,                  // secondary valid flag (mode 1)
    pub clock_time_stamp_nsec: i32,   // nanoseconds from time source (preferred)
    pub receive_time_stamp_nsec: i32, // nanoseconds of receive time (preferred)
    pub dummy: [i32; 8],              // padding to total 200 bytes
}

impl ShmTime {
    pub fn zeroed() -> Self {
        Self {
            mode: 0,
            count: 0,
            valid: 0,
            nsec: 0,
            clock_time_stamp_sec: 0,
            clock_time_stamp_usec: 0,
            receive_time_stamp_sec: 0,
            receive_time_stamp_usec: 0,
            leap: 0,
            precision: 0,
            nsamples: 0,
            valid2: 0,
            clock_time_stamp_nsec: 0,
            receive_time_stamp_nsec: 0,
            dummy: [0; 8],
        }
    }
}

/// Result of reading a time sample from the SHM segment.
#[derive(Debug, Clone)]
pub struct ShmSample {
    /// Clock time: the time according to the refclock.
    pub clock_time: NtpTs64,
    /// Receive time: the time when the refclock received the time signal.
    pub receive_time: NtpTs64,
    /// Leap indicator from the refclock.
    pub leap: LeapIndicator,
    /// Precision of the refclock (log2 seconds).
    pub precision: i8,
}

/// SHM refclock driver instance.
#[derive(Debug)]
pub struct ShmRefclock {
    unit: u8,
    fd: Option<i32>,
    shm_id: Option<i32>,
    mapped: Option<*mut u8>,
    last_count: i32,
    samples_read: u64,
}

// Safe to send across threads (raw pointer is managed internally)
unsafe impl Send for ShmRefclock {}

impl ShmRefclock {
    /// Create a new SHM refclock driver for the given unit number.
    /// The shared memory key is based on the unit: NTP_SHM_KEY + unit.
    pub fn new(unit: u8) -> Self {
        Self {
            unit,
            fd: None,
            shm_id: None,
            mapped: None,
            last_count: -1,
            samples_read: 0,
        }
    }

    /// Open the shared memory segment. Uses shmget/shmat on Linux.
    /// Returns Ok(()) if the segment was opened successfully.
    pub fn open(&mut self) -> Result<(), String> {
        let key = ntp_shm_key(self.unit);

        // Try to create or attach to the shared memory segment
        let shm_id =
            unsafe { libc::shmget(key, SHM_SIZE, libc::IPC_CREAT | libc::IPC_EXCL | 0o660) };

        // If exclusive create failed, segment already exists — open it
        let shm_id = if shm_id < 0 {
            unsafe { libc::shmget(key, SHM_SIZE, 0o660) }
        } else {
            shm_id
        };

        if shm_id < 0 {
            return Err(format!(
                "shmget failed for unit {}: {}",
                self.unit,
                std::io::Error::last_os_error()
            ));
        }

        let ptr = unsafe { libc::shmat(shm_id, std::ptr::null(), 0) };
        if ptr == libc::MAP_FAILED {
            return Err(format!(
                "shmat failed for unit {}: {}",
                self.unit,
                std::io::Error::last_os_error()
            ));
        }

        self.shm_id = Some(shm_id);
        self.mapped = Some(ptr as *mut u8);
        Ok(())
    }

    /// Close the shared memory segment.
    pub fn close(&mut self) {
        if let Some(ptr) = self.mapped {
            unsafe { libc::shmdt(ptr as *mut libc::c_void) };
            self.mapped = None;
        }
        self.shm_id = None;
    }

    /// Read a time sample from the shared memory segment.
    /// Returns Ok(Some(sample)) if a new sample is available,
    /// Ok(None) if no new sample, Err on segment read failure.
    pub fn read_sample(&mut self) -> Result<Option<ShmSample>, String> {
        let ptr = match self.mapped {
            Some(p) => p,
            None => return Err("SHM segment not open".to_string()),
        };

        // Read the shmTime structure from shared memory
        let shm = unsafe {
            let shm_ptr = ptr as *const ShmTime;
            // Volatile read to ensure we get the latest values
            std::ptr::read_volatile(shm_ptr)
        };

        // Check if a new sample is available
        if shm.count == self.last_count {
            return Ok(None);
        }

        if shm.valid == 0 {
            return Ok(None);
        }

        self.last_count = shm.count;
        self.samples_read += 1;

        // Convert to NTP timestamps using ts_to_ntp (seconds + nanoseconds)
        // clock_time_stamp_nsec is preferred if non-zero (higher resolution)
        let clock_time = if shm.clock_time_stamp_nsec != 0 {
            ts_to_ntp(
                shm.clock_time_stamp_sec as i64,
                shm.clock_time_stamp_nsec as i64,
            )
        } else {
            ts_to_ntp(
                shm.clock_time_stamp_sec as i64,
                shm.clock_time_stamp_usec as i64 * 1000,
            )
        };

        let receive_time = if shm.receive_time_stamp_nsec != 0 {
            ts_to_ntp(
                shm.receive_time_stamp_sec as i64,
                shm.receive_time_stamp_nsec as i64,
            )
        } else {
            ts_to_ntp(
                shm.receive_time_stamp_sec as i64,
                shm.receive_time_stamp_usec as i64 * 1000,
            )
        };

        Ok(Some(ShmSample {
            clock_time,
            receive_time,
            leap: LeapIndicator::from_bits(shm.leap as u8),
            precision: shm.precision as i8,
        }))
    }

    /// Number of samples read since the driver was created.
    pub fn samples_read(&self) -> u64 {
        self.samples_read
    }
}

impl Drop for ShmRefclock {
    fn drop(&mut self) {
        self.close();
    }
}

/// Compute the System V IPC key for a SHM refclock unit.
/// NTPsec uses NTP_SHM_KEY (0x4e545030 = "NTP0") + unit.
pub fn ntp_shm_key(unit: u8) -> i32 {
    0x4e545030i32 + unit as i32
}

/// Build a synthetic NTP packet from a SHM sample, suitable for feeding
/// into the daemon engine as a server response.
pub fn shm_sample_to_packet(sample: &ShmSample, precision: i8) -> NtpPacket {
    let mut pkt = NtpPacket::zeroed();
    pkt.li_vn_mode = NtpPacket::set_li_vn_mode(sample.leap, NtpVersion::V4, NtpMode::Server);
    pkt.stratum = 0; // stratum will be set by the engine
    pkt.precision = precision;
    pkt.reference_id = u32::from_be_bytes(*b"SHM\0");
    pkt.reference_ts = sample.clock_time;
    pkt.originate_ts = sample.receive_time;
    pkt.receive_ts = sample.clock_time;
    pkt.transmit_ts = sample.clock_time;
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shm_key() {
        // NTP_SHM_KEY_BASE = 0x4e545030
        assert_eq!(ntp_shm_key(0), 0x4e545030);
        assert_eq!(ntp_shm_key(1), 0x4e545031);
        assert_eq!(ntp_shm_key(2), 0x4e545032);
        assert_eq!(ntp_shm_key(3), 0x4e545033);
    }

    #[test]
    fn test_shm_time_zeroed() {
        let t = ShmTime::zeroed();
        assert_eq!(t.mode, 0);
        assert_eq!(t.count, 0);
        assert_eq!(t.valid, 0);
        assert_eq!(t.dummy.len(), 8);
    }

    #[test]
    fn test_shm_sample_to_packet() {
        let sample = ShmSample {
            clock_time: NtpTs64 {
                seconds: 1000,
                fraction: 0,
            },
            receive_time: NtpTs64 {
                seconds: 1001,
                fraction: 0,
            },
            leap: LeapIndicator::NoWarning,
            precision: -6,
        };
        let pkt = shm_sample_to_packet(&sample, -6);
        assert_eq!(pkt.mode(), NtpMode::Server);
        assert_eq!(pkt.version(), NtpVersion::V4);
        assert_eq!(pkt.leap_indicator(), LeapIndicator::NoWarning);
        assert_eq!(pkt.precision, -6);
        assert_eq!(pkt.reference_id, u32::from_be_bytes(*b"SHM\0"));
    }

    #[test]
    fn test_shm_mode_roundtrip() {
        assert_eq!(ShmMode::from_i32(0), ShmMode::Uninterpolated);
        assert_eq!(ShmMode::from_i32(0).to_i32(), 0);
        assert_eq!(ShmMode::from_i32(1), ShmMode::Interpolated);
        assert_eq!(ShmMode::from_i32(1).to_i32(), 1);
    }
}
