// ──── ntp_syscall.rs ────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_syscall.h
//
// System call wrapper types for adjtimex(2), ntp_adjtime(3), ntp_gettime(3).
// =============================================================================

// ──── Timex — Linux struct timex wrapper ────────────────────────────────────
//
// The `struct timex` (Linux) / `struct ntptimeval` (BSD) carries all
// parameters for the adjtimex/ntp_adjtime system call.  The kernel uses it
// to report and control the phase- and frequency-locked loop that disciplines
// the system clock.

/// A safe Rust representation of the Linux `struct timex`.
///
/// This struct maps directly to the kernel structure used by the `adjtimex()`
/// system call, which serves both as the NTP kernel PLL/API (`ntp_adjtime`)
/// and as a clock-state query (`ntp_gettime`).
///
/// ## Fields
///
/// The fields correspond one-to-one with the kernel's `struct timex` as
/// defined in `<linux/timex.h>` (and by extension, libc's `struct timex`).
///
/// Reference: Linux kernel `include/uapi/linux/timex.h`
///
/// Note: `libc::timeval` does not implement `Eq`, so `Timex` cannot derive
/// `Eq` or `PartialEq`.  Comparison is done field-by-field where needed.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Timex {
    /// Bit mask of which fields to set (see `ModFlags`).
    pub modes: u32,

    /// Time offset (microseconds).  Used when `MOD_OFFSET` is set.
    pub offset: i64,

    /// Frequency adjustment (scaled PPM).  Used when `MOD_FREQUENCY` is set.
    /// Units: 2^-16 ppm (i.e. 1 Hz = 65536).
    pub freq: i64,

    /// Maximum time error (microseconds).  Read-only in the kernel.
    pub maxerror: i64,

    /// Estimated time error (microseconds).  Read-only in the kernel.
    pub esterror: i64,

    /// Clock status bits (see `StatFlags`).  Read-only in the kernel.
    pub status: i32,

    /// PLL time constant.  Used when `MOD_TIMECONST` is set.
    pub constant: i64,

    /// Clock precision (microseconds, read-only).  The kernel computes this
    /// from the clock source resolution.
    pub precision: i64,

    /// Maximum frequency tolerance (scaled PPM, read-only).  Typically
    /// 32_768_000 (500 PPM with max PLL frequency adjustment).
    pub tolerance: i64,

    /// Current time as `timeval` (read-only).  Similar to `gettimeofday()`
    /// but includes NTP-consistent time during a slew.
    pub time: libc::timeval,

    /// Microseconds per tick (typically 10,000 for 100 Hz).  Used when
    /// `MOD_MICRO` or `MOD_NANO` is set.
    pub tick: i64,

    /// PPS frequency (scaled PPM, read-only).
    pub ppsfreq: i64,

    /// PPS jitter (read-only, nanoseconds).
    pub jitter: i64,

    /// PPS interval duration (read-only, seconds).
    pub shift: i32,

    /// PPS stability (scaled PPM, read-only).
    pub stabil: i64,

    /// PPS jitter limit exceeded counter (read-only).
    pub jitcnt: i64,

    /// PPS calibration interval counter (read-only).
    pub calcnt: i64,

    /// PPS calibration error counter (read-only).
    pub errcnt: i64,

    /// PPS stability limit exceeded counter (read-only).
    pub stbcnt: i64,

    /// TAI offset (TAI - UTC), read-only.
    /// Available on Linux kernels >= 2.6.39 with `STA_TAI` status bit.
    pub tai: i32,

    /// Kernel padding/filler fields (40 bytes on x86_64).
    /// Required for the struct to match libc::timex (208 bytes).
    _filler: [i32; 10],
}

// ──── Mode Flags ────────────────────────────────────────────────────────────

/// Bit flags for the `modes` field of `Timex`.
///
/// These indicate which parameters the caller wants to set; unset bits leave
/// the corresponding kernel parameter unchanged.
pub mod mod_flags {
    /// Set the offset.
    pub const MOD_OFFSET: u32 = 0x0001;
    /// Set the frequency.
    pub const MOD_FREQUENCY: u32 = 0x0002;
    /// Set the maximum error.
    pub const MOD_MAXERROR: u32 = 0x0004;
    /// Set the estimated error.
    pub const MOD_ESTERROR: u32 = 0x0008;
    /// Set the clock status.
    pub const MOD_STATUS: u32 = 0x0010;
    /// Set the PLL time constant.
    pub const MOD_TIMECONST: u32 = 0x0020;
    /// Set the PLL interval (obsolete on modern kernels).
    pub const _MOD_PLL: u32 = 0x0040;
    /// Set the PPS signal assert time.
    pub const _MOD_PPSMAX: u32 = 0x0080;
    /// Set the tick value and switch to microsecond resolution.
    pub const MOD_MICRO: u32 = 0x1000;
    /// Set the tick value and switch to nanosecond resolution.
    pub const MOD_NANO: u32 = 0x2000;
    /// Set the clock frequency directly (used by `ntp_adjtime`).
    pub const _MOD_CLKB: u32 = 0x4000;
    /// Set the clock frequency and time (used by `ntp_adjtime`).
    pub const _MOD_CLKA: u32 = 0x8000;
}

// ──── Status Flags ──────────────────────────────────────────────────────────

/// Bit flags for the `status` field returned by the kernel.
///
/// These reflect the current state of the kernel clock discipline.
pub mod stat_flags {
    /// Clock is synchronized to a reliable source.
    pub const STA_PLL: i32 = 0x0001;
    /// Frequency set by PLL frequency correction.
    pub const STA_PPSFREQ: i32 = 0x0002;
    /// Phase set by PPS time signal.
    pub const STA_PPSTIME: i32 = 0x0004;
    /// FLL mode enabled (frequency-locked loop).
    pub const STA_FLL: i32 = 0x0008;
    /// Insert a leap second (add 1 second — 23:59:60).
    pub const STA_INS: i32 = 0x0010;
    /// Delete a leap second (remove 1 second).
    pub const STA_DEL: i32 = 0x0020;
    /// Clock unsynchronized.
    pub const STA_UNSYNC: i32 = 0x0040;
    /// Hold frequency (frequency freeze).
    pub const STA_FREQHOLD: i32 = 0x0080;
    /// PPS signal present and enabled.
    pub const STA_PPSSIGNAL: i32 = 0x0100;
    /// PPS jitter exceeded limit.
    pub const STA_PPSJITTER: i32 = 0x0200;
    /// PPS wander exceeded limit.
    pub const STA_PPSWANDER: i32 = 0x0400;
    /// PPS calibration error.
    pub const STA_PPSERROR: i32 = 0x0800;
    /// Clock hardware is unsynchronized.
    pub const STA_CLOCKERR: i32 = 0x1000;
    /// Nanosecond resolution (vs microsecond).
    pub const STA_NANO: i32 = 0x2000;
    /// TAI offset available (Linux >= 2.6.39).
    pub const STA_MODE: i32 = 0x4000;
    /// Clock was stepped via NTP (Linux >= 4.x).
    pub const STA_CLK: i32 = 0x8000;
}

// ──── Return Status ─────────────────────────────────────────────────────────

/// Return status codes from `adjtimex()` / `ntp_adjtime()`.
///
/// These correspond to the return values of the `adjtimex()` system call,
/// indicating the current clock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ClockState {
    /// Clock is synchronized and running normally.
    Ok = 0,
    /// A precision timer is in use (e.g. TSC calibration).
    Ins = 1,
    /// Clock is being stepped by a leap second (add second).
    JumpSet = 2,
    /// Clock is being stepped by a leap second (delete second).
    JumpDel = 3,
    /// Clock is unsynchronized.
    Unsync = 4,
    /// An error occurred during the system call.
    Error(i32),
}

impl ClockState {
    /// Convert a raw adjtimex return value to a `ClockState`.
    pub fn from_raw(raw: i32) -> Self {
        match raw {
            0 => ClockState::Ok,
            1 => ClockState::Ins,
            2 => ClockState::JumpSet,
            3 => ClockState::JumpDel,
            4 => ClockState::Unsync,
            _ => ClockState::Error(raw),
        }
    }
}

// ──── System Call Wrappers ──────────────────────────────────────────────────

/// Call `adjtimex(2)` (a.k.a. `ntp_adjtime()`) to read or set kernel clock
/// discipline parameters.
///
/// On success, the `Timex` struct is filled in with the kernel's current
/// parameters (including read-only fields), and a [`ClockState`] is returned
/// indicating the clock synchronization state.
///
/// # Arguments
///
/// * `buf` — A mutable reference to a `Timex` struct.  Set `buf.modes` to
///   indicate which fields to set; fields with unset mode bits are ignored
///   (left unchanged in the kernel).
///
/// # Errors
///
/// Returns `Err(String)` if the system call fails with a negative return
/// value (e.g. `EPERM` if the caller lacks `CAP_SYS_TIME`).
pub fn ntp_adjtime(buf: &mut Timex) -> Result<ClockState, String> {
    #[cfg(target_os = "linux")]
    {
        let mut raw: libc::timex = timex_to_libc(buf);
        let rc = unsafe { libc::adjtimex(&mut raw) };
        if rc < 0 {
            return Err(format!(
                "adjtimex failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        *buf = timex_from_libc(&raw);
        Ok(ClockState::from_raw(rc))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = buf;
        Err("adjtimex is not supported on this platform (EPERM)".to_string())
    }
}

/// Get the current kernel clock discipline status (read-only).
///
/// This is equivalent to calling `ntp_adjtime()` with `modes = 0` (no
/// changes requested).  The returned `Timex` contains the kernel's current
/// parameters, including estimated error, precision, TAI offset, etc.
///
/// # Errors
///
/// Returns `Err(String)` if the system call fails.
pub fn ntp_gettime() -> Result<Timex, String> {
    let mut tx = Timex::zeroed();
    ntp_adjtime(&mut tx)?;
    Ok(tx)
}

/// Convenience: return the TAI offset from the kernel (if available).
///
/// This performs an `ntp_gettime()` and returns the `tai` field, which
/// contains (TAI - UTC) in seconds on Linux kernels >= 2.6.39.
pub fn ntp_get_tai_offset() -> Result<i32, String> {
    let tx = ntp_gettime()?;
    Ok(tx.tai)
}

/// Convenience: return the estimated error in microseconds.
pub fn ntp_get_esterror() -> Result<i64, String> {
    let tx = ntp_gettime()?;
    Ok(tx.esterror)
}

/// Convenience: return the maximum error in microseconds.
pub fn ntp_get_maxerror() -> Result<i64, String> {
    let tx = ntp_gettime()?;
    Ok(tx.maxerror)
}

// ──── Timex Constructors & Helpers ──────────────────────────────────────────

impl Timex {
    /// Create a zeroed `Timex` (all fields 0).
    pub const fn zeroed() -> Self {
        Self {
            modes: 0,
            offset: 0,
            freq: 0,
            maxerror: 0,
            esterror: 0,
            status: 0,
            constant: 0,
            precision: 0,
            tolerance: 0,
            time: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            tick: 0,
            ppsfreq: 0,
            jitter: 0,
            shift: 0,
            stabil: 0,
            jitcnt: 0,
            calcnt: 0,
            errcnt: 0,
            stbcnt: 0,
            tai: 0,
            _filler: [0i32; 10],
        }
    }

    /// Create a `Timex` prepared to set the frequency.
    ///
    /// `freq` is in scaled PPM (2^-16 ppm units, i.e. 1 Hz = 65536).
    pub fn with_frequency(freq: i64) -> Self {
        Self {
            modes: mod_flags::MOD_FREQUENCY,
            freq,
            ..Self::zeroed()
        }
    }

    /// Create a `Timex` prepared to set the clock offset.
    ///
    /// `offset` is in microseconds (or nanoseconds if `STA_NANO` is set).
    pub fn with_offset(offset: i64) -> Self {
        Self {
            modes: mod_flags::MOD_OFFSET,
            offset,
            ..Self::zeroed()
        }
    }

    /// Create a `Timex` prepared to set both the offset and frequency.
    pub fn with_offset_and_freq(offset: i64, freq: i64) -> Self {
        Self {
            modes: mod_flags::MOD_OFFSET | mod_flags::MOD_FREQUENCY,
            offset,
            freq,
            ..Self::zeroed()
        }
    }

    /// Create a `Timex` prepared to set the PLL time constant.
    pub fn with_time_constant(constant: i64) -> Self {
        Self {
            modes: mod_flags::MOD_TIMECONST,
            constant,
            ..Self::zeroed()
        }
    }
}

impl Default for Timex {
    fn default() -> Self {
        Self::zeroed()
    }
}

// ──── Conversion helpers between our Timex and libc::timex ──────────────────

#[cfg(target_os = "linux")]
fn timex_to_libc(tx: &Timex) -> libc::timex {
    libc::timex {
        modes: tx.modes,
        offset: tx.offset,
        freq: tx.freq,
        maxerror: tx.maxerror,
        esterror: tx.esterror,
        status: tx.status,
        constant: tx.constant,
        precision: tx.precision,
        tolerance: tx.tolerance,
        time: tx.time,
        tick: tx.tick,
        ppsfreq: tx.ppsfreq,
        jitter: tx.jitter,
        shift: tx.shift,
        stabil: tx.stabil,
        jitcnt: tx.jitcnt,
        calcnt: tx.calcnt,
        errcnt: tx.errcnt,
        stbcnt: tx.stbcnt,
        tai: tx.tai,
        // Zero out unused/pad fields; the kernel ignores them on input.
        ..unsafe { std::mem::zeroed() }
    }
}

#[cfg(target_os = "linux")]
fn timex_from_libc(raw: &libc::timex) -> Timex {
    Timex {
        modes: raw.modes,
        offset: raw.offset,
        freq: raw.freq,
        maxerror: raw.maxerror,
        esterror: raw.esterror,
        status: raw.status,
        constant: raw.constant,
        precision: raw.precision,
        tolerance: raw.tolerance,
        time: raw.time,
        tick: raw.tick,
        ppsfreq: raw.ppsfreq,
        jitter: raw.jitter,
        shift: raw.shift,
        stabil: raw.stabil,
        jitcnt: raw.jitcnt,
        calcnt: raw.calcnt,
        errcnt: raw.errcnt,
        stbcnt: raw.stbcnt,
        tai: raw.tai,
        _filler: [0i32; 10],
    }
}

// ──── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timex_zeroed() {
        let tx = Timex::zeroed();
        assert_eq!(tx.modes, 0);
        assert_eq!(tx.offset, 0);
        assert_eq!(tx.freq, 0);
        assert_eq!(tx.maxerror, 0);
        assert_eq!(tx.esterror, 0);
        assert_eq!(tx.status, 0);
        assert_eq!(tx.constant, 0);
        assert_eq!(tx.precision, 0);
        assert_eq!(tx.tolerance, 0);
        assert_eq!(tx.time.tv_sec, 0);
        assert_eq!(tx.time.tv_usec, 0);
        assert_eq!(tx.tick, 0);
        assert_eq!(tx.ppsfreq, 0);
        assert_eq!(tx.jitter, 0);
        assert_eq!(tx.shift, 0);
        assert_eq!(tx.stabil, 0);
        assert_eq!(tx.jitcnt, 0);
        assert_eq!(tx.calcnt, 0);
        assert_eq!(tx.errcnt, 0);
        assert_eq!(tx.stbcnt, 0);
        assert_eq!(tx.tai, 0);
    }

    #[test]
    fn test_timex_with_frequency() {
        let tx = Timex::with_frequency(65536);
        assert_eq!(tx.modes, mod_flags::MOD_FREQUENCY);
        assert_eq!(tx.freq, 65536);
        assert_eq!(tx.offset, 0);
    }

    #[test]
    fn test_timex_with_offset() {
        let tx = Timex::with_offset(500);
        assert_eq!(tx.modes, mod_flags::MOD_OFFSET);
        assert_eq!(tx.offset, 500);
        assert_eq!(tx.freq, 0);
    }

    #[test]
    fn test_timex_with_offset_and_freq() {
        let tx = Timex::with_offset_and_freq(500, 65536);
        assert_eq!(tx.modes, mod_flags::MOD_OFFSET | mod_flags::MOD_FREQUENCY);
        assert_eq!(tx.offset, 500);
        assert_eq!(tx.freq, 65536);
    }

    #[test]
    fn test_timex_with_time_constant() {
        let tx = Timex::with_time_constant(4);
        assert_eq!(tx.modes, mod_flags::MOD_TIMECONST);
        assert_eq!(tx.constant, 4);
    }

    #[test]
    fn test_timex_default() {
        let tx: Timex = Default::default();
        assert_eq!(tx.modes, 0);
    }

    #[test]
    fn test_clock_state_from_raw() {
        assert_eq!(ClockState::from_raw(0), ClockState::Ok);
        assert_eq!(ClockState::from_raw(1), ClockState::Ins);
        assert_eq!(ClockState::from_raw(2), ClockState::JumpSet);
        assert_eq!(ClockState::from_raw(3), ClockState::JumpDel);
        assert_eq!(ClockState::from_raw(4), ClockState::Unsync);
        assert_eq!(ClockState::from_raw(-1), ClockState::Error(-1));
        assert_eq!(ClockState::from_raw(99), ClockState::Error(99));
    }

    #[test]
    fn test_clock_state_debug() {
        assert_eq!(format!("{:?}", ClockState::Ok), "Ok");
        assert_eq!(format!("{:?}", ClockState::Unsync), "Unsync");
    }

    #[test]
    fn test_mod_flags_values() {
        assert_eq!(mod_flags::MOD_OFFSET, 0x0001);
        assert_eq!(mod_flags::MOD_FREQUENCY, 0x0002);
        assert_eq!(mod_flags::MOD_MAXERROR, 0x0004);
        assert_eq!(mod_flags::MOD_ESTERROR, 0x0008);
        assert_eq!(mod_flags::MOD_STATUS, 0x0010);
        assert_eq!(mod_flags::MOD_TIMECONST, 0x0020);
        assert_eq!(mod_flags::MOD_MICRO, 0x1000);
        assert_eq!(mod_flags::MOD_NANO, 0x2000);
    }

    #[test]
    fn test_stat_flags_values() {
        assert_eq!(stat_flags::STA_PLL, 0x0001);
        assert_eq!(stat_flags::STA_UNSYNC, 0x0040);
        assert_eq!(stat_flags::STA_NANO, 0x2000);
        assert_eq!(stat_flags::STA_CLOCKERR, 0x1000);
    }

    #[test]
    fn test_timex_size() {
        // Our Timex should be at least as large as libc::timex.
        assert!(
            std::mem::size_of::<Timex>() >= std::mem::size_of::<libc::timex>(),
            "Timex ({} bytes) should be >= libc::timex ({} bytes)",
            std::mem::size_of::<Timex>(),
            std::mem::size_of::<libc::timex>()
        );
    }

    #[test]
    fn test_ntp_adjtime_gettime() {
        // This tests ntp_adjtime with modes=0, which is a read-only query.
        // On Linux, this succeeds. On non-Linux, it returns an error.
        let mut tx = Timex::zeroed();
        let result = ntp_adjtime(&mut tx);

        #[cfg(target_os = "linux")]
        {
            assert!(result.is_ok());
            let state = result.unwrap();
            assert!(state == ClockState::Ok || state == ClockState::Unsync);

            // The kernel should have filled in read-only fields.
            assert!(
                tx.precision > 0,
                "precision should be > 0, got {}",
                tx.precision
            );
            assert!(
                tx.tolerance > 0,
                "tolerance should be > 0, got {}",
                tx.tolerance
            );
            assert!(tx.tick > 0, "tick should be > 0, got {}", tx.tick);
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_ntp_gettime() {
        let result = ntp_gettime();

        #[cfg(target_os = "linux")]
        {
            assert!(result.is_ok());
            let tx = result.unwrap();
            assert!(tx.precision > 0);
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_ntp_adjtime_set_offset_permissions() {
        // Try to set the offset. On Linux without CAP_SYS_TIME, this
        // should fail with EPERM. On non-Linux, it fails with the
        // platform error. The key test is that it doesn't crash.
        let mut tx = Timex::with_offset(1); // 1 microsecond
        let result = ntp_adjtime(&mut tx);

        #[cfg(target_os = "linux")]
        {
            // Without CAP_SYS_TIME, we expect EPERM (or similar).
            if let Err(e) = &result {
                assert!(e.contains("adjtimex"));
            }
        }
    }

    #[test]
    fn test_ntp_get_tai_offset() {
        let result = ntp_get_tai_offset();

        #[cfg(target_os = "linux")]
        {
            // TAI offset should be >= 0 on any modern Linux system.
            assert!(result.is_ok());
            // If the kernel supports STA_TAI, we get a non-negative value.
            let tai = result.unwrap();
            assert!(tai >= 0, "TAI offset should be >= 0, got {tai}");
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_ntp_get_esterror() {
        let result = ntp_get_esterror();

        #[cfg(target_os = "linux")]
        {
            assert!(result.is_ok());
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_ntp_get_maxerror() {
        let result = ntp_get_maxerror();

        #[cfg(target_os = "linux")]
        {
            assert!(result.is_ok());
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_err());
        }
    }
}
