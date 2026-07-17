// ──── ntpsec-rs-io — Real OS I/O layer ──────────────────────────────────────
//
// Host mutation behind narrow trait boundaries: clock, sockets, filesystem,
// privileges. The deterministic core (ntpsec-rs-core) never depends on this
// directly; traits are injected at the binary level.
//
// ## Wired traits
//
//   SystemClock    — now, step, slew, read/set frequency via adjtimex
//   NetworkIo      — recv_ntp, send_ntp via NTP/UDP sockets
//   StateStore     — load/save drift, leapsec, stats via atomic files
//   ControlSocket  — mode 6 control protocol socket
//   Privileges     — drop privileges, chroot, seccomp
//   NtsTls         — NTS TLS termination (rustls)
//
// =============================================================================

use ntpsec_rs_core::ntp_fp;
use ntpsec_rs_core::ntp_types::*;

/// Real system clock via adjtimex/clock_gettime.
#[derive(Debug)]
pub struct RealSystemClock;

impl RealSystemClock {
    pub fn new() -> Self {
        Self
    }

    /// Get current system time as NTP timestamp.
    pub fn now(&self) -> NtpTs64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime is a standard system call; the timespec struct
        // is valid for writing.
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        }
        ntp_fp::ts_to_ntp(ts.tv_sec, ts.tv_nsec)
    }
}

/// Real NTP/UDP network I/O.
#[derive(Debug)]
pub struct RealNetworkIo;

impl RealNetworkIo {
    pub fn new() -> Self {
        Self
    }

    /// Receive an NTP packet.
    pub fn recv(&mut self, _buf: &mut [u8]) -> Result<(usize, SockAddr), std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "not yet implemented",
        ))
    }

    /// Send an NTP packet.
    pub fn send(&mut self, _buf: &[u8], _addr: &SockAddr) -> Result<usize, std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "not yet implemented",
        ))
    }
}
