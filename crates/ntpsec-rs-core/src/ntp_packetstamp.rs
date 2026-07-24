// ──── ntp_packetstamp.rs ────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_packetstamp.c
//
// Hardware packet timestamping via SO_TIMESTAMPNS and related ioctls.
// =============================================================================

use std::os::unix::io::RawFd;

/// Timestamping modes supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampMode {
    /// Software timestamps via SO_TIMESTAMPNS (reliable, widely supported)
    Software,
    /// Hardware timestamps via SO_TIMESTAMPING (requires NIC support)
    Hardware,
    /// No timestamping (use system clock at recvfrom time)
    None,
}

/// Enable software receive timestamps on a socket.
pub fn enable_software_timestamps(fd: RawFd) -> Result<(), String> {
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "SO_TIMESTAMPNS failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

/// The NTP timestamping namespace.
/// In production, timestamps from recvmsg() ancillary data are read here.
pub struct PacketStamp {
    pub timestamp: Option<crate::ntp_types::NtpTs64>,
}

impl PacketStamp {
    pub fn new() -> Self {
        Self { timestamp: None }
    }
}
