// ──── ntpsec-rs-io — Real OS I/O layer ──────────────────────────────────────
//
// Implements the SystemClock, NetworkIo, and StateStore traits from
// ntpsec-rs-core using real libc syscalls and std::net sockets.
//
// ## Phase 2.3C
//
//   - RealNetworkIo::recv() uses SO_TIMESTAMPNS kernel receive timestamps
//     via recvmsg() on socket2::Socket, replacing UdpSocket::recv_from()
//   - Kernel timestamp extracted from SCM_TIMESTAMPNS ancillary data
//   - Trace recording and replay support
//
// =============================================================================

use ntpsec_rs_core::ntp_fp;
use ntpsec_rs_core::ntp_io::*;
use ntpsec_rs_core::ntp_types::*;
use socket2::{Domain, Protocol, Socket, Type};

// ──── SystemClock ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RealSystemClock;

impl RealSystemClock {
    pub fn new() -> Self {
        Self
    }
}

impl SystemClock for RealSystemClock {
    fn now(&self) -> NtpTs64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) } != 0 {
            return NtpTs64 {
                seconds: 0,
                fraction: 0,
            };
        }
        ntp_fp::ts_to_ntp(ts.tv_sec, ts.tv_nsec)
    }

    fn step(&mut self, offset: f64) -> Result<(), IoError> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) } != 0 {
            return Err(IoError::ClockFailed("clock_gettime failed".to_string()));
        }
        let new_secs = ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9 + offset;
        let tv_sec = new_secs.floor() as i64;
        let tv_nsec = ((new_secs - tv_sec as f64) * 1e9) as i64;
        let new_ts = libc::timespec {
            tv_sec,
            tv_nsec: tv_nsec.clamp(0, 999_999_999),
        };
        if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &new_ts) } != 0 {
            Err(IoError::ClockFailed(
                std::io::Error::last_os_error().to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn slew(&mut self, offset: f64, freq_ppm: f64) -> Result<(), IoError> {
        let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
        tmx.modes = libc::ADJ_OFFSET | libc::ADJ_FREQUENCY;
        let _ = unsafe { libc::adjtimex(&mut tmx) };
        let nano = (tmx.status & libc::STA_NANO) != 0;
        tmx.modes = libc::ADJ_OFFSET | libc::ADJ_FREQUENCY;
        if nano {
            tmx.offset = (offset * 1e9) as i64;
        } else {
            tmx.offset = (offset * 1e6) as i64;
        }
        tmx.freq = (freq_ppm * (1i64 << 16) as f64) as i64;
        let ret = unsafe { libc::adjtimex(&mut tmx) };
        if ret < 0 {
            Err(IoError::ClockFailed(
                std::io::Error::last_os_error().to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn read_frequency(&self) -> Result<f64, IoError> {
        let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::adjtimex(&mut tmx) };
        if ret < 0 {
            return Err(IoError::ClockFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(tmx.freq as f64 / (1i64 << 16) as f64)
    }

    fn set_frequency(&mut self, freq_ppm: f64) -> Result<(), IoError> {
        self.slew(0.0, freq_ppm)
    }
}

use std::os::unix::io::AsRawFd;

// ──── NetworkIo with SO_TIMESTAMPNS ───────────────────────────────────

#[derive(Debug)]
pub struct RealNetworkIo {
    sockets: Vec<Socket>,
}

impl RealNetworkIo {
    pub fn new() -> Self {
        Self {
            sockets: Vec::new(),
        }
    }
}

impl NetworkIo for RealNetworkIo {
    fn bind(&mut self, addr: &str) -> Result<(), IoError> {
        let sockaddr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| IoError::BindFailed(format!("parse addr: {e}")))?;

        let domain = match sockaddr {
            std::net::SocketAddr::V4(_) => Domain::IPV4,
            std::net::SocketAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| IoError::BindFailed(format!("socket: {e}")))?;

        // Enable SO_TIMESTAMPNS for kernel receive timestamps.
        // Nonblocking polling — timeout is managed by the daemon event loop.
        let tsns: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPNS,
                &tsns as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            // Non-fatal on platforms without SO_TIMESTAMPNS (e.g., macOS, BSD)
        }

        socket
            .bind(&sockaddr.into())
            .map_err(|e| IoError::BindFailed(format!("bind: {e}")))?;

        self.sockets.push(socket);
        Ok(())
    }

    fn recv(&mut self) -> Result<ReceivedDatagram, IoError> {
        let mut buf = vec![0u8; 512];

        for socket in &self.sockets {
            match recvmsg_with_timestamp(socket, &mut buf) {
                Ok(Some((n, src, kernel_ts, ts_source))) => {
                    // Get local address from getsockname
                    let dest_addr = socket_getsockname(socket);

                    let source_netaddr = socketaddr_to_netaddr2(&src);

                    return Ok(ReceivedDatagram {
                        bytes: buf[..n].to_vec(),
                        source: source_netaddr,
                        destination: socketaddr_to_netaddr2(&dest_addr),
                        rx_timestamp: kernel_ts,
                        interface_index: None,
                        timestamp_source: ts_source,
                    });
                }
                Ok(None) => continue, // Timed out, try next socket
                Err(e) => return Err(e),
            }
        }
        Err(IoError::RecvFailed("no data available".to_string()))
    }

    fn send(&mut self, buf: &[u8], dest: &NetAddr) -> Result<usize, IoError> {
        let dest_sa = netaddr_to_socketaddr(dest);
        for socket in &self.sockets {
            match socket.send_to(buf, &dest_sa.into()) {
                Ok(n) => return Ok(n),
                Err(_) => continue,
            }
        }
        if let Some(socket) = self.sockets.first() {
            socket
                .send_to(buf, &dest_sa.into())
                .map_err(|e| IoError::SendFailed(e.to_string()))
        } else {
            Err(IoError::SendFailed("no sockets available".to_string()))
        }
    }
}

/// Receive a datagram with a kernel timestamp using `recvmsg()` + `SO_TIMESTAMPNS`.
///
/// Returns `(bytes_received, source_address, kernel_timestamp, timestamp_source)` on success.
/// Returns `Ok(None)` on timeout (no data available).
fn recvmsg_with_timestamp(
    socket: &Socket,
    buf: &mut [u8],
) -> Result<Option<(usize, std::net::SocketAddr, NtpTs64, TimestampSource)>, IoError> {
    // Prepare the message header for recvmsg
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // Ancillary buffer with 16-byte alignment for cmsghdr + timespec.
    // POSIX requires CMSG_DATA pointers to be suitably aligned for any data type.
    // A 16-byte aligned 256-byte buffer satisfies this on all common architectures.
    #[repr(C, align(16))]
    struct AlignedBuf([u8; 256]);
    let mut aligned = AlignedBuf([0u8; 256]);
    let cmsg_ptr = aligned.0.as_mut_ptr() as *mut libc::c_void;

    // Source address storage
    let mut src_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_ptr;
    msg.msg_controllen = 256;

    // Use the raw file descriptor from socket2
    let fd = socket.as_raw_fd();

    // Non-blocking receive (timeout is handled by the caller's polling loop).
    // Retry on EINTR.
    let ret = loop {
        let r = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
        if r < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(IoError::RecvFailed(err.to_string()));
        }
        break r;
    };

    // Check for truncated data
    if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
        return Err(IoError::RecvFailed("packet truncated".to_string()));
    }
    let cmsg_truncated = (msg.msg_flags & libc::MSG_CTRUNC) != 0;

    let n = ret as usize;

    // Extract kernel timestamp from ancillary data with provenance.
    // If ancillary data was truncated, record that in the source.
    let (kernel_ts, ts_source) = match extract_scm_timestampns_with_source(&msg) {
        Some((ts, source)) => (ts, source),
        None => {
            // Fallback to userspace clock
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            unsafe {
                libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            }
            let source = if cmsg_truncated {
                TimestampSource::AncillaryTruncated
            } else {
                TimestampSource::UserspaceFallback
            };
            (ntp_fp::ts_to_ntp(ts.tv_sec, ts.tv_nsec), source)
        }
    };

    // Convert source address
    let src = match src_addr.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in =
                unsafe { &*(&src_addr as *const _ as *const libc::sockaddr_in) };
            let ip =
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()));
            std::net::SocketAddr::new(ip, u16::from_be(sin.sin_port))
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*(&src_addr as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr));
            std::net::SocketAddr::new(ip, u16::from_be(sin6.sin6_port))
        }
        _ => {
            return Err(IoError::RecvFailed("unknown address family".to_string()));
        }
    };

    Ok(Some((n, src, kernel_ts, ts_source)))
}

/// Walk the control message header chain to find SCM_TIMESTAMPNS and extract the timespec
/// and its provenance (KernelNanoseconds, KernelMicroseconds, or None).
fn extract_scm_timestampns_with_source(msg: &libc::msghdr) -> Option<(NtpTs64, TimestampSource)> {
    let mut cmsg_ptr: *mut libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg_ptr.is_null() {
        let cmsg = unsafe { &*cmsg_ptr };
        if cmsg.cmsg_level == libc::SOL_SOCKET
            && cmsg.cmsg_type == libc::SO_TIMESTAMPNS as libc::c_int
        {
            // Validate cmsg_len before reading a timespec
            let required =
                unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::timespec>() as _) as usize };
            if (cmsg.cmsg_len as usize) < required {
                return None;
            }
            let ts: libc::timespec = unsafe {
                let data_ptr = libc::CMSG_DATA(cmsg_ptr);
                std::ptr::read(data_ptr as *const libc::timespec)
            };
            return Some((
                ntp_fp::ts_to_ntp(ts.tv_sec, ts.tv_nsec),
                TimestampSource::KernelNanoseconds,
            ));
        }
        if cmsg.cmsg_level == libc::SOL_SOCKET
            && cmsg.cmsg_type == libc::SO_TIMESTAMP as libc::c_int
        {
            let required =
                unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::timeval>() as _) as usize };
            if (cmsg.cmsg_len as usize) < required {
                return None;
            }
            let tv: libc::timeval = unsafe {
                let data_ptr = libc::CMSG_DATA(cmsg_ptr);
                std::ptr::read(data_ptr as *const libc::timeval)
            };
            let ntp = ntp_fp::tv_to_ntp(tv.tv_sec as i64, tv.tv_usec as i64);
            return Some((ntp, TimestampSource::KernelMicroseconds));
        }
        cmsg_ptr =
            unsafe { libc::CMSG_NXTHDR(msg as *const libc::msghdr as *mut libc::msghdr, cmsg_ptr) };
    }
    None
}

/// Get the local socket address using getsockname(2).
fn socket_getsockname(socket: &Socket) -> std::net::SocketAddr {
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            socket.as_raw_fd(),
            &mut addr as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if ret != 0 {
        return std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            123,
        );
    }
    match addr.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in =
                unsafe { &*(&addr as *const _ as *const libc::sockaddr_in) };
            let ip =
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()));
            std::net::SocketAddr::new(ip, u16::from_be(sin.sin_port))
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*(&addr as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr));
            std::net::SocketAddr::new(ip, u16::from_be(sin6.sin6_port))
        }
        _ => std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            123,
        ),
    }
}

// ──── Address conversion helpers ──────────────────────────────────────

fn socketaddr_to_netaddr2(sa: &std::net::SocketAddr) -> NetAddr {
    match sa {
        std::net::SocketAddr::V4(v4) => {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&v4.ip().octets());
            NetAddr {
                family: 4,
                addr,
                port: v4.port(),
            }
        }
        std::net::SocketAddr::V6(v6) => NetAddr {
            family: 6,
            addr: v6.ip().octets(),
            port: v6.port(),
        },
    }
}

fn netaddr_to_socketaddr(na: &NetAddr) -> std::net::SocketAddr {
    match na.family {
        4 => {
            let octets = [na.addr[0], na.addr[1], na.addr[2], na.addr[3]];
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                na.port,
            )
        }
        _ => std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(na.addr)),
            na.port,
        ),
    }
}

// ──── StateStore ──────────────────────────────────────────────────────

#[derive(Debug)]
pub struct FileStateStore {
    drift_path: std::path::PathBuf,
    stats_dir: std::path::PathBuf,
}

impl FileStateStore {
    pub fn new(base_path: &std::path::Path) -> Self {
        Self {
            drift_path: base_path.join("ntp.drift"),
            stats_dir: base_path.to_path_buf(),
        }
    }

    /// Create a FileStateStore with a custom drift file path.
    pub fn with_drift_path(base_path: &std::path::Path, drift_file: &std::path::Path) -> Self {
        Self {
            drift_path: drift_file.to_path_buf(),
            stats_dir: base_path.to_path_buf(),
        }
    }
}

impl StateStore for FileStateStore {
    fn load_drift(&self) -> Result<f64, IoError> {
        let content = std::fs::read_to_string(&self.drift_path)
            .map_err(|e| IoError::FileFailed(format!("read drift: {e}")))?;
        content
            .trim()
            .parse::<f64>()
            .map_err(|e| IoError::FileFailed(format!("parse drift: {e}")))
    }

    fn save_drift(&mut self, freq_ppm: f64) -> Result<(), IoError> {
        let tmp_path = self.drift_path.with_extension("drift.tmp");
        std::fs::write(&tmp_path, format!("{:.3}\n", freq_ppm))
            .map_err(|e| IoError::FileFailed(format!("write drift: {e}")))?;
        std::fs::rename(&tmp_path, &self.drift_path)
            .map_err(|e| IoError::FileFailed(format!("rename drift: {e}")))?;
        Ok(())
    }

    fn load_leap(&self) -> Result<String, IoError> {
        let path = self.stats_dir.join("leap-seconds");
        std::fs::read_to_string(&path).map_err(|e| IoError::FileFailed(format!("read leap: {e}")))
    }

    fn append_stats(&mut self, stream: &str, line: &str) -> Result<(), IoError> {
        let path = self.stats_dir.join(stream);
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| IoError::FileFailed(format!("open stats: {e}")))?;
        writeln!(file, "{}", line).map_err(|e| IoError::FileFailed(format!("write stats: {e}")))?;
        Ok(())
    }
}

#[test]
fn test_real_loopback_kernel_timestamp() {
    // Real loopback test: bind, send a packet, receive through RealNetworkIo,
    // and verify the kernel timestamp provenance with nanosecond bounds.
    use std::net::UdpSocket;
    let mut net = RealNetworkIo::new();
    net.bind("127.0.0.1:0").expect("bind loopback");
    let local_addr = net.sockets[0].local_addr().unwrap().as_socket().unwrap();

    // Capture before with nanosecond precision
    let mut ts_before = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts_before);
    }
    let before = ntp_fp::ts_to_ntp(ts_before.tv_sec, ts_before.tv_nsec);

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender.send_to(&[0u8; 48], local_addr).expect("send");

    let dgram = net.recv().expect("recv");

    let mut ts_after = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts_after);
    }
    let after = ntp_fp::ts_to_ntp(ts_after.tv_sec, ts_after.tv_nsec);

    // Packet integrity
    assert_eq!(dgram.bytes, vec![0u8; 48]);
    assert_eq!(dgram.source.addr[..4], [127, 0, 0, 1], "source loopback");

    // Timestamp provenance: on Linux with SO_TIMESTAMPNS, this must be
    // KernelNanoseconds for a loopback test. On platforms without
    // SO_TIMESTAMPNS (macOS, BSD), it will be UserspaceFallback.
    #[cfg(target_os = "linux")]
    assert_eq!(
        dgram.timestamp_source,
        TimestampSource::KernelNanoseconds,
        "On Linux, loopback should produce SCM_TIMESTAMPNS"
    );

    // Verify timestamp is bounded by before/after with nanosecond precision.
    // The kernel timestamp may be captured slightly before `before` if the
    // packet arrived between send_to() and clock_gettime(). Allow 1ms slop.
    let t_rx = ntp_fp::ntp_ts64_to_double(dgram.rx_timestamp);
    let t_before = ntp_fp::ntp_ts64_to_double(before) - 0.001;
    let t_after = ntp_fp::ntp_ts64_to_double(after) + 0.001;
    assert!(
        t_rx >= t_before,
        "rx {:.6}s should be >= before-1ms {:.6}s",
        t_rx,
        t_before
    );
    assert!(
        t_rx <= t_after,
        "rx {:.6}s should be <= after+1ms {:.6}s",
        t_rx,
        t_after
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_clock_now() {
        let clock = RealSystemClock::new();
        let now = clock.now();
        assert!(
            now.seconds > 2_208_988_800,
            "NTP time should be > 1900 epoch"
        );
    }

    #[test]
    fn test_system_clock_frequency() {
        let mut clock = RealSystemClock::new();
        let freq = clock.read_frequency().unwrap();
        assert!(freq.is_finite());
        assert!(
            freq.abs() < 500_000.0,
            "frequency {freq} ppm should be reasonable"
        );
        clock.set_frequency(freq).ok();
    }

    #[test]
    fn test_state_store() {
        let tmp = std::env::temp_dir().join("ntpsec-rs-test-io");
        let _ = std::fs::create_dir_all(&tmp);
        let mut store = FileStateStore::new(&tmp);

        assert!(store.save_drift(42.5).is_ok());
        let loaded = store.load_drift().unwrap();
        assert!((loaded - 42.5).abs() < 0.001);

        assert!(store.append_stats("loopstats", "test line").is_ok());
        let content = std::fs::read_to_string(tmp.join("loopstats")).unwrap();
        assert!(content.contains("test line"));

        let _ = std::fs::remove_file(tmp.join("ntp.drift"));
        let _ = std::fs::remove_file(tmp.join("ntp.drift.tmp"));
        let _ = std::fs::remove_file(tmp.join("loopstats"));
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn test_netaddr_conversion_roundtrip() {
        let addr = netaddr_to_socketaddr(&NetAddr::ipv4(0x7f000001, 123));
        assert_eq!(
            addr,
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                123
            )
        );

        let na = socketaddr_to_netaddr2(&addr);
        assert_eq!(na.port, 123);
        assert_eq!(na.addr[..4], [127, 0, 0, 1]);
    }
}
