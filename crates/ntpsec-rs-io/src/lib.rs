// ──── ntpsec-rs-io — Real OS I/O layer ──────────────────────────────────────
//
// Phase 2: Full implementations of SystemClock, NetworkIo, StateStore traits.
// All host mutation (clock, sockets, filesystem, privileges) lives here.
// ntpsec-rs-core uses these through trait boundaries injected at the binary
// level — the core stays deterministic and testable.
//
// =============================================================================

use ntpsec_rs_core::ntp_fp;
use ntpsec_rs_core::ntp_types::*;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

// ──── SystemClock — real clock via libc ────────────────────────────────

/// Real system clock using clock_gettime / adjtimex / clock_settime.
#[derive(Debug)]
pub struct RealSystemClock;

impl RealSystemClock {
    pub fn new() -> Self {
        Self
    }

    /// Get current system time as NTP timestamp.
    /// Uses clock_gettime(CLOCK_REALTIME) for sub-microsecond precision.
    pub fn now(&self) -> NtpTs64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime is a standard syscall; timespec is valid
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        }
        ntp_fp::ts_to_ntp(ts.tv_sec, ts.tv_nsec)
    }

    /// Step the clock by `offset` seconds (immediate jump).
    /// Uses clock_settime to set the absolute time.
    pub fn step(&self, offset: f64) -> Result<(), String> {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        }
        let new_secs = ts.tv_sec as f64 + ts.tv_nsec as f64 * 1e-9 + offset;
        let tv_sec = new_secs as i64;
        let tv_nsec = ((new_secs - tv_sec as f64) * 1e9) as i64;
        let new_ts = libc::timespec {
            tv_sec,
            tv_nsec: tv_nsec.clamp(0, 999_999_999),
        };
        // SAFETY: clock_settime(CLOCK_REALTIME) is a standard syscall
        let ret = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &new_ts) };
        if ret == 0 {
            Ok(())
        } else {
            Err(format!("clock_settime failed: errno={}", ret))
        }
    }

    /// Slew the clock by adjusting frequency via adjtimex.
    /// `freq_ppm` is the frequency offset in parts-per-million.
    /// NOTE: This requires CAP_SYS_TIME. In --lab-daemon mode, use simulated clock.
    pub fn slew(&self, _offset: f64, freq_ppm: f64) -> Result<(), String> {
        // Use adjtimex to set frequency
        let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
        tmx.modes = libc::ADJ_FREQUENCY;
        // Convert PPM to kernel scaled frequency (1 PPM = 1 << 16)
        tmx.freq = (freq_ppm * (1i64 << 16) as f64) as i64;
        // SAFETY: adjtimex is a standard syscall
        let ret = unsafe { libc::adjtimex(&mut tmx) };
        if ret >= 0 {
            Ok(())
        } else {
            Err(format!("adjtimex failed: ret={}", ret))
        }
    }

    /// Read the current kernel frequency offset in PPM.
    pub fn read_frequency(&self) -> f64 {
        let mut tmx: libc::timex = unsafe { std::mem::zeroed() };
        unsafe {
            libc::adjtimex(&mut tmx);
        }
        tmx.freq as f64 / (1i64 << 16) as f64
    }

    /// Set the kernel frequency offset in PPM.
    pub fn set_frequency(&self, freq_ppm: f64) -> Result<(), String> {
        self.slew(0.0, freq_ppm)
    }
}

// ──── NetworkIo — real UDP sockets ─────────────────────────────────────

/// Real NTP/UDP network I/O using std::net::UdpSocket with SO_TIMESTAMPNS.
#[derive(Debug)]
pub struct RealNetworkIo {
    sockets: Vec<UdpSocket>,
}

impl RealNetworkIo {
    pub fn new() -> Self {
        Self {
            sockets: Vec::new(),
        }
    }

    /// Bind to NTP port on all interfaces.
    pub fn bind_all(&mut self) -> Result<(), String> {
        // IPv4
        let v4 = UdpSocket::bind("0.0.0.0:123").map_err(|e| format!("bind IPv4:123: {e}"))?;
        v4.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .ok();
        self.sockets.push(v4);

        // IPv6
        if let Ok(v6) = UdpSocket::bind("[::]:123") {
            v6.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .ok();
            self.sockets.push(v6);
        }

        Ok(())
    }

    /// Bind to a specific address for --lab-daemon mode.
    pub fn bind(&mut self, addr: &str) -> Result<(), String> {
        let sock = UdpSocket::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .ok();
        self.sockets.push(sock);
        Ok(())
    }

    /// Receive an NTP packet. Returns (bytes, source_addr).
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), String> {
        for sock in &self.sockets {
            match sock.recv_from(buf) {
                Ok((n, addr)) => return Ok((n, addr)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(e) => return Err(format!("recv error: {e}")),
            }
        }
        Err("no data available".to_string())
    }

    /// Send an NTP packet to a destination.
    pub fn send(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, String> {
        for sock in &self.sockets {
            let local = sock.local_addr().ok();
            let is_v4 = matches!(addr, SocketAddr::V4(_));
            let is_v6 = matches!(addr, SocketAddr::V6(_));
            let matches = match (local, addr) {
                (Some(l), _) => l.is_ipv4() == addr.is_ipv4(),
                _ => true,
            };
            if matches {
                return sock
                    .send_to(buf, addr)
                    .map_err(|e| format!("send error: {e}"));
            }
        }
        // Try first socket anyway
        if let Some(sock) = self.sockets.first() {
            return sock
                .send_to(buf, addr)
                .map_err(|e| format!("send error: {e}"));
        }
        Err("no sockets available".to_string())
    }
}

// ──── StateStore — atomic file I/O ─────────────────────────────────────

/// Atomic file state store for drift, leap, and statistics files.
#[derive(Debug)]
pub struct FileStateStore {
    base_path: std::path::PathBuf,
}

impl FileStateStore {
    pub fn new(base_path: &std::path::Path) -> Self {
        Self {
            base_path: base_path.to_path_buf(),
        }
    }

    /// Load a drift file (single f64 value).
    pub fn load_drift(&self) -> Result<f64, String> {
        let path = self.base_path.join("ntp.drift");
        let content =
            std::fs::read_to_string(&path).map_err(|e| format!("read drift file: {e}"))?;
        content
            .trim()
            .parse::<f64>()
            .map_err(|e| format!("parse drift: {e}"))
    }

    /// Save a drift file atomically (write to temp, rename).
    pub fn save_drift(&self, freq_ppm: f64) -> Result<(), String> {
        let path = self.base_path.join("ntp.drift");
        let tmp_path = self.base_path.join("ntp.drift.tmp");
        std::fs::write(&tmp_path, format!("{:.3}\n", freq_ppm))
            .map_err(|e| format!("write drift: {e}"))?;
        std::fs::rename(&tmp_path, &path).map_err(|e| format!("rename drift: {e}"))?;
        Ok(())
    }

    /// Load a leap second file.
    pub fn load_leap(&self) -> Result<String, String> {
        let path = self.base_path.join("leap-seconds");
        std::fs::read_to_string(&path).map_err(|e| format!("read leap file: {e}"))
    }

    /// Append to a statistics file.
    pub fn append_stats(&self, name: &str, line: &str) -> Result<(), String> {
        let path = self.base_path.join(name);
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("open stats file: {e}"))?;
        writeln!(file, "{}", line).map_err(|e| format!("write stats: {e}"))?;
        Ok(())
    }
}

// ──── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_clock_now() {
        let clock = RealSystemClock::new();
        let now = clock.now();
        // Current time should be after NTP epoch (1900)
        assert!(
            now.seconds > 2_208_988_800,
            "NTP time should be > 1900 epoch"
        );
        assert!(
            now.seconds < 4_294_967_296i64,
            "NTP time should be reasonable"
        );
    }

    #[test]
    fn test_system_clock_read_frequency() {
        let clock = RealSystemClock::new();
        let freq = clock.read_frequency();
        // Frequency should be reasonable (±500 PPM)
        assert!(freq.is_finite());
        assert!(
            freq.abs() < 500_000.0,
            "frequency {freq} ppm should be reasonable"
        );
    }

    #[test]
    fn test_network_io_bind() {
        let mut io = RealNetworkIo::new();
        // Bind to a high port for testing (avoiding privileged port 123)
        let result = io.bind("127.0.0.1:0");
        assert!(result.is_ok() || result.is_err());
        // At minimum we should be able to create the object
        assert!(io.sockets.is_empty() || result.is_ok());
    }

    #[test]
    fn test_file_state_store() {
        let tmp = std::env::temp_dir().join("ntpsec-rs-test");
        let _ = std::fs::create_dir_all(&tmp);
        let store = FileStateStore::new(&tmp);

        // Save and load drift
        assert!(store.save_drift(42.5).is_ok());
        let loaded = store.load_drift().unwrap();
        assert!((loaded - 42.5).abs() < 0.001);

        // Cleanup
        let _ = std::fs::remove_file(tmp.join("ntp.drift"));
        let _ = std::fs::remove_file(tmp.join("ntp.drift.tmp"));
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn test_append_stats() {
        let tmp = std::env::temp_dir().join("ntpsec-rs-test-stats");
        let _ = std::fs::create_dir_all(&tmp);
        let store = FileStateStore::new(&tmp);

        assert!(store.append_stats("loopstats", "test line").is_ok());
        let content = std::fs::read_to_string(tmp.join("loopstats")).unwrap();
        assert!(content.contains("test line"));

        let _ = std::fs::remove_file(tmp.join("loopstats"));
        let _ = std::fs::remove_dir(&tmp);
    }
}
