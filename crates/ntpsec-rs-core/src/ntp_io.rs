// ──── ntp_io.rs — I/O trait definitions ─────────────────────────────────
//
// These traits let the deterministic core (ntpsec-rs-core) run without
// touching a real clock, real network, or real filesystem.  The real
// implementations live in ntpsec-rs-io; the lab/replay harness provides
// simulated versions.
//
// =============================================================================

use crate::ntp_types::*;

// ──── Errors ──────────────────────────────────────────────────────────

/// I/O errors that can occur during daemon operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoError {
    /// Could not bind to the requested address/port.
    BindFailed(String),
    /// Receive error.
    RecvFailed(String),
    /// Send error.
    SendFailed(String),
    /// Clock operation failed (step, slew, set_frequency).
    ClockFailed(String),
    /// File read/write error.
    FileFailed(String),
    /// Feature not available (e.g., NTS crypto).
    Unavailable(String),
    /// Permission denied (e.g., need CAP_SYS_TIME).
    PermissionDenied(String),
}

impl std::fmt::Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindFailed(s) => write!(f, "bind failed: {s}"),
            Self::RecvFailed(s) => write!(f, "recv failed: {s}"),
            Self::SendFailed(s) => write!(f, "send failed: {s}"),
            Self::ClockFailed(s) => write!(f, "clock failed: {s}"),
            Self::FileFailed(s) => write!(f, "file failed: {s}"),
            Self::Unavailable(s) => write!(f, "unavailable: {s}"),
            Self::PermissionDenied(s) => write!(f, "permission denied: {s}"),
        }
    }
}

impl std::error::Error for IoError {}

// ──── Received Datagram ───────────────────────────────────────────────

/// Provenance of a receive timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampSource {
    /// Linux kernel nanosecond timestamp from `SCM_TIMESTAMPNS`.
    KernelNanoseconds,
    /// Linux kernel microsecond timestamp from `SCM_TIMESTAMP`.
    KernelMicroseconds,
    /// Userspace `clock_gettime()` fallback.
    UserspaceFallback,
    /// Ancillary data was truncated; timestamp is userspace fallback.
    AncillaryTruncated,
}

/// A received NTP datagram with kernel timestamp.
#[derive(Debug, Clone)]
pub struct ReceivedDatagram {
    pub bytes: Vec<u8>,
    pub source: NetAddr,
    pub destination: NetAddr,
    /// Receive timestamp (T4), captured at kernel level via SO_TIMESTAMPNS.
    pub rx_timestamp: NtpTs64,
    /// Network interface index (for combining with destination address).
    pub interface_index: Option<u32>,
    /// Provenance of the rx_timestamp.
    pub timestamp_source: TimestampSource,
}

impl ReceivedDatagram {
    /// Create a datagram with userspace-fallback timestamp provenance.
    /// Available for tests and lab replay.
    pub fn test(
        bytes: Vec<u8>,
        source: NetAddr,
        destination: NetAddr,
        rx_timestamp: NtpTs64,
    ) -> Self {
        Self {
            bytes,
            source,
            destination,
            rx_timestamp,
            interface_index: None,
            timestamp_source: TimestampSource::UserspaceFallback,
        }
    }
}

/// Network address abstraction (IPv4 or IPv6 with port).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetAddr {
    pub family: u8,     // 4 = IPv4, 6 = IPv6
    pub addr: [u8; 16], // zero-padded address bytes
    pub port: u16,
}

impl NetAddr {
    pub fn ipv4(a: u32, port: u16) -> Self {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&a.to_be_bytes());
        Self {
            family: 4,
            addr,
            port,
        }
    }

    pub fn ipv6(a: &[u8; 16], port: u16) -> Self {
        Self {
            family: 6,
            addr: *a,
            port,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.family == 4
    }
    pub fn is_ipv6(&self) -> bool {
        self.family == 6
    }

    /// Check if this is an IPv4 loopback address (127.0.0.0/8).
    /// Used by loopcast detection to avoid flagging legitimate test traffic.
    pub fn is_ipv4_loopback(&self) -> bool {
        if self.family != 4 {
            return false;
        }
        self.addr[0] == 127
    }

    /// Convert to a std::net::SocketAddr for use with std::net sockets.
    pub fn to_std_socketaddr(&self) -> std::net::SocketAddr {
        match self.family {
            4 => {
                let octets = [self.addr[0], self.addr[1], self.addr[2], self.addr[3]];
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                    self.port,
                )
            }
            _ => std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(self.addr)),
                self.port,
            ),
        }
    }
}

/// Convert a libc sockaddr_storage to a NetAddr (for daemon_engine peer addressing).
pub fn sockaddr_to_netaddr(ss: &libc::sockaddr_storage) -> Option<NetAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let mut addr = [0u8; 16];
            // sin_addr.s_addr is already in network byte order (big-endian) on all platforms.
            // Use to_ne_bytes() to get the raw bytes in host order, then place them.
            addr[..4].copy_from_slice(&sin.sin_addr.s_addr.to_ne_bytes());
            Some(NetAddr {
                family: 4,
                addr,
                port: u16::from_be(sin.sin_port),
            })
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            Some(NetAddr {
                family: 6,
                addr: sin6.sin6_addr.s6_addr,
                port: u16::from_be(sin6.sin6_port),
            })
        }
        _ => None,
    }
}

// ──── SystemClock Trait ───────────────────────────────────────────────

/// Abstract system clock — real or simulated.
pub trait SystemClock {
    fn now(&self) -> NtpTs64;
    fn step(&mut self, offset: f64) -> Result<(), IoError>;
    fn slew(&mut self, offset: f64, freq_ppm: f64) -> Result<(), IoError>;
    fn read_frequency(&self) -> Result<f64, IoError>;
    fn set_frequency(&mut self, freq_ppm: f64) -> Result<(), IoError>;
}

// ──── NetworkIo Trait ─────────────────────────────────────────────────

/// Abstract network I/O — real UDP sockets or replay harness.
pub trait NetworkIo {
    fn bind(&mut self, addr: &str) -> Result<(), IoError>;
    fn recv(&mut self) -> Result<ReceivedDatagram, IoError>;
    fn send(&mut self, buf: &[u8], dest: &NetAddr) -> Result<usize, IoError>;
}

// ──── StateStore Trait ────────────────────────────────────────────────

/// Abstract state persistence — real filesystem or memory.
pub trait StateStore {
    fn load_drift(&self) -> Result<f64, IoError>;
    fn save_drift(&mut self, freq_ppm: f64) -> Result<(), IoError>;
    fn load_leap(&self) -> Result<String, IoError>;
    fn append_stats(&mut self, stream: &str, line: &str) -> Result<(), IoError>;
}

// ──── Daemon Event / Action ───────────────────────────────────────────

/// Events the daemon engine processes.
#[derive(Debug, Clone)]
pub enum DaemonEvent {
    PacketReceived(ReceivedDatagram),
    TimerFired(TimerId),
    Shutdown,
    /// A synthetic NTP packet from a refclock driver.
    RefclockSample {
        associd: u16,
        packet: NtpPacket,
        rx_time: NtpTs64,
    },
}

/// Timer identifiers for the event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerId {
    PeerPoll(usize),
    Housekeeping,
    Reachability,
    LeapFileReload,
    StatsWrite,
}

/// Actions the daemon engine emits.
#[derive(Debug, Clone)]
pub enum DaemonAction {
    Send {
        destination: NetAddr,
        bytes: Vec<u8>,
    },
    AdjustClock(Adjustment),
    PersistDrift(f64),
    AppendStatistic {
        stream: String,
        line: String,
    },
    Log(String),
    /// A refclock sample produced by poll_all(). The daemon loop feeds this
    /// back through engine.handle() as DaemonEvent::RefclockSample.
    RefclockSample {
        associd: u16,
        packet: NtpPacket,
        rx_time: NtpTs64,
    },
}

// Re-export Adjustment from loopfilter for the DaemonAction type.
pub use crate::ntp_loopfilter::Adjustment;

// ──── Simulated Clock (for lab-daemon mode) ────────────────────────────

/// A simulated system clock for deterministic lab testing.
/// Starts at a fixed NTP time and increments only when explicitly advanced
/// via `advance()` or `step()`/`slew()`.
#[derive(Debug, Clone)]
pub struct SimulatedClock {
    /// Current simulated time in NTP timestamp format.
    pub now: NtpTs64,
    /// Simulated frequency offset in PPM.
    pub freq_ppm: f64,
}

impl SimulatedClock {
    pub fn new(start_time: NtpTs64) -> Self {
        Self {
            now: start_time,
            freq_ppm: 0.0,
        }
    }

    /// Create a SimulatedClock starting at the Unix epoch (1970-01-01) as NTP time.
    pub fn unix_epoch() -> Self {
        Self::new(crate::ntp_fp::ts_to_ntp(0, 0))
    }

    /// Advance the simulated clock by `seconds` — used to drive time in lab mode.
    pub fn advance(&mut self, seconds: f64) {
        let secs = seconds.trunc() as i64;
        let frac = (seconds.fract() * NTP_FRAC_PER_SEC as f64) as u32;
        self.now.seconds += secs;
        self.now.fraction = self.now.fraction.wrapping_add(frac);
        // Carry overflow into seconds
        if self.now.fraction < frac && frac != 0 {
            self.now.seconds += 1;
        }
    }
}

impl SystemClock for SimulatedClock {
    fn now(&self) -> NtpTs64 {
        self.now
    }

    fn step(&mut self, offset: f64) -> Result<(), IoError> {
        let secs = offset.trunc() as i64;
        let frac = (offset.fract() * NTP_FRAC_PER_SEC as f64) as i64;
        self.now.seconds += secs;
        if frac >= 0 {
            let f = frac as u32;
            self.now.fraction = self.now.fraction.wrapping_add(f);
            if self.now.fraction < f {
                self.now.seconds += 1;
            }
        } else {
            let f = (-frac) as u32;
            self.now.fraction = self.now.fraction.wrapping_sub(f);
            if self.now.fraction > (!f) {
                self.now.seconds -= 1;
            }
        }
        Ok(())
    }

    fn slew(&mut self, offset: f64, freq_ppm: f64) -> Result<(), IoError> {
        // In simulated mode, apply offset directly (we don't model kernel slewing).
        self.step(offset)?;
        self.freq_ppm = freq_ppm;
        Ok(())
    }

    fn read_frequency(&self) -> Result<f64, IoError> {
        Ok(self.freq_ppm)
    }

    fn set_frequency(&mut self, freq_ppm: f64) -> Result<(), IoError> {
        self.freq_ppm = freq_ppm;
        Ok(())
    }
}

// ──── Memory StateStore (for lab-daemon mode) ──────────────────────────

/// An in-memory state store for deterministic lab testing.
#[derive(Debug, Default)]
pub struct MemoryStateStore {
    pub drift: Option<f64>,
    pub leap_data: Option<String>,
    pub stats: Vec<(String, String)>,
    /// Transcript of all sent packets (for replay verification).
    pub sent_packets: Vec<(NetAddr, Vec<u8>)>,
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for MemoryStateStore {
    fn load_drift(&self) -> Result<f64, IoError> {
        self.drift
            .ok_or_else(|| IoError::FileFailed("no drift data in memory".to_string()))
    }

    fn save_drift(&mut self, freq_ppm: f64) -> Result<(), IoError> {
        self.drift = Some(freq_ppm);
        Ok(())
    }

    fn load_leap(&self) -> Result<String, IoError> {
        self.leap_data
            .clone()
            .ok_or_else(|| IoError::FileFailed("no leap data in memory".to_string()))
    }

    fn append_stats(&mut self, stream: &str, line: &str) -> Result<(), IoError> {
        self.stats.push((stream.to_string(), line.to_string()));
        Ok(())
    }
}

// ──── Replay Network (for lab-daemon mode) ─────────────────────────────

/// A replay network that returns pre-recorded datagrams for deterministic testing.
/// Records all sent packets for transcript assertion.
#[derive(Debug)]
pub struct ReplayNetwork {
    datagrams: Vec<ReceivedDatagram>,
    index: usize,
    /// Transcript of all packets sent via this network.
    pub sent_packets: Vec<(NetAddr, Vec<u8>)>,
}

impl ReplayNetwork {
    pub fn new(datagrams: Vec<ReceivedDatagram>) -> Self {
        Self {
            datagrams,
            index: 0,
            sent_packets: Vec::new(),
        }
    }
}

impl NetworkIo for ReplayNetwork {
    fn bind(&mut self, _addr: &str) -> Result<(), IoError> {
        Ok(()) // No-op for replay
    }

    fn recv(&mut self) -> Result<ReceivedDatagram, IoError> {
        if self.index < self.datagrams.len() {
            let dgram = self.datagrams[self.index].clone();
            self.index += 1;
            Ok(dgram)
        } else {
            Err(IoError::RecvFailed("replay buffer exhausted".to_string()))
        }
    }

    fn send(&mut self, buf: &[u8], dest: &NetAddr) -> Result<usize, IoError> {
        // Record sent packet in the transcript
        self.sent_packets.push((*dest, buf.to_vec()));
        Ok(buf.len())
    }
}

// ──── Packet Trace ────────────────────────────────────────────────────

/// Direction of a traced NTP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDirection {
    /// Packet sent by the daemon (outbound).
    Sent,
    /// Packet received by the daemon (inbound).
    Received,
}

/// A single traced NTP packet with timestamp and direction.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    /// NTP timestamp when this packet was captured.
    pub timestamp: NtpTs64,
    /// Direction (sent or received).
    pub direction: TraceDirection,
    /// Source address.
    pub source: NetAddr,
    /// Destination address.
    pub destination: NetAddr,
    /// Raw packet bytes.
    pub bytes: Vec<u8>,
}

/// A recorded NTP packet trace for replay and analysis.
#[derive(Debug, Default, Clone)]
pub struct PacketTrace {
    entries: Vec<TraceEntry>,
}

impl PacketTrace {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a trace entry.
    pub fn push(&mut self, entry: TraceEntry) {
        self.entries.push(entry);
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get an entry by index.
    pub fn get(&self, index: usize) -> Option<&TraceEntry> {
        self.entries.get(index)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &TraceEntry> {
        self.entries.iter()
    }

    /// Record a sent or received packet.
    pub fn record(
        &mut self,
        direction: TraceDirection,
        source: NetAddr,
        destination: NetAddr,
        bytes: &[u8],
    ) {
        // Use the current time approximation
        let timestamp = NtpTs64 {
            seconds: 0,
            fraction: 0,
        };
        self.entries.push(TraceEntry {
            timestamp,
            direction,
            source,
            destination,
            bytes: bytes.to_vec(),
        });
    }

    /// Save the trace to a simple JSON format.
    pub fn to_json(&self) -> String {
        let mut json = String::from("[\n");
        for (i, entry) in self.entries.iter().enumerate() {
            let dir = match entry.direction {
                TraceDirection::Sent => "send",
                TraceDirection::Received => "recv",
            };
            let hex = entry
                .bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            let comma = if i < self.entries.len() - 1 { "," } else { "" };
            json.push_str(&format!(
                "  {{ \"t\": {:.3}, \"dir\": \"{}\", \"src\": \"{}:{}\", \"dst\": \"{}:{}\", \"len\": {}, \"hex\": \"{}\" }}{}\n",
                crate::ntp_fp::ntp_ts64_to_double(entry.timestamp),
                dir,
                std::net::IpAddr::from(entry.source.addr),
                entry.source.port,
                std::net::IpAddr::from(entry.destination.addr),
                entry.destination.port,
                entry.bytes.len(),
                hex,
                comma,
            ));
        }
        json.push_str("]\n");
        json
    }

    /// Load a trace from JSON format.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let mut trace = PacketTrace::new();
        // Simple line-by-line JSON parser for trace format
        // Format: {"t": 1234.567, "dir": "send", "src": "...", "dst": "...", "len": 48, "hex": "..."}
        for line in json.lines() {
            let line = line.trim();
            if !line.starts_with('{') || !line.ends_with('}') {
                continue;
            }
            let inner = &line[1..line.len() - 1];
            let mut t = 0.0f64;
            let mut dir = String::new();
            let mut hex = String::new();
            let mut len = 0usize;
            for part in inner.split(',') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("\"t\": ") {
                    t = val.parse().unwrap_or(0.0);
                } else if let Some(val) = part.strip_prefix("\"dir\": \"") {
                    dir = val.trim_end_matches('"').to_string();
                } else if let Some(val) = part.strip_prefix("\"len\": ") {
                    len = val.parse().unwrap_or(0);
                } else if let Some(val) = part.strip_prefix("\"hex\": \"") {
                    hex = val.trim_end_matches('"').to_string();
                }
            }
            if hex.len() >= len * 2 && len > 0 {
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                    .collect();
                if bytes.len() >= 48 {
                    let direction = if dir == "send" {
                        TraceDirection::Sent
                    } else {
                        TraceDirection::Received
                    };
                    let secs = t.trunc() as i64 + crate::ntp_types::NTP_EPOCH_OFFSET as i64;
                    let frac = (t.fract() * crate::ntp_types::NTP_FRAC_PER_SEC as f64) as u32;
                    trace.entries.push(TraceEntry {
                        timestamp: NtpTs64 {
                            seconds: secs,
                            fraction: frac,
                        },
                        direction,
                        source: NetAddr::ipv4(0x7f000001, 123),
                        destination: NetAddr::ipv4(0x7f000001, 123),
                        bytes,
                    });
                }
            }
        }
        Ok(trace)
    }
}
