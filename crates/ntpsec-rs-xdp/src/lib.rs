// ──── lib.rs ──────────────────────────────────────────────────────────────────
// Userspace loader for the ntpsec-rs XDP timestamp program.
//
// Provides:
// - `NtpXdpTimestamp`: loads, attaches, and detaches the XDP program
// - `NtpTimestampEvent`: parsed event data from the perf event buffer
// - `XdpCollector`: high-level interface for the daemon event loop
// =============================================================================

#![doc = include_str!("../README.md")]

use std::time::Duration;

use aya::maps::PerfEventArray;
use aya::programs::xdp::XdpLinkId;
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use ntpsec_rs_core::ntp_types::NtpTs64;
use thiserror::Error;

/// Error type for XDP operations.
#[derive(Error, Debug)]
pub enum XdpError {
    /// Failed to load the BPF object file.
    #[error("BPF load error: {0}")]
    BpfLoad(#[from] aya::BpfError),

    /// Failed to attach the XDP program to an interface.
    #[error("XDP attach error: {0}")]
    XdpAttach(String),

    /// Failed to detach the XDP program.
    #[error("XDP detach error: {0}")]
    XdpDetach(String),

    /// Error reading from the perf event buffer.
    #[error("Perf event error: {0}")]
    PerfEvent(String),

    /// Interface not found or not available.
    #[error("Interface error: {0}")]
    Interface(String),

    /// The BPF object does not contain the expected XDP program.
    #[error("XDP program 'ntp_timestamp' not found in BPF object")]
    ProgramNotFound,

    /// Map error.
    #[error("Map error: {0}")]
    Map(#[from] aya::maps::MapError),
}

/// A single NTP timestamp event captured by the XDP/BPF program.
///
/// Fields are kept in sync with `NtpXdpEvent` in `xdp/src/ntp_timestamp.rs`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NtpTimestampEvent {
    /// Source IPv4 address in network byte order.
    pub source_ip: [u8; 4],
    /// Destination IPv4 address in network byte order.
    pub dest_ip: [u8; 4],
    /// Kernel timestamp in nanoseconds (CLOCK_MONOTONIC / bpf_ktime_get_ns).
    pub timestamp_ns: u64,
    /// UDP source port.
    pub src_port: u16,
    /// UDP destination port.
    pub dst_port: u16,
    /// Packet length in bytes.
    pub pkt_len: u16,
    /// Padding to match the BPF struct layout.
    _padding: [u8; 4],
}

impl NtpTimestampEvent {
    /// Convert source IP to a standard IPv4 address.
    pub fn source_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.source_ip)
    }

    /// Convert destination IP to a standard IPv4 address.
    pub fn dest_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.dest_ip)
    }

    /// Timestamp as a `std::time::Duration` since boot (CLOCK_MONOTONIC).
    pub fn duration_since_boot(&self) -> Duration {
        Duration::from_nanos(self.timestamp_ns)
    }
}

/// XDP timestamp collector.
///
/// Manages the lifecycle of the XDP program and provides access to captured
/// NTP packet timestamps via synchronous polling.
///
/// ## Ownership model
///
/// The `Bpf` object owns the loaded programs and maps. We keep it alive for
/// the duration of the attachment. The XDP program is accessed via mutable
/// references obtained from `Bpf::program_mut()` as needed (detach),
/// rather than storing a long-lived reference.
pub struct NtpXdpTimestamp {
    /// The loaded BPF object — must stay alive while the XDP program is loaded.
    bpf: Option<Bpf>,
    /// The link ID returned by attach, needed for detach.
    link_id: Option<XdpLinkId>,
    /// The network interface the program is attached to.
    interface: String,
}

impl NtpXdpTimestamp {
    /// Load and attach the XDP program to a network interface.
    pub fn attach(interface: &str) -> Result<Self, XdpError> {
        let bpf_elf_path = env!("XDP_BPF_ELF");

        let mut bpf = Bpf::load_file(bpf_elf_path).map_err(XdpError::BpfLoad)?;

        let xdp_prog: &mut Xdp = bpf
            .program_mut("ntp_timestamp")
            .ok_or(XdpError::ProgramNotFound)?
            .try_into()
            .map_err(|e| XdpError::XdpAttach(format!("Failed to get XDP program: {}", e)))?;

        xdp_prog
            .load()
            .map_err(|e| XdpError::XdpAttach(format!("Failed to load XDP program: {}", e)))?;

        let link_id = xdp_prog
            .attach(interface, XdpFlags::default())
            .map_err(|e| {
                XdpError::XdpAttach(format!(
                    "Failed to attach XDP to '{}': {}. \
                     Try SKB mode (generic) or ensure the interface supports native XDP.",
                    interface, e
                ))
            })?;

        tracing::info!("XDP program 'ntp_timestamp' attached to '{}'", interface);

        Ok(Self {
            bpf: Some(bpf),
            link_id: Some(link_id),
            interface: interface.to_string(),
        })
    }

    /// Detach the XDP program from the interface.
    pub fn detach(&mut self) -> Result<(), XdpError> {
        if let Some(link_id) = self.link_id.take() {
            if let Some(ref mut bpf) = self.bpf {
                if let Some(prog) = bpf.program_mut("ntp_timestamp") {
                    let xdp_prog: Result<&mut Xdp, _> = prog.try_into();
                    if let Ok(xdp) = xdp_prog {
                        xdp.detach(link_id).map_err(|e| {
                            XdpError::XdpDetach(format!(
                                "Failed to detach XDP from '{}': {}",
                                self.interface, e
                            ))
                        })?;
                    }
                }
            }
            tracing::info!("XDP program detached from '{}'", self.interface);
        }

        // Drop the BPF object to unload the program from the kernel.
        self.bpf.take();

        Ok(())
    }

    /// Return the interface name this XDP program is attached to.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Whether the XDP program is currently attached.
    pub fn is_attached(&self) -> bool {
        self.link_id.is_some()
    }

    /// Read all available timestamp events from the perf event buffers.
    ///
    /// This performs a synchronous, non-blocking poll of all per-CPU perf
    /// event buffers. Opens buffers fresh each time to avoid storing
    /// complex generic types on the struct.
    pub fn read_timestamps(&mut self) -> Vec<NtpTimestampEvent> {
        let bpf = match self.bpf.as_mut() {
            Some(b) => b,
            None => return Vec::new(),
        };

        let map = match bpf.map_mut("NTP_TIMESTAMPS") {
            Some(m) => m,
            None => {
                tracing::warn!("Map 'NTP_TIMESTAMPS' not found");
                return Vec::new();
            }
        };

        let mut perf_array = match PerfEventArray::try_from(map) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("Failed to create PerfEventArray: {}", e);
                return Vec::new();
            }
        };

        let cpus = match online_cpus() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to get online CPUs: {}", e);
                return Vec::new();
            }
        };

        let mut events = Vec::with_capacity(64);
        let event_size = std::mem::size_of::<NtpTimestampEvent>();

        for cpu_id in &cpus {
            let mut buffer = match perf_array.open(*cpu_id, None) {
                Ok(buf) => buf,
                Err(e) => {
                    tracing::debug!("Failed to open perf buffer for CPU {}: {}", cpu_id, e);
                    continue;
                }
            };

            if !buffer.readable() {
                continue;
            }

            let mut out_bufs = [BytesMut::with_capacity(4096)];

            match buffer.read_events(&mut out_bufs) {
                Ok(result) => {
                    for buf in &out_bufs {
                        for chunk in buf.chunks(event_size) {
                            if chunk.len() >= event_size {
                                let event: NtpTimestampEvent = unsafe {
                                    core::ptr::read(chunk.as_ptr() as *const NtpTimestampEvent)
                                };
                                events.push(event);
                            }
                        }
                    }
                    if result.lost > 0 {
                        tracing::warn!(
                            "XDP perf buffer on CPU {}: {} events lost (overflow)",
                            cpu_id,
                            result.lost
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("XDP perf event read error on CPU {}: {}", cpu_id, e);
                }
            }
        }

        events
    }
}

impl Drop for NtpXdpTimestamp {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

// ──── Integration Helpers ───────────────────────────────────────────────────

/// Convert an XDP timestamp (CLOCK_MONOTONIC nanoseconds) to an NTP timestamp.
pub fn xdp_timestamp_to_ntp(
    xdp_ns: u64,
    _realtime_ntp_ts: NtpTs64,
    monotonic_ns_at_reference: u64,
) -> NtpTs64 {
    let elapsed_ns = xdp_ns.saturating_sub(monotonic_ns_at_reference);
    let elapsed_secs = (elapsed_ns as f64) / 1_000_000_000.0;
    ntpsec_rs_core::ntp_fp::ts_to_ntp(
        elapsed_secs as i64,
        ((elapsed_secs.fract() * 1_000_000_000.0) as i64).abs(),
    )
}

/// Snapshot the offset between CLOCK_MONOTONIC and CLOCK_REALTIME.
pub fn clock_offset_snapshot() -> Result<(u64, u64), XdpError> {
    let mut mono_ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut real_ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono_ts) };
    if ret != 0 {
        return Err(XdpError::PerfEvent(
            "clock_gettime(CLOCK_MONOTONIC) failed".to_string(),
        ));
    }

    let ret = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut real_ts) };
    if ret != 0 {
        return Err(XdpError::PerfEvent(
            "clock_gettime(CLOCK_REALTIME) failed".to_string(),
        ));
    }

    let mono_ns = (mono_ts.tv_sec as u64) * 1_000_000_000 + (mono_ts.tv_nsec as u64);
    let real_ns = (real_ts.tv_sec as u64) * 1_000_000_000 + (real_ts.tv_nsec as u64);

    Ok((mono_ns, real_ns))
}

/// A running XDP timestamp collector, ready for daemon integration.
pub struct XdpCollector {
    inner: NtpXdpTimestamp,
    mono_ns_at_ref: u64,
    real_ns_at_ref: u64,
}

impl XdpCollector {
    /// Create and start a new XDP collector on the given interface.
    pub fn start(interface: &str) -> Result<Self, XdpError> {
        let inner = NtpXdpTimestamp::attach(interface)?;
        let (mono_ns_at_ref, real_ns_at_ref) = clock_offset_snapshot()?;

        Ok(Self {
            inner,
            mono_ns_at_ref,
            real_ns_at_ref,
        })
    }

    /// Poll for the next batch of timestamp events.
    pub fn poll(&mut self) -> Vec<NtpTimestampEvent> {
        self.inner.read_timestamps()
    }

    /// Stop the collector and detach the XDP program.
    pub fn stop(&mut self) -> Result<(), XdpError> {
        self.inner.detach()
    }

    /// Get the interface name.
    pub fn interface(&self) -> &str {
        self.inner.interface()
    }

    /// Whether the collector is active.
    pub fn is_active(&self) -> bool {
        self.inner.is_attached()
    }

    /// Reference CLOCK_MONOTONIC nanosecond timestamp (taken at attach time).
    pub fn mono_ns_at_ref(&self) -> u64 {
        self.mono_ns_at_ref
    }

    /// Reference CLOCK_REALTIME nanosecond timestamp (taken at attach time).
    pub fn real_ns_at_ref(&self) -> u64 {
        self.real_ns_at_ref
    }
}

// ──── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_timestamp_event_size() {
        assert_eq!(
            std::mem::size_of::<NtpTimestampEvent>(),
            32,
            "NtpTimestampEvent must be 32 bytes"
        );
    }

    #[test]
    fn test_ntp_timestamp_event_addr_conversion() {
        let event = NtpTimestampEvent {
            source_ip: [192, 168, 1, 1],
            dest_ip: [10, 0, 0, 1],
            timestamp_ns: 1_000_000_000,
            src_port: 123,
            dst_port: 45678,
            pkt_len: 48,
            _padding: [0u8; 4],
        };

        assert_eq!(event.source_addr(), std::net::Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(event.dest_addr(), std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(event.duration_since_boot(), Duration::from_secs(1));
    }

    #[test]
    fn test_xdp_error_display() {
        let err = XdpError::Interface("eth0 not found".to_string());
        assert!(err.to_string().contains("eth0"));
    }

    #[test]
    fn test_xdp_timestamp_to_ntp() {
        let xdp_ns = 5_000_000_000;
        let ref_ns = 1_000_000_000;
        let result = xdp_timestamp_to_ntp(
            xdp_ns,
            NtpTs64 {
                seconds: 0,
                fraction: 0,
            },
            ref_ns,
        );
        assert!(result.seconds >= 0);
        assert!(result.seconds <= 5);
    }
}
