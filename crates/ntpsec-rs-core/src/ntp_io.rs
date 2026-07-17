// ──── ntp_io.rs ─────────────────────────────────────────────────────────────
// I/O trait definitions for ntpsec-rs-core.
// Actual I/O implementation lives in ntpsec-rs-io crate.
// =============================================================================

use crate::ntp_types::*;

/// Network I/O trait — implemented by ntpsec-rs-io for real sockets
/// and by replay harness for deterministic trace replay.
pub trait NetworkIo {
    type Error: std::error::Error;

    /// Receive an NTP packet.
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, SockAddr), Self::Error>;

    /// Send an NTP packet.
    fn send(&mut self, buf: &[u8], addr: &SockAddr) -> Result<usize, Self::Error>;

    /// Get the socket's timestamp (if hardware timestamping enabled).
    fn rx_timestamp(&self) -> Option<NtpTs64> {
        None
    }
}
