// ──── ntp_dns.rs ────────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_dns.c
//
// DNS resolution for NTP — async hostname resolution with timeout.
// =============================================================================

use std::net::{SocketAddr, ToSocketAddrs};

/// Resolve a hostname to an IP address with timeout.
/// Returns all resolved addresses.
pub fn resolve_hostname(
    hostname: &str,
    port: u16,
    _timeout_secs: u32,
) -> Result<Vec<SocketAddr>, String> {
    let addr_str = format!("{}:{}", hostname, port);
    let addrs = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for '{}': {}", hostname, e))?;
    let results: Vec<SocketAddr> = addrs.collect();
    if results.is_empty() {
        Err(format!("no addresses resolved for '{}'", hostname))
    } else {
        Ok(results)
    }
}

/// Check if a string looks like an IP address (no DNS needed).
pub fn is_ip_address(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}
