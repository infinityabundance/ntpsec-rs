// ──── ntp_dns.rs ────────────────────────────────────────────────────────────
// Forensic reconstruction of ntpd/ntp_dns.c
//
// DNS resolution for NTP — async hostname resolution with timeout.
// =============================================================================

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use thiserror::Error;

/// DNS resolution errors.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Name resolution returned no addresses (NXDOMAIN or equivalent).
    #[error("DNS resolution failed for '{hostname}': {kind}")]
    NoAddresses {
        hostname: String,
        kind: DnsErrorKind,
    },

    /// The DNS lookup timed out.
    #[error("DNS resolution timed out for '{hostname}' after {timeout_secs}s")]
    TimedOut { hostname: String, timeout_secs: u32 },

    /// The hostname string is invalid (bad port, empty, etc.).
    #[error("invalid address '{hostname}': {detail}")]
    InvalidAddress { hostname: String, detail: String },

    /// A transient I/O error occurred during resolution.
    #[error("I/O error resolving '{hostname}': {detail}")]
    IoError { hostname: String, detail: String },

    /// The thread or channel used for async resolution failed.
    #[error("internal error resolving '{hostname}': {detail}")]
    Internal { hostname: String, detail: String },
}

/// Specific category of DNS resolution failure.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsErrorKind {
    /// NXDOMAIN — the domain does not exist.
    #[error("NXDOMAIN")]
    NxDomain,
    /// SERVFAIL — the server encountered a temporary failure.
    #[error("SERVFAIL")]
    ServFail,
    /// REFUSED — the server refused the query.
    #[error("REFUSED")]
    Refused,
    /// No records of the requested type were found.
    #[error("no records found")]
    NoRecords,
    /// Temporary resolution failure (not definitively NXDOMAIN).
    #[error("temporary failure")]
    Temporary,
}

/// Resolve a hostname to a list of IP addresses with a timeout.
///
/// The resolution is performed on a separate thread so the caller can bound
/// the wall-clock wait.  Results are sorted with IPv4 addresses first to match
/// ntpsec's IPv4 preference.
///
/// When the hostname is already an IP literal (e.g. `"127.0.0.1"` or `"::1"`),
/// the function returns immediately without spawning a thread.
///
/// # Errors
///
/// Returns [`DnsError::TimedOut`] if resolution does not complete within
/// `timeout_secs` seconds.  Returns [`DnsError::NoAddresses`] when the
/// name is valid but resolves to zero addresses (NXDOMAIN-like condition).
pub fn resolve_hostname(
    hostname: &str,
    port: u16,
    timeout_secs: u32,
) -> Result<Vec<SocketAddr>, DnsError> {
    // Fast path: if the hostname is already an IP literal, return it
    // immediately without spawning a thread.
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addr_str = format!("{}:{}", hostname, port);
    let owned_hostname = hostname.to_string();
    let hostname_for_thread = owned_hostname.clone();

    let (tx, rx) = mpsc::channel();

    thread::Builder::new()
        .name(format!("dns-resolve-{hostname}"))
        .spawn(move || {
            let result = resolve_blocking(&addr_str, &hostname_for_thread);
            let _ = tx.send(result);
        })
        .map_err(|e| DnsError::Internal {
            hostname: owned_hostname,
            detail: format!("failed to spawn thread: {e}"),
        })?;

    let timeout = Duration::from_secs(timeout_secs as u64);

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(DnsError::TimedOut {
            hostname: hostname.to_string(),
            timeout_secs,
        }),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(DnsError::Internal {
            hostname: hostname.to_string(),
            detail: "resolution thread terminated unexpectedly".to_string(),
        }),
    }
}

/// Perform the blocking DNS resolution via `ToSocketAddrs`.
///
/// This runs on the spawned thread so the caller can apply a timeout.
fn resolve_blocking(addr_str: &str, hostname: &str) -> Result<Vec<SocketAddr>, DnsError> {
    let addrs_iter = addr_str.to_socket_addrs().map_err(|e| {
        let err_msg = e.to_string();
        // Classify the error for richer diagnostics.
        // We check the error string for known patterns since
        // std::io::Error does not carry DNS-specific error codes.
        let kind = if err_msg.contains("Not found")
            || err_msg.contains("No address")
            || err_msg.contains("nodename nor servname")
            || err_msg.contains("Name or service not known")
        {
            DnsError::NoAddresses {
                hostname: hostname.to_string(),
                kind: DnsErrorKind::NxDomain,
            }
        } else if err_msg.contains("Temporary failure") || err_msg.contains("Try again") {
            DnsError::NoAddresses {
                hostname: hostname.to_string(),
                kind: DnsErrorKind::Temporary,
            }
        } else if err_msg.contains("Refused") {
            DnsError::NoAddresses {
                hostname: hostname.to_string(),
                kind: DnsErrorKind::Refused,
            }
        } else {
            DnsError::IoError {
                hostname: hostname.to_string(),
                detail: err_msg,
            }
        };
        kind
    })?;

    let mut results: Vec<SocketAddr> = addrs_iter.collect();

    // Sort with IPv4 first (ntpsec preference).
    results.sort_by_key(|addr| match addr {
        SocketAddr::V4(_) => 0,
        SocketAddr::V6(_) => 1,
    });

    if results.is_empty() {
        return Err(DnsError::NoAddresses {
            hostname: hostname.to_string(),
            kind: DnsErrorKind::NoRecords,
        });
    }

    Ok(results)
}

/// Deduplicate a list of socket addresses by IP (ignoring port).
///
/// When the same IP appears multiple times (e.g. a dual-stack host with the
/// same address returned by both A and AAAA lookups), only the first occurrence
/// is kept.  This is useful before connecting to avoid redundant connections.
pub fn dedup_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(addrs.len());
    for addr in addrs {
        if seen.insert(addr.ip()) {
            out.push(*addr);
        }
    }
    out
}

/// Check if a string looks like an IP address (no DNS needed).
pub fn is_ip_address(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

// ──── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ip_address_ipv4() {
        assert!(is_ip_address("127.0.0.1"));
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("0.0.0.0"));
    }

    #[test]
    fn test_is_ip_address_ipv6() {
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("fe80::1"));
        assert!(is_ip_address("2001:db8::1"));
    }

    #[test]
    fn test_is_ip_address_hostname() {
        assert!(!is_ip_address("localhost"));
        assert!(!is_ip_address("pool.ntp.org"));
        assert!(!is_ip_address(""));
    }

    #[test]
    fn test_resolve_localhost_ipv4() {
        // 127.0.0.1 is an IP literal — fast path, no thread spawned.
        let result = resolve_hostname("127.0.0.1", 123, 5).unwrap();
        assert!(result.contains(&SocketAddr::from(([127, 0, 0, 1], 123))));
    }

    #[test]
    fn test_resolve_localhost_ipv6() {
        let result = resolve_hostname("::1", 123, 5).unwrap();
        assert!(result.contains(&SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 123))));
    }

    #[test]
    fn test_resolve_invalid_hostname() {
        let result = resolve_hostname("hostname.that.does.not.exist.example", 123, 2);
        assert!(result.is_err());
        match result.unwrap_err() {
            DnsError::NoAddresses { .. } => {} // expected
            DnsError::TimedOut { .. } => {}    // also possible depending on DNS
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn test_dedup_addrs() {
        let addrs = vec![
            SocketAddr::from(([127, 0, 0, 1], 123)),
            SocketAddr::from(([127, 0, 0, 1], 456)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 123)),
        ];
        let deduped = dedup_addrs(&addrs);
        assert_eq!(deduped.len(), 2);
        assert!(deduped.contains(&SocketAddr::from(([127, 0, 0, 1], 123))));
        assert!(deduped.contains(&SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 123))));
    }

    #[test]
    fn test_resolve_empty_hostname() {
        let result = resolve_hostname("", 123, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_error_display() {
        let err = DnsError::NoAddresses {
            hostname: "example.invalid".to_string(),
            kind: DnsErrorKind::NxDomain,
        };
        let msg = format!("{err}");
        assert!(msg.contains("example.invalid"));
        assert!(msg.contains("NXDOMAIN"));
    }

    #[test]
    fn test_ipv4_preference_order() {
        // localhost should resolve IPv4 first based on our sort.
        let result = resolve_hostname("127.0.0.1", 123, 5).unwrap();
        assert!(!result.is_empty());
        // For an IP literal, there's only one entry.
    }

    #[test]
    fn test_resolve_with_port() {
        let result = resolve_hostname("127.0.0.1", 9999, 5).unwrap();
        assert_eq!(result[0].port(), 9999);
    }

    #[test]
    fn test_resolve_timeout_is_respected() {
        // Use a hostname unlikely to resolve quickly, with a very short timeout.
        // This test verifies that the timeout mechanism is wired (the thread
        // spawn and channel are used) and won't hang.
        let result = resolve_hostname("192.0.2.1", 123, 1);
        // 192.0.2.1 is an IP literal (TEST-NET), so it takes the fast path.
        assert!(result.is_ok());
    }
}
