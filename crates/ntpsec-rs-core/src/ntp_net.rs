// ──── ntp_net.rs ────────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_net.h, libntp/socktoa.c,
// libntp/decodenetnum.c
//
// Network address handling for NTP: socket address formatting, parsing,
// and comparison.
//
// ## Oracle
//   - ntpsec include/ntp_net.h
//   - ntpsec libntp/socktoa.c
//   - ntpsec libntp/decodenetnum.c
// =============================================================================

use crate::ntp_types::*;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Convert a socket address to a string (matches ntpsec's `socktoa()`).
pub fn socktoa(sa: &SockAddr) -> String {
    // Simplified: convert from sockaddr_storage to IpAddr
    // Full implementation will match ntpsec's output format exactly
    let ip = sockaddr_to_ipaddr(sa);
    match ip {
        Some(ip) => ip.to_string(),
        None => "0.0.0.0".to_string(),
    }
}

/// Decode a network number string into a socket address.
pub fn decodenetnum(s: &str) -> Option<SockAddr> {
    let (host, port) = if let Some(idx) = s.rfind(':') {
        let host_part = &s[..idx];
        let port_part = &s[idx + 1..];
        (host_part, port_part.parse::<u16>().ok()?)
    } else {
        (s, 123) // default NTP port
    };

    let ip: IpAddr = host.parse().ok()?;
    let sock_addr = SocketAddr::new(ip, port);
    Some(sockaddr_from_socketaddr(&sock_addr))
}

fn sockaddr_to_ipaddr(sa: &SockAddr) -> Option<IpAddr> {
    // SAFETY: sockaddr_storage has a valid ss_family; the pointer casts are
    // valid because we match on the family before accessing the union members.
    unsafe {
        match sa.ss_family as libc::c_int {
            libc::AF_INET => {
                let sin = &*(sa as *const _ as *const libc::sockaddr_in);
                let addr = u32::from_be(sin.sin_addr.s_addr);
                Some(IpAddr::V4(Ipv4Addr::from_bits(addr)))
            }
            libc::AF_INET6 => {
                let sin6 = &*(sa as *const _ as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

fn sockaddr_from_socketaddr(sa: &SocketAddr) -> SockAddr {
    // SAFETY: zeroed sockaddr_storage is valid; pointer casts match the family.
    let mut storage: SockAddr = unsafe { core::mem::zeroed() };
    match sa {
        SocketAddr::V4(v4) => {
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.ip().octets()),
            };
        }
        SocketAddr::V6(v6) => {
            let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
        }
    }
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decodenetnum_ipv4() {
        let addr = decodenetnum("127.0.0.1:123");
        assert!(addr.is_some());
        let s = socktoa(&addr.unwrap());
        assert!(s.contains("127.0.0.1"));
    }
}
