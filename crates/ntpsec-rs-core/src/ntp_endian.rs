// ──── ntp_endian.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_endian.h and libntp/ntp_endian.c
//
// Endian conversion utilities for NTP's network-byte-order fields.
//
// ## Oracle
//   - ntpsec include/ntp_endian.h
// =============================================================================

use core::mem;

/// Swap bytes in a 16-bit value.
#[inline]
pub fn swap_u16(x: u16) -> u16 {
    x.swap_bytes()
}

/// Swap bytes in a 32-bit value.
#[inline]
pub fn swap_u32(x: u32) -> u32 {
    x.swap_bytes()
}

/// Swap bytes in a 64-bit value.
#[inline]
pub fn swap_u64(x: u64) -> u64 {
    x.swap_bytes()
}

/// Convert u16 from host to network byte order.
#[inline]
pub fn hton16(x: u16) -> u16 {
    x.to_be()
}

/// Convert u16 from network to host byte order.
#[inline]
pub fn ntoh16(x: u16) -> u16 {
    u16::from_be(x)
}

/// Convert u32 from host to network byte order.
#[inline]
pub fn hton32(x: u32) -> u32 {
    x.to_be()
}

/// Convert u32 from network to host byte order.
#[inline]
pub fn ntoh32(x: u32) -> u32 {
    u32::from_be(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endian_roundtrip() {
        assert_eq!(ntoh16(hton16(0x1234)), 0x1234);
        assert_eq!(ntoh32(hton32(0x12345678)), 0x12345678);
    }
}
