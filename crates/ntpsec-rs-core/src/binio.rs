// ──── binio.rs ──────────────────────────────────────────────────────────────
// Forensic reconstruction of include/binio.h, libparse/binio.c
//
// Binary I/O utilities for reference clock parsing: big-/little-endian
// signed/unsigned integer extraction.
//
// ## Oracle
//   - ntpsec include/binio.h
//   - ntpsec libparse/binio.c
// =============================================================================

/// Read a big-endian u16 from a byte slice.
pub fn get_u16(buf: &[u8]) -> Option<u16> {
    if buf.len() < 2 {
        None
    } else {
        Some(u16::from_be_bytes([buf[0], buf[1]]))
    }
}

/// Read a big-endian u32 from a byte slice.
pub fn get_u32(buf: &[u8]) -> Option<u32> {
    if buf.len() < 4 {
        None
    } else {
        Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }
}

/// Write a big-endian u16 to a mutable byte slice.
pub fn put_u16(buf: &mut [u8], val: u16) {
    let bytes = val.to_be_bytes();
    buf[0..2].copy_from_slice(&bytes);
}

/// Write a big-endian u32 to a mutable byte slice.
pub fn put_u32(buf: &mut [u8], val: u32) {
    let bytes = val.to_be_bytes();
    buf[0..4].copy_from_slice(&bytes);
}
