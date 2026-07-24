// ──── ieee754io.rs ──────────────────────────────────────────────────────────
// Forensic reconstruction of include/ieee754io.h, libparse/ieee754io.c
//
// IEEE 754 binary floating-point I/O for reference clock parsing.
// =============================================================================

/// Decode an IEEE 754 32-bit float from big-endian bytes.
pub fn get_f32_be(buf: &[u8]) -> Option<f32> {
    if buf.len() < 4 {
        None
    } else {
        Some(f32::from_bits(u32::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3],
        ])))
    }
}

/// Decode an IEEE 754 64-bit double from big-endian bytes.
pub fn get_f64_be(buf: &[u8]) -> Option<f64> {
    if buf.len() < 8 {
        None
    } else {
        Some(f64::from_bits(u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])))
    }
}

/// Encode an f32 as big-endian bytes.
pub fn put_f32_be(buf: &mut [u8], val: f32) {
    let bytes = val.to_bits().to_be_bytes();
    buf[0..4].copy_from_slice(&bytes);
}

/// Encode an f64 as big-endian bytes.
pub fn put_f64_be(buf: &mut [u8], val: f64) {
    let bytes = val.to_bits().to_be_bytes();
    buf[0..8].copy_from_slice(&bytes);
}
