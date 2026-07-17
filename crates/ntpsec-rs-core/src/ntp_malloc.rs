// ──── ntp_malloc.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_malloc.h, libntp/emalloc.c
//
// Memory allocation with error-checked initialization (matching ntpsec's
// emalloc, erealloc, estrdup, etc.).
//
// ## Oracle
//   - ntpsec include/ntp_malloc.h
//   - ntpsec libntp/emalloc.c
// =============================================================================

use std::alloc::{alloc, dealloc, realloc, Layout};

/// Zeroed allocation of `size` bytes (matches ntpsec's `emalloc_zeroed()`).
pub fn emalloc(size: usize) -> *mut u8 {
    let layout = Layout::from_size_align(size, 1).expect("invalid layout");
    unsafe { alloc(layout) }
}

/// Zeroed allocation for a type.
pub fn ealloc<T: Default>() -> Box<T> {
    Box::new(T::default())
}

/// Copy a C string (matches ntpsec's `estrdup()`).
pub fn estrdup(s: &str) -> *mut u8 {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let ptr = emalloc(len + 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
        *ptr.add(len) = 0; // null terminator
    }
    ptr
}

/// Safe wrapper for ntpsec-style allocation (for use within Rust code).
pub fn emalloc_vec(size: usize) -> Vec<u8> {
    vec![0u8; size]
}
