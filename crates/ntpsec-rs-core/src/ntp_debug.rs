// ──── ntp_debug.rs ──────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_debug.h
//
// Debug trace macros. In debug builds, these emit tracing output.
// =============================================================================

/// Debug trace macro (matches ntpsec's DPRINTF).
#[macro_export]
macro_rules! ntp_debug {
    ($level:expr, $($arg:tt)+) => {
        if cfg!(debug_assertions) {
            #[cfg(debug_assertions)]
            eprintln!("[NTP-DEBUG:{}] {}", $level, format_args!($($arg)+));
        }
    };
}
