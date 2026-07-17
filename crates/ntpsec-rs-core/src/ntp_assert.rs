// ──── ntp_assert.rs ─────────────────────────────────────────────────────────
// Forensic reconstruction of include/ntp_assert.h
//
// NTPsec assertion macros. In debug builds, these panic; in release, they
// may be compiled out depending on configuration.
// =============================================================================

/// NTPsec-style assertion.
#[macro_export]
macro_rules! ntp_assert {
    ($cond:expr) => {
        if cfg!(debug_assertions) {
            assert!($cond, "NTP assertion failed");
        }
    };
    ($cond:expr, $msg:expr) => {
        if cfg!(debug_assertions) {
            assert!($cond, "NTP assertion failed: {}", $msg);
        }
    };
}

/// NTPsec-style invariant assertion.
#[macro_export]
macro_rules! ntp_invariant {
    ($cond:expr) => {
        assert!($cond, "NTP invariant violated");
    };
    ($cond:expr, $msg:expr) => {
        assert!($cond, "NTP invariant violated: {}", $msg);
    };
}

/// NTPsec-style require (precondition check).
#[macro_export]
macro_rules! ntp_require {
    ($cond:expr) => {
        if cfg!(debug_assertions) {
            assert!($cond, "NTP precondition failed");
        }
    };
    ($cond:expr, $msg:expr) => {
        if cfg!(debug_assertions) {
            assert!($cond, "NTP precondition failed: {}", $msg);
        }
    };
}
