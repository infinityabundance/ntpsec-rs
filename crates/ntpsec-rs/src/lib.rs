// ──── ntpsec-rs — Facade crate ──────────────────────────────────────────────
//
// Re-exports ntpsec-rs-core as the public API. Users who want the full
// deterministic brain can use `use ntpsec_rs::*`.
//
// =============================================================================

pub use ntpsec_rs_core::*;
#[cfg(feature = "ntpsec-rs-io")]
pub use ntpsec_rs_io as io;
