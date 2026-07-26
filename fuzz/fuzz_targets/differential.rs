#![no_main]

use libfuzzer_sys::fuzz_target;

// Import the differential fuzzing harness.
// (The fuzz crate's Cargo.toml references ntpsec-rs-core; the differential
//  module is included as a regular module within the fuzz crate.)
/// The differential fuzzing harness lives at fuzz/differential/mod.rs
/// (one directory up from fuzz_targets/).
#[path = "../differential/mod.rs"]
mod differential;

use differential::run_fuzz_input;

fuzz_target!(|data: &[u8]| {
    // We need at least one byte to determine the mode.
    if data.is_empty() {
        return;
    }

    let result = run_fuzz_input(data);

    // Report invariant violations as test failures (libfuzzer will
    // capture the crashing input in the corpus).
    if let Some(ref violation) = result.violation {
        panic!("Invariant violation: {}", violation);
    }

    // Report panics as failures.
    if result.panicked {
        panic!("Engine panicked during packet handling");
    }

    // `result.snapshots` is available here for optional logging or
    // statistical analysis, but in fuzzing mode we just check invariants.
    let _ = result.snapshots;
});
