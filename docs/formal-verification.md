# Formal Verification with Kani

This document describes the Kani formal verification harnesses for ntpsec-rs.
Kani is a bounded model checker for Rust that verifies memory safety, absence
of panics, and user-specified assertions.

## What Kani Proves

### 1. Clock Filter Convergence (`kani_clock_filter_convergence`)

Proves that `LoopFilter::local_clock()` satisfies three critical properties:

- **No NaN/Inf**: The returned `Adjustment` variant never contains `f64::NAN`
  or `f64::INFINITY` when given finite, bounded inputs.
- **Valid variant**: The function always returns one of the five `Adjustment`
  variants (`Step`, `Slew`, `KernelSlew`, `Panic`, `Ignore`), never panics,
  and never returns an uninitialized/malformed value.
- **Bounded output**: When the result is `Slew(phase_adj, freq)`, the phase
  adjustment magnitude does not exceed the input offset magnitude plus a small
  epsilon (`1e-6` seconds) accounting for numerical error in the frequency
  computation. Additionally, the frequency field is bounded to ±500 PPM
  (`MAX_FREQ_PPM`).

### 2. No Panic Under Any Valid Input (`kani_local_clock_no_panic`)

Proves that `LoopFilter::local_clock()` never panics (via `unwrap()`, index
bounds, arithmetic overflow, or assertion failure) for ANY combination of:

- All four discipline types (`Pll`, `PllFll`, `Fll`, `KernelPll`)
- Symbolic `step_threshold` (0 to 1000 seconds)
- Symbolic `panic_threshold` (0 to 100000 seconds)
- Symbolic initial state (offset, frequency, phase, jitter, tc, clock_set)
- Symbolic input offset and timestamp

The proof constrains inputs to finite, physically reasonable values and
verifies that no code path triggers a panic.

### 3. Clock Filter Safety (`kani_clock_filter_entry_no_panic`)

Proves that `ClockFilter::add_sample()`, `ClockFilter::filter()`, and
`ClockFilter::filter_jitter()` never panic for any finite, bounded input.

### 4. Clock Intersection Safety (`kani_clock_intersection_no_panic`)

Proves that the `clock_intersection()` algorithm (RFC 5905 §11.2.1) never
panics when processing up to 3 symbolic peers with finite, valid state.
This covers the three-tuple majority clique scan and falseticker detection.

### 5. f64-to-NTP-Short Conversion (`kani_f64_to_ntp_short_safe`)

Proves that `f64_to_ntp_short()` never panics and always produces a valid
`u32` for any finite input in the range `[0, 65535]`.

### 6. Root Distance Safety (`kani_root_distance_no_panic`)

Proves that `root_distance()` and `root_dispersion()` never panic for any
finite, non-negative peer state values.

### 7. Timestamp Conversion (`kani_ntp_ts_conversion_no_overflow`)

Proves that `ts_to_ntp()` and `ntp_to_ts()` — the core NTP↔Unix timestamp
conversion functions — never panic and round-trip without error for any
reasonable input range (±2^40 seconds from epoch).

### 8. NTP Short Conversion (`kani_ntp_short_conversion_safe`)

Proves that `ntp_short_to_double()` always returns a finite, non-negative
value in the range `[0, 65536]` for any valid `NtpShort` input.

### 9. Wire Format Conversion (`kani_ntp_ts64_to_wire_safe`)

Proves that `ntp_ts64_to_wire()` never panics for any valid `NtpTs64`.

## Running the Proofs

```bash
# Run all Kani proofs for the core crate
cargo kani --tests kani_proof -p ntpsec-rs-core

# Run a specific proof harness
cargo kani --tests kani_proof -p ntpsec-rs-core --harness kani_clock_filter_convergence

# Run with verbose output
RUST_LOG=kani=info cargo kani --tests kani_proof -p ntpsec-rs-core

# Run with a different unwinding bound (for larger state spaces)
cargo kani --tests kani_proof -p ntpsec-rs-core --unwind 20
```

### Requirements

- Install Kani: `cargo install kani-verifier`
- Or use the Docker image: `ghcr.io/model-checking/kani:latest`

## Proof Coverage

| Proof Harness                       | Lines of Code | Modules Covered           |
|--------------------------------------|---------------|---------------------------|
| `kani_clock_filter_convergence`      | ~40           | `ntp_loopfilter`          |
| `kani_local_clock_no_panic`          | ~55           | `ntp_loopfilter`          |
| `kani_clock_filter_entry_no_panic`   | ~35           | `ntp_proto` (ClockFilter) |
| `kani_clock_intersection_no_panic`   | ~40           | `ntp_proto` (selection)   |
| `kani_f64_to_ntp_short_safe`         | ~15           | `ntp_proto`               |
| `kani_root_distance_no_panic`        | ~30           | `ntp_proto`               |
| `kani_ntp_ts_conversion_no_overflow` | ~20           | `ntp_fp`                  |
| `kani_ntp_short_conversion_safe`     | ~15           | `ntp_fp`                  |
| `kani_ntp_ts64_to_wire_safe`         | ~10           | `ntp_fp`                  |

### Coverage Gaps (Future Work)

- **Full clock_cluster + clock_combine pipeline**: The selection algorithm
  (`clock_cluster`, `clock_combine`) is not yet verified due to higher
  state-space complexity (depends on the number of survivors from
  `clock_intersection`, creating a path-dependent state explosion).

- **Multi-step convergence**: The current clock filter proof only verifies a
  single call to `local_clock`. A full multi-step convergence proof would
  require bounded model checking over N iterations (state machine
  unrolling), which is computationally expensive.

- **Float arithmetic accuracy**: Kani treats `f64` as an opaque type. We can
  verify that values are finite and bounded, but we cannot prove precise
  numerical accuracy of the PLL/FLL update equations. For numerical accuracy,
  see the convergence tests in `convergence_test.rs`.

- **Packet parsing**: `split_packet_tail()` and `NtpPacket::decode_full()`
  are not yet verified (they involve slicing and Vec allocation).

- **Auth/MAC verification**: The cryptographic verification functions
  depend on external crates (digest, cmac) whose internal behavior Kani
  treats as uninterpreted.

## How to Add New Proofs

### Adding a harness

1. Create a new function in `crates/ntpsec-rs-core/tests/kani_proof.rs`
   annotated with `#[kani::proof]`:

```rust
#[kani::proof]
fn kani_my_new_proof() {
    // 1. Set up symbolic inputs
    let x: u32 = kani::any();
    kani::assume(x < 100);

    // 2. Call the function under test
    let result = my_function(x);

    // 3. Assert properties
    assert!(result.is_ok());
}
```

2. Run it: `cargo kani --tests kani_proof -p ntpsec-rs-core --harness kani_my_new_proof`

### Guidelines

- **Constrain inputs tightly**: Use `kani::assume()` to restrict symbolic
  values to realistic ranges. This keeps the state space tractable.
- **Use `#[kani::unwind(N)]`**: Set an explicit unwinding bound on proofs
  that involve loops. Start with N=5 and increase until the proof is
  sound (no spurious failures).
- **Start small**: Begin with a single function and a few constraints.
  Gradually expand the harness as you gain confidence.
- **Avoid Vec allocations**: Kani struggles with heap-allocated data.
  Prefer arrays and fixed-size structures in proofs.

## Limitations

### Floating-Point Arithmetic

Kani models `f64` as an opaque 64-bit value. It can verify:
- Values are finite (not NaN or Inf)
- Values satisfy inequality constraints
- Operations don't panic

But it **cannot** verify:
- Precise numerical accuracy of floating-point computations
- Rounding error bounds beyond what's expressed as assertions
- IEEE 754 compliance of specific operations

For floating-point accuracy verification, rely on the test suite
(`cargo test`) and convergence tests (`convergence_test.rs`) rather than
Kani.

### Assumption Completeness

The proofs are only as strong as their assumptions. If an assumption is
too permissive (e.g., allowing values that never occur in practice), the
proof may be weaker than expected. If an assumption is too restrictive,
the proof may not cover real-world inputs.

Key assumptions in the current harnesses:
- Offsets are finite and bounded to ±1000 seconds (reasonable for NTP)
- Frequencies are bounded to ±500 PPM (`MAX_FREQ_PPM`)
- Time constants are within `[MIN_TC, MAX_TC]` (3 to 17)
- Timestamps are within ±2^31 seconds of epoch (~68 years)

### State Space Explosion

Some properties cannot be verified because the state space grows
exponentially with:
- Number of symbolic peers (bounded to 3 in intersection proof)
- Number of loop iterations (use `#[kani::unwind]` to limit)
- Number of struct fields (each adds binary decisions)

If a proof times out or runs out of memory, try:
1. Reducing the number of symbolic values
2. Adding tighter assumptions
3. Splitting the proof into smaller sub-proofs
4. Increasing the solver memory: `KANI_MEMORY_LIMIT=65536 cargo kani ...`
