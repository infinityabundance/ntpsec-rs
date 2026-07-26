# Differential Fuzzer for ntpsec-rs

This directory contains a differential fuzzing harness for the
`ntpsec-rs` NTP daemon engine. It exercises the `DaemonEngine` with
mutated NTP packets and checks invariants on the resulting state.

## How It Works

```
fuzzer input (raw bytes)
    │
    ▼
mutate_packet() — produces a valid 48-byte NTP header + optional tail
    │
    ▼
create_minimal_engine() — fresh DaemonEngine with one configured peer
    │
    ▼
engine.handle(DaemonEvent::PacketReceived(...)) — process NTP packet
    │
    ▼
take_snapshot() — capture all system & peer state
    │
    ▼
check_invariants() — validate f64, stratum, leap, peers, associds
```

The fuzzer runs inside a `std::panic::catch_unwind` boundary, so
panics are detected without crashing the fuzzer process.

## How to Run

### Prerequisites

```bash
# Install cargo-fuzz (if not already installed)
cargo install cargo-fuzz

# Navigate to the fuzz crate
cd fuzz
```

### Run the differential fuzzer

```bash
# Run indefinitely (hit Ctrl-C to stop)
cargo fuzz run differential

# Run with a timeout (e.g., 10 minutes)
cargo fuzz run differential -- -max_total_time=600

# Run with a specific seed corpus directory
cargo fuzz run differential fuzz/corpus/differential

# Run with more parallelism
cargo fuzz run differential --jobs=4
```

### Build the fuzzer without running

```bash
cargo fuzz build differential
```

### Minimal reproducing input

If the fuzzer finds a crash, it writes the reproducing input to
`fuzz/artifacts/differential/crash-*`. Replay it:

```bash
cargo fuzz run differential fuzz/artifacts/differential/crash-<hash>
```

## Interpreting Results

### Invariant violations

The fuzzer panics with a descriptive message on the first invariant
violation. Example:

```
Invariant violation: system.sys_offset is not finite: NaN
```

This tells you:
- **What failed:** `sys_offset` is NaN
- **Where to look:** `check_invariants()` in `fuzz/differential/mod.rs`
- **What to fix:** The engine code path that produced the NaN.

### Panics

If the engine itself panics (e.g., `unwrap()` on `None`, index out of
bounds), the panic message is captured and reported as:

```
Engine panicked during packet handling
```

Reproduce with the crashing input and run outside cargo-fuzz with
`RUST_BACKTRACE=1` to get the full stack trace.

### State snapshots

Every fuzzer run records `StateSnapshot` entries containing the full
system and peer table state. These can be used for:

- **Regression testing:** Replay inputs against a known-good engine
  and compare snapshots to detect regressions.
- **Oracle comparison:** Run the same input through ntpsec's C daemon
  (via `ntpd --g` or a Python oracle script) and compare snapshots.
- **Coverage analysis:** Identify which code paths were exercised.

## State Snapshots

The `StateSnapshot` struct captures:

| Field | Description |
|-------|-------------|
| `packet_index` | Sequence number (0-based) |
| `li_vn_mode` | Raw first byte of the NTP packet |
| `mode` | Decoded NTP mode |
| `leap` | System leap indicator |
| `stratum` | System stratum |
| `sys_offset` | Clock offset estimate (seconds) |
| `sys_jitter` | System jitter (seconds) |
| `sys_frequency` | Frequency drift (PPM) |
| `sys_rootdist` | Root synchronization distance |
| `root_delay` | System root delay |
| `root_dispersion` | System root dispersion |
| `peer_count` | Number of peers |
| `reference_id` | System reference identifier |
| `peer_table` | Per-peer state (associd, stratum, offset, delay, etc.) |
| `action_count` | Number of actions returned by handle() |

## How to Add New Scenarios

### Adding a new packet mode or version

Edit the `EXERCISED_MODES` and `EXERCISED_VERSIONS` constants in
`fuzz/differential/mod.rs`:

```rust
const EXERCISED_MODES: &[NtpMode] = &[
    NtpMode::Reserved,
    NtpMode::SymActive,
    // ... add new modes here
];
```

### Adding a new configuration profile

Create a new engine factory function in `fuzz/differential/mod.rs`:

```rust
pub fn create_engine_with_multiple_peers() -> (DaemonEngine, Vec<NetAddr>) {
    // ...
}
```

Then add a new fuzz target or extend `run_fuzz_input` to accept
a `scenario` parameter.

### Adding extension field or MAC fuzzing

The packet tail (bytes 48+) is appended verbatim to the 48-byte header.
To exercise extension field parsing, add structured fuzzing in
`mutate_packet()` that generates valid TLV extension fields in the tail.

### Comparison with NTPsec oracle

1. Capture a sequence of `StateSnapshot` entries during fuzzing.
2. Export them as JSON or CBOR.
3. Feed the same input packets to `ntpd` (or `ntple` from ntpsec)
   and record equivalent state.
4. Compare the two outputs field-by-field.

The snapshot format is designed to be serializable (all fields are
plain data types) and directly comparable with C ntpsec output.

## File Layout

```
fuzz/
├── Cargo.toml                          # Cargo-fuzz workspace config
├── fuzz_targets/
│   ├── ntp_packet_decode.rs            # Existing: NTP packet decode
│   ├── mode6_decode.rs                 # Existing: mode-6 control decode
│   ├── config_parser.rs                # Existing: config file parser
│   ├── extension_fields.rs             # Existing: extension fields
│   └── differential.rs                 # NEW: differential fuzzer target
├── differential/
│   ├── mod.rs                          # Harness: mutation, engine, invariants
│   ├── INVARIANTS.md                   # Invariant documentation
│   └── README.md                       # This file
├── corpus/
│   ├── ntp_packet_decode/              # Seeds for packet decode
│   ├── differential/                   # NEW: seeds for differential fuzzer
│   └── ...
└── artifacts/
    └── differential/                   # Crash artifacts (auto-created)
```
