# Differential Fuzzing Invariants

This document describes all invariants checked by the differential fuzzer,
why they matter, and how to add new ones.

## Checked Invariants

### 1. No NaN or Inf in floating-point values

**Checked fields:**
- `system.sys_offset` — clock offset estimate
- `system.sys_jitter` — system jitter
- `system.sys_frequency` — frequency drift (PPM)
- `system.sys_rootdist` — root synchronization distance
- `system.root_delay` — system root delay
- `system.root_dispersion` — system root dispersion
- `peers[i].offset` — per-peer offset
- `peers[i].delay` — per-peer round-trip delay
- `peers[i].dispersion` — per-peer dispersion
- `peers[i].jitter` — per-peer jitter
- `peers[i].selection_jitter` — selection jitter (φ_λ)
- `peers[i].root_delay` — peer's root delay
- `peers[i].root_dispersion` — peer's root dispersion

**Why it matters:** NaN/Inf in any computed value can propagate silently
through clock discipline and timekeeping. NTP is a numerical algorithm;
IEEE 754 special values represent undefined or divergent behavior that
indicates a logic bug (e.g., 0/0, overflow, or missing guard against
degenerate input).

### 2. Stratum stays in valid range [0, 16]

**Checked fields:**
- `system.stratum`
- `peers[i].stratum`

**Valid range:** `0` (unspecified) through `16` (unsynchronized).
Values `1–15` indicate a synchronized clock at the given distance
from the reference.

**Why it matters:** Stratum > 16 (or overflow to 0 via wrap) causes
comparison bugs in clock selection, allows unsynchronized peers to
be selected as system peer, or causes out-of-bounds panic if used
as an array index. NTPsec defines `NTP_MAXSTRAT = 16` in `ntp_proto.rs`.

### 3. Leap indicator stays in valid range [0, 3]

**Checked fields:**
- `system.leap`
- `peers[i].leap`

**Valid values:**
| Value | Meaning |
|-------|---------|
| 0     | No warning |
| 1     | Add leap second (last minute has 61 seconds) |
| 2     | Remove leap second (last minute has 59 seconds) |
| 3     | Alarm (clock not synchronized) |

**Why it matters:** Leap is a 2-bit field. Values outside [0, 3] indicate
memory corruption, bit-shift bugs, or invalid enum construction. An
invalid leap can cause downstream code to emit malformed NTP packets
or misbehave in leap-second processing.

### 4. Peer table doesn't grow unbounded

**Threshold:** `MAX_PEERS = 128`

**Why it matters:** The peer table should be bounded by the configured
`maxclock` (default 14 in NTPsec). Unbounded growth indicates a memory
leak — typically an ephemeral association being created on every packet
but never cleaned up. This invariant catches the "ephemeral sympassive
self-DoS" class of bugs.

### 5. No duplicate association IDs

**Checked:** All `peers[i].associd` values are unique.

**Why it matters:** Duplicate association IDs cause undefined behavior
in lookup logic (`find_peer_by_associd`), timer dispatch, and mode-6
control responses. The allocator uses a monotonically increasing `u16`
and wraps at `u16::MAX` — but if a bug causes reuse or the allocator
fails to skip occupied IDs, duplicates appear.

### 6. No panic/unwinding during `engine.handle()`

Panics are caught with `std::panic::catch_unwind` at the fuzzer
boundary and reported as violations.

**Why it matters:** NTP daemons must be crash-resistant. A remotely-
triggerable panic is a denial-of-service vulnerability. Every panic
detected by fuzzing must be fixed or converted to a logged error.

## How to Add a New Invariant

1. **Add the check function** in `fuzz/differential/mod.rs` inside the
   `check_invariants()` function or as a new helper.

   ```rust
   // Inside check_invariants():
   if engine.system.sys_status == 0xDEAD {
       return Err("sys_status is DEAD".to_string());
   }
   ```

2. **If it checks a new floating-point field**, add a `check_finite()` call:

   ```rust
   check_finite("system.sys_wander", engine.system.sys_wander)?;
   ```

3. **If it requires new fields in the snapshot**, extend `StateSnapshot`
   and `take_snapshot()` in the same file.

4. **Tests:** Add a regression test in the `differential` module that
   constructs a known-bad engine state and asserts the invariant catches it.

   ```rust
   #[test]
   fn test_invariant_catches_bad_stratum() {
       let (mut engine, _) = create_minimal_engine();
       engine.system.stratum = 255;
       assert!(check_invariants(&engine).is_err());
   }
   ```

5. **Document it:** Add a row to this file describing what the invariant
   checks, which fields it covers, and why it matters.

## Design Principles

- **Fail closed:** If an invariant cannot be evaluated (e.g., a field is
  corrupted), it should return an error rather than silently passing.
- **Deterministic:** Invariants must be pure functions of engine state.
  No randomness, no I/O.
- **Cheap to compute:** Invariant checking happens on every fuzzer
  iteration. Avoid O(n²) or allocation-heavy checks where possible.
  The dup-associd check is O(p) in peer count and uses a small `HashSet`.
- **Actionable messages:** Every violation includes the actual value
  and the field name so it can be immediately triaged.
