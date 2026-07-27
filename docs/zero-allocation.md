# Zero-Allocation Hot-Path Strategy

This document describes the zero-allocation strategy for the ntpsec-rs daemon
hot path — the code path that handles every received NTP packet.

## Motivation

Each received NTP packet generates a response. On a busy NTP server handling
thousands of packets per second, heap allocations on the hot path cause:

1. **Memory fragmentation**: Repeated `Vec` allocations fragment the heap,
   degrading performance over time.
2. **Cache misses**: Heap-allocated data has poor cache locality compared
   to stack-allocated data.
3. **GC/allocator pressure**: Even with a modern allocator (jemalloc, mimalloc),
   allocation has overhead (lock contention, TLS access).
4. **Determinism**: Heap allocation failures are hard to model in proofs.
   A zero-allocation hot path is easier to verify with Kani.

## Target Hot Path

The critical hot path for an NTP server is:

```
UDP socket recv()
    ↓
ReceivedDatagram construction
    ↓
handle_packet()         ← allocates Vec<DaemonAction>, Vec<u8> for responses
    ├── handle_control() ← allocates heavily (String, Vec)
    └── handle_server_response()
    ↓
DaemonAction::Send { bytes }
    ↓
UDP socket send()
```

## Allocations Removed

### 1. ReceivedDatagram (Input Buffer)

**Before**: `bytes: Vec<u8>`
**After**: `bytes: [u8; NTP_MAX_PACKET_SIZE]` + `len: usize`

The I/O layer writes directly into the fixed-size buffer, eliminating the
per-packet heap allocation. `NTP_MAX_PACKET_SIZE = 512` bytes fits on the
stack and covers the largest valid NTP packet (RFC 5905).

**Impact**: ~512 bytes per packet eliminated from heap allocation.

### 2. Packet Encoding (Output Buffer)

**Before**: `resp.encode_header().to_vec()` + `bytes.extend_from_slice(&mac)`
**After**: `resp.encode_with_mac(mac)` — single pre-allocated `Vec`

Added `NtpPacket::encode_with_mac()` that pre-allocates the exact capacity
needed (48 bytes + optional MAC), avoiding the double-allocation pattern.

**Impact**: Reduces from 2 allocations to 1 per response packet.

### 3. Test Boundary

**Before**: `ReceivedDatagram::test(bytes: Vec<u8>, ...)`
**After**: `ReceivedDatagram::test(bytes: impl AsRef<[u8]>, ...)`

Tests no longer need to create a `Vec` just to construct a test datagram.
They can pass `&[u8]` or `&[u8; 48]` directly.

**Impact**: Eliminates test-only allocations that could distort benchmarks.

## Remaining Allocations (Acceptable)

### DaemonAction::Send { bytes: Vec<u8> }

The `Send` action must own a `Vec<u8>` because:
- Response packets have variable size (48-byte header + optional MAC)
- The I/O layer takes ownership of the bytes for async send
- The alternative (copying into a fixed buffer per send) wastes stack space

**Acceptable**: This is a single allocation per response, and the response
is sent immediately (the Vec is consumed by the I/O layer).

### handle_control() — Mode 6

Mode 6 control protocol responses are complex (variable lists, formatted
strings). Eliminating all allocations here would require:
- Replacing `String` formatting with fixed buffers and `write!` formatting
- Pre-calculating response sizes for static allocation
- Using `arrayvec` or `heapless` for bounded collections

This is lower priority because Mode 6 (ntpq) requests are infrequent
compared to NTP time queries (Mode 3/4).

### String formatting in Log actions

`DaemonAction::Log(String)` is used for diagnostic messages. These are
allocated and immediately consumed by the event loop. Not on the critical
timing path.

## Future Work

1. **Replace `Vec<ExtensionField>` with fixed array**: `split_packet_tail()`
   returns a `Vec<ExtensionField>`. Since NTP packets have at most a few
   extension fields, this could be a fixed-size array `[Option<ExtensionField>; 8]`.

2. **Static control response buffers**: Mode 6 response data could be written
   directly into a pre-allocated buffer instead of building a `String` then
   converting to bytes.

3. **`heapless::Vec` for bounded collections**: Use `heapless::Vec<T, N>` for
   collections with known maximum sizes (peer list, clock filter entries).

4. **Pool allocator for response buffers**: Re-use `[u8; NTP_MAX_PACKET_SIZE]`
   buffers for outgoing packets, similar to `RecvBufPool` for incoming packets.

## Verification

### Compile-time checks

The `#![forbid(unsafe_code)]` in hot-path modules (where feasible) ensures
no hidden allocations through `unsafe` code.

### Runtime checks

```bash
# Check for heap allocations in the hot path
cargo build --release --features debug-allocations

# Run with valgrind to measure heap usage
valgrind --tool=massif --massif-out-file=massif.out ./target/release/ntpd-rs -c test.conf
ms_print massif.out | head -40
```

### CI

A CI script `ci/check-allocations.sh` runs the test suite with `--release`
and checks that the hot-path modules don't perform unexpected allocations
using `#[cfg(debug_assertions)]` instrumentation.

## Summary

| Allocation Site | Status | Technique |
|-----------------|--------|-----------|
| `ReceivedDatagram.bytes` | ✅ Fixed | `[u8; 512]` stack buffer |
| `encode_header().to_vec()` | ✅ Fixed | `encode_with_mac()` pre-allocation |
| `DaemonAction::Send { bytes }` | ⚠️ Remaining | Single allocation, immediately consumed |
| `split_packet_tail` ext fields | ❌ Future | Fixed-size array |
| Mode 6 control responses | ❌ Future | Static buffers |
| Log messages | ❌ Acceptable | Deferred |
