# ntpsec-rs-core

**Deterministic time-discipline engine — wire codec, Mode 6 control protocol, authentication, reference clocks, and Network Time Security (NTS).**

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). Version 0.3.48.

---

## Overview

`ntpsec-rs-core` is the deterministic, side-effect-free brain of the ntpsec-rs
ecosystem. It contains the re-implemented logic of every NTPsec C translation
unit that can be reasoned about **without** touching a real clock, real network
sockets, or a real filesystem. Host mutation lives behind trait boundaries in
`ntpsec-rs-io`; the core stays pure.

This crate is designed to be usable in `no_std` environments, making it
suitable for embedded systems, bootloaders, and other constrained contexts
where the full I/O stack is unavailable.

### Architecture

The crate is organized as a forensic reconstruction of the NTPsec C codebase,
developed through a rigorous multi-phase methodology:

1. **Deep Doxygen indexing** of the NTPsec oracle to extract every function
   signature, type definition, constant, and macro.
2. **Deterministic trace replay** — captured NTPsec packet receipts are
   replayed through the Rust code and outputs are compared byte-for-byte.
3. **Protocol-spec cross-check** — NTP RFCs (RFC 5905, 5906, 5907, 5908, 7821,
   7822, 8573, NTS RFC 8915) and NIST known-answer tests classify where NTPsec
   policy differs from generic protocol truth.
4. **Court-backed evidence** — every admitted behavior links to a reproducible
   court case in `docs/courts/`.

## Module Organization

The crate exports 60+ public modules, each mapping to a corresponding NTPsec C
translation unit:

### Core Protocol (`ntp_proto`, `daemon_engine`)
- **`daemon_engine`** — Top-level deterministic engine: peer management, pool
  state, NTS-KE jobs, DNS resolution, refclock driver lifecycle. Central type:
  `DaemonEngine`.
- **`ntp_proto`** — NTP on-wire protocol logic: packet validation, mode
  dispatch, origin timestamp checks, duplicate detection, KoD handling.

### Wire Codec (`ntp_fp`, `ntp_types`, `ntp_endian`, `binio`, `ieee754io`)
- **`ntp_fp`** — NTP fixed-point timestamp arithmetic (LFP/UFP conversion,
  add/sub, comparison).
- **`ntp_types`** — Core type definitions: `l_fp`, `s_fp`, `NtpVersion`,
  `NtpLeap`, `NtpMode`, `NtpStratum`.
- **`ntp_endian`** — Network-byte-order encoding/decoding.
- **`binio`** — Binary I/O primitives for wire format.
- **`ieee754io`** — IEEE 754 double-precision floating-point wire encoding
  used in NTPv4 extension fields.

### Mode 6 Control Protocol (`ntp_control`, `control_client`)
- **`ntp_control`** — Mode 6 packet construction, parsing, and system/peer
  variable encoding. Implements the full NTP control message protocol.
- **`control_client`** — High-level Mode 6 query client: `read_system_vars`,
  `read_peer_vars`, `read_associations`, `read_mru_list`. Used by
  `ntpsec-rs-query`, `ntpsec-rs-mon`, `ntpsec-rs-trace`.

### Authentication (`ntp_auth`)
- Symmetric key authentication with MD5, SHA-1, SHA-256/384/512, and AES-CMAC.
- Key ID management, key lookup, packet authentication code computation and
  verification.
- Parse and serialize `ntp.keys`-format key files.

### NTS — Network Time Security (`nts`, `nts_client`, `nts_cookie`, `nts_extens`, `nts_server`)
- **`nts`** — NTS constants, parameter types, cookie structures.
- **`nts_client`** — NTS client-side logic: NTS-KE handshake, cookie
  management, server negotiation.
- **`nts_cookie`** — NTS cookie encoding/decoding, AES-SIV encryption.
- **`nts_extens`** — NTS extension field encoding: authenticator, cookie,
  cookie-placeholder, unique-identifier, NTS Auth Result.
- **`nts_server`** — NTS server-side logic: cookie decryption, NTS-KE
  response generation.

### Reference Clock Framework (`ntp_refclock`, `refclock_*`)
- **`ntp_refclock`** — Abstract refclock driver interface and parser
  infrastructure.
- **`refclock_generic`** — Generic refclock driver framework (mode 1).
- **`refclock_gpsd`** — GPSD refclock driver.
- **`refclock_nmea`** — NMEA 0183 GPS sentence parser.
- **`refclock_pps`**, **`refclock_pps_api`** — Pulse-per-second drivers.
- **`refclock_shm`** — Shared-memory SHM refclock driver.
- **`refclock_local`** — Local clock driver (undisciplined).
- **`refclock_arbiter`** — Arbiter GPS refclock.
- **`refclock_hpgps`** — HP GPS reference clock.
- **`refclock_jjy`** — JJY (Japan) refclock.
- **`refclock_modem`** — Modem/automodem refclock.
- **`refclock_oncore`** — Motorola Oncore GPS.
- **`refclock_spectracom`** — Spectracom refclock.
- **`refclock_trimble`** — Trimble GPS refclock.
- **`refclock_truetime`** — TrueTime GPS refclock.
- **`refclock_zyfer`** — Zyfer refclock.

### Clock Filter, Selection, and Discipline
- **`ntp_loopfilter`** — Clock discipline algorithm: phase-locked loop (PLL)
  and frequency-locked loop (FLL) control, drift compensation, frequency
  estimation.
- **`ntp_peer`** — Peer data structures, reachability register, peer timer
  management, clock filter.
- **`ntp_proto`** includes the selection algorithm (clock cluster) and
  combining (weighted average of surviving peers).

### Supporting Infrastructure
- **`ntp_calendar`** — Calendar date/time arithmetic, Julian date conversion.
- **`ntp_leapsec`** — Leap second table management, file parsing, TAI-GPS
  offset table.
- **`ntp_timer`** — Event timer management.
- **`ntp_config`** — Configuration parsing infrastructure.
- **`ntp_scanner`** — Configuration file lexical scanner.
- **`ntp_dns`** — DNS resolution data structures.
- **`ntp_restrict`** — Access restriction list.
- **`ntp_monitor`** — MRU (Most Recently Used) list for traffic monitoring.
- **`ntp_lists`** — Linked list data structures.
- **`ntp_sandbox`** — Sandbox/seccomp configuration data.
- **`ntp_signd`** — MS-SNTP signed association support.
- **`ntp_util`** — Utility functions.
- **`ntp_io`** — Abstract I/O interface definitions (trait boundaries).
- **`ntp_malloc`** — Memory allocation wrappers.
- **`ntp_syscall`** — System call abstractions (trait boundaries).
- **`ntp_syslog`** — Syslog message formatting.
- **`ntp_debug`** — Debug/trace output.
- **`ntp_assert`** — Assertion macros.
- **`ntp_packetstamp`** — Packet timestamp structures.
- **`ntp_recvbuff`** — Receive buffer management.
- **`ntp_net`** — Network address type definitions: `sockaddr_u`, `netaddr_t`,
  `is_any`, `is_multicast`.
- **`ntp_filegen`** — File generation / statistics file management.
- **`gpstolfp`** — GPS-to-LFP time conversion.
- **`timespecops`** — Timespec arithmetic operations.
- **`parse`** — Generic parse module for configuration and driver parsing.
- **`ntpdig_proto`** — Client query protocol (mode 3) used by
  `ntpsec-rs-dig`.
- **`leap_query`** — Leap second file query protocol.

## `no_std` Compatibility

The crate is designed from the ground up for `no_std` compatibility. All
protocol logic, wire encoding/decoding, timestamp arithmetic, authentication,
and clock discipline algorithms use only `core` and `libm` where floating-point
is needed. The standard library is required only for test infrastructure and
feature-gated I/O trait definitions.

To use without the standard library:

```toml
[dependencies]
ntpsec-rs-core = { version = "0.3", default-features = false }
```

> **Note:** Currently there are no Cargo feature flags; `no_std` readiness is
> structural. Feature flags for explicit `no_std` selection will be added in a
> future release.

## Test Coverage

The crate includes **769+ tests** (0 failing), covering:

- Wire format encoding/decoding roundtrips
- Authentication tag computation and verification (all digest types)
- Mode 6 control message parse/serialize
- Clock filter add/sort/select
- NTP timestamp arithmetic edge cases (wraparound, overflow)
- NTS cookie encrypt/decrypt
- Reference clock driver parsers
- Selection algorithm with known-answer test vectors
- Clock discipline PLL/FLL step response
- Leap second table file parsing

Tests use deterministic inputs and are suitable for `cargo test` without
external dependencies.

## Usage

Add `ntpsec-rs-core` to your `Cargo.toml`:

```toml
[dependencies]
ntpsec-rs-core = "0.3"
```

### Example: Creating an Engine and Processing a Packet

```rust
use ntpsec_rs_core::{
    daemon_engine::DaemonEngine,
    ntp_types::{NtpTimestamp, NtpMode},
    ntp_recvbuff::RecvBuffer,
};

// Create a deterministic engine with default configuration.
// The DaemonEngine operates on the "court principle" — every mutation
// of system state is tracked and can be reproduced for verification.
let mut engine = DaemonEngine::new();

// Simulate receiving an NTP mode 4 (server) packet.
// In a real deployment, this buffer would come from a UDP socket read
// via ntpsec-rs-io.
let packet_data: Vec<u8> = vec![
    0x24, 0x01, 0x02, 0x03,  // LI=0, VN=4, Mode=4, Stratum=2
    // ... full packet would follow
];

let recv_buf = RecvBuffer::from_bytes(&packet_data);

// Process the packet through the engine.
// The engine handles: authentication verification, clock filter insertion,
// selection, combining, and clock discipline — all without touching the
// host clock or network.
engine.process_packet(recv_buf);

// After processing, query the engine for current system state.
let sysvars = engine.system_variables();
println!("Stratum: {}, Offset: {:?}", sysvars.stratum(), sysvars.offset());
```

## Further Reading

- **[Architecture documentation](../../docs/architecture.md)** — Full system
  architecture overview.
- **[Ported modules document](../../docs/ntpsec-code-archaeology-atlas.md)** —
  Mapping of ntpsec C modules to Rust modules.
- **[Methodology](../../docs/methodology.md)** — Forensic reconstruction
  methodology and court process.
- **[Replacement contract](https://github.com/infinityabundance/ntpsec-rs/blob/main/docs/replacement-contract.md)** —
  Formal specification of NTPsec behavioral equivalence.

## License

Licensed under either of [MIT](https://opensource.org/license/mit/) or
[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) at your option.

## Related Crates

All crates in the ntpsec-rs workspace on crates.io:

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [ntpsec-rs-core](https://crates.io/crates/ntpsec-rs-core) | Deterministic engine, wire codec, Mode 6, auth, refclocks, NTS | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-core.svg)](https://crates.io/crates/ntpsec-rs-core) |
| [ntpsec-rs-io](https://crates.io/crates/ntpsec-rs-io) | Real I/O layer (system clock, network, state store) | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-io.svg)](https://crates.io/crates/ntpsec-rs-io) |
| [ntpsec-rs](https://crates.io/crates/ntpsec-rs) | Umbrella facade crate | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs.svg)](https://crates.io/crates/ntpsec-rs) |
| [ntpsec-rs-d](https://crates.io/crates/ntpsec-rs-d) | ntpd-rs — NTP daemon binary | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-d.svg)](https://crates.io/crates/ntpsec-rs-d) |
| [ntpsec-rs-query](https://crates.io/crates/ntpsec-rs-query) | ntpq-rs — Mode 6 query client | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-query.svg)](https://crates.io/crates/ntpsec-rs-query) |
| [ntpsec-rs-dig](https://crates.io/crates/ntpsec-rs-dig) | ntpdig-rs — NTP query tool | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-dig.svg)](https://crates.io/crates/ntpsec-rs-dig) |
| [ntpsec-rs-keygen](https://crates.io/crates/ntpsec-rs-keygen) | NTP key generation | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-keygen.svg)](https://crates.io/crates/ntpsec-rs-keygen) |
| [ntpsec-rs-leapfetch](https://crates.io/crates/ntpsec-rs-leapfetch) | Leap second file fetcher | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-leapfetch.svg)](https://crates.io/crates/ntpsec-rs-leapfetch) |
| [ntpsec-rs-mon](https://crates.io/crates/ntpsec-rs-mon) | Real-time NTP monitoring tool | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-mon.svg)](https://crates.io/crates/ntpsec-rs-mon) |
| [ntpsec-rs-trace](https://crates.io/crates/ntpsec-rs-trace) | NTP path trace tool | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-trace.svg)](https://crates.io/crates/ntpsec-rs-trace) |
| [ntpsec-rs-wait](https://crates.io/crates/ntpsec-rs-wait) | Wait until NTP server reachable | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-wait.svg)](https://crates.io/crates/ntpsec-rs-wait) |
| [ntpsec-rs-viz](https://crates.io/crates/ntpsec-rs-viz) | NTP data visualization | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-viz.svg)](https://crates.io/crates/ntpsec-rs-viz) |
| [ntpsec-rs-frob](https://crates.io/crates/ntpsec-rs-frob) | NTP configuration manipulator | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-frob.svg)](https://crates.io/crates/ntpsec-rs-frob) |
| [ntpsec-rs-snmpd](https://crates.io/crates/ntpsec-rs-snmpd) | SNMP monitoring daemon | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-snmpd.svg)](https://crates.io/crates/ntpsec-rs-snmpd) |
| [ntpsec-rs-time](https://crates.io/crates/ntpsec-rs-time) | Single-shot time query tool | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-time.svg)](https://crates.io/crates/ntpsec-rs-time) |
| [ntpsec-rs-sweep](https://crates.io/crates/ntpsec-rs-sweep) | Sweep through servers collecting stats | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-sweep.svg)](https://crates.io/crates/ntpsec-rs-sweep) |
| [ntpsec-rs-loggps](https://crates.io/crates/ntpsec-rs-loggps) | GPS reference clock logging | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-loggps.svg)](https://crates.io/crates/ntpsec-rs-loggps) |
| [ntpsec-rs-logtemp](https://crates.io/crates/ntpsec-rs-logtemp) | System temperature logging | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-logtemp.svg)](https://crates.io/crates/ntpsec-rs-logtemp) |

## GitHub Repository

[https://github.com/infinityabundance/ntpsec-rs](https://github.com/infinityabundance/ntpsec-rs)
