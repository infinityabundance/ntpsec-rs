# ntpsec-rs-io

**Real I/O layer — system clock access, network sockets, and persistent state store.**

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). Version 0.3.48.

---

## Overview

`ntpsec-rs-io` is the real-world I/O bridge for the ntpsec-rs ecosystem. It
provides concrete implementations of the trait boundaries defined in
`ntpsec-rs-core`, connecting the deterministic time-discipline engine to the
actual operating system.

The crate implements three core trait interfaces:

| Trait | Implementation | Purpose |
|-------|---------------|---------|
| `SystemClock` | `RealSystemClock` | Read/step/slew the host system clock via POSIX calls |
| `NetworkIo` | `RealNetworkIo` | UDP sockets with kernel hardware timestamps |
| `StateStore` | `FileStateStore` | Persistent drift file, stats, and leap second data |

This separation is deliberate: `ntpsec-rs-core` is pure logic (testable,
deterministic, `no_std`), while `ntpsec-rs-io` is the platform-specific
implementation that makes it work on real hardware.

---

## System Clock — `RealSystemClock`

Wraps the POSIX clock API with NTP-appropriate semantics:

- **`now()`** — Reads `CLOCK_REALTIME` or `CLOCK_MONOTONIC` via `clock_gettime`
  with nanosecond precision. Returns an NTP `l_fp` timestamp.
- **`step(offset)`** — Immediately adjusts the system clock by the given offset
  using `settimeofday` or `clock_settime`. Used for initial clock correction
  (step mode).
- **`slew(offset, frequency)`** — Adjusts the clock gradually using `adjtimex`
  (Linux) or `ntp_adjtime` (BSD). Used for ongoing clock discipline (slew mode).
  Adjusts both the time offset and the tick frequency in one operation.
- **`read_frequency()`** — Reads the current kernel frequency offset (PPM)
  from the `adjtimex`/`ntp_adjtime` status.
- **`set_frequency(freq)`** — Sets the kernel frequency offset (PPM).

### Linux-Specific Features

On Linux, `RealSystemClock` leverages `adjtimex` for fine-grained control:

- `ADJ_OFFSET` — Time offset adjustment (up to ±500 ms in slew mode)
- `ADJ_FREQUENCY` — Tick frequency adjustment (±500 PPM)
- `ADJ_STATUS` / `STA_PLL` — Status flags for PLL/FLL control
- `ADJ_MAXERROR` / `ADJ_ESTERROR` — Clock error estimation
- `ADJ_TAI` — TAI offset for leap second support (≥ Linux 3.10 via
  `clock_adjtime`)

---

## Network I/O — `RealNetworkIo`

Provides UDP socket management with kernel hardware timestamp support for
precise packet timing:

- **`bind(address, port)`** — Creates and binds a UDP socket. On Linux, enables
  `SO_TIMESTAMPING` for hardware and software timestamp generation.
- **`recv()`** — Receives an NTP packet with its receive timestamp. Uses
  `recvmsg` with `SO_TIMESTAMPING` ancillary data to extract the precise arrival
  time from the network interface card or kernel.
- **`send(packet, addr)`** — Transmits an NTP response/request to a remote peer.
- **Polling infrastructure** — `epoll`-based readiness polling with a fallback
  to `select` when `epoll` is unavailable. `get_poll_fds()` and
  `poll_readable(timeout)` provide an async-ready interface for the daemon event
  loop.

### Timestamp Architecture

The `recvmsg_with_timestamp` function extracts receive timestamps from
`SCM_TIMESTAMPING` control messages (Linux), which can provide three
timestamps per packet:

1. **Software timestamp** — kernel software timestamp at the protocol stack
2. **Hardware timestamp** — NIC hardware timestamp when available (requires
   `SOF_TIMESTAMPING_RX_HARDWARE`)
3. **Raw hardware timestamp** — NIC raw timestamp before system clock
   conversion

These timestamps are critical for sub-microsecond NTP synchronization accuracy.

---

## State Store — `FileStateStore`

Persists NTP daemon state to the filesystem in a format compatible with
existing NTPsec monitoring and analysis tools:

- **`load_drift()` / `save_drift(freq)`** — Reads/writes the drift file
  (typically `/var/lib/ntp/ntp.drift`). Stores the current frequency
  offset in PPM so the daemon can recover its frequency estimate across
  restarts.
- **`load_leap()`** — Loads leap second table data from the filesystem.
- **`append_stats(kind, data)`** — Appends statistics records to loopstats,
  peerstats, or clockstats files. These are plain-text, space-delimited files
  consumable by `ntpviz-rs` and standard graphing tools.

Default paths:
- Drift file: `/var/lib/ntp/ntp.drift`
- Stats directory: `/var/log/ntp/`

These can be customized via `FileStateStore::with_drift_path()`.

---

## Connecting Core to System

The relationship between `ntpsec-rs-core` and `ntpsec-rs-io` follows the
**dependency inversion principle**:

```
┌──────────────────────┐     traits      ┌──────────────────────┐
│   ntpsec-rs-core     │ ◄────────────── │    ntpsec-rs-io      │
│                      │                 │                      │
│  DaemonEngine        │  SystemClock    │  RealSystemClock     │
│  ntp_proto           │  NetworkIo      │  RealNetworkIo       │
│  clock filter        │  StateStore     │  FileStateStore      │
│  selection algorithm │                 │                      │
│  discipline          │                 │  (Linux-specific:    │
│  (pure, deterministic)│                │   adjtimex, epoll,   │
│                      │                 │   SO_TIMESTAMPING)   │
└──────────────────────┘                 └──────────────────────┘
```

The daemon binary (`ntpsec-rs-d`) wires them together:

```rust,ignore
use ntpsec_rs_core::daemon_engine::DaemonEngine;
use ntpsec_rs_io::{RealSystemClock, RealNetworkIo, FileStateStore};

let clock = RealSystemClock::new();
let network = RealNetworkIo::new().unwrap();
let store = FileStateStore::new();
let mut engine = DaemonEngine::new();
```

---

## Platform Support

| Feature | Linux | BSD | macOS |
|---------|-------|-----|-------|
| `clock_gettime` | ✅ | ✅ | ✅ |
| `adjtimex` | ✅ | `ntp_adjtime` | ❌ |
| `settimeofday` | ✅ | ✅ | ✅ |
| `SO_TIMESTAMPING` | ✅ | ❌ | ❌ |
| `epoll` | ✅ | ❌ (`kqueue`) | ❌ (`kqueue`) |
| Capabilities | ✅ | ❌ | ❌ |
| seccomp | ✅ | ❌ | ❌ |

> **Note:** Linux-specific features (kernel timestamps, epoll, adjtimex,
> capabilities, seccomp) are the primary target. Other platforms use POSIX
> fallbacks.

---

## Test Coverage

The crate includes integration-style tests that exercise the real I/O stack:

- **`test_system_clock_now`** — Verifies `RealSystemClock::now()` returns a
  reasonable current timestamp.
- **`test_system_clock_frequency`** — Tests reading kernel frequency offset.
- **`test_state_store`** — Tests drift file read/write roundtrip.
- **`test_netaddr_conversion_roundtrip`** — Tests socket address <-> NTP
  network address conversion.
- **`test_real_loopback_kernel_timestamp`** — Tests kernel timestamp generation
  on loopback (requires appropriate privileges).

---

## Usage

```toml
[dependencies]
ntpsec-rs-io = "0.3"
```

### Example: Read System Clock

```rust,ignore
use ntpsec_rs_io::RealSystemClock;
use ntpsec_rs_core::ntp_io::SystemClock;

let clock = RealSystemClock::new();
let now = clock.now();
println!("Current time (NTP l_fp): {}", now);
```

### Example: Open a UDP Socket

```rust,ignore
use ntpsec_rs_io::RealNetworkIo;
use ntpsec_rs_core::ntp_io::NetworkIo;

let mut net = RealNetworkIo::new().unwrap();
net.bind("0.0.0.0", 123).unwrap();
let (packet, sender, recv_ts) = net.recv().unwrap();
```

### Example: Save Drift

```rust,ignore
use ntpsec_rs_io::FileStateStore;
use ntpsec_rs_core::ntp_io::StateStore;

let store = FileStateStore::new();
store.save_drift(2.345).unwrap(); // Save +2.345 PPM drift
```

---

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
