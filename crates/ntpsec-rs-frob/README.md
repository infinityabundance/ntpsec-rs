# ntpsec-rs-frob

[![crates.io](https://img.shields.io/crates/v/ntpsec-rs-frob.svg)](https://crates.io/crates/ntpsec-rs-frob)
[![Documentation](https://img.shields.io/docsrs/ntpsec-rs-frob)](https://docs.rs/ntpsec-rs-frob)
[![License](https://img.shields.io/crates/l/ntpsec-rs-frob.svg)](https://crates.io/crates/ntpsec-rs-frob)

**ntpfrob-rs** — NTP system utility toolkit for the ntpsec-rs workspace. Provides direct
access to kernel timekeeping operations via `adjtimex` system calls — measuring precision,
assessing jitter, inspecting clock status, and making microsecond-level adjustments to the
system clock.

Equivalent to NTPsec's `ntpfrob` (C, 6 files across the `ntpfrob/` directory).

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). v0.3.48.

---

## Overview

`ntpfrob-rs` brings together a collection of low-level system clock diagnostics and
manipulation commands. These operations, traditionally implemented in C using `adjtimex(2)`
and other Linux system calls, are now available in safe Rust:

| Subcommand | Description |
|------------|-------------|
| `status` | Show kernel clock status via adjtimex (default) |
| `precision` | Measure and display system clock precision |
| `jitter` | Measure clock jitter over 100 consecutive samples |
| `dump` | Hex dump an NTP packet from stdin |
| `bumpclock` | Advance the system clock by 1 millisecond |
| `tickadj` | Get or set the kernel tick value (microseconds) |
| `ppsapi` | Test PPS API availability via `/dev/pps0` |

### Oracle

```
ntpsec ntpfrob/ (6 C source files: ntpfrob.c, jitter.c, precision.c, ...)
```

---

## Usage

### Show kernel clock status

```sh
ntpfrob-rs status
```

Displays the full kernel timekeeping state from `adjtimex(2)`:

```
Kernel clock status:
  return code: 0 (OK (TIME_OK))
  offset:      42 ns
  frequency:   11.423 ppm (748568 raw)
  maxerror:    156 us
  esterror:    156 us
  status:      0x2001 (PLL,NANO)
  constant:    10
  precision:   1 us (log2 ≈ 0)
  tolerance:   500.000 ppm
  tick:        10000 us
  TAI offset:  37
```

### Measure precision

```sh
ntpfrob-rs precision
```

```
System precision: 1 us (log2 ≈ 0)
```

### Measure clock jitter

```sh
ntpfrob-rs jitter
```

```
Measuring clock jitter (100 samples)...
  min: 42 ns
  max: 1853 ns
  mean: 64 ns
  estimated jitter: 1811 ns
```

### Dump an NTP packet

```sh
ntpfrob-rs dump < /tmp/ntp-packet.bin
```

```
Read 48 bytes:
0000  24 00 04 fa 00 00 00 00  00 00 00 4b 00 00 00 00  $..........K....
0010  d2 f8 00 00 00 00 00 00  d2 f8 07 47 00 00 00 00  ...........G....
0020  d2 f8 07 47 00 00 00 00  d2 f8 07 48 49 a5 e4 01  ...G.......HI...
```

### Bump clock forward by 1ms

```sh
sudo ntpfrob-rs bumpclock
```

```
Clock bumped forward by 1 ms
```

### Get/set tick adjustment

```sh
# Get current tick
ntpfrob-rs tickadj

# Set tick to 10000 microseconds
sudo ntpfrob-rs tickadj 10000
```

### Test PPS API

```sh
ntpfrob-rs ppsapi
```

```
PPS API test: opening /dev/pps0...
  /dev/pps0: No such file or directory (PPS not available)
```

---

## Related Crates

All crates in the ntpsec-rs workspace on crates.io:

- [ntpsec-rs-core](https://crates.io/crates/ntpsec-rs-core) — deterministic engine, wire codec, Mode 6 control, authentication, refclocks, NTS
- [ntpsec-rs-io](https://crates.io/crates/ntpsec-rs-io) — real I/O layer (system clock, network, state store)
- [ntpsec-rs](https://crates.io/crates/ntpsec-rs) — umbrella facade crate
- [ntpsec-rs-d](https://crates.io/crates/ntpsec-rs-d) — ntpd-rs daemon binary
- [ntpsec-rs-query](https://crates.io/crates/ntpsec-rs-query) — ntpq-rs query client
- [ntpsec-rs-dig](https://crates.io/crates/ntpsec-rs-dig) — ntpdig-rs query tool
- [ntpsec-rs-keygen](https://crates.io/crates/ntpsec-rs-keygen) — NTP key generation
- [ntpsec-rs-leapfetch](https://crates.io/crates/ntpsec-rs-leapfetch) — leap second file fetcher
- [ntpsec-rs-mon](https://crates.io/crates/ntpsec-rs-mon) — monitoring tool
- [ntpsec-rs-trace](https://crates.io/crates/ntpsec-rs-trace) — NTP trace tool
- [ntpsec-rs-wait](https://crates.io/crates/ntpsec-rs-wait) — NTP wait tool
- [ntpsec-rs-viz](https://crates.io/crates/ntpsec-rs-viz) — NTP visualization
- [ntpsec-rs-frob](https://crates.io/crates/ntpsec-rs-frob) — NTP system utilities
- [ntpsec-rs-snmpd](https://crates.io/crates/ntpsec-rs-snmpd) — SNMP monitoring daemon
- [ntpsec-rs-time](https://crates.io/crates/ntpsec-rs-time) — kernel time management
- [ntpsec-rs-sweep](https://crates.io/crates/ntpsec-rs-sweep) — NTP sweep tool
- [ntpsec-rs-loggps](https://crates.io/crates/ntpsec-rs-loggps) — GPS logging
- [ntpsec-rs-logtemp](https://crates.io/crates/ntpsec-rs-logtemp) — temperature logging

## GitHub Repository

[https://github.com/infinityabundance/ntpsec-rs](https://github.com/infinityabundance/ntpsec-rs)
