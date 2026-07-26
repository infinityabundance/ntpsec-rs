# ntpsec-rs-time

[![crates.io](https://img.shields.io/crates/v/ntpsec-rs-time.svg)](https://crates.io/crates/ntpsec-rs-time)
[![Documentation](https://img.shields.io/docsrs/ntpsec-rs-time)](https://docs.rs/ntpsec-rs-time)
[![License](https://img.shields.io/crates/l/ntpsec-rs-time.svg)](https://crates.io/crates/ntpsec-rs-time)

**ntptime-rs** — Kernel time management tool for the ntpsec-rs workspace. Reads and displays
the system clock's kernel timekeeping state via the `adjtimex(2)` / `ntp_adjtime()` system
call, showing precision, offset, frequency error, jitter, status flags, TAI offset, and more.

Equivalent to NTPsec's `ntptime` (C, ~13K).

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). v0.3.48.

---

## Overview

The Linux kernel maintains a rich set of timekeeping state accessible via the `adjtimex(2)`
system call. This state is used by the NTP daemon's discipline loop to steer the system
clock. `ntptime-rs` provides a human-readable view of this state, including:

| Field | Description |
|-------|-------------|
| **Time** | Current system time (hex NTP format + ISO 8601) |
| **Return code** | Clock status: OK, INS, DEL, OOP, WAIT, or ERROR |
| **Maximum error** | Upper bound on clock error (microseconds) |
| **Estimated error** | Current estimated clock error (microseconds) |
| **TAI offset** | Current TAI - UTC offset (seconds), 0 if not set |
| **Status flags** | PLL/FLL mode, PPS state, nano vs micro, unsync, etc. |
| **PLL offset** | Phase-locked loop correction (ns or us) |
| **Frequency** | Clock frequency error (ppm) |
| **Maximum jitter** | Observed clock jitter |
| **Interval** | PLL/FLL time constant |
| **Sanity** | PASS if TIME_OK, FAIL otherwise |

In verbose mode (`-v`), it also displays the complete `ntp_adjtime()` output including
raw frequency, PPS frequency, shift, stability, and all counter values.

### Oracle

```
ntpsec ntptime/ntptime.c (C, 13K)
```

---

## Usage

### Basic output

```sh
ntptime-rs
```

```
ntp_gettime() returns code 0 (OK)
  time e5f5a2a0.0bb15908  2026-07-26T12:34:56.045
  maximum error 156 us, estimated error 156 us
  TAI offset: 37
  status: 0x2001 (PLL,NANO)
  pll offset: 42 ns, frequency: 11.423 ppm, maximum jitter: 2 us
  interval: 10 s, sanity: PASS
```

This shows an NTP-synchronized clock with nanosecond resolution, a TAI offset of 37
seconds, frequency error of ~11.4 ppm, and the PLL actively steering.

### Verbose output

```sh
ntptime-rs -v
```

Displays the standard ntp_gettime() output followed by the full ntp_adjtime() state:

```
ntp_gettime() returns code 0 (OK)
  ... (standard fields) ...

ntp_adjtime() returns code 0 (OK)
  mode: 0x0 (none)
  offset: 42, freq: 748568, maxerror: 156, esterror: 156
  status: 0x2001, constant: 10, precision: 1
  tolerance: 500.000 ppm, ppsfrequency: 0, jitter: 2856
  shift: 0, stabil: 0, jitcnt: 12, calcnt: 1047, errcnt: 0, stbcnt: 0
```

### Interpreting the output

**Clock synchronized (`TIME_OK`, sanity PASS):**
The daemon is disciplined and the clock is reliable. Low offset and frequency
indicate good synchronization quality.

**Clock unsynchronized (`TIME_ERROR`, sanity FAIL):**
The daemon has lost contact with all NTP servers, or the clock was never
synchronized. The `UNSYNC` status flag will be set.

**Leap second pending (`TIME_INS` or `TIME_DEL`):**
A leap second event is scheduled. The daemon has been notified via the
leap-seconds file and will handle insertion or deletion automatically.

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
