# ntpsec-rs-trace — ntptrace-rs

**NTP path trace tool — traces the synchronization chain from a host to the reference clock.**

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). Version 0.3.48.

---

## Overview

`ntptrace-rs` traces the NTP synchronization chain from a given host back to
the ultimate reference clock (stratum 0/1 source). It recursively queries
each hop's system peer, following the `sys.peer` chain and reporting stratum,
offset, and delay at each step.

This is a forensic Rust reconstruction of the NTPsec `ntptrace` Python client.

### How It Works

1. **Query the starting host** for its system variables via Mode 6.
2. **Extract the system peer** (`syspeer` association ID) and that peer's
   address.
3. **Display the hop** — host, refid, stratum, offset, delay.
4. **Follow the chain** — If the peer has a lower stratum, recursively query
   it.
5. **Stop when** — The reference clock (stratum 0/1) is reached, the host is
   unsynchronized (stratum ≥ 15), or the maximum depth is exceeded.

---

## Usage

### Basic Trace

```bash
ntptrace-rs
```

Traces from the local host (`127.0.0.1`):

```
ntptrace-rs v0.3.48 — NTP trace tool (Rust)
Tracing from: 127.0.0.1 (max depth: 10)

          host           refid  st      offset       delay
------------------------------------------------------------
     127.0.0.1      203.0.113.1   3    0.000456   0.012345
   ntp.example.com          GPS   2    0.000321   0.014567
```

### Trace from a Specific Host

```bash
ntptrace-rs ntp.example.com
```

### Custom Maximum Depth

```bash
ntptrace-rs -d 5
```

Limits the trace to 5 hops from the starting host.

### Custom Timeout

```bash
ntptrace-rs -t 10
```

Each hop query has a 10-second timeout (default: 5).

---

## Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `host` | Hostname or IP to start tracing from | `127.0.0.1` |
| `-d, --max-depth <n>` | Maximum trace depth (hops) | `10` |
| `-t, --timeout <secs>` | Timeout per host query in seconds | `5` |

---

## Output Format

```
          host           refid  st      offset       delay
------------------------------------------------------------
   ntp.example.com          GPS   2    0.000456   0.012345
```

| Column | Description |
|--------|-------------|
| `host` | Hostname or IP address of the queried NTP daemon |
| `refid` | Reference identifier of the time source |
| `st` | Stratum level (1 = primary, 2–15 = secondary, 16 = unsynchronized) |
| `offset` | Reported clock offset in seconds |
| `delay` | Reported round-trip delay in seconds |

### Error Handling

When a host is unreachable or returns an error, `ntptrace-rs` reports it
gracefully:

| Indicator | Meaning |
|-----------|---------|
| `TIMEOUT` | Query timed out |
| `UNREACH` | Network connection failed |
| `ERROR` | Other query error (protocol, authentication, etc.) |

In all error cases, the trace stops at that point rather than continuing into
unknown territory.

---

## Trace Termination Conditions

The trace stops when any of the following conditions are met:

1. **Reference clock reached** — The current host has stratum 0 or 1
   (typically a GPS receiver, atomic clock, or NIST time service).
2. **Unsynchronized host** — Stratum ≥ 15 indicates the host is not
   synchronized to any time source.
3. **Maximum depth exceeded** — The `--max-depth` limit is reached.
4. **Query failure** — The target host is unreachable or returns an error.
5. **Loop detected** — The trace detects it is revisiting a host already in
   the chain, preventing infinite loops.

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
