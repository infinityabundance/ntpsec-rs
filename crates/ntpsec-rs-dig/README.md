# ntpsec-rs-dig — ntpdig-rs

**NTP mode 3 (client) query tool — a drop-in replacement for `ntpdig` from NTPsec.**

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). Version 0.3.48.

---

## Overview

`ntpdig-rs` is a simple, single-shot NTP query tool that sends NTP mode 3
(client) packets to a remote NTP server and displays the response. It is the
Rust equivalent of the `ntpdig` tool from NTPsec, used for quickly checking
the time offset, delay, and jitter against an NTP server.

The tool resolves the server hostname (or uses an IP directly), sends one or
more NTP queries, and displays the server's reported time, offset, delay, and
dispersion.

---

## Usage

### Basic Query

```bash
ntpdig-rs pool.ntp.org
```

Output:

```
ntpdig-rs v0.3.48 — NTP query tool (Rust)
Querying pool.ntp.org:123

     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
*pool.ntp.org     .GPS.            2 u    -   64    1   12.345   0.456   0.789

time: 2025-01-15T12:34:56Z, clock offset: 0.000456s
```

### Multiple Samples

```bash
ntpdig-rs -s 4 pool.ntp.org
```

Queries the server 4 times and displays the aggregated result. Useful for
measuring jitter and establishing confidence in the offset estimate.

### Verbose Output

```bash
ntpdig-rs -v ntp.example.com
```

Shows additional details:

```
  Verbose details:
    Root delay:      0.003125 s
    Root dispersion: 0.001234 s
    Precision:       2^-24 (0.0000000596 s)
    Leap indicator:  NoWarning
    Round-trip delay: 0.012345 s
    Dispersion:      0.000789 s
```

### Force IPv4 or IPv6

```bash
ntpdig-rs -4 pool.ntp.org    # IPv4 only
ntpdig-rs -6 pool.ntp.org    # IPv6 only
```

### Custom Port

```bash
ntpdig-rs -p 124 ntp.example.com
```

### Custom Timeout

```bash
ntpdig-rs -t 10 pool.ntp.org    # 10-second timeout
```

---

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `server` | NTP server to query (hostname or IP) |
| `-4` | Force IPv4 only |
| `-6` | Force IPv6 only |
| `-v, --verbose` | Verbose output with detailed timing information |
| `-t, --timeout <secs>` | Query timeout in seconds (default: 5) |
| `-p, --port <port>` | Server port number (default: 123) |
| `-s, --samples <n>` | Number of NTP samples to take (default: 1) |

---

## DNS Resolution

The tool performs DNS resolution of the server hostname, supporting both A
(IPv4) and AAAA (IPv6) records. The address family can be restricted with
`-4` or `-6`.

---

## NTS Support

NTS (Network Time Security) support for authenticated time queries is planned,
building on the NTS client infrastructure in `ntpsec-rs-core`. When enabled,
`ntpdig-rs` will:

1. Perform an NTS-KE handshake over TCP on port 4460
2. Obtain encrypted NTS cookies
3. Send NTP queries with NTS extension fields
4. Verify NTS authenticators on responses

---

## Output Interpretation

| Field | Description |
|-------|-------------|
| `remote` | NTP server hostname or IP address |
| `refid` | Server's reference identifier (clock source) |
| `st` | Server stratum (1 = primary, 2-15 = secondary, 16 = unsynchronized) |
| `t` | Peer type (`u` = unicast, `b` = broadcast, `l` = local) |
| `when` | Seconds since last packet (shown as `-` for single query) |
| `poll` | Poll interval in seconds |
| `reach` | Reachability register (octal) |
| `delay` | Round-trip delay in milliseconds |
| `offset` | Clock offset in milliseconds |
| `jitter` | Dispersion/jitter in milliseconds |
| `time` | Server-reported reference time (ISO 8601) |
| `clock offset` | Computed clock offset in seconds |

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
