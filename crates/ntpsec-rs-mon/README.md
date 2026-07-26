# ntpsec-rs-mon — ntpmon-rs

**Real-time NTP monitoring tool — continuously polls and displays NTP daemon state.**

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). Version 0.3.48.

---

## Overview

`ntpmon-rs` is a real-time NTP monitoring tool that continuously polls a
running `ntpd-rs` daemon (or any NTPsec-compatible daemon) and displays
live-updating system state and peer status information. It is a forensic Rust
reconstruction of the NTPsec `ntpmon` Python client.

The tool uses Mode 6 control protocol queries to retrieve:
- **System variables** — Stratum, leap indicator, offset, frequency, delay,
  root delay, root dispersion, uptime
- **Association status** — Configured vs. reachable peers
- **Per-peer details** — Tally code, remote address, refid, stratum, offset,
  delay, jitter, reachability register

---

## Usage

### Basic Monitoring

```bash
ntpmon-rs
```

Connects to the local NTP daemon (`127.0.0.1:123`) and displays updates every
2 seconds:

```
ntpmon-rs v0.3.48 — NTP monitor (Rust)
Monitoring: 127.0.0.1:123 (every 2s)
Press Ctrl-C to stop.

--- iteration=1 elapsed=00:00:02 ---
  stratum=3 leap=0 offset=0.000456 freq=3.141 delay=0.012345 rootdelay=0.003125 rootdisp=0.001234
  uptime=12:34:56 display=
  associations: 4 configured, 3 reachable
    *  ntp.example.com  refid=GPS   st=2  offset= 0.000456  delay= 0.012345  jitter= 0.000789  reach=ff
    +  ntp2.example.com refid=GPS   st=2  offset= 0.000321  delay= 0.014567  jitter= 0.000654  reach=ff
    -  ntp3.example.com refid=GPS   st=3  offset=-0.001234  delay= 0.025678  jitter= 0.001111  reach=ff
```

### Monitor a Remote Host

```bash
ntpmon-rs ntp.example.com
```

### Custom Port

```bash
ntpmon-rs -p 124
```

### Custom Refresh Interval

```bash
ntpmon-rs -r 5    # Update every 5 seconds
```

### Limited Iterations

```bash
ntpmon-rs -n 10   # Display 10 updates, then exit
```

---

## Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `host` | NTP daemon host to monitor | `127.0.0.1` |
| `-p, --port <port>` | Port number | `123` |
| `-r, --interval <secs>` | Refresh interval in seconds | `2` |
| `-n, --count <n>` | Number of iterations (0 = infinite) | `0` |

---

## Display Fields

### System Variables

| Field | Description |
|-------|-------------|
| `stratum` | Daemon's stratum level (1–16) |
| `leap` | Leap indicator (0=no warning, 1=add leap second, 2=subtract, 3=unsynchronized) |
| `offset` | Current estimated clock offset in seconds |
| `freq` | Current frequency offset in PPM (parts per million) |
| `delay` | Current estimated delay in seconds |
| `rootdelay` | Total round-trip delay to the primary reference source |
| `rootdisp` | Total dispersion to the primary reference source |
| `uptime` | Daemon uptime (formatted as `[days]d [hours]:[min]:[sec]`) |

### Peer Display

Each peer is shown with a **tally code** indicating its status in the
selection algorithm:

| Tally Code | Meaning |
|------------|---------|
| `*` | System peer (current synchronization source) |
| `+` | Included in the candidate set |
| `-` | Discarded by the clustering algorithm (falseticker) |
| `~` | Configured but unreachable |
| ` ` | Normal peer (not selected) |

Additional peer fields:
- `refid` — Reference clock identifier
- `st` — Peer stratum
- `offset` — Estimated clock offset in seconds
- `delay` — Round-trip delay in seconds
- `jitter` — Offset dispersion in seconds
- `reach` — Reachability register (hex, FF = 8 consecutive successful polls)

---

## Signal Handling

`ntpmon-rs` installs signal handlers for graceful shutdown:

- **Ctrl-C (SIGINT)** — Stops monitoring and exits cleanly
- **SIGTERM** — Stops monitoring and exits cleanly

After shutdown, a final message is displayed:

```
ntpmon-rs: monitoring stopped.
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
