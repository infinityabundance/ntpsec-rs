# ntpsec-rs-loggps

[![crates.io](https://img.shields.io/crates/v/ntpsec-rs-loggps.svg)](https://crates.io/crates/ntpsec-rs-loggps)
[![Documentation](https://img.shields.io/docsrs/ntpsec-rs-loggps)](https://docs.rs/ntpsec-rs-loggps)
[![License](https://img.shields.io/crates/l/ntpsec-rs-loggps.svg)](https://crates.io/crates/ntpsec-rs-loggps)

**ntploggps-rs** — GPS reference clock logging daemon for the ntpsec-rs workspace.
Reads data from GPS receivers (via gpsd or serial devices) and continuously logs time,
position, and satellite information for post-processing and clock stability analysis.

Equivalent to NTPsec's `ntploggps` (Python, ~8K).

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). v0.3.48.

---

## Overview

GPS reference clocks provide the highest-accuracy time source for NTP deployments. The
`ntploggps-rs` daemon connects to a GPS data source — either a `gpsd` daemon running on
the network or a directly attached serial GPS device — and records timestamped observations
for:

- **Clock stability analysis** — correlate GPS time against system time over long intervals
- **Position logging** — record receiver location for mobile or field deployments
- **Satellite visibility** — track which satellites are in view and providing fixes
- **Post-processing** — analyze timing jitter and accuracy of the GPS reference

The daemon runs as a persistent service, appending to the log file every poll interval.

### Oracle

```
ntpsec ntpclients/ntploggps.py (Python, 8K)
```

---

## Usage

### Basic usage (default gpsd source)

```sh
ntploggps-rs
```

Connects to `gpsd://localhost` and logs data to `/var/log/ntpstats/gpsd` every 10 seconds.

### Specify a custom GPS source

```sh
ntploggps-rs gpsd://192.168.1.100:2947
```

Connects to a remote gpsd instance.

### Custom output path

```sh
sudo ntploggps-rs -o /var/log/ntpstats/gps-observations
```

### Custom poll interval

```sh
ntploggps-rs -i 30
```

Logs GPS data every 30 seconds instead of the default 10.

### Command-line options

| Option | Description | Default |
|--------|-------------|---------|
| `source` | GPS source (gpsd://host or serial device path) | `gpsd://localhost` |
| `-o`, `--output` | Output file path | `/var/log/ntpstats/gpsd` |
| `-i`, `--interval` | Poll interval in seconds | `10` |

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
