# ntpsec-rs-logtemp

[![crates.io](https://img.shields.io/crates/v/ntpsec-rs-logtemp.svg)](https://crates.io/crates/ntpsec-rs-logtemp)
[![Documentation](https://img.shields.io/docsrs/ntpsec-rs-logtemp)](https://docs.rs/ntpsec-rs-logtemp)
[![License](https://img.shields.io/crates/l/ntpsec-rs-logtemp.svg)](https://crates.io/crates/ntpsec-rs-logtemp)

**ntplogtemp-rs** — System temperature logging daemon for the ntpsec-rs workspace.
Monitors and records system temperature data from sysfs thermal zones, enabling operators
to correlate environmental temperature changes with NTP clock stability.

Equivalent to NTPsec's `ntplogtemp` (Python, ~10K).

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). v0.3.48.

---

## Overview

Temperature variation is one of the most significant environmental factors affecting quartz
oscillator accuracy. As temperature rises or falls, the oscillator frequency shifts,
introducing timing error that the NTP discipline loop must compensate for. The
`ntplogtemp-rs` daemon records system temperature alongside timestamps so that:

- **Post-hoc analysis** can correlate clock offset spikes with temperature swings
- **Environmental profiling** identifies thermally unstable hardware
- **Temperature-compensated crystal oscillators (TCXOs)** can be validated
- **Long-term trend analysis** reveals seasonal effects on clock stability

The daemon reads temperature from Linux sysfs thermal zones (typically
`/sys/class/thermal/thermal_zone*/temp`) and appends timestamped readings to a log file
at a configurable interval.

### Oracle

```
ntpsec ntpclients/ntplogtemp.py (Python, 10K)
```

---

## Usage

### Basic usage (default sysfs path)

```sh
ntplogtemp-rs
```

Reads CPU temperature from `/sys/class/thermal/thermal_zone0/temp` every 60 seconds
and appends to `/var/log/ntpstats/temperature`.

### Custom temperature source

```sh
ntplogtemp-rs /sys/class/thermal/thermal_zone1/temp
```

For systems with multiple thermal zones (e.g., CPU core, GPU, battery).

### Custom output path and interval

```sh
sudo ntplogtemp-rs -o /var/log/ntpstats/temp.log -i 30
```

Logs temperature every 30 seconds to a custom log file.

### Monitoring in real time

```sh
ntplogtemp-rs -i 5
```

Poll every 5 seconds for fine-grained environmental monitoring.

### Command-line options

| Option | Description | Default |
|--------|-------------|---------|
| `source` | Temperature source (sysfs path) | `/sys/class/thermal/thermal_zone0/temp` |
| `-o`, `--output` | Output file path | `/var/log/ntpstats/temperature` |
| `-i`, `--interval` | Poll interval in seconds | `60` |

### Log format

Each line in the log file contains:

```
<unix_timestamp> <temperature_celsius>
```

Example:

```
1721952000 45.327
1721952060 45.412
1721952120 44.998
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
