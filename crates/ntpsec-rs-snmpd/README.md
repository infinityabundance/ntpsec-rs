# ntpsec-rs-snmpd

[![crates.io](https://img.shields.io/crates/v/ntpsec-rs-snmpd.svg)](https://crates.io/crates/ntpsec-rs-snmpd)
[![Documentation](https://img.shields.io/docsrs/ntpsec-rs-snmpd)](https://docs.rs/ntpsec-rs-snmpd)
[![License](https://img.shields.io/crates/l/ntpsec-rs-snmpd.svg)](https://crates.io/crates/ntpsec-rs-snmpd)

**ntpsnmpd-rs** — SNMP monitoring daemon for the ntpsec-rs workspace. Polls a running
NTP daemon via Mode 6 control queries and exports key performance metrics — stratum,
offset, frequency, jitter, root delay, root dispersion — for ingestion by network
monitoring systems.

Equivalent to NTPsec's `ntpsnmpd` (Python, ~48K, plus `agentx.py` and `agentx_packet.py`).

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). v0.3.48.

---

## Overview

Network monitoring infrastructure often relies on SNMP (Simple Network Management Protocol)
to collect health metrics from managed devices. `ntpsnmpd-rs` bridges the NTP daemon's
internal state — accessible via Mode 6 control protocol — into a format consumable by
SNMP collectors such as Nagios, Zabbix, Prometheus (via SNMP exporter), and others.

The daemon runs as a persistent service, periodically querying a local or remote ntpd-rs
instance and writing structured data to a file that an SNMP agent or sidecar can serve:

| Metric | Source | Description |
|--------|--------|-------------|
| `stratum` | `read_system_vars()` | Distance from reference clock |
| `offset` | `read_system_vars()` | Clock offset from reference (seconds) |
| `frequency` | `read_system_vars()` | Clock frequency error (ppm) |
| `sys_jitter` | `read_system_vars()` | System clock jitter (seconds) |
| `root_delay` | `read_system_vars()` | Round-trip delay to root (seconds) |
| `root_dispersion` | `read_system_vars()` | Dispersion to root (seconds) |

### Oracle

```
ntpsec ntpclients/ntpsnmpd.py (Python, 48K)
ntpsec pylib/agentx.py
ntpsec pylib/agentx_packet.py
```

---

## Usage

### Basic usage (local daemon)

```sh
ntpsnmpd-rs
```

Polls ntpd-rs at `127.0.0.1:123` every 60 seconds, writing statistics to
`/var/log/ntpstats/snmp`.

### Remote NTP daemon

```sh
ntpsnmpd-rs 192.168.1.100 -p 123
```

Polls a remote ntpd-rs instance.

### Custom SNMP port and output

```sh
ntpsnmpd-rs -s 1161 -o /var/log/ntpstats/ntp-snmp-data
```

### Fast polling for detailed monitoring

```sh
ntpsnmpd-rs -i 5
```

Poll every 5 seconds for higher-resolution monitoring data.

### Command-line options

| Option | Description | Default |
|--------|-------------|---------|
| `host` | NTP daemon host | `127.0.0.1` |
| `-p`, `--port` | NTP daemon port | `123` |
| `-s`, `--snmp-port` | SNMP agent port | `1161` |
| `-i`, `--interval` | Poll interval in seconds | `60` |
| `-o`, `--output` | Output file for SNMP data | `/var/log/ntpstats/snmp` |

### Output format

Each poll writes a key=value file:

```
stratum=2
offset=0.003412
frequency=11.423
sys_jitter=0.000156
root_delay=0.021
root_dispersion=0.008
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
