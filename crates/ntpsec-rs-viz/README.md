# ntpsec-rs-viz — ntpviz-rs

**NTP data visualization tool — reads and displays NTP statistics files.**

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). Version 0.3.48.

---

## Overview

`ntpviz-rs` reads NTP statistics files produced by `ntpd-rs` (or any
NTPsec-compatible daemon) and provides human-readable summaries and
visualizations of time synchronization data. It is a forensic Rust
reconstruction of the NTPsec `ntpviz` Python client.

The tool parses three types of NTP statistics files:

| File | Source | Contents |
|------|--------|----------|
| `loopstats` | Clock discipline module | Time offset, drift (frequency), jitter over time |
| `peerstats` | Peer module | Per-peer offset, delay, jitter samples |
| `clockstats` | Reference clock drivers | Reference clock time and status data |

---

## Usage

### Display Statistics File Contents

```bash
ntpviz-rs /var/log/ntp/loopstats
```

Output:

```
File: /var/log/ntp/loopstats
Records: 1440

# Each line: MJD second offset drift jitter
60375 12345.678 0.000456 3.141 0.000789
60375 12346.678 0.000432 3.142 0.000765
...
```

### Show Summary Statistics

```bash
ntpviz-rs -s /var/log/ntp/loopstats
```

Produces a statistical summary:

```
File: /var/log/ntp/loopstats
Records: 1440

Loopstats summary:
  samples:     1440
  mean offset: 0.000423 ms
  min offset:  -0.001234 ms
  max offset:  0.001567 ms
  stddev:      0.000345 ms
```

### Peer Statistics Summary

```bash
ntpviz-rs -s /var/log/ntp/peerstats
```

Shows per-peer offset statistics:

```
File: /var/log/ntp/peerstats
Records: 4320

Peerstats summary by peer:
  ntp.example.com: 1440 samples, mean offset 0.000456 ms
  ntp2.example.com: 1440 samples, mean offset 0.000321 ms
  ntp3.example.com: 1440 samples, mean offset -0.000234 ms
```

---

## Statistics File Formats

### Loopstats

Each line in the loopstats file follows this format:

```
MJD second offset drift jitter
```

| Field | Description |
|-------|-------------|
| `MJD` | Modified Julian Date (days since 1858-11-17) |
| `second` | Seconds since midnight UTC |
| `offset` | Clock offset in seconds |
| `drift` | Frequency drift in PPM (parts per million) |
| `jitter` | Clock jitter/second in seconds |

### Peerstats

Each line in the peerstats file follows this format:

```
MJD second srcaddr dstaddr offset delay jitter
```

| Field | Description |
|-------|-------------|
| `MJD` | Modified Julian Date |
| `second` | Seconds since midnight UTC |
| `srcaddr` | Source (remote peer) IP address |
| `dstaddr` | Destination (local) IP address |
| `offset` | Estimated clock offset in seconds |
| `delay` | Round-trip delay in seconds |
| `jitter` | Offset dispersion in seconds |

### Clockstats

Reference clock statistics file format varies by driver. Common fields
include:

```
MJD second clock_id status timecode
```

---

## Analysis Features

### Loopstats Analysis

When run with `-s` on a loopstats file, `ntpviz-rs` computes:

- **Sample count** — Total number of data points
- **Mean offset** — Average clock offset over the sampling period
- **Min/max offset** — Extreme values, useful for identifying outliers
- **Standard deviation** — Quantitative measure of clock stability

### Peerstats Analysis

When run with `-s` on a peerstats file, `ntpviz-rs` groups data by peer
address and computes the mean offset for each peer. This helps identify:

- Which peers provide the most consistent time
- Systematic biases in certain peer paths
- Long-term drift patterns

---

## Integration with Other Tools

The statistics files are plain-text and can be used with standard command-line
tools:

```bash
# Count records
wc -l /var/log/ntp/loopstats

# Find max offset
awk '{print $3}' /var/log/ntp/loopstats | sort -n | tail -1

# Plot with gnuplot
gnuplot -e "plot '/var/log/ntp/loopstats' using 3 with lines"
```

Future releases will include native graphical output capabilities (PNG, SVG).

---

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `file` | Path to an NTP statistics file (loopstats, peerstats, clockstats) |
| `-s, --summary` | Show summary statistics instead of raw file contents |

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
