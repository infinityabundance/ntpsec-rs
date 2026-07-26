# ntpsec-rs-sweep

[![crates.io](https://img.shields.io/crates/v/ntpsec-rs-sweep.svg)](https://crates.io/crates/ntpsec-rs-sweep)
[![Documentation](https://img.shields.io/docsrs/ntpsec-rs-sweep)](https://docs.rs/ntpsec-rs-sweep)
[![License](https://img.shields.io/crates/l/ntpsec-rs-sweep.svg)](https://crates.io/crates/ntpsec-rs-sweep)

**ntpsweep-rs** — NTP network sweep tool for the ntpsec-rs workspace. Iterates through a
list of NTP servers, queries each one, and reports offset, delay, stratum, and reference
identifier — enabling rapid assessment of clock quality across a pool of candidates.

Equivalent to NTPsec's `ntpsweep` (Python, ~8K).

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). v0.3.48.

---

## Overview

When selecting NTP servers for a deployment, it's essential to evaluate which peers provide
the most accurate and stable time. `ntpsweep-rs` sweeps through a list of NTP servers —
provided on the command line or from a file — and performs a Mode 3 (client) query against
each one, collecting and displaying:

- **Offset** — time difference between client and server (seconds)
- **Delay** — round-trip network delay (seconds)
- **Stratum** — distance from the reference clock (lower is better)
- **Ref ID** — reference clock identifier (e.g., GPS, PPS, or upstream server name)

This is especially useful for:

- Evaluating candidate NTP pool servers before configuring the daemon
- Diagnosing which servers in a configured set are underperforming
- Benchmarking NTP server farms for latency and accuracy
- Auditing the quality of service from public NTP pools

### Oracle

```
ntpsec ntpclients/ntpsweep.py (Python, 8K)
```

---

## Usage

### Sweep specific servers

```sh
ntpsweep-rs pool.ntp.org time.google.com time.cloudflare.com
```

```
pool.ntp.org offset=0.003412s delay=0.021000s stratum=2 refid=GPS
time.google.com offset=0.001234s delay=0.005000s stratum=1 refid=.GOO
time.cloudflare.com offset=0.002710s delay=0.008000s stratum=1 refid=.CFL
```

### Sweep from a host file

```sh
cat > ntp_servers.txt << EOF
# NTP server list (one per line)
pool.ntp.org
time.google.com
time.cloudflare.com
time.windows.com
EOF

ntpsweep-rs -f ntp_servers.txt
```

### Custom timeout

```sh
ntpsweep-rs -t 10 pool.ntp.org time.apple.com
```

Uses a 10-second timeout per host instead of the default 5.

### Custom port

```sh
ntpsweep-rs -p 1234 192.168.1.100
```

Queries a non-standard NTP port.

### Combining CLI args and file

```sh
ntpsweep-rs -f pool_list.txt time.google.com
```

Processes servers from both the file and command-line arguments.

### Command-line options

| Option | Description | Default |
|--------|-------------|---------|
| `hosts` | NTP servers to query | (required) |
| `-f`, `--host-file` | Host list file (one per line, # comments) | — |
| `-t`, `--timeout` | Timeout per host in seconds | `5` |
| `-p`, `--port` | NTP port number | `123` |

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
