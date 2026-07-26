# ntpsec-rs-wait — ntpwait-rs

**NTP wait tool — blocks until an NTP server becomes reachable or a time condition is met.**

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). Version 0.3.48.

---

## Overview

`ntpwait-rs` is a utility tool that blocks execution until an NTP server
becomes reachable or a time synchronization condition is satisfied. It is a
forensic Rust reconstruction of the NTPsec `ntpwait` Python client.

This tool is primarily used in **boot scripts** and **deployment automation**
to ensure that time synchronization is established before starting
time-sensitive services.

---

## Use Cases

### Boot Scripts

In system startup sequences, `ntpwait-rs` ensures the system clock is
synchronized before dependent services start:

```bash
#!/bin/sh
# Start NTP daemon
ntpd-rs -n &
# Wait for synchronization
ntpwait-rs -t 60
# Start time-sensitive services
postgresql start
```

### Deployment Automation

In container orchestration or CI/CD pipelines, verify time sync before
running distributed tests:

```bash
ntpwait-rs -t 300 -v
if [ $? -eq 0 ]; then
    echo "Time is synchronized. Proceeding with deployment..."
    deploy
else
    echo "WARNING: NTP did not synchronize within timeout."
fi
```

### Configuration Management

As a precondition in Ansible, Puppet, or Chef playbooks:

```yaml
- name: Wait for NTP sync
  command: ntpwait-rs -t 120
  register: ntp_result
```

---

## Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --timeout <secs>` | Maximum wait time in seconds | `30` |
| `-p, --poll-interval <secs>` | How often to poll for sync status | `1` |
| `-v, --verbose` | Enable verbose output showing polling progress | false |
| `-c, --command <cmd>` | ntpq command to check synchronization status | `rv 0` |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | NTP server is reachable / time condition met |
| `1` | Timeout reached without synchronization |
| `2` | Error (connection refused, protocol error, etc.) |

---

## Usage Examples

### Basic Wait (30-second default timeout)

```bash
ntpwait-rs
```

### Wait with Custom Timeout

```bash
ntpwait-rs -t 120
```

Waits up to 120 seconds for NTP synchronization.

### Verbose Mode

```bash
ntpwait-rs -v -t 60
```

Shows periodic status updates while waiting:

```
ntpwait-rs v0.3.48 — NTP wait tool (Rust)
Waiting up to 60 seconds for NTP sync...
  poll 1: not synchronized yet (stratum=16)
  poll 2: not synchronized yet (stratum=16)
  poll 3: synchronized (stratum=3, offset=0.000456s)
NTP synchronization achieved after 3 seconds.
```

### Fast Polling

```bash
ntpwait-rs -p 5 -t 30
```

Polls every 5 seconds instead of the default 1 second.

---

## Integration with systemd

```
[Unit]
Description=MyService - requires NTP sync
Requires=ntpd-rs.service
After=ntpd-rs.service

[Service]
Type=oneshot
ExecStartPre=/usr/bin/ntpwait-rs -t 60
ExecStart=/usr/bin/my-service
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
