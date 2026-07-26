# ntpsec-rs-d — ntpd-rs

**Full NTP daemon binary — a drop-in replacement for `ntpd` from NTPsec.**

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). Version 0.3.48.

---

## Overview

`ntpd-rs` is a complete Network Time Protocol daemon that synchronizes the
system clock to remote NTP servers and/or reference clocks. It is designed as a
drop-in replacement for the `ntpd` daemon from NTPsec, with compatible command
line flags, configuration file format, drift file format, and statistics files.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      ntpd-rs Event Loop                         │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐ │
│  │ Peer     │   │ Network  │   │ Clock    │   │ State        │ │
│  │ Manager  │──▶│ I/O      │──▶│Discipline│──▶│ Store        │ │
│  │          │   │ (epoll)  │   │ (PLL/FLL)│   │ (drift file) │ │
│  └──────────┘   └──────────┘   └──────────┘   └──────────────┘ │
│       │              │               │                          │
│       ▼              ▼               ▼                          │
│  ┌──────────┐   ┌──────────┐   ┌──────────────┐                │
│  │ DNS      │   │ Kernel   │   │ Privilege    │                │
│  │ Resolver │   │Timestamps│   │ + Seccomp    │                │
│  └──────────┘   └──────────┘   └──────────────┘                │
└────────────────────────────────────────────────────────────────┘
```

### Peer Management

The daemon manages a set of configured peers (from `ntp.conf`). Each peer is
polled at an adaptive interval, and incoming server responses are processed
through:

1. **Authentication verification** — If the peer is configured with a key ID,
   the response's MAC is verified using MD5, SHA-1, SHA-256/384/512, or
   AES-CMAC.
2. **NTS validation** — If NTS is negotiated, extension fields are validated and
   cookies are processed.
3. **Clock filter** — The most recent offset/delay samples are stored in a
   shift-register filter. The peer's offset is the sample with minimum delay.
4. **Selection algorithm** — Intersection and clustering algorithms identify
   falsetickers and select the best clock source.
5. **Combining** — The offsets of selected peers are combined into a weighted
   average.

### Clock Discipline

The daemon's clock discipline uses a hybrid PLL/FLL (Phase-Locked Loop /
Frequency-Locked Loop):

- **Initial synchronization** — Large offsets (>128 ms) trigger a step
  correction using `settimeofday`.
- **Ongoing tracking** — Small offsets are corrected by slewing the clock
  via `adjtimex` (Linux) or `ntp_adjtime` (BSD).
- **Frequency drift** — The frequency offset (PPM) is tracked and periodically
  saved to the drift file for recovery across daemon restarts.

### Event Loop

The main event loop uses `epoll` (Linux) to multiplex:

- NTP client/server packet reception
- NTS-KE connection events
- Timer expirations (peer poll intervals, system polls)
- Signal handling (SIGINT, SIGTERM, SIGHUP, SIGUSR1)
- Mode 6 control queries from `ntpq-rs`, `ntpmon-rs`, and `ntptrace-rs`

---

## Command-Line Flags

`ntpd-rs` supports flags compatible with NTPsec's `ntpd`:

| Flag | Description |
|------|-------------|
| `-c <file>` | Specify configuration file (default: `/etc/ntp.conf`) |
| `-n` | No fork — run in the foreground |
| `-I <addr>` | Bind to specific interface address |
| `-4` | IPv4 only |
| `-6` | IPv6 only |
| `-u <user>` | Drop privileges to this user after startup |
| `-p <pidfile>` | Write PID to this file |
| `-l <logfile>` | Log output to this file |
| `-i <jaildir>` | chroot jail directory |
| `-k <keyfile>` | Specify authentication key file |
| `--trustedkey <id>` | Mark a key as trusted |
| `--driftfile <file>` | Drift file path |
| `--slew` | Always slew, never step |
| `--panicgate` | Force initial step (ignore panic threshold) |
| `--wait-sync` | Wait for initial synchronization before exiting |
| `--nice <level>` | Set nice priority level |
| `--trace` | Enable protocol trace |
| `--seccomp` | Enable seccomp BPF sandboxing |
| `--metrics-port <port>` | Prometheus metrics HTTP endpoint port (e.g., 9090) |

### Usage Examples

Start the daemon in the background with default settings:
```bash
ntpd-rs
```

Run in the foreground with a custom config:
```bash
ntpd-rs -n -c /etc/ntp/my-ntp.conf
```

Force IPv4 and log to a file:
```bash
ntpd-rs -4 -l /var/log/ntp.log
```

Drop privileges and use seccomp:
```bash
ntpd-rs -u ntp --seccomp
```

Enable Prometheus metrics on port 9090:
```bash
ntpd-rs --metrics-port 9090
```

---

## Privilege Dropping

On Linux, the daemon drops privileges after binding sockets and opening
required files, using the following sequence:

1. Bind UDP sockets on port 123 (requires `CAP_NET_BIND_SERVICE`).
2. Open drift file, log file, and PID file.
3. Call `prctl(PR_SET_KEEPCAPS, 1)` to retain capabilities.
4. Set the user/group to the specified unprivileged user (e.g., `ntp`).
5. Apply `cap_set_proc` to reduce the capability set to only what's needed:
   - `CAP_SYS_TIME` — For clock adjustment (`adjtimex`, `settimeofday`)
   - `CAP_NET_BIND_SERVICE` — Already used, dropped after bind
   - `CAP_SYS_RESOURCE` — For setpriority/nice
   - `CAP_SYS_CHROOT` — For `--jaildir` support

---

## Seccomp BPF Sandbox

When `--seccomp` is enabled, the daemon installs a BPF seccomp filter after
initialization that restricts allowed system calls to a minimal whitelist:

| Allowed Syscall Group | Purpose |
|-----------------------|---------|
| `read`, `write`, `recvmsg`, `sendto` | Network I/O |
| `clock_gettime`, `adjtimex`, `gettimeofday` | Clock operations |
| `epoll_wait`, `epoll_ctl` | Event loop |
| `nanosleep` | Timer waits |
| `sigaction`, `sigreturn`, `rt_sigprocmask` | Signal handling |
| `mmap`, `munmap`, `brk`, `mprotect` | Memory management |
| `exit_group`, `exit` | Process termination |

Any unexpected syscall causes immediate process termination with `SIGSYS`,
providing strong protection against kernel-level exploits.

---

## Daemon Binary Court

`ntpd-rs` operates on the **court principle**: every mutation of daemon state
is tracked and can be reproduced for verification. The daemon binary spawns
the actual ntpsec-rs engine (`DaemonEngine` from `ntpsec-rs-core`) and
communicates with it through a well-defined interface. Mode 6 queries to the
daemon are validated against known-answer tests from the court system.

See the [court documentation](https://github.com/infinityabundance/ntpsec-rs/blob/main/docs/courts/)
for traceability evidence.

---

## systemd Service Integration

An example systemd service unit:

```ini
[Unit]
Description=Network Time Service (ntpsec-rs)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/ntpd-rs -n -u ntp
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=ntp
AmbientCapabilities=CAP_SYS_TIME CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/ntp /var/log/ntp

[Install]
WantedBy=multi-user.target
```

---

## Drift File and Statistics Compatibility

`ntpd-rs` maintains NTPsec-compatible files:

**Drift file** (`/var/lib/ntp/ntp.drift`):
```
freq 3.1415
```
The frequency offset (in PPM) is saved every 15 minutes and on daemon
shutdown, enabling recovery across restarts.

**Statistics files** (`/var/log/ntp/`):
- `loopstats` — Clock discipline statistics (MJD, time, offset, drift, jitter)
- `peerstats` — Per-peer statistics (MJD, time, src-addr, dst-addr,
  offset, delay, jitter)
- `clockstats` — Reference clock driver statistics

These are plain-text, space-delimited files compatible with `ntpviz-rs` and
the original NTPsec analysis tools.

---

## Related Crates

All crates in the ntpsec-rs workspace on crates.io:

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [ntpsec-rs-core](https://crates.io/crates/ntpsec-rs-core) | Deterministic engine, wire codec, Mode 6, auth, refclocks, NTS | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-core.svg)](https://crates.io/crates/ntpsec-rs-core) |
| [ntpsec-rs-io](https://crates.io/crates/ntpsec-rs-io) | Real I/O layer (system clock, network, state store) | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-io.svg)](https://crates.io/crates/ntpsec-rs-io) |
| [ntpsec-rs](https://crates.io/crates/ntpsec-rs) | Umbrella facade crate | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs.svg)](https://crates.io/crates/ntpsec-rs) |
| [ntpsec-rs-d](https://crates.io/crates/ntpsec-rs-d) | ntpd-rs — NTP daemon binary | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-d.svg)](https://crates.io/crates/ntpsec-rs-d) |
| [ntpsec-rs-metrics](https://crates.io/crates/ntpsec-rs-metrics) | Prometheus metrics endpoint | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-metrics.svg)](https://crates.io/crates/ntpsec-rs-metrics) |
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
