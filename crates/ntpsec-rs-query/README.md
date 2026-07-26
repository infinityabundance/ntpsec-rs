# ntpsec-rs-query — ntpq-rs

**NTP Mode 6 control protocol query client — a drop-in replacement for `ntpq` from NTPsec.**

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). Version 0.3.48.

---

## Overview

`ntpq-rs` is a Mode 6 control protocol client that queries the state of a
running NTP daemon. It is a forensic Rust reconstruction of the NTPsec
`ntpq` Python client, with the same command set and output format.

The tool communicates with the NTP daemon using Mode 6 (control) messages on
port 123 (default). It supports a rich set of query commands for inspecting
daemon state, peer status, authentication statistics, kernel information, and
more.

---

## Commands

`ntpq-rs` supports the full set of NTPq commands:

| Command | Aliases | Description |
|---------|---------|-------------|
| `rv` | — | Read system variables (default) or peer variables with associd |
| `peers` | `pe` | Show peer summary table (all configured + reachable peers) |
| `apeers` | `ape` | Show active peers (reachable only) |
| `lpeers` | `lpe` | List all peers (including unreachable) |
| `associations` | `as` | Show association IDs and status codes |
| `sysinfo` | — | Detailed system information display |
| `kerninfo` | — | Kernel timekeeping information |
| `authinfo` | — | Authentication module statistics |
| `clockvar` | `cv` | Read clock variables for a specific association |
| `mrulist` | — | Display Most Recently Used (MRU) list of client traffic |
| `monitor` | `ntpmon` | Show system variables and all associations |
| `trace` | `ntptrace` | Trace the NTP synchronization chain |

### Read Variables (`rv`)

By default, `ntpq-rs` reads and displays system variables from the daemon:

```
$ ntpq-rs -c rv
associd=0 status=0664 leap=0 stratum=3 precision=-24 rootdelay=3.125
rootdisp=1.234 refid=203.0.113.1 reftime=f298c000.00000000
clock=ef2a8000.00000000 peer=12345 offset=0.123 syspeer=12345
```

With an association ID, it reads peer variables:

```
$ ntpq-rs -c "rv 12345"
associd=12345 status=9614 conf=1 reach=1 auth=1 stratum=2
srcadr=203.0.113.1 srchost=ntp.example.com refid=GPS
offset=0.456 delay=12.345 jitter=0.789
```

### Peers Table (`peers`, `apeers`, `lpeers`)

Displays a formatted peer table identical to the classic `ntpq -p` output:

```
$ ntpq-rs -c peers
     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
*ntp.example.com  .GPS.            2 u   32   64  377   12.34    0.456   0.789
+ntp2.example.com 203.0.113.2     2 u   15   64  377   14.56    0.321   0.654
-time.example.com 203.0.113.3     3 u   28   64  377   25.67   -1.234   1.111
```

The tally codes match NTPsec conventions:
- `*` — System peer (synchronization source)
- `+` — Candidate peer (in the selection set)
- `-` — Falseticker (discarded by the selection algorithm)
- `~` — Peer configured but unreachable

### Associations (`associations`)

Lists all configured associations and their status:

```
$ ntpq-rs -c associations

associd=0 status=0664 leap=0 stratum=3 precision=-24 rootdelay=3.125
rootdisp=1.234 refid=203.0.113.1
```

### System Information (`sysinfo`)

Displays a comprehensive formatted summary of daemon state:

```
$ ntpq-rs -c sysinfo
=== System Information ===
  associd              = 0
  status               = 0664
  stratum              = 3
  refid                = 203.0.113.1
  offset               = 0.123
  frequency            = 3.141
  ...
```

### Kernel Information (`kerninfo`)

Displays kernel timekeeping statistics (from `adjtimex`):

```
$ ntpq-rs -c kerninfo
=== Kernel Information ===
  offset               = 0.123
  frequency            = 3.141
  sys_jitter           = 0.001
  clk_wander           = 0.002
  rootdelay            = 3.125
  rootdisp             = 1.234
  tc                   = 6
  mintc                = 3
  precision            = -24
  stratum              = 3
```

### Authentication Information (`authinfo`)

Displays statistics from the daemon's authentication module:

```
$ ntpq-rs -c authinfo
=== Authentication Information ===
  auth_badauth          = 0
  auth_badkey           = 0
  auth_decrypts         = 42
  auth_encrypts         = 42
  auth_foundkey         = 1
  auth_notfound         = 0
  auth_keys             = 10
```

### MRU List (`mrulist`)

Displays the Most Recently Used list of recent client traffic:

```
$ ntpq-rs -c mrulist
  srcaddr              srcport  count  avgdelay  avgoffset
  192.168.1.1          42315    12     3.124     0.015
  192.168.1.2          38561    5      4.567     0.023
```

---

## Usage

### Basic System Query

```bash
ntpq-rs
```

### Execute Specific Commands

```bash
ntpq-rs -c peers
ntpq-rs -c "rv 12345"
ntpq-rs -c associations -c sysinfo
```

### Query a Remote Daemon

```bash
ntpq-rs ntp.example.com -c peers
```

### Use the `-p` Shorthand

```bash
ntpq-rs -p
```
Equivalent to `ntpq-rs -c peers`.

### Custom Port

```bash
ntpq-rs -P 124 -c peers
```

### Authentication

```bash
ntpq-rs -a 10 -k /etc/ntp.keys -c rv
```

### Force IPv4/IPv6

```bash
ntpq-rs --ipv4 -c peers
ntpq-rs --ipv6 -c peers
```

---

## Command-Line Flags

| Flag | Description |
|------|-------------|
| `host` | Target NTP daemon host (default: `127.0.0.1`) |
| `-P, --port <port>` | Port number (default: 123) |
| `-c, --command <cmd>` | Execute a command (can be specified multiple times) |
| `-p` | Shorthand for `-c peers` |
| `-n, --numeric` | Numeric output only (no DNS resolution) |
| `-v, --verbose` | Verbose output |
| `-d, --debug` | Debug mode |
| `-a, --auth-key <id>` | Authentication key ID |
| `-k, --key-file <file>` | Authentication key file |
| `-t, --timeout <secs>` | Timeout in seconds (default: 5) |
| `--ipv4` | Force IPv4 only |
| `--ipv6` | Force IPv6 only |

---

## Output Parity with NTPsec `ntpq`

`ntpq-rs` is validated against the NTPsec `ntpq` Python client through
deterministic trace replay. Key output parity targets:

- Peer table column alignment and formatting
- Tally code characters (`*`, `+`, `-`, `~`, ` `)
- System variable names and value formatting
- Association status interpretation
- Error messages and exit codes

---

## Interactive Shell Mode

When invoked without `-c` flags, `ntpq-rs` runs a single `rv` query and
displays system variables. A full interactive shell (REPL mode) is planned
for a future release.

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
