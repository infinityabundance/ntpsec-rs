# ntpsec-rs-leapfetch

[![crates.io](https://img.shields.io/crates/v/ntpsec-rs-leapfetch.svg)](https://crates.io/crates/ntpsec-rs-leapfetch)
[![Documentation](https://img.shields.io/docsrs/ntpsec-rs-leapfetch)](https://docs.rs/ntpsec-rs-leapfetch)
[![License](https://img.shields.io/crates/l/ntpsec-rs-leapfetch.svg)](https://crates.io/crates/ntpsec-rs-leapfetch)

**ntpleapfetch-rs** — Leap second file fetcher for the ntpsec-rs workspace. Downloads and
validates leap-second files from authoritative IETF sources, ensuring the NTP daemon always
has accurate leap second information for proper UTC dissemination.

Equivalent to NTPsec's `ntpleapfetch` (shell script, ~14K).

Part of the [ntpsec-rs](https://crates.io/crates/ntpsec-rs) workspace — a forensic Rust
reconstruction of [NTPsec](https://www.ntpsec.org/). v0.3.48.

---

## Overview

Leap seconds are inserted (or deleted) by the International Earth Rotation and Reference
Systems Service (IERS) to keep UTC within 0.9 seconds of astronomical time. The NTP daemon
needs a current `leap-seconds.list` file to know when a leap second event occurs and
whether to insert or delete a second.

`ntpleapfetch-rs` handles the full lifecycle:

1. **Downloads** the leap-seconds file from the IETF time zone data repository
2. **Validates** the content (checks for IERS header markers)
3. **Checks expiry** — only re-downloads if the existing file is stale
4. **Installs** the file to the configured output path (default: `/var/lib/ntp/leap-seconds`)
5. **Supports stdout printing** for inspection without file writes

### Oracle

```
ntpsec ntpclients/ntpleapfetch (shell, 14K)
```

---

## Usage

### Basic usage (download and install)

```sh
sudo ntpleapfetch-rs
```

Downloads the leap-second file from the default IETF URL and writes it to
`/var/lib/ntp/leap-seconds`. Skips download if the existing file is still current.

### Custom output path

```sh
sudo ntpleapfetch-rs -o /etc/ntp/leap-seconds
```

### Force re-download

```sh
sudo ntpleapfetch-rs -f
```

Downloads even if the existing file is current and unexpired.

### Print to stdout (no file write)

```sh
ntpleapfetch-rs -p
```

Prints the leap-second file content to stdout. Useful for inspection or piping:

```sh
ntpleapfetch-rs -p | head -20
```

### Custom URL and verbose mode

```sh
ntpleapfetch-rs -u https://example.com/leap-seconds.list -v
```

### Command-line options

| Option | Description | Default |
|--------|-------------|---------|
| `-o`, `--output` | Leap file output path | `/var/lib/ntp/leap-seconds` |
| `-u`, `--url` | Download URL | `https://www.ietf.org/timezones/data/leap-seconds.list` |
| `-f`, `--force` | Force download even if current | — |
| `-v`, `--verbose` | Verbose output | — |
| `-p`, `--print` | Print to stdout instead of writing file | — |

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
