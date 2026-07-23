# ntpsec-rs

[![crates.io](https://img.shields.io/crates/v/ntpsec-rs.svg)](https://crates.io/crates/ntpsec-rs)
[![License](https://img.shields.io/crates/l/ntpsec-rs.svg)](https://crates.io/crates/ntpsec-rs)
[![Repository](https://img.shields.io/badge/github-infinityabundance%2Fntpsec--rs-blue)](https://github.com/infinityabundance/ntpsec-rs)

**ntpsec-rs** is a forensic Rust reconstruction of [NTPsec](https://www.ntpsec.org/) — a
secure, modern, full-featured implementation of the Network Time Protocol. The entire NTPsec
ecosystem — daemon, query tools, monitoring utilities, and supporting libraries — is being
rebuilt in safe, idiomatic Rust, organized as a Cargo workspace of focused sub-crates.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Crates](#crates)
- [Building](#building)
- [Running](#running)
- [Project Status](#project-status)
- [License](#license)
- [Links](#links)

---

## Project Overview

NTPsec is a hardened, security-focused fork of the classic NTP reference implementation.
**ntpsec-rs** reimplements the NTPsec codebase in Rust, leveraging Rust's safety guarantees,
modern tooling (Cargo, crates.io), and ecosystem libraries to produce a reliable,
memory-safe NTP implementation.

The workspace follows a modular design:

- **Core libraries** — protocol encoding/decoding, state machines, authentication, NTS
- **I/O layer** — system clock interaction, network sockets, drift-file persistence
- **Daemon** — the ntpd replacement (`ntpd-rs`)
- **Tooling** — query clients (`ntpq-rs`, `ntpdig-rs`), diagnostics, monitoring, visualization
- **Utilities** — key generation, leap-second fetching, configuration manipulation

---

## Architecture

```
                        ┌──────────────────────────────────────────┐
                        │              ntpsec-rs                   │
                        │         (umbrella facade)                │
                        └───────────┬──────────────────────────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             ▼                      ▼                      ▼
   ┌─────────────────┐   ┌──────────────────┐   ┌────────────────────┐
   │  ntpsec-rs-core  │   │   ntpsec-rs-io   │   │   Binaries / Tools │
   │  (no_std-ready)  │   │  (std required)  │   │   (14 crates)      │
   │                  │   │                  │   │                    │
   │ • Wire codec     │   │ • System clock   │   │ • ntpd-rs          │
   │ • Mode 6 control │   │ • UDP sockets    │   │ • ntpq-rs          │
   │ • Auth (MD5/SHA) │   │ • State store    │   │ • ntpdig-rs        │
   │ • NTS            │   │ • Refclock I/O   │   │ • ...              │
   │ • Refclocks      │   │                  │   │                    │
   │ • Engine         │   │                  │   │                    │
   └─────────────────┘   └──────────────────┘   └────────────────────┘
```

- **ntpsec-rs-core** — Pure protocol logic. Deterministic engine, wire format codec (NTP v4),
  Mode 6 control protocol, symmetric-key and NTS (Network Time Security) authentication,
  reference clock drivers. Designed to be `no_std` compatible where possible.
- **ntpsec-rs-io** — Real-world I/O. System clock access (`clock_gettime`/`settimeofday`),
  UDP sockets, drift-file and state persistence.
- **Tooling crates** — Each provides a standalone binary, building on top of `core` and `io`.

---

## Crates

The workspace publishes **18 crates** to [crates.io](https://crates.io/). All are prefixed
`ntpsec-rs-*`.

### Core Libraries

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [ntpsec-rs-core](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-core) | Deterministic engine, wire codec, Mode 6 control, authentication, refclocks, NTS | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-core.svg)](https://crates.io/crates/ntpsec-rs-core) |
| [ntpsec-rs-io](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-io) | Real I/O layer (system clock, network sockets, state store) | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-io.svg)](https://crates.io/crates/ntpsec-rs-io) |

### Daemon and Facade

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [ntpsec-rs](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs) | Umbrella facade crate re-exporting all public APIs | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs.svg)](https://crates.io/crates/ntpsec-rs) |
| [ntpsec-rs-d](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-d) | ntpd-rs — NTP daemon binary | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-d.svg)](https://crates.io/crates/ntpsec-rs-d) |

### Query Tools

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [ntpsec-rs-query](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-query) | ntpq-rs — Mode 6 control query client | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-query.svg)](https://crates.io/crates/ntpsec-rs-query) |
| [ntpsec-rs-dig](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-dig) | ntpdig-rs — NTP mode 3 query tool | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-dig.svg)](https://crates.io/crates/ntpsec-rs-dig) |
| [ntpsec-rs-time](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-time) | Single-shot time query tool | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-time.svg)](https://crates.io/crates/ntpsec-rs-time) |
| [ntpsec-rs-sweep](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-sweep) | Sweep through servers collecting stats | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-sweep.svg)](https://crates.io/crates/ntpsec-rs-sweep) |

### Monitoring and Diagnostics

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [ntpsec-rs-mon](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-mon) | Real-time NTP monitoring tool | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-mon.svg)](https://crates.io/crates/ntpsec-rs-mon) |
| [ntpsec-rs-trace](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-trace) | NTP path trace tool | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-trace.svg)](https://crates.io/crates/ntpsec-rs-trace) |
| [ntpsec-rs-snmpd](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-snmpd) | SNMP monitoring daemon | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-snmpd.svg)](https://crates.io/crates/ntpsec-rs-snmpd) |
| [ntpsec-rs-viz](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-viz) | NTP data visualization | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-viz.svg)](https://crates.io/crates/ntpsec-rs-viz) |

### Utilities

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [ntpsec-rs-keygen](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-keygen) | NTP symmetric key generation | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-keygen.svg)](https://crates.io/crates/ntpsec-rs-keygen) |
| [ntpsec-rs-leapfetch](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-leapfetch) | Leap second file fetcher | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-leapfetch.svg)](https://crates.io/crates/ntpsec-rs-leapfetch) |
| [ntpsec-rs-wait](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-wait) | Wait until NTP server reachable | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-wait.svg)](https://crates.io/crates/ntpsec-rs-wait) |
| [ntpsec-rs-frob](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-frob) | NTP configuration manipulator | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-frob.svg)](https://crates.io/crates/ntpsec-rs-frob) |

### Data Logging

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [ntpsec-rs-loggps](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-loggps) | GPS reference clock logging | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-loggps.svg)](https://crates.io/crates/ntpsec-rs-loggps) |
| [ntpsec-rs-logtemp](https://github.com/infinityabundance/ntpsec-rs/tree/main/crates/ntpsec-rs-logtemp) | System temperature logging | [![crates.io](https://img.shields.io/crates/v/ntpsec-rs-logtemp.svg)](https://crates.io/crates/ntpsec-rs-logtemp) |

---

## Building

### Prerequisites

- Rust 1.75+ (stable toolchain)
- Cargo (included with Rust)
- Linux (primary target; other Unix-likes may work)

### Build the entire workspace

```sh
git clone https://github.com/infinityabundance/ntpsec-rs.git
cd ntpsec-rs
cargo build --workspace
```

### Build a specific crate

```sh
cargo build -p ntpsec-rs-core
cargo build -p ntpsec-rs-d
```

### Release build

```sh
cargo build --workspace --release
```

Release binaries will be placed in `target/release/`. Notable binaries include:

| Binary | Crate | Purpose |
|--------|-------|---------|
| `ntpd-rs` | ntpsec-rs-d | NTP daemon |
| `ntpq-rs` | ntpsec-rs-query | Query client |
| `ntpdig-rs` | ntpsec-rs-dig | Query tool |
| `ntpkeygen` | ntpsec-rs-keygen | Key generation |
| `ntpleapfetch` | ntpsec-rs-leapfetch | Leap second fetcher |
| `ntpmon` | ntpsec-rs-mon | Monitor tool |
| `ntptrace` | ntpsec-rs-trace | Trace tool |
| `ntpwait` | ntpsec-rs-wait | Wait tool |
| `ntpviz` | ntpsec-rs-viz | Visualization |
| `ntpfrob` | ntpsec-rs-frob | Config manipulator |
| `ntpsnmpd` | ntpsec-rs-snmpd | SNMP daemon |
| `ntptime` | ntpsec-rs-time | Time query |
| `ntpsweep` | ntpsec-rs-sweep | Sweep tool |
| `ntploggps` | ntpsec-rs-loggps | GPS logging |
| `ntplogtemp` | ntpsec-rs-logtemp | Temperature logging |

### Cross-compilation

The `ntpsec-rs-core` crate is designed to be `no_std` compatible where practical,
enabling its use in embedded environments.

---

## Running

### Start the daemon

```sh
sudo ./target/release/ntpd-rs -c /etc/ntp.conf
```

### Query the daemon

```sh
./target/release/ntpq-rs -c peers
./target/release/ntpq-rs -c associations
```

### Check time offset

```sh
./target/release/ntpdig-rs pool.ntp.org
```

---

## Project Status

This is an active forensic reconstruction project. The crate structure and public API
may change as development progresses. Key milestones:

- ☑ Core protocol codec (NTP v4 wire format, Mode 6 control)
- ☑ Authentication (MD5, SHA-1, SHA-256/384/512)
- ☑ NTS (Network Time Security) basic support
- ☑ Reference clock framework
- ☑ Deterministic engine (clock filter, selection, combining, discipline)
- ☑ I/O layer (system clock, UDP sockets, state store)
- ☑ Daemon skeleton
- ☐ Full daemon integration and lifecycle management
- ☐ Comprehensive test suite
- ☐ Fuzz testing and security audit
- ☐ Production readiness

---

## License

This project is distributed under the same license as NTPsec. See the
[LICENSE](https://github.com/infinityabundance/ntpsec-rs/blob/main/LICENSE) file
for details.

---

## Links

- **GitHub Repository**: [https://github.com/infinityabundance/ntpsec-rs](https://github.com/infinityabundance/ntpsec-rs)
- **NTPsec Project**: [https://www.ntpsec.org/](https://www.ntpsec.org/)
- **NTP Protocol**: [RFC 5905](https://datatracker.ietf.org/doc/html/rfc5905)
- **NTS (Network Time Security)**: [RFC 8915](https://datatracker.ietf.org/doc/html/rfc8915)
- **crates.io**: [https://crates.io/crates/ntpsec-rs](https://crates.io/crates/ntpsec-rs)
