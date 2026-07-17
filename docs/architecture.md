# Architecture

`ntpsec-rs` is organized so that the parts of NTPsec that can be reasoned about
*deterministically* are isolated from the parts that touch the host. This is not
a stylistic choice — it is the precondition for the forensic method, which
depends on replaying behavior without a real clock, real network, or privileges.

## Workspace layout

```
crates/
  ntpsec-rs-core       the deterministic time-discipline brain (48+ ported modules)
  ntpsec-rs-io         real OS I/O layer (libc syscall wrappers)
  ntpsec-rs-facade     facade crate re-exporting ntpsec-rs-core
  ntpd-rs              daemon/replay binary (lab daemon, replay, --cmdmon)
  ntpq-rs              control client & output-parity tool
  ntpdig-rs            NTP query tool
  ntpkeygen-rs         key generation
  ntpleapfetch-rs      leap second fetcher
  ntpmon-rs            real-time monitor
  ntptrace-rs          trace tool
  ntpwait-rs           wait tool
  ntpviz-rs            visualization tool
  ntpfrob-rs           system utilities
  ntpsnmpd-rs          SNMP daemon
  ntptime-rs           kernel time management
  ntpsweep-rs          network sweep tool
  ntploggps-rs         GPS logging daemon
  ntplogtemp-rs        temperature logging daemon
  xtask                build/automation (doc generation, freshness gate, comparative diagnostics)
```

## Deterministic-core principle

Everything in `ntpsec-rs-core` is total and side-effect-free — no file I/O, no
sockets, no clock reads — with a small number of documented exceptions. The rest
of `core` stays deterministic, which keeps the unit tests reproducible and lets
the same code run under a simulated clock during replay.

## Trait boundaries (implemented)

Host mutation lives behind narrow traits so the brain never depends on the
real environment. The implemented seams are:

```rust
trait SystemClock  { /* now, step, slew, read/set frequency — via adjtimex */ }
trait NetworkIo    { /* recv_ntp, send_ntp, recv_control, send_control */ }
t trait StateStore  { /* load/save drift, leapsec, stats — atomic files */ }
trait ControlSocket{ /* recv command, send response — mode 6 */ }
trait NtsTls       { /* NTS TLS termination */ }
t trait Privileges  { /* drop privs, sandbox (seccomp) */ }
```

with three wirings:

```
real daemon:  RealSystemClock + UdpSockets + FileStateStore + UnixControlSocket + NtsTls
replay:       SimulatedClock  + TraceNetwork + MemoryStateStore + TraceControlSocket + NullNts
oracle:       captured ntpd trace + ntpsec-rs replay + byte/behavior compare
```

All traits are wired in the `--lab-daemon` mode.

## Why not one big async daemon

A single opaque async application would make behavior non-reproducible and hide
state. We prefer an explicit event loop and typed state transitions so that every
decision (sample accept/reject, source select, step vs slew) is observable and
can be pinned to a court. Determinism first; performance and concurrency later,
and only where measured.

## Key architectural differences from upstream ntpsec

| Aspect | Upstream ntpsec (C) | ntpsec-rs (Rust) |
|--------|-------------------|-----------------|
| Build system | Waf (Python) | Cargo + xtask |
| Language | C99 + Python | Rust (edition 2024) |
| Client tools | Python scripts | Native Rust binaries |
| Config parser | Bison/yacc + scanner | Rust `nom`-based parser |
| NTS crypto | OpenSSL | `rustls` + `aes-siv` (Rust) |
| Packet I/O | Raw sockets | Tokio UDP + `socket2` |
| JSON parsing | libjsmn (embedded C) | `serde_json` |
| Memory safety | Manual | Compiler-enforced |
| Thread model | Signal-driven + select | Tokio async (where measured) |

## Drop-in replacement mode

The real ntpsec binaries (`ntpd`, `ntpq`, `ntpdig`, etc.) are the behavioral
oracle. ntpsec-rs is designed so that:

1. `ntpd-rs --config /etc/ntp.conf` produces identical runtime behavior to
   `ntpd -c /etc/ntp.conf`
2. `ntpq-rs -c peers` produces identical output to `ntpq -c peers`
3. `ntpdig-rs pool.ntp.org` produces identical output to `ntpdig pool.ntp.org`

Verification is done via the Docker oracle VM matrix (see
[docker/README.md](../docker/README.md)).
