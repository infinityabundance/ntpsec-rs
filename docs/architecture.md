# Architecture

`ntpsec-rs` is organized so that the parts of NTPsec that can be reasoned about
*deterministically* are isolated from the parts that touch the host. This is not
a stylistic choice — it is the precondition for the forensic method, which
depends on replaying behavior without a real clock, real network, or privileges.

## Workspace layout

```
crates/
  ntpsec-rs-core       deterministic time-discipline brain (48+ ported modules)
  ntpsec-rs-io         real OS I/O layer (libc syscall wrappers)
  ntpsec-rs            facade crate re-exporting ntpsec-rs-core for external consumers
  ntpsec-rs-d          daemon/replay binary (lab daemon, replay, --cmdmon)
  ntpsec-rs-query      control client & output-parity tool (ntpq)
  ntpsec-rs-dig        NTP query tool (ntpdig)
  ntpsec-rs-keygen     key generation tool
  ntpsec-rs-leapfetch  leap second fetcher
  ntpsec-rs-mon        real-time monitor
  ntpsec-rs-trace      trace tool
  ntpsec-rs-wait       wait tool
  ntpsec-rs-viz        visualization & plotting
  ntpsec-rs-frob       system utilities
  ntpsec-rs-snmpd      SNMP daemon agent
  ntpsec-rs-time       kernel time management
  ntpsec-rs-sweep      network sweep tool
  ntpsec-rs-loggps     GPS logging daemon
  ntpsec-rs-logtemp    temperature logging daemon
  xtask                build/automation (doc generation, freshness gate, comparative diagnostics)
```

All crates share workspace version `0.3.48`, edition `2021`.

## Deterministic-core principle

Everything in `ntpsec-rs-core` is total and side-effect-free — no file I/O, no
sockets, no clock reads — with a small number of documented exceptions. The rest
of `core` stays deterministic, which keeps the unit tests reproducible and lets
the same code run under a simulated clock during replay.

The core crate contains:

- **Time-discipline engine**: clock filter, clock select, clock cluster, clock
  combine, loop filter (the five stages of NTP clock selection and discipline).
- **Packet encoding/decoding**: NTPv4 wire format, Mode 6 control messages,
  NTS extensions, authentication extensions.
- **Configuration model**: type-safe representation of every `ntp.conf` directive.
- **Peer state machine**: lifecycle from `SYSTIMER_RESET` through reachability
  register to synchronized peer.
- **NTS crypto state**: AEAD nonce tracking, key derivation, cookie management.

None of these modules touch the host clock, open sockets, or read files. They
operate on abstract `Instant` values, abstract `SocketAddr` values, and
caller-provided byte buffers.

## Trait boundaries (implemented)

Host mutation lives behind narrow traits so the brain never depends on the
real environment. The implemented seams are:

```rust
trait SystemClock   { /* now, step, slew, read/set frequency — via adjtimex */ }
trait NetworkIo     { /* recv_ntp, send_ntp, recv_control, send_control */ }
trait StateStore    { /* load/save drift, leapsec, stats — atomic files */ }
trait ControlSocket { /* recv command, send response — mode 6 */ }
trait NtsTls        { /* NTS TLS termination */ }
trait Privileges    { /* drop privs, sandbox (seccomp) */ }
```

with three wirings:

```
real daemon:  RealSystemClock + UdpSockets + FileStateStore + UnixControlSocket + NtsTls
replay:       SimulatedClock  + TraceNetwork + MemoryStateStore + TraceControlSocket + NullNts
oracle:       captured ntpd trace + ntpsec-rs replay + byte/behavior compare
```

All traits are wired in the `--lab-daemon` mode.

## Daemon architecture

### Event loop

The daemon binary (`ntpsec-rs-d`) runs a single-threaded event loop built on
Tokio + `epoll`. The loop processes four event sources:

1. **Timer tick** — driven by the kernel clock via `timerfd` at the NTP poll
   interval (default 64 s, adaptive via poll reachability).
2. **Network I/O** — UDP socket readiness for NTP and Mode 6 packets.
3. **Control socket** — Unix domain socket for `ntpsec-rs-query` (ntpq)
   communication.
4. **Signal handler** — SIGHUP (reopen config), SIGTERM/SIGINT (graceful
   shutdown), SIGUSR1 (stats dump).

Every iteration of the event loop invokes `engine_tick()` on the core
discipline engine, which drives the peer poll schedule, packet dispatch,
clock selection, and loop filter.

### Engine tick

The engine tick (`ntpsec-rs-core::engine::tick`) is the central state
transition function. Each tick:

1. Advances each peer's poll timer and fires timers (poll, reachability,
   manycast).
2. For each ready peer: constructs a poll packet, passes it through the
   network I/O trait.
3. Processes received packets through the packet pipeline: decode →
   authenticate → validate timestamps → update peer statistics.
4. Runs clock selection: filter → select → cluster → combine.
5. Updates the loop filter: computes clock offset and frequency adjustment.
6. Issues clock step or slew commands through the `SystemClock` trait.

The engine is pure — all side effects flow through the trait boundaries above.

### Peer lifecycle

Each peer instance tracks:

- **Poll state**: `hpoll`, `ppoll`, `poll_skip`, `poll_phase` — matching
  NTPsec's peer poll state machine.
- **Reachability register**: 8-bit shift register updated each poll cycle.
  A peer is considered unreachable when the register reaches zero.
- **Autonomous reacquisition**: When a pool server drops out (reachability
  register → 0 → `sys_peer` loss), the engine autonomously resolves the pool
  DNS name and replaces the server. This is verified in the soak court.
- **Packet variables**: offset, delay, dispersion, jitter, filter bank (8
  deep per peer).

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
| Language | C99 + Python | Rust (edition 2021) |
| Client tools | Python scripts | Native Rust binaries |
| Config parser | Bison/yacc + scanner | Rust `nom`-based parser |
| NTS crypto | OpenSSL | `rustls` + `aes-siv` (Rust) |
| Packet I/O | Raw sockets | Tokio UDP + `socket2` |
| JSON parsing | libjsmn (embedded C) | `serde_json` |
| Memory safety | Manual | Compiler-enforced |
| Thread model | Signal-driven + select | Tokio async (where measured) |

## Test architecture

ntpsec-rs uses a three-layer test architecture:

### Layer 1: Unit tests (in-crate)

Every module in `ntpsec-rs-core` maintains deterministic unit tests that
exercise individual functions with known inputs and expected outputs. These
run in-process without I/O and use simulated clocks. Currently 769+ tests.

### Layer 2: Daemon binary court

The **daemon binary court** (`daemon_binary_court` test in `ntpsec-rs-d`)
starts the real daemon binary in a subprocess, sends it Mode 6 control queries,
injects synthetic packets, and verifies the daemon's response. This exercises
the full init→serve→shutdown lifecycle through the actual process boundary,
proving the binary is a well-behaved citizen.

### Layer 3: Soak court

The **soak court** (`soak_court` test in `ntpsec-rs-core`) runs the engine
tick loop through thousands of accelerated cycles with synthetic peer
interaction. It verifies:

- Peer loss and autonomous reacquisition
- Exactly-once clock step/slew boundary (no double-apply, no missed ticks)
- Reachability register evolution
- Pool server replacement after unreachability
- Long-term stability under continuous poll cycles

A scheduled nightly job runs 100k cycles (≈24 hours accelerated).

### Layer 4: Docker oracle

The **Docker oracle** (see below) runs full end-to-end comparison against the
real NTPsec `ntpd` in isolated network namespaces.

## Docker oracle topology

The Docker oracle runs side-by-side comparison in three configurations:

### 1. Two-sided comparison (docker-compose.yml)

```
┌─────────────┐       ┌──────────────┐       ┌───────────┐
│             │       │              │       │           │
│  ntpd (C)   │──────▶│   oracle     │◀──────│  ntpd-rs  │
│  (oracle)   │       │   harness    │       │  (test)   │
│             │       │              │       │           │
└─────────────┘       └──────────────┘       └───────────┘
```

The oracle harness (`oracle_harness.py`) feeds identical synthetic NTP packet
streams to both daemons and compares their state transitions and responses.
40+ scenarios covering:
- Basic client/server synchronization
- Symmetric peer mode
- NTS-KE + NTP-over-NTS
- Mode 6 read/write operations
- Access restriction enforcement
- Broadcast client mode
- Authentication (symmetric key)
- Multiple server selection
- Reserved/edge version numbers (VN=0, VN=7)
- Reserved mode (mode=0)
- Timestamp edge cases (epoch 0, max u32)
- Protocol field saturations (root delay, poll interval)
- All-zero and all-ones headers
- Sequence number edge cases (SEQ=0, SEQ=65535)
- Authenticated and unauthenticated Mode 6 queries
- Back-to-back packet bursts
- Pool DNS resolution

### 2. NTS-KE interop (docker-compose.nts.yml)

```
┌──────────────┐       ┌───────────┐
│  chronyd     │◀──────│ ntpd-rs   │
│  (NTS-KE     │       │ (NTS      │
│   oracle)    │       │  client)  │
└──────────────┘       └───────────┘
```

Validates that ntpsec-rs's NTS-KE implementation can successfully negotiate
with chrony as a reference NTS-KE server.

### 3. Package swap (docker-compose.swap.yml)

```
┌─────────────────────────────────────────────────┐
│                                                 │
│  Start NTPsec → verify → install ntpsec-rs     │
│  .deb packages → stop NTPsec → start ntpd-rs   │
│  → verify protocol equivalence                  │
│                                                 │
└─────────────────────────────────────────────────┘
```

Proves a live upgrade path on Ubuntu 24.04.

## CI pipeline

The CI pipeline ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml))
runs 9 hard-gate jobs:

| Job | Purpose |
|-----|---------|
| `test` (stable) | Full workspace build + 769+ tests on Rust stable |
| `test` (nightly) | Full workspace build + tests on nightly |
| `cross` (aarch64) | Cross-compile for ARM64 Linux |
| `cross` (musl) | Cross-compile for x86_64 musl (static) |
| `oracle` | One-sided + two-sided Docker oracle comparison |
| `soak` | Accelerated soak court + daemon binary court |
| `fuzz` | 4 fuzz targets (ntp_packet_decode, mode6_decode, config_parser, extension_fields) |
| `package-swap` | Live NTPsec → ntpsec-rs swap test |
| `nts-ke-interop` | NTS-KE handshake with chrony |

Plus a scheduled `nightly-soak` job that runs 100k-cycle soak (≈24h accelerated).

All gates are hard — a failure in any job blocks PR merge.

## Drop-in replacement mode

The real ntpsec binaries (`ntpd`, `ntpq`, `ntpdig`, etc.) are the behavioral
oracle. ntpsec-rs is designed so that:

1. `ntpsec-rs-d --config /etc/ntp.conf` produces equivalent runtime behavior to
   `ntpd -c /etc/ntp.conf`
2. `ntpsec-rs-query -c peers` produces equivalent output to `ntpq -c peers`
3. `ntpsec-rs-dig pool.ntp.org` produces equivalent output to `ntpdig pool.ntp.org`

Verification is done via the Docker oracle topology and the package-swap CI job
(see [`tests/docker/`](../tests/docker/)).
