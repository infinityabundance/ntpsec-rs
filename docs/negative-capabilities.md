# Negative Capabilities

> "The power of holding two contradictory beliefs in one's mind simultaneously,
> and accepting both of them." — F. Scott Fitzgerald, "The Crack-Up"

This document records every behavior that ntpsec-rs **intentionally does NOT
implement** that upstream ntpsec does — along with the rationale. These are
deployment-boundary decisions, not gaps. Every entry is classified as one of:

- **🔲 LAB-ONLY**: Implemented in the core but gated behind a feature flag;
  safe to disable in production.
- **⚠️ DEFERRED**: Known behavior that will be implemented in a later phase.
- **🚫 WONTFIX**: Behavior explicitly not planned; use another tool.
- **🗑️ DEPRECATED**: Behavior deprecated or removed by upstream ntpsec itself.
- **🎯 NTP-OUT-OF-SCOPE**: Behavior that is not part of NTP proper (e.g., system
  management unrelated to timekeeping).

## Classification categories

| # | Capability | ntpsec feature | ntpsec-rs status | Rationale |
|---|-----------|---------------|------------------|-----------|
| 1 | **Process-arbitration (ntpd -g)** | Step the clock on first synchronization | ✅ PORTED | Core NTP behavior |
| 2 | **ntpd -q** | Query-only mode (set clock once, exit) | ✅ PORTED | Core NTP behavior |
| 3 | **ntpd -x** | Slew-only mode (never step) | ✅ PORTED | Core NTP behavior |
| 4 | **ntpd -A / --no-auth** | Disable authentication | ✅ PORTED | Core NTP behavior |
| 5 | **ntpd -n / --nofork** | No fork | ✅ PORTED | Core daemon behavior |
| 6 | **ntpd -p / --private** | Private key file | ✅ PORTED | Core NTP behavior |
| 7 | **ntpd -b / --bcastsync** | Broadcast client sync | ✅ PORTED | Core NTP client behavior |
| 8 | **Seccomp sandboxing** | `ntp_sandbox.c` | 🔲 LAB-ONLY | Requires architecture-specific BPF; enabled with `--seccomp` |
| 9 | **chroot support** | `ntpd -i <dir>` | 🔲 LAB-ONLY | Requires careful filesystem setup; gated behind feature |
| 10 | **Deferred DNS resolution** | `ntp_dns.c` async DNS | ⚠️ DEFERRED | Requires async DNS resolver; Phase 2 |
| 11 | **NTS-KE server** | NTS key establishment server | ⚠️ DEFERRED | TLS-heavy; Phase 2 |
| 12 | **NTS-KE client** | NTS key establishment client | ⚠️ DEFERRED | Phase 2 |
| 13 | **NTS cookie decryption** | `nts_cookie.c` | ✅ PORTED | Core NTS; AES-SIV in Rust |
| 14 | **NTS extension fields** | `nts_extens.c` | ✅ PORTED | Core NTS |
| 15 | **Reference clock: GPSD** | `refclock_gpsd.c` | ⚠️ DEFERRED | Requires gpsd socket; Phase 2 |
| 16 | **Reference clock: NMEA** | `refclock_nmea.c` | ⚠️ DEFERRED | Serial device; Phase 2 |
| 17 | **Reference clock: PPS** | `refclock_pps.c` | ⚠️ DEFERRED | Kernel PPS; Phase 2 |
| 18 | **Refclock: SHM** | `refclock_shm.c` | ⚠️ DEFERRED | POSIX shared memory; Phase 2 |
| 19 | **Refclock: generic** | `refclock_generic.c` | ⚠️ DEFERRED | 155K C file; Phase 2 |
| 20 | **Refclock: JJY** | `refclock_jjy.c` | ⚠️ DEFERRED | Japanese time signal; Phase 3 |
| 21 | **Refclock: Oncore** | `refclock_oncore.c` | ⚠️ DEFERRED | Motorola Oncore GPS; Phase 3 |
| 22 | **Refclock: Trimble** | `refclock_trimble.c` | ⚠️ DEFERRED | Trimble GPS; Phase 3 |
| 23 | **Refclock: TrueTime** | `refclock_truetime.c` | ⚠️ DEFERRED | Phase 3 |
| 24 | **Refclock: Spectracom** | `refclock_spectracom.c` | ⚠️ DEFERRED | Phase 3 |
| 25 | **Refclock: Arbiter** | `refclock_arbiter.c` | ⚠️ DEFERRED | Phase 3 |
| 26 | **Refclock: HPGPS** | `refclock_hpgps.c` | ⚠️ DEFERRED | Phase 3 |
| 27 | **Refclock: Modem** | `refclock_modem.c` | ⚠️ DEFERRED | Phase 3 |
| 28 | **Refclock: Zyfer** | `refclock_zyfer.c` | ⚠️ DEFERRED | Phase 3 |
| 29 | **Refclock: Local** | `refclock_local.c` | ✅ PORTED | Simple LCL driver |
| 30 | **SNMP agent** | `ntpsnmpd` / `pylib/agentx.py` | ⚠️ DEFERRED | SNMP framework; Phase 2 |
| 31 | **Hardware timestamping** | `ntp_packetstamp.c` | ⚠️ DEFERRED | Linux SO_TIMESTAMPING; Phase 2 |
| 32 | **OpenSSL key generation** | ntpkeygen | ⚠️ DEFERRED | Phase 2; using `rcgen` |
| 33 | **Automatic leap file fetch** | ntpleapfetch | ⚠️ DEFERRED | Phase 2 |
| 34 | **ntpviz plotting** | ntpviz.py | ⚠️ DEFERRED | Phase 2 |
| 35 | **ntpmon real-time display** | ntpmon.py | ⚠️ DEFERRED | Curses TUI; Phase 2 |
| 36 | **ntpsweep** | ntpsweep.py | ⚠️ DEFERRED | Phase 2 |
| 37 | **ntploggps** | ntploggps.py | ⚠️ DEFERRED | Phase 2 |
| 38 | **ntplogtemp** | ntplogtemp.py | ⚠️ DEFERRED | Phase 2 |
| 39 | **ntptrace** | ntptrace.py | ⚠️ DEFERRED | Phase 2 |
| 40 | **Syslog output** | `ntp_syslog.c` messages | ✅ PORTED | Core logging |
| 41 | **Statistics logging** | `ntp_filegen.c` | ✅ PORTED | Core logging |
| 42 | **Loopback refclock** | 127.127.1.0 | ✅ PORTED | Core refclock |
| 43 | **Leap smear** | leap smear processing | ✅ PORTED | Core NTP behavior |
| 44 | **Autokey** | Autokey authentication | 🗑️ DEPRECATED | Removed in NTPsec; not implemented |
| 45 | **Mode 7 (ntpdc)** | Private NTP mode | 🗑️ DEPRECATED | Removed in NTPsec; use mode 6 |
| 46 | **MD5-only auth** | Keyed MD5 | ✅ PORTED | Still supported in ntpsec |
| 47 | **AES-128-CMAC** | RFC 7822 MAC | ✅ PORTED | Core auth |
| 48 | **AES-SIV-CMACE** | NTS cookie cipher | ✅ PORTED | Core NTS |
| 49 | **write-only / restrict** | Access controls | ✅ PORTED | Core ntpsec security |
| 50 | **Remote configuration** | `ntpq -c "config ..."` | ✅ PORTED | Core control protocol |
| 51 | **Signal handling** | SIGHUP, SIGINT, SIGTERM | ✅ PORTED | Core daemon |

## Detailed deployment-boundary notes

### Seccomp sandboxing (🔲 LAB-ONLY)

ntpsec's seccomp filter in `ntp_sandbox.c` is Linux/x86_64 specific and uses
architecture-specific syscall numbers. ntpsec-rs provides the filter logic in
`ntp_sandbox.rs` but it only activates with `--seccomp`. The filter is compiled
via the `seccomp` feature flag and is lab-only because it requires runtime
architecture detection and may need adjustment for non-x86_64 platforms.

### Reference clock drivers (⚠️ DEFERRED)

The 15 refclock drivers in ntpsec are ported in phases:

- **Phase 1**: Local clock (127.127.1.0) and PPS — completed.
- **Phase 2**: GPSD, NMEA, SHM, PPS — the four most commonly used drivers.
- **Phase 3**: JJY, Oncore, Trimble, TrueTime, Spectracom, Arbiter, HPGPS,
  Modem, Zyfer — niche hardware drivers.

Each refclock driver requires:
1. The IO/timing logic (in `ntpsec-rs-core`)
2. A device interface (in `ntpsec-rs-io`)
3. Oracle validation against real hardware or captured traces

### NTS (⚠️ DEFERRED for server)

NTS is a large protocol (RFC 8915, ~60 pages):

- **Cookie operations**: Ported (crate-private AES-SIV implementation)
- **Extension fields**: Ported
- **NTS-KE server**: Deferred; requires TLS termination
- **NTS-KE client**: Deferred; requires HTTP-like TLS exchange

The NTS cookie encryption/decryption is implemented using a pure-Rust AES-SIV
implementation (no OpenSSL dependency).
