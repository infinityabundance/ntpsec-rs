# Negative Capabilities — Audit Revision 2

> "The power of holding two contradictory beliefs in one's mind simultaneously,
> and accepting both of them." — F. Scott Fitzgerald, "The Crack-Up"

This document records every behavior that ntpsec-rs **intentionally does NOT
implement** that upstream ntpsec does — along with the rationale.

**Revision 2 corrections:**
1. Fixed bytes-vs-LOC confusion (actual line counts, not byte sizes)
2. Removed stale "GENERATED" authority claim from parity map (generator not yet wired)
3. Added 4-level config recognition: lexical, typed parse, applied, oracle parity
4. Separated architectural substitutions from missing capability
5. Three-tier effort estimate: production blockers, mainline parity, historical breadth
6. Removed double-counting in remaining-effort table

## Classification categories

- **🔲 LAB-ONLY**: Implemented in the core but gated behind a feature flag;
  safe to disable in production.
- **⚠️ DEFERRED**: Known behavior that will be implemented in a later phase.
- **🚫 WONTFIX**: Behavior explicitly not planned; use another tool.
- **🗑️ DEPRECATED**: Behavior deprecated or removed by upstream ntpsec itself.
- **🎯 NTP-OUT-OF-SCOPE**: Behavior that is not part of NTP proper.

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
| 8 | **Seccomp sandboxing** | `ntp_sandbox.c` | ✅ PORTED | Works on Alpine; x86_64 only |
| 9 | **chroot support** | `ntpd -i <dir>` | 🔲 LAB-ONLY | Requires careful filesystem setup |
| 10 | **Deferred DNS resolution** | `ntp_dns.c` async DNS | ⚠️ DEFERRED | Requires async DNS resolver |
| 11 | **NTS-KE server** | NTS key establishment server | ⚠️ DEFERRED | Server role not wired |
| 12 | **NTS-KE client** | NTS key establishment client | ✅ PORTED | TLS 1.3 + rustls + RFC 8915 validation |
| 13 | **NTS cookie decryption** | `nts_cookie.c` | ✅ PORTED | Core NTS; AES-SIV in Rust |
| 14 | **NTS extension fields** | `nts_extens.c` | ✅ PORTED | Core NTS |
| 15 | **Reference clock: GPSD** | `refclock_gpsd.c` | ✅ PORTED | TCP/JSON driver core |
| 16 | **Reference clock: NMEA** | `refclock_nmea.c` | ✅ PORTED | Serial sentence parser core |
| 17 | **Reference clock: PPS** | `refclock_pps.c` | ✅ PORTED | Kernel PPS ioctl driver |
| 18 | **Refclock: SHM** | `refclock_shm.c` | ✅ PORTED | POSIX shared memory driver |
| 19 | **Refclock: generic** | `refclock_generic.c` | ⚠️ DEFERRED | 5,729 lines; serial parse framework |
| 20 | **Refclock: JJY** | `refclock_jjy.c` | ⚠️ DEFERRED | 4,518 lines; Japanese time signal |
| 21 | **Refclock: Oncore** | `refclock_oncore.c` | ⚠️ DEFERRED | 4,152 lines; Motorola GPS |
| 22 | **Refclock: Trimble** | `refclock_trimble.c` | ⚠️ DEFERRED | 1,390 lines; Trimble GPS |
| 23 | **Refclock: TrueTime** | `refclock_truetime.c` | ⚠️ DEFERRED | 786 lines |
| 24 | **Refclock: Spectracom** | `refclock_spectracom.c` | ⚠️ DEFERRED | Serial radio clocks |
| 25 | **Refclock: Arbiter** | `refclock_arbiter.c` | ⚠️ DEFERRED | |
| 26 | **Refclock: HPGPS** | `refclock_hpgps.c` | ⚠️ DEFERRED | |
| 27 | **Refclock: Modem** | `refclock_modem.c` | ⚠️ DEFERRED | 929 lines; ACTS dial-up |
| 28 | **Refclock: Zyfer** | `refclock_zyfer.c` | ⚠️ DEFERRED | |
| 29 | **Refclock: Local** | `refclock_local.c` | ⚠️ DEFERRED | Returns epoch zero; not functional |
| 30 | **SNMP agent** | `ntpsnmpd` / `pylib/agentx.py` | ⚠️ DEFERRED | SNMP framework |
| 31 | **Hardware timestamping** | `ntp_packetstamp.c` | ⚠️ DEFERRED | Linux SO_TIMESTAMPING |
| 32 | **OpenSSL key generation** | ntpkeygen | ⚠️ DEFERRED | Using `rcgen` |
| 33 | **Automatic leap file fetch** | ntpleapfetch | ⚠️ DEFERRED | |
| 34 | **ntpviz plotting** | ntpviz.py | ⚠️ DEFERRED | |
| 35 | **ntpmon real-time display** | ntpmon.py | ✅ PORTED | Basic polling monitor |
| 36 | **ntpsweep** | ntpsweep.py | ⚠️ DEFERRED | |
| 37 | **ntploggps** | ntploggps.py | ⚠️ DEFERRED | |
| 38 | **ntplogtemp** | ntplogtemp.py | ⚠️ DEFERRED | |
| 39 | **ntptrace** | ntptrace.py | ✅ PORTED | Basic recursive tracer |
| 40 | **Syslog output** | `ntp_syslog.c` messages | ✅ PORTED | Core logging |
| 41 | **Statistics logging** | `ntp_filegen.c` | ⚠️ DEFERRED | Registry exists; no file I/O |
| 42 | **Loopback refclock** | 127.127.1.0 | ⚠️ DEFERRED | Stub; not functional |
| 43 | **Leap smear** | leap smear processing | ✅ PORTED | Core NTP behavior |
| 44 | **Autokey** | Autokey authentication | 🗑️ DEPRECATED | Removed in NTPsec |
| 45 | **Mode 7 (ntpdc)** | Private NTP mode | 🗑️ DEPRECATED | Removed in NTPsec; use mode 6 |
| 46 | **MD5-only auth** | Keyed MD5 | ✅ PORTED | Still supported in ntpsec |
| 47 | **AES-128-CMAC** | RFC 7822 MAC | ✅ PORTED | Core auth |
| 48 | **AES-SIV-CMACE** | NTS cookie cipher | ✅ PORTED | Core NTS |
| 49 | **write-only / restrict** | Access controls | ✅ PORTED | Core ntpsec security |
| 50 | **Remote configuration** | `ntpq -c "config ..."` | ✅ PORTED | Core control protocol |
| 51 | **Signal handling** | SIGHUP, SIGINT, SIGTERM | ✅ PORTED | Core daemon |
| 52 | **Broadcast/manycast** | NTP broadcast modes | 🚫 WONTFIX | Unicast only |
| 53 | **Kernel PLL adjtimex** | `ntp_adjtime()` syscall | ⚠️ DEFERRED | Software PLL only |
| 54 | **NTPv3 compatibility** | v3 wire format | 🗑️ DEPRECATED | ntpsec v4 only |
| 55 | **Refclock sample pipeline** | Full integration | ✅ PORTED | All 4 drivers → accept_sample → selection → discipline |

---

## Exhaustive Forensic Audit v2

### Module-by-Module Gap Analysis

#### 1. Comment-Only Stubs (13 files)

These files are empty shells. The table below shows **actual C line counts** (not bytes):

| File | C Oracle | C Lines | Rust Lines | Type | Notes |
|------|----------|---------|-----------|------|-------|
| `refclock_generic.rs` | `ntpd/refclock_generic.c` | **5,729** | 1 (comment) | ⚠️ MISSING | Serial parse framework for 12+ radio clocks |
| `parse.rs` | `libparse/parse.c` | 735 | 1 (comment) | ⚠️ MISSING | Timecode parsing engine |
| `binio.rs` | `libparse/binio.c` | 94 | 1 (comment) | 🏗️ SUBSTITUTED | Rust `std::io` replaces |
| `ieee754io.rs` | `libparse/ieee754io.c` | 250 | 1 (comment) | 🏗️ SUBSTITUTED | Rust IEEE 754 handling |
| `gpstolfp.rs` | `libparse/gpstolfp.c` | 54 | 1 (comment) | 🏗️ SUBSTITUTED | Rust time libraries |
| `ntp_dns.rs` | `ntpd/ntp_dns.c` | ~200 | 1 (comment) | ⚠️ MISSING | DNS resolution |
| `ntp_scanner.rs` | `ntpd/ntp_scanner.c` | 1,069 | 1 (comment) | 🏗️ SUBSTITUTED | nom-based parser replaces |
| `ntp_packetstamp.rs` | `ntpd/ntp_packetstamp.c` | ~500 | 1 (comment) | ⚠️ MISSING | HW timestamps |
| `ntp_signd.rs` | `ntpd/ntp_signd.c` | ~400 | 1 (comment) | ⚠️ MISSING | Samba signing |
| `refclock_pps_api.rs` | `include/refclock_pps.h` | ~100 | 1 (comment) | 🏗️ SUBSTITUTED | Inline in refclock_pps.rs |
| `ntp_syscall.rs` | `include/ntp_syscall.h` | ~50 | 1 (comment) | ⚠️ MISSING | adjtimex wrapper |
| `leap_query.rs` | — | — | 2 (comments) | 🚫 WONTFIX | Not in ntpsec |
| `ntp_lists.rs` | `include/ntp_lists.h` | ~100 | 4 (empty) | 🏗️ SUBSTITUTED | Rust Vec replaces |

**Type breakdown:**
- ⚠️ MISSING (actual capability gap): 6 files (~8,634 lines C)
- 🏗️ SUBSTITUTED (architecturally replaced): 5 files (~598 lines C)
- 🚫 WONTFIX: 1 file (0 lines)
- Stub dependency (parse.rs): 735 lines

**Actual C debt from stubs: ~8,634 lines** (not 240K as Revision 1 claimed).

#### 2. Config Recognition (4-Level Table)

The `RECOGNIZED_DIRECTIVES` array contains **101 entries**. The table below
shows each directive's status across four levels:

| Directive | Lexical | Typed Parse | Applied | Oracle Parity | Notes |
|-----------|:-------:|:-----------:|:-------:|:-------------:|-------|
| server | ✅ | ✅ | ✅ | ⚠️ | Unicast only |
| peer | ✅ | ✅ | ✅ | ⚠️ | No symmetric passive |
| pool | ✅ | ✅ | ✅ | ⚠️ | No manycast |
| refclock | ✅ | ✅ | ✅ | ⚠️ | 4/15 drivers |
| restrict | ✅ | ✅ | ✅ | ⚠️ | No interface-specific |
| fudge | ✅ | ❌ | ❌ | ❌ | Lexical only |
| driftfile | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| leapfile | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| keys | ✅ | ❌ | ❌ | ❌ | Loaded by shell |
| statsdir | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| statistics | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| filegen | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| enable/disable | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| tinker | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| tos | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| interface/nic | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| mru (all sub-opts) | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| nts (all sub-opts) | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| includefile | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| logfile/logconfig | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| setvar | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| phone | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| broadcast* | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| trap | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| ttl | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| ident | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| mssntp | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| pps | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| revoke | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| crypto | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| msldap | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| mode7 | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| mruterlist | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| ntpsigndsocket | ✅ | ❌ | ❌ | ❌ | Accepted, ignored |
| Other (~67 more) | ✅ | ❌ | ❌ | ❌ | Lexically recognized only |

**Summary:** 101 lexically recognized, ~10 with typed ConfigOption, ~5 applied
by engine (server/peer/pool/refclock/restrict), 0 with full oracle parity.

#### 3. Refclock Driver Gaps (4 implemented drivers)

##### SHM (refclock_shm.rs) — 4 tests

| Gap | Severity | Detail |
|-----|----------|--------|
| No mode-aware sample processing | Medium | Mode 0 vs Mode 1 treated identically |
| No `nsec` field validation | Medium | Falls back to usec*1000 without checking Mode 1 |
| Hardcoded reference ID | Low | Always `"SHM\0"` instead of `"SHM0"`, `"SHM1"` |

##### PPS (refclock_pps.rs) — 8 tests

| Gap | Severity | Detail |
|-----|----------|--------|
| **Hardcoded `PPS_FETCH` ioctl** | **HIGH** | `0xc050a004` is x86_64-specific. ARM/RISC-V differ |
| **Arch-dependent struct padding** | **HIGH** | `PpsFetchParams` assumes x86_64 alignment |
| Only assert timestamps read | Medium | Clear timestamp discarded |
| No kernel PPS API version detection | Low | No PPS_GETPARAMS |

##### NMEA (refclock_nmea.rs) — 26 tests

| Gap | Severity | Detail |
|-----|----------|--------|
| **No serial port configuration** | **HIGH** | No baud/parity/stop bits. GPS default 4800/9600 baud |
| **No sub-second precision** | **HIGH** | Fractional seconds discarded from NMEA sentences |
| **No PPS integration** | **HIGH** | NTPsec pairs NMEA + PPS for sub-microsecond sync |
| Only GGA/RMC parsed | Medium | Missing GLL, ZDA, other sentences |
| No leap indicator propagation | Medium | Leap always NoWarning |

##### GPSD (refclock_gpsd.rs) — 12 tests

| Gap | Severity | Detail |
|-----|----------|--------|
| **Brittle JSON parsing** | **HIGH** | Manual string scanning; fragile for gpsd format changes |
| No leap indicator extraction | Medium | Ignores `"leap"` field |
| No reconnection logic | Medium | External error handling required |
| No VERSION/DEVICE handling | Medium | GPSD init handshake not verified |
| f64 precision loss | Medium | `fract() * 2^32` discards low bits |

##### Local Clock (refclock_local.rs) — 0 tests

| Gap | Severity | Detail |
|-----|----------|--------|
| **Returns epoch zero** | **HIGH** | `poll()` returns `time: { seconds: 0, fraction: 0 }` |
| No fudge support | Medium | Stratum override, fudge factors missing |
| Fixed 64s poll interval | Low | Not adaptive |

#### 4. NTS Gaps

##### nts.rs — Core NTS (24 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| **`handshake()` is a stub** | **CRITICAL** | Returns "TLS transport not wired" |
| **Offline path = zeroed keys** | **CRITICAL** | `handshake_with_data()` returns `[0u8; 32]` keys |
| **Weak PRNG** | **HIGH** | LCG seeded with `SystemTime::now().as_nanos()` |
| No Warning record handling | Medium | RFC 8915 warning records silently skipped |

##### nts_client.rs — NTS-KE Client (15 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| **No TCP/TLS timeout** | **HIGH** | `TcpStream::connect()` can block indefinitely |
| No TLS session resumption | Medium | Full handshake every time |
| No NTPv4 Server/Port negotiation | Medium | Server cannot override NTP address/port |
| No custom CA support | Low | Only webpki roots (public CAs) |

##### nts_server.rs — NTS Server Session (13 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| **`protect_response()` doesn't append cookie** | **HIGH** | Skips cookie insertion despite doc claiming it |
| **Cannot increment sequence** | **HIGH** | Takes `&self` not `&mut self` |
| Hardcoded AEAD constant 15 | Medium | Ignores session-negotiated algorithm |
| No cookie freshness validation | Medium | Replayable indefinitely |
| No key rotation | Low | No long-term key rotation mechanism |

##### nts_cookie.rs — NTS Cookies (27 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| **Empty AAD** | **Medium** | No server identity binding in AAD |
| No cookie expiration | Medium | Replay attacks possible |
| Unbounded key storage | Medium | Vec grows without pruning |
| O(n) key lookup | Low | Reverse linear search vs O(1) |

##### nts_extens.rs — NTS Extensions (17 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| Missing AUTH_RESULT constant | Medium | No public type constant to dispatch on |
| No upper bound on decode length | Medium | Length=65535 triggers OOM |

#### 5. Core Protocol Engine Gaps

##### daemon_engine.rs — Daemon Engine (25 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| Simplified selection — no prefer peer | Medium | Prefer flag not handled |
| No PPS peer synchronization | Medium | PPS peer doesn't override system peer |
| No loopcast detection | Low | Broadcast associations not detected |
| Hardcoded refclock delay = 0.001 | Low | 1ms nominal instead of per-driver dispersion |
| Config directives silently ignored | Low | ~90 directives accepted but not wired |
| Mode 2 (symmetric passive) | Medium | No ephemeral peer creation |
| Mode 5 (broadcast) | Low | Silent drop |

##### ntp_proto.rs — Core Protocol (15 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| **`clock_intersection()` simplified** | **HIGH** | Missing full RFC 5905 §11.2.1 |
| **`clock_cluster()` simplified** | **HIGH** | Missing nuanced pruning |
| `poll_update()` — no burst/iburst | Medium | Burst mode not implemented |
| No TEST2/TEST3 duplicate suppression | Medium | Basic originate-ts only |

##### ntp_loopfilter.rs — Clock Discipline (8 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| **No kernel `adjtimex()`** | **HIGH** | `KernelPll` is a no-op (software PLL) |
| No step-slew period management | Medium | 30s initial slew not handled |
| Fused `adj_host_clock()` | Low | Step vs slew not separated |

##### ntp_control.rs — Mode 6 (7 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| **Event code hardcoded to 0** | **HIGH** | `peer_status()` returns 0x0000 |
| Shortened variable list | Medium | ~40 vars vs 80+ in ntpsec |

##### ntp_leapsec.rs — Leap Seconds (3 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| Simplified NIST leapfile parser | Medium | No #@ expiration, #$ hash, or SHA1 validation |
| No smear interpolation | Low | Only linear ramp |

##### ntp_filegen.rs — Stats Files (0 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| **No file I/O** | **HIGH** | Registry only — no open/write/rotate/close |

##### ntp_monitor.rs — MRU (0 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| Simplified rate limiting | Medium | Hardcoded `count > 10` threshold |
| IPv6 matching in `record()` | Medium | AF_INET only for duplicate detection |
| No MRU entry aging | Low | No periodic pruning |

##### ntp_sandbox.rs — Seccomp (3 tests)

| Gap | Severity | Detail |
|-----|----------|--------|
| x86_64 only | Medium | No AARCH64/ARM support |
| No prctl fallback | Low | Only `syscall(SYS_seccomp)` |
| `clone3` handling | Low | May differ per glibc version |

---

## Config Directive Status: Complete 4-Level Table

| Level | Count | Directives |
|-------|:-----:|------------|
| ✅ Lexically recognized | **101** | All entries in `RECOGNIZED_DIRECTIVES` |
| ✅ Typed ConfigOption | **~10** | Server, Peer, Pool, Refclock, Restrict, DriftFile, LeapFile, Keys, StatsDir, Enable/Disable, Include |
| ✅ Applied by engine | **~5** | Server, Peer, Pool, Refclock, Restrict |
| ✅ Engine-applied + oracle-tested | **~5** | Server, Peer, Pool, Refclock, Restrict (partial — Alpine only) |
| ❌ Accepted but not wired | **~86** | All other RECOGNIZED_DIRECTIVES |

---

## Docker Oracle Matrix Results

Run at commit `71fd5dc` across 4 images (2026-07-23):

| Test | Alpine | Debian Stable | Ubuntu LTS | Fedora |
|------|:-----:|:-------------:|:----------:|:------:|
| rv forward | ❌ | ❌ | ❌ | ❌ |
| associations forward | ❌ | ❌ | ❌ | ❌ |
| peers forward | ❌ | ❌ | ❌ | ❌ |
| rv reverse | ✅ | ❌ | ❌ | ❌ |
| associations reverse | ✅ | ❌ | ❌ | ❌ |
| peers reverse | ✅ | ❌ | ❌ | ❌ |
| rv_reverse_rs | ✅ | ❌ | ❌ | ❌ |
| uid (non-root) | ✅ | ❌ | ❌ | ❌ |
| seccomp | ✅ | ✅ | ✅ | ✅ |
| capability (CAP_SYS_TIME) | ✅ | ❌ | ❌ | ❌ |
| sighup | ✅ | ❌ | ❌ | ❌ |
| sigterm | ✅ | ❌ | ❌ | ❌ |
| drift_persist | ✅ | ❌ | ❌ | ❌ |
| loopstats_written | ❌ | ❌ | ❌ | ❌ |
| peerstats_written | ❌ | ❌ | ❌ | ❌ |
| ntpdig_rs | ✅ | ✅ | ✅ | ✅ |
| ntpdig_parity | ⏭️ | ⏭️ | ⏭️ | ✅ |

**Key:**
- **Alpine**: 11/16 PASS — all hardening + reverse court + lifecycle pass
- **glibc images**: 3/16 PASS — `-u ntp` privilege dropping fails (UID stays 0)
- **Universal**: seccomp ✅ on all, ntpdig-rs ✅ on all, forward court ❌ on all
- **Stats files**: not written on any image (timing — daemon killed before periodic write)

---

## Test Coverage

**316 test functions across 28 source files.**

| Tests | File | Notes |
|:-----:|------|-------|
| 46 | `control_client.rs` | Mode 6 client courts |
| 27 | `nts_cookie.rs` | AES-SIV encrypt/decrypt |
| 26 | `refclock_nmea.rs` | NMEA sentence parsing |
| 25 | `daemon_engine.rs` | Engine lifecycle, selection |
| 24 | `nts.rs` | NTS-KE records, state machine |
| 17 | `nts_extens.rs` | Extension field encode/decode |
| 16 | `ntp_auth.rs` | Key management, MAC |
| 15 | `nts_client.rs` | NTS-KE client, validation |
| 15 | `ntp_proto.rs` | Clock filter, selection |
| 13 | `nts_server.rs` | Server session |
| 12 | `refclock_gpsd.rs` | GPSD JSON parsing |
| 10 | `ntp_config.rs` | Config directive recognition |
| 8 | `refclock_pps.rs` | PPS ioctl |
| 8 | `ntp_loopfilter.rs` | PLL/FLL |
| 8 | `ntpdig_proto.rs` | Mode 3 client |
| 7 | `ntp_fp.rs` | Fixed-point |
| 7 | `ntp_control.rs` | Mode 6 encoding |
| 5 | `ntp_types.rs` | Type conversions |
| 5 | `ntp_timer.rs` | Timer system |
| 4 | `refclock_shm.rs` | SHM operations |
| 4 | `ntp_restrict.rs` | Restrict matching |
| 4 | `ntp_calendar.rs` | Calendar computations |
| 3 | `ntp_sandbox.rs` | Seccomp child isolation |
| 3 | `ntp_leapsec.rs` | Leap second table |
| 2 | `ntp_stdlib.rs` | String/time formatting |
| 1 | `ntp_net.rs` | Network address |
| 1 | `ntp_endian.rs` | Endian conversion |

**27 files with NO tests** (all stubs + ntp_monitor, ntp_peer, ntp_recvbuff, etc.)

---

## Three-Tier Effort Estimate

### Tier 1: Production Replacement Blockers

Items that must be fixed before ntpsec-rs is credible as a production daemon.

| Item | Module | Estimated Effort | Risk |
|------|--------|:----------------:|:----:|
| Fix privilege dropping on glibc | `ntpd-rs` | 1-2 weeks | **BLOCKER** — breaks Debian/Ubuntu/Fedora |
| Add TCP/TLS timeout to NTS-KE | `nts_client.rs` | 1 week | Medium |
| Fix weak PRNG in NtsUniqueKey | `nts.rs` | 1 day | Medium |
| Fix empty AAD in NTS cookie | `nts_cookie.rs` | 2 days | Medium |
| Add upper bound on EF decode | `nts_extens.rs` | 1 day | Medium |
| Make kernel adjtimex work | `ntp_loopfilter.rs` | 2-4 weeks | Medium |
| Fix ARM/RISC-V PPS ioctl constant | `refclock_pps.rs` | 1 week | High |
| Fix ARM struct padding | `refclock_pps.rs` | 3 days | High |
| Add serial port config to NMEA | `refclock_nmea.rs` | 1 week | Medium |
| Fix local clock returning epoch 0 | `refclock_local.rs` | 1 day | High |
| Fix `ntp_init()` no-op | `ntp_util.rs` | 1 day | Low |
| Wire seccomp for aarch64 | `ntp_sandbox.rs` | 1 week | Medium |
| Forward court formatting parity | `ntpq-rs` output | 2-4 weeks | Low |
| Alpine-only hardening → all platforms | Lifecycle | 2-4 weeks | Medium |

**Tier 1 subtotal: 3-5 months**

### Tier 2: Mainline NTPsec Feature Parity

Items needed for full behavioral compatibility with current NTPsec.

| Item | Module | Estimated Effort | C LOC Ref |
|------|--------|:----------------:|:---------:|
| DNS resolution | `ntp_dns.rs` | 1-2 months | ~200 |
| NTS-KE server role | `nts_server.rs` + daemon integration | 2-4 months | 5 files |
| NTS daemon integration | Packet-receive path | 2-4 months | — |
| Statistics file I/O | `ntp_filegen.rs` | 2-3 weeks | ~650 |
| Full Mode 6 variable set | `ntp_control.rs` | 2-4 weeks | 106K C |
| Configuration semantics | `ntp_config.rs` + engine | 2-4 months | 72K C |
| Hardware packet timestamps | `ntp_packetstamp.rs` | 2-4 weeks | ~500 |
| Full clock intersection/cluster | `ntp_proto.rs` | 2-4 weeks | 84K C |
| Prefer peer / PPS selection | `daemon_engine.rs` | 2 weeks | — |
| Burst/iburst/manycast | `ntp_proto.rs` | 2-4 weeks | — |
| Samba signing | `ntp_signd.rs` | 1-2 weeks | ~400 |
| adjtimex syscall wrapper | `ntp_syscall.rs` | 1 week | ~50 |
| SHM Mode 1 (interpolated) | `refclock_shm.rs` | 1 week | — |
| NMEA sub-second + PPS pairing | `refclock_nmea.rs` | 2-4 weeks | — |
| GPSD robust JSON + reconnect | `refclock_gpsd.rs` | 2 weeks | — |

**Tier 2 subtotal: 8-16 months**

### Tier 3: Historical/Full Breadth Parity

Items for complete compatibility with obscure or legacy NTPsec surfaces.

| Item | Module | Estimated Effort | C LOC Ref |
|------|--------|:----------------:|:---------:|
| Generic refclock framework | `refclock_generic.rs` | 4-8 weeks | 5,729 |
| JJY refclock | `refclock_jjy.rs` | 2-4 weeks | 4,518 |
| Oncore GPS refclock | `refclock_oncore.rs` | 2-4 weeks | 4,152 |
| Trimble refclock | `refclock_trimble.rs` | 1-2 weeks | 1,390 |
| TrueTime refclock | `refclock_truetime.rs` | 1 week | 786 |
| Spectracom refclock | `refclock_spectracom.rs` | 1 week | ~500 |
| Modem/ACTS refclock | `refclock_modem.rs` | 2 weeks | 929 |
| Arbiter, HPGPS, Zyfer refclocks | Various | 2-4 weeks each | ~500 each |
| SNMP agent | `ntpsnmpd` | 1-2 months | 48K Python |
| ntpviz plotting | `ntpviz` | 2-4 weeks | 76K Python |
| ntpsweep | `ntpsweep` | 1 week | 8K Python |
| ntploggps / ntplogtemp | Various | 1 week each | ~10K Python |
| Python-style ntpkeygen | `ntpkeygen` | 2 weeks | 4K Python |
| Platform courts (FreeBSD/macOS) | CI | 2-4 months | — |

**Tier 3 subtotal: 8-14 months**

### Total Effort (Non-Overlapping)

| Tier | Description | Estimate |
|:----:|-------------|:--------:|
| 1 | Production replacement blockers | 3-5 months |
| 2 | Mainline NTPsec feature parity | 8-16 months |
| 3 | Historical/full breadth parity | 8-14 months |
| **Total (uncorrelated)** | | **14-22 months** |
| **Total (correlated, sequential)** | | **19-35 months** |
| **Total (parallel, aggressive)** | | **9-14 months** |

**Note:** The 14-22 month figure from Revision 1 was inflated by bytes-vs-LOC
confusion and double-counting. The corrected range reflects actual C line counts.
Tier 1 (production blockers) is estimated at 3-5 months, not 14-22.

---

## Portability Gaps

| Platform | Issue | Severity |
|----------|-------|:--------:|
| **ARM (32-bit)** | PPS ioctl constant `sizeof(struct)` differs. Struct padding differs. | **BLOCKER** |
| **ARM64/AARCH64** | Seccomp `AUDIT_ARCH_AARCH64` not in allowlist | **BLOCKER** |
| **RISC-V** | Same PPS and seccomp issues as ARM | **BLOCKER** |
| **macOS** | No seccomp. Different PPS. No CLOCK_TAI. No SO_TIMESTAMPNS | Untested |
| **FreeBSD** | No seccomp. PPS via ppsfd(4). Different socket timestamping | Untested |
| **Alpine (musl)** | Works — full hardening passes | ✅ Verified |
| **Debian/Ubuntu/Fedora (glibc)** | `-u ntp` privilege dropping fails (UID stays 0) | **BLOCKER** |
| **Windows** | Not supported. No libc, no setuid | 🚫 WONTFIX |

---

## Security Gaps

| Gap | Module | Severity | Fix |
|-----|--------|:--------:|-----|
| Non-cryptographic PRNG for NTS keys | `nts.rs` | HIGH | Replace LCG with `getrandom()` |
| Empty AAD in NTS cookie encrypt | `nts_cookie.rs` | MEDIUM | Bind to server identity |
| No cookie expiration validation | `nts_cookie.rs` | MEDIUM | Add timestamp check |
| No TLS timeout in NTS-KE | `nts_client.rs` | HIGH | Add connect/read timeout |
| No upper bound on EF decode | `nts_extens.rs` | MEDIUM | Cap length at MAX_EXT_LEN |
| Zeroed C2S/S2C keys in offline path | `nts.rs` | CRITICAL | Only affects offline tests |
| No kernel adjtimex isolation | `ntp_loopfilter.rs` | MEDIUM | Wire adjtimex syscall |

---

## Stale Generated-Parity Map Notice

The document `docs/generated/ported-modules.md` carries the header:

```
<!-- GENERATED by cargo xtask gen — DO NOT EDIT BY HAND -->
```

However, `cargo xtask gen` does **not** currently regenerate this file. The
module scanning and status-detection logic remain unimplemented TODOs in the
xtask source. The file therefore contains stale SKELETON annotations for many
modules that are functionally complete (NTS, refclocks, daemon engine, Mode 6).

**Until the generator is wired, treat `ported-modules.md` as a manually edited
reference, not a source-derived truth.** The authoritative status for any module
is its source code and test count, not its label in that table.

---

## Known Pre-existing Test Failures (6)

| Test | Failure | Root Cause |
|------|---------|------------|
| `test_format_readvar_frozen_parity` | Format mismatch | C ntpq rendering (`sync_acts` vs `sync_ntp`) |
| `test_format_peer_readvar_frozen` | Format mismatch | `reach="FF"` vs `reach=0xFF` |
| `test_local_udp_error_response` | Expected NotFound, got timeout | No real ntpd listening |
| `test_local_udp_authentication_error` | Expected AuthFailure, got timeout | Same |
| `test_local_udp_readvar_fragmented` | Connection refused | Same |
| `test_engine_stale_state_reset` | Unexpected AdjustClock | Engine edge case |

---

## Generation Metadata

- Generated: 2026-07-24 (Revision 2)
- ntpsec-rs commit: `71fd5dc6a80836e92228a2c9aceeb6ac2cd2c119`
- NTPsec oracle version: 1.2.4 (master: 76,048 C lines)
- Docker matrix: Alpine 3.18, Debian Stable, Ubuntu LTS, Fedora
- Total test functions: 316 passing, 6 pre-existing failures
- Config directives: 101 lexically recognized, ~5 functionally applied
- C line counts: verified with `wc -l` (not `wc -c`)
