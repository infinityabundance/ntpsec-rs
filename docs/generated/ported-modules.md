<!-- Phase 3 sealed at v0.3.8 — this file is manually updated to reflect current state. -->

# Ported Modules (v0.3.8)

Status as of 2026-07-24 at commit `64a122e`. 524 tests pass, 3 pre-existing
network-dependent failures remain.

Status definitions:

- **✅ PORTED**: Functionally complete, differential-tested against oracle
- **🔧 IN PROGRESS**: Structure ported, implementation in progress
- **📋 SKELETON**: Module skeleton present, not yet implemented
- **⏳ DEFERRED**: Implementation deferred to a later phase
- **🚫 NOT PLANNED**: Will not be ported (deprecated/out of scope)

## libntp (28 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| libntp/authkeys.c | ntpsec_rs_core::ntp_auth | ✅ PORTED | Auth key management, 16 tests |
| libntp/authreadkeys.c | ntpsec_rs_core::ntp_auth | ✅ PORTED | Key file parsing |
| libntp/clocktime.c | ntpsec_rs_core::ntp_calendar | ✅ PORTED | Calendar conversion |
| libntp/clockwork.c | ntpsec_rs_core::ntp_util | 🔧 IN PROGRESS | Utility functions |
| libntp/decodenetnum.c | ntpsec_rs_core::ntp_net | ✅ PORTED | Network number decoding |
| libntp/dolfptoa.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Fixed-point formatting |
| libntp/emalloc.c | ntpsec_rs_core::ntp_malloc | ✅ PORTED | Error-checked allocations |
| libntp/getopt.c | (not needed) | 🚫 NOT PLANNED | Replaced by clap |
| libntp/hextolfp.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Hex to fixed-point |
| libntp/initnetwork.c | ntpsec_rs_io | ✅ PORTED | Network initialization |
| libntp/isc_interfaceiter.c | ntpsec_rs_io | 🔧 IN PROGRESS | Interface iteration |
| libntp/isc_net.c | ntpsec_rs_core::ntp_net | 🔧 IN PROGRESS | ISC network utils |
| libntp/lib_strbuf.c | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | String buffer pool |
| libntp/macencrypt.c | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | MAC computation |
| libntp/msyslog.c | ntpsec_rs_core::ntp_syslog | ✅ PORTED | Syslog output |
| libntp/ntp_c.c | ntpsec_rs_core | ✅ PORTED | NTP C-string helpers |
| libntp/ntp_calendar.c | ntpsec_rs_core::ntp_calendar | ✅ PORTED | Calendar computations |
| libntp/ntp_endian.c | ntpsec_rs_core::ntp_endian | ✅ PORTED | Endian conversion |
| libntp/ntp_random.c | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | Random number source |
| libntp/numtoa.c | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | Number to address string |
| libntp/prettydate.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Date formatting |
| libntp/refidsmear.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Refid smear detection |
| libntp/socket.c | ntpsec_rs_io | ✅ PORTED | Socket creation |
| libntp/socktoa.c | ntpsec_rs_core::ntp_net | 🔧 IN PROGRESS | Socket to address |
| libntp/ssl_init.c | ntpsec_rs_io | ✅ PORTED | TLS init |
| libntp/statestr.c | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | Event string names |
| libntp/strl_obsd.c | (not needed) | 🚫 NOT PLANNED | Use Rust string handling |
| libntp/syssignal.c | ntpsec_rs_io | ✅ PORTED | Signal handling |
| libntp/systime.c | ntpsec_rs_io | ✅ PORTED | System time calls |
| libntp/timespecops.c | ntpsec_rs_core::timespecops | ✅ PORTED | Timespec operations |

## libparse (17 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| libparse/parse.c | ntpsec_rs_core::parse | ✅ PORTED | Parse engine, 10 tests |
| libparse/binio.c | ntpsec_rs_core::binio | ✅ PORTED | Binary I/O utilities |
| libparse/ieee754io.c | ntpsec_rs_core::ieee754io | ✅ PORTED | IEEE 754 I/O |
| libparse/gpstolfp.c | ntpsec_rs_core::gpstolfp | ✅ PORTED | GPS to timestamp |
| libparse/clk_*.c | (deferred) | ⏳ DEFERRED | 12 clock drivers — niche hardware |
| libparse/data_mbg.c | (deferred) | ⏳ DEFERRED | Meinberg data |
| libparse/info_trimble.c | (deferred) | ⏳ DEFERRED | Trimble info |
| libparse/trim_info.c | (deferred) | ⏳ DEFERRED | Trimble info |

## ntpd core (18 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| ntpd/ntpd.c | ntpsec-rs-d | ✅ PORTED | Daemon main, hardening lifecycle |
| ntpd/ntp_proto.c | ntpsec_rs_core::ntp_proto | 🔧 IN PROGRESS | Protocol engine — full intersection, combine, filter |
| ntpd/ntp_io.c | ntpsec_rs_io | ✅ PORTED | I/O dispatch traits |
| ntpd/ntp_control.c | ntpsec_rs_core::ntp_control | 🔧 IN PROGRESS | Mode 6 — READSTAT, READVAR, status encoding |
| ntpd/ntp_config.c | ntpsec_rs_core::ntp_config | 🔧 IN PROGRESS | Config parser — 103 directives recognized |
| ntpd/ntp_loopfilter.c | ntpsec_rs_core::ntp_loopfilter | ✅ PORTED | Clock discipline — PLL/FLL, adjtimex |
| ntpd/ntp_peer.c | ntpsec_rs_core::ntp_peer | ✅ PORTED | Peer management, 5 tests |
| ntpd/ntp_timer.c | ntpsec_rs_core::ntp_timer | ✅ PORTED | Timer events, 5 tests |
| ntpd/ntp_leapsec.c | ntpsec_rs_core::ntp_leapsec | 🔧 IN PROGRESS | Leap seconds, 3 tests |
| ntpd/ntp_util.c | ntpsec_rs_core::ntp_util | ✅ PORTED | Utilities — ntp_init, refid_from_addr |
| ntpd/ntp_restrict.c | ntpsec_rs_core::ntp_restrict | ✅ PORTED | Access control, 4 tests |
| ntpd/ntp_monitor.c | ntpsec_rs_core::ntp_monitor | ✅ PORTED | MRU monitoring, rate limiting |
| ntpd/ntp_sandbox.c | ntpsec_rs_core::ntp_sandbox | ✅ PORTED | Seccomp BPF, 3 tests |
| ntpd/ntp_refclock.c | ntpsec_rs_core::ntp_refclock | ✅ PORTED | Refclock manager |
| ntpd/ntp_filegen.c | ntpsec_rs_core::ntp_filegen | ✅ PORTED | Stats generation with file I/O + rotation |
| ntpd/ntp_dns.c | ntpsec_rs_core::ntp_dns | ✅ PORTED | DNS resolution |
| ntpd/ntp_signd.c | ntpsec_rs_core::ntp_signd | ✅ PORTED | Samba signing scaffold |
| ntpd/ntp_recvbuff.c | ntpsec_rs_core::ntp_recvbuff | ✅ PORTED | Buffer pool |

## NTS (5 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| ntpd/nts.c | ntpsec_rs_core::nts | ✅ PORTED | NTS core — state machine, records, 24 tests |
| ntpd/nts_client.c | ntpsec_rs_core::nts_client | ✅ PORTED | NTS-KE TLS 1.3 client, RFC 8915 validation, 15 tests |
| ntpd/nts_server.c | ntpsec_rs_core::nts_server | 🔧 IN PROGRESS | NTS server — session auth, protect, KE handler, 23 tests |
| ntpd/nts_cookie.c | ntpsec_rs_core::nts_cookie | ✅ PORTED | NTS cookies — AES-SIV-CMAC-256, key rotation, 27 tests |
| ntpd/nts_extens.c | ntpsec_rs_core::nts_extens | ✅ PORTED | NTS extensions — all 4 field types, 17 tests |

## Refclock drivers (16 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| refclock_local.c | ntpsec_rs_core::refclock_local | ✅ PORTED | Local clock — returns system time |
| refclock_pps.c | ntpsec_rs_core::refclock_pps | ✅ PORTED | PPS — kernel ioctl, 8 tests |
| refclock_shm.c | ntpsec_rs_core::refclock_shm | ✅ PORTED | SHM — shmget/shmat, 4 tests |
| refclock_gpsd.c | ntpsec_rs_core::refclock_gpsd | ✅ PORTED | GPSD — TCP/JSON with serde, 12 tests |
| refclock_nmea.c | ntpsec_rs_core::refclock_nmea | ✅ PORTED | NMEA — GGA/RMC parser, 26 tests |
| refclock_jjy.c | ntpsec_rs_core::refclock_jjy | ✅ PORTED | JJY — 7 receiver subtypes |
| refclock_oncore.c | ntpsec_rs_core::refclock_oncore | ✅ PORTED | Oncore — Motorola binary protocol |
| refclock_trimble.c | ntpsec_rs_core::refclock_trimble | ✅ PORTED | Trimble — TSIP DLE/ETX |
| refclock_truetime.c | ntpsec_rs_core::refclock_truetime | ✅ PORTED | TrueTime — GPS receivers |
| refclock_spectracom.c | ntpsec_rs_core::refclock_spectracom | ✅ PORTED | Spectracom — radio clocks |
| refclock_arbiter.c | ntpsec_rs_core::refclock_arbiter | ✅ PORTED | Arbiter — 1088A/B GPS |
| refclock_hpgps.c | ntpsec_rs_core::refclock_hpgps | ✅ PORTED | HP GPS — Z3801A |
| refclock_modem.c | ntpsec_rs_core::refclock_modem | ✅ PORTED | Modem — ACTS dial-up |
| refclock_zyfer.c | ntpsec_rs_core::refclock_zyfer | ✅ PORTED | Zyfer — GPStarplus |
| refclock_generic.c | ntpsec_rs_core::refclock_generic | ✅ PORTED | Generic — read_timecode with parse engine |

## Headers ported as Rust modules

| Header | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| include/ntp.h | ntpsec_rs_core::ntp_types | ✅ PORTED | Core types |
| include/ntp_fp.h | ntpsec_rs_core::ntp_fp | ✅ PORTED | Fixed-point |
| include/ntp_calendar.h | ntpsec_rs_core::ntp_calendar | ✅ PORTED | Calendar types |
| include/ntp_types.h | ntpsec_rs_core::ntp_types | ✅ PORTED | Sized types |
| include/ntp_net.h | ntpsec_rs_core::ntp_net | 📋 SKELETON | Network types |
| include/ntp_stdlib.h | ntpsec_rs_core::ntp_stdlib | 📋 SKELETON | Stdlib types |
| include/ntp_malloc.h | ntpsec_rs_core::ntp_malloc | 📋 SKELETON | Memory types |
| include/ntp_syslog.h | ntpsec_rs_core::ntp_syslog | 📋 SKELETON | Syslog types |
| include/ntp_auth.h | ntpsec_rs_core::ntp_auth | 📋 SKELETON | Auth types |
| include/ntpd.h | ntpsec_rs_core::ntp_config | 📋 SKELETON | Daemon types |
| include/ntp_refclock.h | ntpsec_rs_core::ntp_refclock | 📋 SKELETON | Refclock types |
| include/ntp_lists.h | ntpsec_rs_core::ntp_lists | 📋 SKELETON | List types |
| include/nts.h | ntpsec_rs_core::nts | 📋 SKELETON | NTS types |
| include/nts2.h | ntpsec_rs_core::nts | 📋 SKELETON | NTS internal |
| include/recvbuff.h | ntpsec_rs_core::ntp_recvbuff | 📋 SKELETON | Buffer types |
