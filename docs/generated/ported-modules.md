# Ported Modules

<!-- ⚠️ STALE — `cargo xtask gen` does not yet regenerate this file.
     The generator logic is a TODO. Status labels may not reflect current code.
     See negative-capabilities.md Revision 2 for authoritative module status. -->

This document lists every ntpsec C translation unit and its ntpsec-rs port
status. Status definitions:

- **✅ PORTED**: Functionally complete, differential-tested against oracle
- **🔧 IN PROGRESS**: Structure ported, implementation in progress
- **📋 SKELETON**: Module skeleton present, not yet implemented
- **⏳ DEFERRED**: Implementation deferred to a later phase
- **🚫 NOT PLANNED**: Will not be ported (deprecated/out of scope)

## libntp (28 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| libntp/authkeys.c | ntpsec_rs_core::ntp_auth | 📋 SKELETON | Auth key management |
| libntp/authreadkeys.c | ntpsec_rs_core::ntp_auth | 📋 SKELETON | Read keys file |
| libntp/clocktime.c | ntpsec_rs_core::ntp_calendar | 📋 SKELETON | Calendar conversion |
| libntp/clockwork.c | ntpsec_rs_core::ntp_util | 📋 SKELETON | Clock work estimates |
| libntp/decodenetnum.c | ntpsec_rs_core::ntp_net | 📋 SKELETON | Decode network numbers |
| libntp/dolfptoa.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Fixed-point formatting |
| libntp/emalloc.c | ntpsec_rs_core::ntp_malloc | 📋 SKELETON | Error-checked allocations |
| libntp/getopt.c | (not needed) | 🚫 NOT PLANNED | Use clap |
| libntp/hextolfp.c | ntpsec_rs_core::ntp_fp | 📋 SKELETON | Hex to fixed-point |
| libntp/initnetwork.c | ntpsec_rs_io | 📋 SKELETON | Network init |
| libntp/isc_interfaceiter.c | ntpsec_rs_io | 📋 SKELETON | Interface iteration |
| libntp/isc_net.c | ntpsec_rs_core::ntp_net | 📋 SKELETON | ISC network utils |
| libntp/lib_strbuf.c | ntpsec_rs_core::ntp_stdlib | 📋 SKELETON | String buffer pool |
| libntp/macencrypt.c | ntpsec_rs_core::ntp_stdlib | 📋 SKELETON | MAC computation |
| libntp/msyslog.c | ntpsec_rs_core::ntp_syslog | 📋 SKELETON | Syslog output |
| libntp/ntp_c.c | ntpsec_rs_core | 📋 SKELETON | NTP C-string helpers |
| libntp/ntp_calendar.c | ntpsec_rs_core::ntp_calendar | ✅ PORTED | Calendar computations |
| libntp/ntp_endian.c | ntpsec_rs_core::ntp_endian | 📋 SKELETON | Endian conversion |
| libntp/ntp_random.c | ntpsec_rs_core::ntp_stdlib | 📋 SKELETON | Random number source |
| libntp/numtoa.c | ntpsec_rs_core::ntp_stdlib | 📋 SKELETON | Number to address string |
| libntp/prettydate.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Date formatting |
| libntp/refidsmear.c | ntpsec_rs_core::ntp_fp | 📋 SKELETON | Refid smear detection |
| libntp/socket.c | ntpsec_rs_io | 📋 SKELETON | Socket creation |
| libntp/socktoa.c | ntpsec_rs_core::ntp_net | 📋 SKELETON | Socket to address |
| libntp/ssl_init.c | ntpsec_rs_io | 📋 SKELETON | TLS init |
| libntp/statestr.c | ntpsec_rs_core::ntp_stdlib | 📋 SKELETON | Event string names |
| libntp/strl_obsd.c | (not needed) | 🚫 NOT PLANNED | Use Rust string handling |
| libntp/syssignal.c | ntpsec_rs_io | 📋 SKELETON | Signal handling |
| libntp/systime.c | ntpsec_rs_io | 📋 SKELETON | System time calls |
| libntp/timespecops.c | ntpsec_rs_core::timespecops | 📋 SKELETON | Timespec operations |

## libparse (17 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| libparse/parse.c | ntpsec_rs_core::parse | 📋 SKELETON | Parse engine |
| libparse/binio.c | ntpsec_rs_core::binio | 📋 SKELETON | Binary I/O |
| libparse/ieee754io.c | ntpsec_rs_core::ieee754io | 📋 SKELETON | IEEE 754 I/O |
| libparse/gpstolfp.c | ntpsec_rs_core::gpstolfp | 📋 SKELETON | GPS to timestamp |
| libparse/clk_*.c | (deferred) | ⏳ DEFERRED | 12 clock drivers |
| libparse/data_mbg.c | (deferred) | ⏳ DEFERRED | Meinberg data |
| libparse/info_trimble.c | (deferred) | ⏳ DEFERRED | Trimble info |
| libparse/trim_info.c | (deferred) | ⏳ DEFERRED | Trimble info |

## ntpd core (18 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| ntpd/ntpd.c | ntpd_rs | 📋 SKELETON | Daemon main |
| ntpd/ntp_proto.c | ntpsec_rs_core::ntp_proto | 📋 SKELETON | Protocol engine (84K) |
| ntpd/ntp_io.c | ntpsec_rs_io | 📋 SKELETON | I/O dispatch (72K) |
| ntpd/ntp_control.c | ntpsec_rs_core::ntp_control | 📋 SKELETON | Mode 6 (106K) |
| ntpd/ntp_config.c | ntpsec_rs_core::ntp_config | 📋 SKELETON | Config parser (72K) |
| ntpd/ntp_loopfilter.c | ntpsec_rs_core::ntp_loopfilter | 📋 SKELETON | Clock discipline |
| ntpd/ntp_peer.c | ntpsec_rs_core::ntp_peer | 📋 SKELETON | Peer management |
| ntpd/ntp_timer.c | ntpsec_rs_core::ntp_timer | 📋 SKELETON | Timer events |
| ntpd/ntp_leapsec.c | ntpsec_rs_core::ntp_leapsec | 📋 SKELETON | Leap seconds |
| ntpd/ntp_util.c | ntpsec_rs_core::ntp_util | 📋 SKELETON | Utilities |
| ntpd/ntp_restrict.c | ntpsec_rs_core::ntp_restrict | 📋 SKELETON | Access control |
| ntpd/ntp_monitor.c | ntpsec_rs_core::ntp_monitor | 📋 SKELETON | Monitoring |
| ntpd/ntp_sandbox.c | ntpsec_rs_core::ntp_sandbox | 📋 SKELETON | Seccomp |
| ntpd/ntp_refclock.c | ntpsec_rs_core::ntp_refclock | 📋 SKELETON | Refclock base |
| ntpd/ntp_filegen.c | ntpsec_rs_core::ntp_filegen | 📋 SKELETON | Stats generation |
| ntpd/ntp_dns.c | ntpsec_rs_core::ntp_dns | 📋 SKELETON | DNS |
| ntpd/ntp_signd.c | ntpsec_rs_core::ntp_signd | 📋 SKELETON | Samba signing |
| ntpd/ntp_recvbuff.c | ntpsec_rs_core::ntp_recvbuff | 📋 SKELETON | Buffer pool |

## NTS (5 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| ntpd/nts.c | ntpsec_rs_core::nts | 📋 SKELETON | NTS core |
| ntpd/nts_client.c | ntpsec_rs_core::nts_client | 📋 SKELETON | NTS client |
| ntpd/nts_server.c | ntpsec_rs_core::nts_server | 📋 SKELETON | NTS server |
| ntpd/nts_cookie.c | ntpsec_rs_core::nts_cookie | 📋 SKELETON | NTS cookies |
| ntpd/nts_extens.c | ntpsec_rs_core::nts_extens | 📋 SKELETON | NTS extensions |

## Refclock drivers (16 files)

| C file | Rust module | Status | Notes |
|--------|-----------|--------|-------|
| refclock_local.c | ntpsec_rs_core::refclock_local | 📋 SKELETON | Local clock |
| refclock_pps.c | ntpsec_rs_core::refclock_pps | 📋 SKELETON | PPS |
| refclock_shm.c | ntpsec_rs_core::refclock_shm | 📋 SKELETON | SHM |
| refclock_gpsd.c | (deferred) | ⏳ DEFERRED | GPSD |
| refclock_nmea.c | (deferred) | ⏳ DEFERRED | NMEA |
| refclock_*.c (11 more) | (deferred) | ⏳ DEFERRED | Other drivers |

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
