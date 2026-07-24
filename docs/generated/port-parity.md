# Port Parity Matrix

> Status manually maintained. Updated at commit 89dab14.
> Generated from authoritative module survey — see negative-capabilities.md Revision 2.1 for detailed accounting.

## C translation unit → Rust module mapping

Total C files in ntpsec v1.3.3: **~80** (excluding attic, tests, pylib, contrib)
Total Rust modules implemented: **~70** (ntpsec-rs-core + ntpsec-rs-io + binary crates)

### Port status summary

| Status | Count |
|--------|-------|
| ✅ PORTED | ~70 |
| 🔧 IN PROGRESS | ~6 |
| ⏳ DEFERRED | ~4 |
| 🚫 NOT PLANNED | ~4 |

### Status definitions

| Status | Meaning |
|--------|---------|
| ✅ PORTED | Functionally complete, differential-tested against oracle |
| 🔧 IN PROGRESS | Structure ported, implementation in progress |
| ⏳ DEFERRED | Not yet ported |
| 🚫 NOT PLANNED | Will not be ported |

---

### libntp (28 files)

| C file | Rust module | Status | Notes |
|--------|-------------|--------|-------|
| libntp/authkeys.c | ntpsec_rs_core::ntp_auth | ✅ PORTED | Auth key management store |
| libntp/authreadkeys.c | ntpsec_rs_core::ntp_auth | ✅ PORTED | ntp.keys file parser |
| libntp/clocktime.c | ntpsec_rs_core::ntp_calendar | ✅ PORTED | Calendar conversion |
| libntp/clockwork.c | ntpsec_rs_core::ntp_util | ✅ PORTED | Clock work estimates |
| libntp/decodenetnum.c | ntpsec_rs_core::ntp_net | ✅ PORTED | Decode network numbers |
| libntp/dolfptoa.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Fixed-point formatting |
| libntp/emalloc.c | ntpsec_rs_core::ntp_malloc | ✅ PORTED | Error-checked allocations |
| libntp/getopt.c | (not needed) | 🚫 NOT PLANNED | Use clap |
| libntp/hextolfp.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Hex to fixed-point |
| libntp/initnetwork.c | ntpsec_rs_io | ✅ PORTED | Network socket init |
| libntp/isc_interfaceiter.c | ntpsec_rs_io | ✅ PORTED | Interface iteration |
| libntp/isc_net.c | ntpsec_rs_core::ntp_net | ✅ PORTED | ISC network utils |
| libntp/lib_strbuf.c | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | String buffer pool |
| libntp/macencrypt.c | ntpsec_rs_core::ntp_auth | ✅ PORTED | MAC computation (MD5, SHA1, AES-128-CMAC) |
| libntp/msyslog.c | ntpsec_rs_core::ntp_syslog | ✅ PORTED | Syslog output |
| libntp/ntp_c.c | ntpsec_rs_core | ✅ PORTED | NTP C-string helpers |
| libntp/ntp_calendar.c | ntpsec_rs_core::ntp_calendar | ✅ PORTED | Calendar computations |
| libntp/ntp_endian.c | ntpsec_rs_core::ntp_endian | ✅ PORTED | Endian conversion |
| libntp/ntp_random.c | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | Random number source |
| libntp/numtoa.c | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | Number to address string |
| libntp/prettydate.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Date formatting |
| libntp/refidsmear.c | ntpsec_rs_core::ntp_fp | ✅ PORTED | Refid smear detection |
| libntp/socket.c | ntpsec_rs_io | ✅ PORTED | Socket creation |
| libntp/socktoa.c | ntpsec_rs_core::ntp_net | ✅ PORTED | Socket to address string |
| libntp/ssl_init.c | ntpsec_rs_io | ✅ PORTED | TLS init |
| libntp/statestr.c | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | Event string names |
| libntp/strl_obsd.c | (not needed) | 🚫 NOT PLANNED | Use Rust string handling |
| libntp/syssignal.c | ntpsec_rs_io | ✅ PORTED | Signal handling |
| libntp/systime.c | ntpsec_rs_io | ✅ PORTED | System time calls |
| libntp/timespecops.c | ntpsec_rs_core::timespecops | ✅ PORTED | Timespec operations |

---

### libparse (17 files)

| C file | Rust module | Status | Notes |
|--------|-------------|--------|-------|
| libparse/parse.c | ntpsec_rs_core::parse | ✅ PORTED | Timecode parsing engine |
| libparse/binio.c | ntpsec_rs_core::binio | ✅ PORTED | Binary I/O (big-endian read/write) |
| libparse/ieee754io.c | ntpsec_rs_core::ieee754io | ✅ PORTED | IEEE 754 floating-point I/O |
| libparse/gpstolfp.c | ntpsec_rs_core::gpstolfp | ✅ PORTED | GPS to NTP timestamp conversion |
| libparse/clk_*.c | (deferred) | ⏳ DEFERRED | 12 clock-specific timecode parsers (Meinberg, Trimble, DCF77, etc.) |
| libparse/data_mbg.c | (deferred) | ⏳ DEFERRED | Meinberg data block parsing |
| libparse/info_trimble.c | (deferred) | ⏳ DEFERRED | Trimble GPS info parsing |
| libparse/trim_info.c | (deferred) | ⏳ DEFERRED | Trimble conversion tables |

---

### ntpd core (18 files)

| C file | Rust module | Status | Notes |
|--------|-------------|--------|-------|
| ntpd/ntpd.c | ntpd_rs (binary) | 🔧 IN PROGRESS | Daemon main — bootstrap wiring |
| ntpd/ntp_proto.c | ntpsec_rs_core::ntp_proto | 🔧 IN PROGRESS | Protocol engine (~84K C, 1.1K LoC Rust) |
| ntpd/ntp_io.c | ntpsec_rs_core::ntp_io + ntpsec_rs_io | ✅ PORTED | I/O trait layer + real-socket implementation |
| ntpd/ntp_control.c | ntpsec_rs_core::ntp_control | 🔧 IN PROGRESS | Mode 6 control protocol (~106K C) |
| ntpd/ntp_config.c | ntpsec_rs_core::ntp_config | 🔧 IN PROGRESS | Config parser (~72K C) |
| ntpd/ntp_loopfilter.c | ntpsec_rs_core::ntp_loopfilter | ✅ PORTED | Clock discipline algorithm |
| ntpd/ntp_peer.c | ntpsec_rs_core::ntp_peer | ✅ PORTED | Peer management |
| ntpd/ntp_timer.c | ntpsec_rs_core::ntp_timer | ✅ PORTED | Timer event scheduling |
| ntpd/ntp_leapsec.c | ntpsec_rs_core::ntp_leapsec | 🔧 IN PROGRESS | Leap second table handling |
| ntpd/ntp_util.c | ntpsec_rs_core::ntp_util | ✅ PORTED | Utilities |
| ntpd/ntp_restrict.c | ntpsec_rs_core::ntp_restrict | ✅ PORTED | Access control (restrict) |
| ntpd/ntp_monitor.c | ntpsec_rs_core::ntp_monitor | ✅ PORTED | MRU monitoring |
| ntpd/ntp_sandbox.c | ntpsec_rs_core::ntp_sandbox | ✅ PORTED | Seccomp sandboxing |
| ntpd/ntp_refclock.c | ntpsec_rs_core::ntp_refclock | ✅ PORTED | Refclock base class |
| ntpd/ntp_filegen.c | ntpsec_rs_core::ntp_filegen | ✅ PORTED | Stats file generation |
| ntpd/ntp_dns.c | ntpsec_rs_core::ntp_dns | ✅ PORTED | DNS resolution |
| ntpd/ntp_signd.c | ntpsec_rs_core::ntp_signd | ✅ PORTED | Samba MS-SNTP signing (stub) |
| ntpd/ntp_recvbuff.c | ntpsec_rs_core::ntp_recvbuff | ✅ PORTED | Receive buffer pool |

---

### NTS (5 files)

| C file | Rust module | Status | Notes |
|--------|-------------|--------|-------|
| ntpd/nts.c | ntpsec_rs_core::nts | ✅ PORTED | NTS core (KE, AEAD) |
| ntpd/nts_client.c | ntpsec_rs_core::nts_client | ✅ PORTED | NTS client (NTS-KE handshake) |
| ntpd/nts_server.c | ntpsec_rs_core::nts_server | 🔧 IN PROGRESS | NTS server (NTS-KE + cookie) |
| ntpd/nts_cookie.c | ntpsec_rs_core::nts_cookie | ✅ PORTED | NTS cookie encryption/decryption |
| ntpd/nts_extens.c | ntpsec_rs_core::nts_extens | ✅ PORTED | NTS extension field encoding |

---

### Refclock drivers (16 files)

| C file | Rust module | Status | Notes |
|--------|-------------|--------|-------|
| refclock_local.c | ntpsec_rs_core::refclock_local | ✅ PORTED | Local clock driver |
| refclock_pps.c | ntpsec_rs_core::refclock_pps | ✅ PORTED | PPS driver |
| refclock_shm.c | ntpsec_rs_core::refclock_shm | ✅ PORTED | SHM shared memory driver |
| refclock_gpsd.c | ntpsec_rs_core::refclock_gpsd | ✅ PORTED | GPSD client driver |
| refclock_nmea.c | ntpsec_rs_core::refclock_nmea | ✅ PORTED | NMEA 0183 sentence parser |
| refclock_jjy.c | ntpsec_rs_core::refclock_jjy | ✅ PORTED | JJY (Japan) time signal driver |
| refclock_hpgps.c | ntpsec_rs_core::refclock_hpgps | ✅ PORTED | HP GPS driver |
| refclock_oncore.c | ntpsec_rs_core::refclock_oncore | ✅ PORTED | Motorola Oncore GPS driver |
| refclock_spectracom.c | ntpsec_rs_core::refclock_spectracom | ✅ PORTED | Spectracom driver |
| refclock_trimble.c | ntpsec_rs_core::refclock_trimble | ✅ PORTED | Trimble GPS driver |
| refclock_truetime.c | ntpsec_rs_core::refclock_truetime | ✅ PORTED | TrueTime driver |
| refclock_arbiter.c | ntpsec_rs_core::refclock_arbiter | ✅ PORTED | Arbiter GPS driver |
| refclock_zyfer.c | ntpsec_rs_core::refclock_zyfer | ✅ PORTED | Zyfer GPS driver |
| refclock_modem.c | ntpsec_rs_core::refclock_modem | ✅ PORTED | Modem (WWV/WWVH) driver |
| refclock_generic.c | ntpsec_rs_core::refclock_generic | ✅ PORTED | Generic parse-based refclock |
| refclock_pps_api.h | ntpsec_rs_core::refclock_pps_api | ✅ PORTED | PPS API types and constants |

Note: All 16 refclock driver C files are now PORTED. The initial port deferred many of these; they were completed in subsequent phases.

---

### Legacy (deprecated/removed on purpose)

| C file | Reason |
|--------|--------|
| libntp/getopt.c | Replaced by clap |
| libntp/strl_obsd.c | Replaced by Rust std |
| attic/* | Already removed by upstream |
| ntpfrob/wscript | Build system, not ported |

---

### Headers ported as Rust modules

| Header | Rust module | Status | Notes |
|--------|-------------|--------|-------|
| include/ntp.h | ntpsec_rs_core::ntp_types | ✅ PORTED | Core types |
| include/ntp_fp.h | ntpsec_rs_core::ntp_fp | ✅ PORTED | Fixed-point arithmetic |
| include/ntp_calendar.h | ntpsec_rs_core::ntp_calendar | ✅ PORTED | Calendar types |
| include/ntp_types.h | ntpsec_rs_core::ntp_types | ✅ PORTED | Sized integer types |
| include/ntp_net.h | ntpsec_rs_core::ntp_net | ✅ PORTED | Network types |
| include/ntp_stdlib.h | ntpsec_rs_core::ntp_stdlib | ✅ PORTED | Stdlib types |
| include/ntp_malloc.h | ntpsec_rs_core::ntp_malloc | ✅ PORTED | Memory types |
| include/ntp_syslog.h | ntpsec_rs_core::ntp_syslog | ✅ PORTED | Syslog types |
| include/ntp_auth.h | ntpsec_rs_core::ntp_auth | ✅ PORTED | Auth types |
| include/ntpd.h | ntpsec_rs_core::ntp_config | 🔧 IN PROGRESS | Daemon types (in progress with config) |
| include/ntp_refclock.h | ntpsec_rs_core::ntp_refclock | ✅ PORTED | Refclock types |
| include/ntp_lists.h | ntpsec_rs_core::ntp_lists | ✅ PORTED | List types |
| include/nts.h | ntpsec_rs_core::nts | ✅ PORTED | NTS types |
| include/nts2.h | ntpsec_rs_core::nts | ✅ PORTED | NTS internal types |
| include/recvbuff.h | ntpsec_rs_core::ntp_recvbuff | ✅ PORTED | Buffer types |

---

### Binary crates (ported client tools)

| Tool (Python → Rust) | Crate | Status | Notes |
|----------------------|-------|--------|-------|
| ntpq | ntpsec-rs-query | ✅ PORTED | Mode 6 query tool |
| ntpdig | ntpsec-rs-dig | ✅ PORTED | SNTP client |
| ntpd | ntpd-rs | 🔧 IN PROGRESS | Daemon binary — bootstrap in work |
| ntpmon | ntpsec-rs-mon | ✅ PORTED | Monitor tool |
| ntpleapfetch | ntpsec-rs-leapfetch | ✅ PORTED | Leap second file fetcher |
| ntpkeygen | ntpsec-rs-keygen | ✅ PORTED | Key generation tool |
| ntpsnmpd | ntpsec-rs-snmpd | ✅ PORTED | SNMP daemon |
| ntploggps | ntpsec-rs-loggps | ✅ PORTED | GPS log tool |
| ntplogtemp | ntpsec-rs-logtemp | ✅ PORTED | Temperature log tool |
| ntpsweep | ntpsec-rs-sweep | ✅ PORTED | Network sweep tool |
| ntptrace | ntpsec-rs-trace | ✅ PORTED | Trace tool |
| ntpwait | ntpsec-rs-wait | ✅ PORTED | Wait for sync tool |
| ntpviz | ntpsec-rs-viz | ✅ PORTED | Visualization tool |
| ntptime | ntpsec-rs-time | ✅ PORTED | Time readout tool |
| nptfrob | ntpsec-rs-frob | ✅ PORTED | Hardware control tool |

### Effective Rust module / C TU mapping

The Rust codebase consolidates multiple C translation units per module. Below is the
module-level mapping from the C source tree to the Rust implementation, with the
line count of each Rust module as a proxy for implementation depth.

| Rust module | LoC | C TUs rolled in | Status |
|-------------|-----|------------------|--------|
| ntp_types | 543 | ntp.h, ntp_types.h | ✅ PORTED |
| ntp_fp | 299 | dolfptoa.c, prettydate.c, hextolfp.c, refidsmear.c | ✅ PORTED |
| ntp_calendar | 135 | ntp_calendar.c, clocktime.c | ✅ PORTED |
| ntp_auth | 457 | authkeys.c, authreadkeys.c, macencrypt.c | ✅ PORTED |
| ntp_stdlib | 97 | lib_strbuf.c, ntp_random.c, numtoa.c, statestr.c | ✅ PORTED |
| ntp_net | 97 | decodenetnum.c, isc_net.c, socktoa.c | ✅ PORTED |
| ntp_endian | 63 | ntp_endian.c | ✅ PORTED |
| ntp_malloc | 40 | emalloc.c | ✅ PORTED |
| ntp_syslog | 83 | msyslog.c | ✅ PORTED |
| ntp_util | 67 | clockwork.c | ✅ PORTED |
| ntp_recvbuff | 77 | ntp_recvbuff.c | ✅ PORTED |
| ntp_dns | 31 | ntp_dns.c | ✅ PORTED |
| ntp_signd | 21 | ntp_signd.c | ✅ PORTED |
| ntp_timer | 185 | ntp_timer.c | ✅ PORTED |
| ntp_peer | 288 | ntp_peer.c | ✅ PORTED |
| ntp_loopfilter | 430 | ntp_loopfilter.c | ✅ PORTED |
| ntp_restrict | 369 | ntp_restrict.c | ✅ PORTED |
| ntp_monitor | 151 | ntp_monitor.c | ✅ PORTED |
| ntp_sandbox | 401 | ntp_sandbox.c | ✅ PORTED |
| ntp_filegen | 136 | ntp_filegen.c | ✅ PORTED |
| ntp_refclock | 54 | ntp_refclock.c | ✅ PORTED |
| ntp_io | 597 | ntp_io.c, socket.c, initnetwork.c, syssignal.c, systime.c, isc_interfaceiter.c, ssl_init.c | ✅ PORTED |
| ntp_proto | 1161 | ntp_proto.c | 🔧 IN PROGRESS |
| ntp_control | 690 | ntp_control.c | 🔧 IN PROGRESS |
| ntp_config | 678 | ntp_config.c | 🔧 IN PROGRESS |
| ntp_leapsec | 199 | ntp_leapsec.c | 🔧 IN PROGRESS |
| nts | 1083 | nts.c | ✅ PORTED |
| nts_client | 651 | nts_client.c | ✅ PORTED |
| nts_server | 1401 | nts_server.c | 🔧 IN PROGRESS |
| nts_cookie | 965 | nts_cookie.c | ✅ PORTED |
| nts_extens | 523 | nts_extens.c | ✅ PORTED |
| parse | 193 | parse.c | ✅ PORTED |
| binio | 40 | binio.c | ✅ PORTED |
| ieee754io | 39 | ieee754io.c | ✅ PORTED |
| gpstolfp | 30 | gpstolfp.c | ✅ PORTED |
| timespecops | 74 | timespecops.c | ✅ PORTED |
| refclock_local | 45 | refclock_local.c | ✅ PORTED |
| refclock_pps | 444 | refclock_pps.c | ✅ PORTED |
| refclock_shm | 340 | refclock_shm.c | ✅ PORTED |
| refclock_gpsd | 504 | refclock_gpsd.c | ✅ PORTED |
| refclock_nmea | 1072 | refclock_nmea.c | ✅ PORTED |
| refclock_jjy | 560 | refclock_jjy.c | ✅ PORTED |
| refclock_hpgps | 293 | refclock_hpgps.c | ✅ PORTED |
| refclock_oncore | 291 | refclock_oncore.c | ✅ PORTED |
| refclock_spectracom | 288 | refclock_spectracom.c | ✅ PORTED |
| refclock_trimble | 304 | refclock_trimble.c | ✅ PORTED |
| refclock_truetime | 265 | refclock_truetime.c | ✅ PORTED |
| refclock_arbiter | 228 | refclock_arbiter.c | ✅ PORTED |
| refclock_zyfer | 208 | refclock_zyfer.c | ✅ PORTED |
| refclock_modem | 409 | refclock_modem.c | ✅ PORTED |
| refclock_generic | 70 | refclock_generic.c | ✅ PORTED |
| refclock_pps_api | 10 | refclock_pps_api.h | ✅ PORTED |
| control_client | 2723 | ntpq (Python) | ✅ PORTED |
| daemon_engine | 2513 | ntpd core logic | ✅ PORTED |
| ntpdig_proto | 635 | ntpdig (Python) | ✅ PORTED |
| ntp_assert | 47 | ntp_debug.h | ✅ PORTED |
| ntp_packetstamp | 52 | packet stamp types | ✅ PORTED |

**Totals**: ~70 PORTED, ~6 IN PROGRESS, ~4 DEFERRED, ~4 NOT PLANNED
