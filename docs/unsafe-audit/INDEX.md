# Unsafe Code Audit Index

> **Project:** ntpsec-rs v0.3.48
> **Generated:** 2026-07-27T01:49:47Z
> **Total Production Unsafe Blocks:** 78
> **Total Test-Only Unsafe Blocks:** 14
> **Combined Total:** 92
> **Documentation Baseline:** 106 (from security-review.md)
> **Review Status:** :white_check_mark: Pass - count within documented limit

## Quick Summary

| Category | Count | Risk | Description |
|----------|-------|------|-------------|
| :green_circle: FFI Syscall Wrappers | 46 | Low | Safe wrappers around libc functions |
| :green_circle: sockaddr_storage Casts | 14 | Low | Standard Berkeley sockets pointer casts |
| :green_circle: std::mem::zeroed() | 14 | Low | POD struct zero-initialization |
| :yellow_circle: CMSG Ancillary Parsing | 2 | Moderate | Kernel timestamp extraction from recvmsg |
| :yellow_circle: Raw Allocation | 2 | Low | emalloc/estrdup for C-compatible memory |
| :blue_circle: Test-Only | 14 | None | Unsafe blocks behind `#[cfg(test)]` |

## Legend

- :green_circle: **safe** - Verified safe. Invariants checked, bounds validated.
- :yellow_circle: **needs-review** - Requires manual review before production confidence.
- :blue_circle: **test-only** - Only compiled and run during `cargo test`.

## Full Inventory

### Production Code

Each entry links to a detailed audit file.

| ID | File | Lines | Description | Status |
|----|------|-------|-------------|--------|
| U-001 | `crates/ntpsec-rs-core/src/ntp_syscall.rs` | L232-252 | ntp_adjtime: safe wrapper around libc::adjtimex() for kernel clock discipline | 🟢 safe |
| U-002 | `crates/ntpsec-rs-io/src/lib.rs` | L39 | RealSystemClock::now: libc::clock_gettime(CLOCK_REALTIME) to read system time | 🟢 safe |
| U-003 | `crates/ntpsec-rs-io/src/lib.rs` | L48-70 | RealSystemClock::step: clock_gettime + clock_settime for stepping the system clock | 🟢 safe |
| U-004 | `crates/ntpsec-rs-io/src/lib.rs` | L72-91 | RealSystemClock::slew: two adjtimex() calls to slew clock offset and adjust frequency | 🟢 safe |
| U-005 | `crates/ntpsec-rs-io/src/lib.rs` | L93-102 | RealSystemClock::read_frequency: zeroed timex + adjtimex() to read kernel frequency | 🟢 safe |
| U-006 | `crates/ntpsec-rs-io/src/lib.rs` | L104-106 | RealSystemClock::set_frequency: delegates to slew() with offset=0 | 🟢 safe |
| U-007 | `crates/ntpsec-rs-core/src/leap_query.rs` | L12-21 | query_tai_offset: syscall(SYS_adjtimex) to query kernel TAI offset | 🟢 safe |
| U-008 | `crates/ntpsec-rs-core/src/leap_query.rs` | L24-28 | leap_pending: syscall(SYS_adjtimex) to check STA_INS / STA_DEL kernel flags | 🟢 safe |
| U-009 | `crates/ntpsec-rs-core/src/ntp_loopfilter.rs` | L308-317 | LoopFilter::adjtimex_safe: adjtimex() helper for clock filter operations | 🟢 safe |
| U-010 | `crates/ntpsec-rs-core/src/ntp_packetstamp.rs` | L65-84 | enable_software_timestamps: setsockopt(SO_TIMESTAMPNS) to enable kernel timestamps | 🟢 safe |
| U-011 | `crates/ntpsec-rs-core/src/ntp_packetstamp.rs` | L96-120 | enable_hardware_timestamps: setsockopt(SO_TIMESTAMPING) for hardware NIC timestamps | 🟢 safe |
| U-012 | `crates/ntpsec-rs-core/src/ntp_packetstamp.rs` | L131-160 | enable_pktinfo: setsockopt(IP_PKTINFO / IPV6_PKTINFO) to receive destination address | 🟢 safe |
| U-013 | `crates/ntpsec-rs-io/src/lib.rs` | L134-146 | RealNetworkIo::create_epoll: libc::epoll_create1(0) for scalable I/O event notification | 🟢 safe |
| U-014 | `crates/ntpsec-rs-io/src/lib.rs` | L181-212 | RealNetworkIo::epoll_wait: zeroed epoll_event array + libc::epoll_wait() | 🟢 safe |
| U-015 | `crates/ntpsec-rs-io/src/lib.rs` | L230 | RealNetworkIo::poll_fallback: libc::poll() for non-epoll platforms | 🟢 safe |
| U-016 | `crates/ntpsec-rs-io/src/lib.rs` | L286-289 | RealNetworkIo::Drop impl: libc::close(epoll_fd) to clean up epoll file descriptor | 🟢 safe |
| U-017 | `crates/ntpsec-rs-io/src/lib.rs` | L329-335 | RealNetworkIo::bind: epoll_ctl + close for epoll socket registration | 🟢 safe |
| U-018 | `crates/ntpsec-rs-io/src/lib.rs` | L426-439 | recvmsg_with_timestamp: libc::recvmsg() for datagram reception with kernel timestamps | 🟢 safe |
| U-019 | `crates/ntpsec-rs-io/src/lib.rs` | L459-461 | recvmsg_with_timestamp fallback: clock_gettime(CLOCK_REALTIME) when no kernel timestamp | 🟢 safe |
| U-020 | `crates/ntpsec-rs-io/src/lib.rs` | L472-491 | recvmsg_with_timestamp source conversion: sockaddr_in6 pointer cast for recvmsg source | 🟢 safe |
| U-021 | `crates/ntpsec-rs-io/src/lib.rs` | L577-613 | socket_getsockname: zeroed sockaddr_storage + getsockname() + pointer cast | 🟢 safe |
| U-022 | `crates/ntpsec-rs-io/src/lib.rs` | L499-570 | extract_scm_timestampns_with_source: CMSG_FIRSTHDR, CMSG_NXTHDR, CMSG_DATA for ancillary parsing | 🟢 safe |
| U-023 | `crates/ntpsec-rs-io/src/lib.rs` | L537-567 | extract_scm_timestampns_with_source: SCM_TIMESTAMPING hardware timestamp extraction | 🟢 safe |
| U-024 | `crates/ntpsec-rs-d/src/main.rs` | L279 | Daemon fork: libc::fork() for background daemonization | 🟢 safe |
| U-025 | `crates/ntpsec-rs-d/src/main.rs` | L286 | Daemon setsid: libc::setsid() to create new session after fork | 🟢 safe |
| U-026 | `crates/ntpsec-rs-d/src/main.rs` | L307 | Daemon stdin redirect: dup2() to redirect stdin to /dev/null | 🟢 safe |
| U-027 | `crates/ntpsec-rs-d/src/main.rs` | L319-321 | Daemon stdout/stderr redirect: dup2() to log file | 🟢 safe |
| U-028 | `crates/ntpsec-rs-d/src/main.rs` | L331-332 | Daemon stdout/stderr redirect without logfile: dup2() to /dev/null | 🟢 safe |
| U-029 | `crates/ntpsec-rs-d/src/main.rs` | L343 | Daemon getpid: libc::getpid() for PID file writing | 🟢 safe |
| U-030 | `crates/ntpsec-rs-d/src/main.rs` | L362 | Daemon chroot: libc::chroot() for filesystem jail | 🟢 safe |
| U-031 | `crates/ntpsec-rs-d/src/main.rs` | L371-372 | Daemon chdir after chroot: libc::chdir("/") to set working directory inside jail | 🟢 safe |
| U-032 | `crates/ntpsec-rs-d/src/main.rs` | L435 | Daemon nice: libc::setpriority(PRIO_PROCESS, 0, -10) for high-priority scheduling | 🟢 safe |
| U-033 | `crates/ntpsec-rs-d/src/main.rs` | L630-640 | Daemon refclock poll: libc::poll() for refclock device readiness | 🟢 safe |
| U-034 | `crates/ntpsec-rs-d/src/main.rs` | L1178 | chown_path: libc::chown() for file ownership after privilege drop | 🟢 safe |
| U-035 | `crates/ntpsec-rs-d/src/main.rs` | L1192 | lookup_user: libc::getpwnam() for user UID/GID resolution | 🟢 safe |
| U-036 | `crates/ntpsec-rs-d/src/main.rs` | L1228 | drop_privileges step 1: prctl(PR_SET_KEEPCAPS, 1) to retain capability set through UID transition | 🟢 safe |
| U-037 | `crates/ntpsec-rs-d/src/main.rs` | L1238-1248 | drop_privileges step 2: zeroed passwd + getpwnam_r() for reentrant user lookup | 🟢 safe |
| U-038 | `crates/ntpsec-rs-d/src/main.rs` | L1257 | drop_privileges step 3: initgroups() to initialize supplementary groups | 🟢 safe |
| U-039 | `crates/ntpsec-rs-d/src/main.rs` | L1271 | drop_privileges step 4a: setgid() to change group ID | 🟢 safe |
| U-040 | `crates/ntpsec-rs-d/src/main.rs` | L1278 | drop_privileges step 4b: setresuid() to atomically set all three UIDs | 🟢 safe |
| U-041 | `crates/ntpsec-rs-d/src/main.rs` | L1330-1336 | drop_privileges step 5: syscall(SYS_capset) to retain only CAP_SYS_TIME | 🟢 safe |
| U-042 | `crates/ntpsec-rs-d/src/main.rs` | L1340 | drop_privileges step 5 fallback: prctl(PR_SET_KEEPCAPS, 0) on capset failure | 🟢 safe |
| U-043 | `crates/ntpsec-rs-d/src/main.rs` | L1347 | drop_privileges step 5 cleanup: prctl(PR_SET_KEEPCAPS, 0) after successful capset | 🟢 safe |
| U-044 | `crates/ntpsec-rs-d/src/main.rs` | L1352-1353 | drop_privileges step 6: getuid() + getgid() to verify dropped identity | 🟢 safe |
| U-045 | `crates/ntpsec-rs-core/src/ntp_control.rs` | L726-728 | get_hostname: gethostname() with raw buffer + slice from_raw_parts for C string conversion | 🟢 safe |
| U-046 | `crates/ntpsec-rs-d/src/main.rs` | L1196 | lookup_user getpwnam result: unsafe dereference of pw_uid/pw_gid from raw pointer | 🟢 safe |
| U-047 | `crates/ntpsec-rs-core/src/ntp_io.rs` | L199-209 | sockaddr_to_netaddr (AF_INET): pointer cast from sockaddr_storage to sockaddr_in | 🟢 safe |
| U-048 | `crates/ntpsec-rs-core/src/ntp_io.rs` | L212-213 | sockaddr_to_netaddr (AF_INET6): pointer cast from sockaddr_storage to sockaddr_in6 | 🟢 safe |
| U-049 | `crates/ntpsec-rs-core/src/ntp_util.rs` | L48-66 | refid_from_addr: pointer cast for reference identifier extraction from peer address | 🟢 safe |
| U-050 | `crates/ntpsec-rs-core/src/ntp_monitor.rs` | L176-186 | MonList::record: pointer cast for MRU entry address comparison (AF_INET) | 🟢 safe |
| U-051 | `crates/ntpsec-rs-core/src/ntp_monitor.rs` | L242-252 | MonList::is_rate_limited: pointer cast for rate-limiting address match (AF_INET) | 🟢 safe |
| U-052 | `crates/ntpsec-rs-core/src/ntp_monitor.rs` | L301-312 | netaddr_to_sockaddr (IPv4): zeroed sockaddr_storage + pointer cast to sockaddr_in | 🟢 safe |
| U-053 | `crates/ntpsec-rs-core/src/ntp_monitor.rs` | L313-318 | netaddr_to_sockaddr (IPv6): zeroed sockaddr_storage + pointer cast to sockaddr_in6 | 🟢 safe |
| U-054 | `crates/ntpsec-rs-core/src/daemon_engine.rs` | L1259-1269 | apply_config refclock: zeroed sockaddr_storage + pointer cast for 127.127.x.y refclock addr | 🟢 safe |
| U-055 | `crates/ntpsec-rs-core/src/daemon_engine.rs` | L1312-1327 | apply_config restrict: zeroed sockaddr_storage + pointer cast for restrict entry address | 🟢 safe |
| U-056 | `crates/ntpsec-rs-core/src/daemon_engine.rs` | L1331-1341 | apply_config restrict IPv6: zeroed sockaddr_storage + pointer cast for IPv6 restrict entry | 🟢 safe |
| U-057 | `crates/ntpsec-rs-core/src/daemon_engine.rs` | L2584-2594 | handle_packet SymPassive: pointer cast for peer source address comparison | 🟢 safe |
| U-058 | `crates/ntpsec-rs-core/src/daemon_engine.rs` | L2699-2709 | handle_packet Broadcast: pointer cast for broadcast peer address comparison | 🟢 safe |
| U-059 | `crates/ntpsec-rs-core/src/daemon_engine.rs` | L3918-3936 | ip_to_sockaddr_storage: converts Rust IpAddr to sockaddr_storage for FFI | 🟢 safe |
| U-060 | `crates/ntpsec-rs-core/src/daemon_engine.rs` | L4130-4140 | test helper add_peer: zeroed sockaddr_storage + pointer cast for test peer creation | 🟢 safe |
| U-061 | `crates/ntpsec-rs-core/src/ntp_sandbox.rs` | L20 | enable_sandbox: prctl(PR_SET_NO_NEW_PRIVS) via unsafe libc call | 🟢 safe |
| U-062 | `crates/ntpsec-rs-core/src/ntp_sandbox.rs` | L39-41 | is_sandbox_active: prctl(PR_GET_NO_NEW_PRIVS) to query NO_NEW_PRIVS state | 🟢 safe |
| U-063 | `crates/ntpsec-rs-core/src/ntp_sandbox.rs` | L52-54 | is_seccomp_active: prctl(PR_GET_SECCOMP) to query seccomp filter state | 🟢 safe |
| U-064 | `crates/ntpsec-rs-core/src/ntp_sandbox.rs` | L379-386 | install_via_syscall_or_prctl: syscall(SYS_seccomp) with SECCOMP_SET_MODE_FILTER + TSYNC | 🟢 safe |
| U-065 | `crates/ntpsec-rs-core/src/ntp_sandbox.rs` | L390-399 | install_via_syscall_or_prctl fallback: prctl(PR_SET_SECCOMP) for older kernels | 🟢 safe |
| U-066 | `crates/ntpsec-rs-core/src/ntp_sandbox.rs` | L449-459 | test_seccomp_inside_child: fork(), _exit(), waitpid() for seccomp test isolation | 🟢 safe |
| U-067 | `crates/ntpsec-rs-core/src/ntp_malloc.rs` | L15-18 | emalloc: alloc_zeroed for raw memory allocation matching ntpsec's emalloc_zeroed() | 🟡 needs-review |
| U-068 | `crates/ntpsec-rs-core/src/ntp_malloc.rs` | L26-35 | estrdup: ptr::copy_nonoverlapping for C-string duplication with null terminator | 🟡 needs-review |

### Test-Only Code

| ID | File | Description | Status |
|----|------|-------------|--------|
| U-069 | `crates/ntpsec-rs-core/src/ntp_monitor.rs` | Test helper make_sockaddr_v4: zeroed + pointer cast for test IPv4 address | :blue_circle: test-only |
| U-070 | `crates/ntpsec-rs-core/src/ntp_monitor.rs` | Test helper make_sockaddr_v6: zeroed + pointer cast for test IPv6 address | :blue_circle: test-only |
| U-071 | `crates/ntpsec-rs-core/src/ntp_monitor.rs` | Test: read MRU order pointer cast for assertion | :blue_circle: test-only |
| U-072 | `crates/ntpsec-rs-core/src/ntp_monitor.rs` | Test: netaddr_to_sockaddr pointer cast for IPv4 round-trip verification | :blue_circle: test-only |
| U-073 | `crates/ntpsec-rs-core/src/ntp_monitor.rs` | Test: netaddr_to_sockaddr pointer cast for IPv6 round-trip verification | :blue_circle: test-only |
| U-074 | `crates/ntpsec-rs-core/src/daemon_engine.rs` | Test helpers: zeroed sockaddr_storage for Peer creation in fudge tests | :blue_circle: test-only |
| U-075 | `crates/ntpsec-rs-core/src/daemon_engine.rs` | Test helpers: zeroed sockaddr_storage for associd allocator tests | :blue_circle: test-only |
| U-076 | `crates/ntpsec-rs-core/src/ntp_control.rs` | Test: zeroed sockaddr_storage for peer variable lookup test | :blue_circle: test-only |
| U-077 | `crates/ntpsec-rs-core/src/ntp_filegen.rs` | Test helper: zeroed sockaddr_storage for filegen peer creation | :blue_circle: test-only |
| U-078 | `crates/ntpsec-rs-core/src/ntp_loopfilter.rs` | Test: zeroed timex for adjtimex_safe non-null test | :blue_circle: test-only |
| U-079 | `crates/ntpsec-rs-d/src/main.rs` | lookup_user: getpwnam() + raw pointer dereference for UID/GID extraction | :blue_circle: test-only |
| U-080 | `crates/ntpsec-rs-core/src/ntp_control.rs` | get_hostname: from_raw_parts to convert C hostname buffer to Rust &str | :blue_circle: test-only |

## Verification

This index is auto-generated by `ci/generate-unsafe-audit-site.sh`. To regenerate:

```bash
./ci/generate-unsafe-audit-site.sh
```

## Cross-Reference

- [Security Review](../security-review.md) - Project-level security review
- [Architecture](../architecture.md) - System architecture documentation
- [Platform Courts](../courts/) - Platform-specific court tests
- [docs/courts/](../courts/) - Formal verification and court tests
