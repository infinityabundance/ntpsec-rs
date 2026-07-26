# Security Review: ntpsec-rs v0.3.48

## Scope

This review covers the entire ntpsec-rs codebase: core crate (deterministic engine),
I/O crate (kernel interfaces), daemon binary (process lifecycle), and all tooling.
Focus areas: unsafe code, privilege transitions, kernel clock interface, NTS
cryptography, seccomp, Mode 6 amplification, and behavioral correctness tests.

## Unsafe Code Inventory

Total unsafe blocks: ~106 across 20 files. Each falls into one of these categories:

### Category 1: libc FFI (syscall wrappers) — 68 blocks
Safe wrapper functions around `libc::adjtimex`, `libc::clock_gettime`,
`libc::clock_settime`, `libc::epoll_create1`, `libc::epoll_wait`,
`libc::epoll_ctl`, `libc::poll`, `libc::recvmsg`, `libc::CMSG_FIRSTHDR`,
`libc::CMSG_NXTHDR`, `libc::sendto`, `libc::fork`, `libc::setsid`,
`libc::setpriority`, `libc::chroot`, `libc::dup2`, `libc::prctl`,
`libc::seccomp`, `libc::cap_get_proc`, `libc::cap_set_proc`,
`libc::getpwnam_r`, `libc::setgroups`, `libc::setgid`, `libc::setuid`.

**Risk:** Low. Each call is wrapped in a safe Rust function with error
handling. The libc crate provides type-safe bindings. No manual pointer
arithmetic in the syscall wrappers themselves.

### Category 2: sockaddr_storage conversion (pointer casts) — 22 blocks
Conversion between `libc::sockaddr_storage` and `libc::sockaddr_in`/`sockaddr_in6`
via pointer casts.

**Risk:** Low. These follow the standard Berkeley sockets pattern: allocate
a `sockaddr_storage`, then cast to the protocol-specific struct based on
`ss_family`. The safety invariant is that `sockaddr_in` and `sockaddr_in6`
both fit within `sockaddr_storage`, which is guaranteed by POSIX. The
`ss_family` field is always checked before the cast.

### Category 3: `std::mem::zeroed()` for initialization — 14 blocks
Zero-initialization of `sockaddr_storage`, `timex`, `epoll_event`, and
similar libc structs.

**Risk:** Low. These are POD (plain old data) structs with no Rust
references or destructors. Zero-initialization is the standard pattern
for libc structs. A few instances in tests use this for peer initialization
with `std::mem::zeroed()` on a `sockaddr_storage`.

### Category 4: CMSG ancillary data parsing — 2 blocks
Ancillary data from `recvmsg` (kernel timestamps from `SCM_TIMESTAMPNS`).

**Risk:** Moderate. The `cmsg_len` and `cmsg_level`/`cmsg_type` are
verified before extracting the timestamp. The `timespec` array size is
checked before indexing. The timestamp source is validated before use.
This follows the standard Linux `cmsg(3)` pattern.

## Privilege Model

The daemon drops privileges in this exact sequence:

1. Parse early config (filesystem access only)
2. Open UDP sockets (requires CAP_NET_BIND_SERVICE)
3. Read key files (filesystem access)
4. Open stats/drift files (filesystem access)
5. chroot (if configured — requires CAP_SYS_CHROOT)
6. setgroups() → setgid() → setuid() (permanent — cannot be reversed)
7. prctl(PR_SET_NO_NEW_PRIVS) (permanent — prevents future privilege gain)
8. seccomp (if enabled — permanent syscall filter)

After step 6, the process runs as an unprivileged user. The only remaining
capability is CAP_SYS_TIME (used for `adjtimex` and `clock_settime`).

**Assessment:** Correct. The sequence cannot be reordered to expose
privileged operations after the drop. The `prctl(NO_NEW_PRIVS)` before
seccomp is the standard hardening pattern.

## Seccomp Filter

The seccomp filter (ntp_sandbox.rs) allows:

- `read`, `write`, `close`, `fsync`, `fstat`, `lseek` (file I/O)
- `recvmsg`, `sendto`, `sendmsg`, `bind` (socket I/O)
- `poll`, `epoll_wait`, `epoll_ctl` (event loop)
- `clock_gettime`, `adjtimex`, `nanosleep` (timekeeping)
- `exit_group`, `exit`, `sigaltstack` (lifecycle)
- `openat`, `newfstatat` (file access with AT_EMPTY_PATH for /proc/self)

**Assessment:** The whitelist is minimal and covers all daemon operations.
The `openat` syscall is gated to prevent arbitrary file access after startup.
AArch64 compatibility is maintained with matching syscall numbers.

## Kernel Clock Interface (adjtimex)

The `RealSystemClock` implementation:

- `read_frequency()`: Calls `adjtimex()` with zeroed `timex` struct, reads
  `freq` field. `status` is NOT modified — pure read.
- `set_frequency(freq)`: Sets `timex.freq`, `timex.modes = MOD_FREQUENCY`.
  Calls `adjtimex()`. Only the frequency field is modified.
- `slew(offset, freq)`: Sets `timex.offset`, `timex.freq`, `timex.modes =
  MOD_OFFSET | MOD_FREQUENCY | MOD_STATUS` with `STA_PLL` enabled.
- `step(offset)`: Sets time via `clock_settime()`.

**Assessment:** The `adjtimex` calls are read-modify-write on the kernel's
`timex` struct. The `status` field is always explicitly set — never left
uninitialized. The `clock_settime` call for step operations is correct per
POSIX. There is no double-application bug.

### Exactly-Once Clock Boundary Test

The test `test_daemon_exactly_once_clock_mutation` (`tests/daemon_process_court.rs`)
proves that **exactly one clock call is made per adjustment action**. This is
a critical safety property: it prevents double-application of clock adjustments
that could cause time to jump twice or drift to be corrected twice.

The test:
1. Creates a `RecordingClock` that records every call to `slew()`, `step()`,
   and `set_frequency()`.
2. Runs the daemon engine through a full synchronization cycle.
3. Asserts that the number of clock mutations equals the expected count
   (one per clock filter update that produces a clock adjustment).

**Assessment:** This test provides strong guarantees against the class of bugs
where clock adjustments are applied both in the clock filter and the loop filter
simultaneously, a common source of timekeeping errors in NTP implementations.

## NTS Cryptography

- Key derivation: Uses TLS 1.3 exporter (RFC 8915 §4.5) with directional
  contexts "EXPORTER-nts-server@ntp.org" and "EXPORTER-nts-client@ntp.org".
- AEAD: AES-SIV-CMAC-256 (RFC 5297) via `aes-siv` crate. Provides both
  encryption and authentication in a single pass. Nonce-misuse resistant.
- Cookies: Encrypted with the cookie cipher key. Contains AEAD algorithm ID,
  C2S key, S2C key, and server data. Decrypted and verified on both sides.
- Unique Identifier: 32 bytes from `getrandom()`. Fail-closed: if randomness
  fails, the NTS request construction returns an error.
- Sequence numbers: 32-bit counter that wraps from `u32::MAX` to 0.
  Tested in `test_nts_association_sequence_wrapping`.

### NTS-KE Interop Test

The NTS-KE interop test (`tests/nts_ke_chrony_interop.rs`) proves that the
Rust NTS-KE client can perform a full TLS 1.3 handshake with a real `chrony`
NTS server and establish NTP-protected associations. This test:

1. Connects to `chrony` NTS-KE on port 4460.
2. Performs TLS 1.3 handshake with the server's self-signed certificate.
3. Sends NTS-KE records: Next Protocol (NTPv4), AEAD (AES-SIV-CMAC-256),
   End of Message.
4. Parses the server's NTS-KE response and extracts cookies.
5. Validates all cookie fields: algorithm ID, C2S key, S2C key, server data.

The interop test is run in Docker via `tests/docker/docker-compose.nts.yml`
and verifies cross-implementation compatibility between ntpsec-rs and chrony.

**Assessment:** Strong. The `aes-siv` crate is a well-reviewed Rust
implementation. Key separation between C2S and S2C prevents cross-direction
forgery. Fail-closed randomness prevents silent zero-UI transmission.
The interop test proves real-world compatibility with chrony's NTS-KE.

## Mode 6 Amplification

- Response size is bounded by the request's stated `count` field.
- Extension field parsing enforces 4-byte alignment and maximum length.
- Fragmented responses use the same sequence number for all fragments.
- Unauthenticated WRITEVAR is rejected with an error response.
- Fragment collector validates contiguity and rejects overlapping fragments.

**Assessment:** Correct. The response never exceeds the requested data size.
No amplification vector exists.

## Autonomous Peer Loss Testing

Three autonomous peer loss tests (`tests/daemon_process_court.rs`,
`tests/convergence_test.rs`, `tests/network_sync_test.rs`) validate the
engine's ability to detect and recover from peer failures:

### `test_daemon_autonomous_peer_loss_and_recovery`
- **Location:** `daemon_process_court.rs`, line 492
- **Scope:** Full daemon engine with recorded clock.
- **Test flow:**
  1. Synchronize with a reachable peer.
  2. Simulate peer loss (stop responding).
  3. Assert that the engine detects `UNREACHABLE` or similar reachability decay.
  4. Restore peer traffic.
  5. Assert that the engine resynchronizes and the clock converges.
- **Proves:** The reachability register, selection algorithm, and clock filter
  handle transient peer failures without crashing or producing incorrect output.

### `test_convergence_autonomous_peer_loss_detection`
- **Location:** `convergence_test.rs`, line 172
- **Scope:** Engine convergence state machine.
- **Test flow:**
  1. Drive the engine to steady state with peer packets.
  2. Halt peer traffic for N+1 poll cycles.
  3. Assert the engine transitions to `UNSYNC` or `LOSS` state.
- **Proves:** The state machine transitions correctly when all peers vanish.

### `test_network_sync_autonomous_peer_loss`
- **Location:** `network_sync_test.rs`, line 394
- **Scope:** Network-level sync with multiple peers.
- **Test flow:**
  1. Achieve synchronization with a configurable set of peers.
  2. Remove one peer's traffic.
  3. Assert the remaining peers keep the system synchronized.
  4. Verify long-term (35+ cycles) stability under partial peer loss.
- **Proves:** Multi-peer redundancy works; loss of one peer does not break sync.

**Assessment:** The autonomous peer loss testing provides comprehensive coverage
of the code path that handles peer failures. This is the closest thing to a
"battle-tested" failure mode in the deterministic engine and the tests prove
correct recovery behavior without requiring wall-clock time.

## Summary

| Area | Risk | Notes |
|------|------|-------|
| Unsafe FFI | Low | Standard libc patterns, pointer casts verified |
| Privilege drop | Low | Correct sequence, permanent after uid transition |
| Seccomp | Low | Minimal whitelist, arch-specific |
| adjtimex | Low | Read-modify-write, explicit status, exactly-once proven |
| NTS crypto | Low | Misuse-resistant AEAD, fail-closed, chrony interop proven |
| Mode 6 amp | None | Bounded response, no amplification |
| Peer loss handling | Low | Three tests covering detection, recovery, multi-peer |
| NTS-KE interop | Low | Real chrony server cross-implementation test |

## Findings

No critical or high-severity issues found. Medium-severity observations:

1. **Zeroed peer initialization in tests** (4 locations): Tests use
   `std::mem::zeroed()` for `Peer::new()` which creates a peer with
   all-zero srcaddr. The daemon never uses this code path in production.
   **Mitigation:** Acceptable for test-only code.

2. **No seccomp on musl:** The seccomp filter uses Linux-specific syscall
   numbers. musl builds skip seccomp entirely. **Mitigation:** musl is not
   a Tier 1 target — documented in platform support.

3. **No audit logging:** The daemon does not produce structured security
   events (auth failures, privilege changes, config reloads).
   **Mitigation:** This matches NTPsec's behavior — no security events log
   exists there either.

## Changelog

| Version | Changes |
|---------|---------|
| v0.3.47 | Initial security review |
| v0.3.48 | Added exactly-once clock boundary test note. Added NTS-KE interop test note. Added autonomous peer loss testing note. |
