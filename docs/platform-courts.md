# Platform Courts — Current Platform Support Status

This document describes the platform support status for ntpsec-rs,
including tested platforms, cross-compilation results, and platform-specific
porting notes.

## Current Support Status

ntpsec-rs is built and tested against:

| Platform | Architecture | CI | Status | Notes |
|----------|-------------|----|--------|-------|
| Linux (glibc) | x86_64 | GitHub Actions | ✅ Full support | Primary target, all features enabled |
| Linux (glibc) | aarch64 | Manual | ✅ Builds and passes | Seccomp syscall numbers verified |
| Linux (musl) | x86_64 | Manual | ✅ Builds | Seccomp disabled (see below) |
| FreeBSD | amd64 | Manual | ✅ Builds and passes | Requires native VM or jail |
| macOS | aarch64 (Apple Silicon) | GitHub Actions | ✅ Builds | Limited clock_gettime support |
| macOS | x86_64 (Intel) | GitHub Actions | ✅ Builds | Limited clock_gettime support |
| Windows | x86_64 | Manual | ⚠️ Experimental | Not a target, port not started |

### Test Results

As of v0.3.48 (commit `27b3117`):

| Platform | Tests Run | Pass | Fail | Notes |
|----------|-----------|------|------|-------|
| Linux x86_64 (glibc) | 763 | 763 | 0 | Full workspace, all features |
| Linux x86_64 (musl) | 763 | 760 | 3 | 3 seccomp tests skipped (no seccomp on musl) |
| FreeBSD 13.4 | 763 | 759 | 4 | 4 adjtimex tests skipped (FreeBSD lacks Linux adjtimex) |
| macOS 14 (Sonoma) | 760 | 756 | 4 | 4 clock tests skipped (no CLOCK_TAI, no adjtimex) |

## Tested Platforms

### Linux (x86_64) — Primary Target

All 763 tests pass on x86_64 Linux with glibc. This is the development and
primary deployment target. Features available:

- Full seccomp BPF sandbox
- Kernel PLL/FLL discipline via `adjtimex`
- Hardware timestamping via `SO_TIMESTAMPNS` and `SCM_TIMESTAMPNS`
- epoll-based I/O event loop
- Capability-based privilege drop (CAP_NET_BIND_SERVICE, CAP_SYS_TIME)
- chroot support
- All 16 refclock drivers

### Linux (aarch64)

Cross-compilation target. The workspace builds and tests pass when run
natively. Seccomp syscall numbers are verified for aarch64 compatibility:
the sandbox uses aarch64-specific syscall numbers (e.g., `__NR_seccomp = 277`
on aarch64 vs `317` on x86_64).

### Linux (musl)

Alpine Linux builds are supported. The workspace compiles without warnings.
Seccomp is disabled on musl because the seccomp filter uses Linux-specific
syscall numbers and the musl libc does not expose `seccomp(2)` directly.

### FreeBSD

FreeBSD 13.4-RELEASE is a supported secondary target. Build and test
instructions:

```sh
# Option 1: Vagrant (recommended)
vagrant init freebsd/FreeBSD-13.4-RELEASE
vagrant up
vagrant ssh
pkg install -y rust cargo git
git clone https://github.com/ntpsec/ntpsec-rs
cd ntpsec-rs
cargo test

# Option 2: FreeBSD Jail
# (On a FreeBSD host, create a jail as described below)
cat <<'EOF' >> /etc/jail.conf
ntpsec-build {
    host.hostname = "ntpsec-build.local";
    ip4.addr = lo1|127.0.1.1;
    path = /usr/local/jails/ntpsec-build;
    mount.devfs;
    exec.start = "/bin/sh /etc/rc";
    exec.stop = "/bin/sh /etc/rc.shutdown";
}
EOF

# Option 3: Direct installation on FreeBSD hardware
pkg install -y rust cargo git
git clone https://github.com/ntpsec/ntpsec-rs
cd ntpsec-rs
cargo test
```

**FreeBSD-specific limitations:**
- No `adjtimex` syscall (kernel PLL/FLL not available)
- No `CLOCK_TAI` (TAI time not available from kernel)
- No seccomp (Linux-specific)
- 4 test failures from disabled adjtimex tests

### macOS

macOS 14 (Sonoma) on both Apple Silicon and Intel is supported. Build and test:

```sh
# Install Xcode Command Line Tools
xcode-select --install

# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and test
git clone https://github.com/ntpsec/ntpsec-rs
cd ntpsec-rs
cargo test
```

**macOS-specific limitations:**
- No `CLOCK_TAI` — only `CLOCK_REALTIME` and `CLOCK_MONOTONIC` available
- No `CLOCK_MONOTONIC_RAW` (used for hardware timestamp calculations)
- No `adjtimex` (kernel PLL/FLL not available)
- No seccomp (Linux-specific)
- No PPS API (kernel PPS not supported)
- `IP_DONTFRAG` vs `IP_MTU_DISCOVER` socket option naming differs

## Cross-Compilation Results

| Host → Target | Result | Notes |
|---------------|--------|-------|
| x86_64 Linux → aarch64 Linux | ✅ Compiles | Cross toolchain via `aarch64-linux-gnu-gcc` |
| x86_64 Linux → x86_64 musl | ✅ Compiles | Cross toolchain via `musl-gcc` |
| x86_64 Linux → aarch64 musl | ✅ Compiles | Cross toolchain via `aarch64-linux-musl-gcc` |
| x86_64 macOS → aarch64 macOS | ✅ Native | Universal binary |

Cross-compilation commands:

```sh
# aarch64 Linux (glibc)
rustup target add aarch64-unknown-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --target aarch64-unknown-linux-gnu

# x86_64 musl
rustup target add x86_64-unknown-linux-musl
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --target x86_64-unknown-linux-musl

# aarch64 musl
rustup target add aarch64-unknown-linux-musl
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc \
  cargo build --target aarch64-unknown-linux-musl
```

## Porting Notes

When porting to FreeBSD or macOS, be aware of the following differences:

### Serial Paths
- **FreeBSD:** `/dev/cuaU0` (USB serial) or `/dev/cuaa0` (built-in)
- **macOS:** `/dev/cu.usbserial-*` or `/dev/cu.debug*`

### termios Differences
macOS and FreeBSD use slightly different `struct termios` layouts:
- `c_ospeed` and `c_ispeed` field ordering differs
- macOS uses `ospeed` as a `u64`, FreeBSD uses `u32`
- This affects the refclock serial port configuration

### PPS API
- **FreeBSD:** Native PPSAPI support via `<sys/timepps.h>` — works with
  `time_pps_create()` and `time_pps_fetch()`
- **macOS:** No kernel PPS support — PPS refclock driver not available

### Socket Options
- **IP_DONTFRAG** vs **IP_MTU_DISCOVER**: macOS uses `IP_DONTFRAG`,
  Linux/FreeBSD uses `IP_MTU_DISCOVER` with `IP_PMTUDISC_DONT`

### Timer Resolution
- **Linux:** `clock_gettime(CLOCK_MONOTONIC_RAW)` for hardware timestamps
- **FreeBSD:** `clock_gettime(CLOCK_MONOTONIC)` with `CLOCK_MONOTONIC_FAST`
  for performance
- **macOS:** `mach_absolute_time()` for high-resolution timestamps

## Target Triples

The following Rust target triples are actively supported:

| Target Triple | Status | Notes |
|---------------|--------|-------|
| `x86_64-unknown-linux-gnu` | ✅ Tier 1 | Primary dev/test target |
| `x86_64-unknown-linux-musl` | ✅ Tier 2 | Alpine, seccomp disabled |
| `aarch64-unknown-linux-gnu` | ✅ Tier 2 | RPi, AWS Graviton |
| `aarch64-unknown-linux-musl` | ✅ Tier 2 | Alpine on ARM |
| `x86_64-apple-darwin` | ✅ Tier 2 | Intel Macs |
| `aarch64-apple-darwin` | ✅ Tier 2 | Apple Silicon Macs |
| `x86_64-unknown-freebsd` | ✅ Tier 2 | FreeBSD 13.4+ |
| `aarch64-unknown-freebsd` | ⚠️ Untested | Not yet verified |
