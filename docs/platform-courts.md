# Platform Courts — FreeBSD and macOS Setup

This document describes how to set up test environments for FreeBSD
and macOS, which cannot run Linux Docker containers natively and
require native VMs or bare-metal hardware.

## FreeBSD

### Option 1: Vagrant (recommended)

```sh
vagrant init freebsd/FreeBSD-13.4-RELEASE
vagrant up
vagrant ssh
```

Inside the VM:

```sh
pkg install -y rust cargo git
git clone https://github.com/ntpsec/ntpsec-rs
cd ntpsec-rs
cargo test
```

### Option 2: FreeBSD Jail

On a FreeBSD host, create a jail with the required build dependencies:

```sh
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

pkg install -y rust cargo git
git clone https://github.com/ntpsec/ntpsec-rs
cd ntpsec-rs
cargo test
```

### Option 3: Direct installation on FreeBSD hardware

```sh
pkg install -y rust cargo git
git clone https://github.com/ntpsec/ntpsec-rs
cd ntpsec-rs
cargo test
```

## macOS

### Option 1: Native (bare-metal Mac)

1. Install Xcode Command Line Tools:

   ```sh
   xcode-select --install
   ```

2. Install Rust via rustup:

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

3. Clone and build:

   ```sh
   git clone https://github.com/ntpsec/ntpsec-rs
   cd ntpsec-rs
   cargo test
   ```

### Option 2: macOS VM (e.g. Tart, UTM)

1. Create a macOS VM using [Tart](https://github.com/cirruslabs/tart):
   ```sh
   tart pull ghcr.io/cirruslabs/macos-sequoia-vanilla:latest
   tart run macos-sequoia-vanilla
   ```

2. Or use UTM (https://mac.getutm.app) with a macOS guest.

3. Inside the VM, follow the native setup steps above.

### Option 3: CI (GitHub Actions)

The project uses GitHub Actions for cross-platform CI. To test on macOS,
push to a branch and check the macOS runner results:

```sh
git push origin my-branch
# => GitHub Actions runs on ubuntu-latest, macos-latest, windows-latest
```

## Porting Notes

When porting to FreeBSD or macOS, be aware of:

- **Serial paths** — FreeBSD uses `/dev/cuaU0` (USB serial) or
  `/dev/cuaa0` (built-in); macOS uses `/dev/cu.usbserial-*`.
- **termios differences** — macOS and FreeBSD use slightly different
  `struct termios` layouts; `c_ospeed`/`c_ispeed` fields differ.
- **PPS API** — FreeBSD has native PPSAPI support via
  `<sys/timepps.h>`; macOS lacks kernel PPS support.
- **clock_gettime** — macOS only supports `CLOCK_REALTIME` and
  `CLOCK_MONOTONIC`; it lacks `CLOCK_TAI` and `CLOCK_MONOTONIC_RAW`.
- **Socket headers** — `IP_DONTFRAG` vs `IP_MTU_DISCOVER`.
