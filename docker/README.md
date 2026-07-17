# Docker Oracle VM Matrix

This directory contains Docker orchestration for the ntpsec oracle VM matrix.
Each container runs both the real ntpsec (C) and ntpsec-rs (Rust), allowing
byte-level comparison of their behavior across multiple operating systems.

## OS matrix

| OS | Dockerfile | ntpsec source | Status |
|----|-----------|---------------|--------|
| Alpine Linux 3.20 | `alpine.dockerfile` | apk | Ready |
| Debian 12 (stable) | `debian-stable.dockerfile` | package | Ready |
| Debian 13 (testing) | `debian-testing.dockerfile` | package | Ready |
| Ubuntu 24.04 LTS | `ubuntu-lts.dockerfile` | package | Ready |
| Fedora 40 | `fedora.dockerfile` | package | Ready |
| Rocky Linux 9 | `rocky.dockerfile` | package | Ready |

## Building

```sh
# Build all oracle containers
./build-all.sh

# Build a specific container
docker build -f alpine.dockerfile -t ntpsec-oracle:alpine .
```

## Running

```sh
# Start the oracle daemon
./run-oracle.sh alpine

# Run parity tests
./run-parity.sh alpine

# Run the full matrix
./run-matrix.sh
```

## What each test does

1. Start real ntpd in the container with a test config
2. Query it with real ntpq and capture output
3. Start ntpsec-rs ntpd-rs with the same config
4. Query it with ntpsec-rs ntpq-rs
5. Byte-compare all outputs
6. Report PASS/FAIL for every comparison point
