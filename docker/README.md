# Docker Testing Infrastructure

This directory previously contained Docker oracle matrix files for parity
testing against NTPsec across multiple OS distributions.

## Current Docker Infrastructure

The Docker-based testing infrastructure has been **moved to `tests/docker/`**
and reorganized around three Docker Compose topologies:

### 1. Oracle Differential Test Lab (`tests/docker/docker-compose.yml`)

Runs `ntpsec-rs` and NTPsec side-by-side in isolated network namespaces,
feeds them identical synthetic packet streams, and compares daemon state.

```sh
cd ntpsec-rs
docker compose -f tests/docker/docker-compose.yml up --build
docker compose -f tests/docker/docker-compose.yml logs -f oracle
```

**Topology:**
- `ntpsec-oracle` — NTPsec reference daemon (from Ubuntu 22.04 package)
- `ntpsec-rs` — ntpsec-rs daemon under test (from local build or `.deb`)
- `harness` — Python-based synthetic packet generator (`oracle_harness.py`)

**Component files:**
- `tests/docker/docker-compose.yml` — service definitions
- `tests/docker/oracle_harness.py` — differential test orchestration
- `tests/docker/Dockerfile.harness` — Python test harness image
- `tests/docker/Dockerfile.ntpsec-rs` — Rust builder image (builds from source)
- `tests/docker/Dockerfile.package` — .deb package installer image
- `tests/docker/ntp-oracle.conf` — NTPsec oracle daemon config
- `tests/docker/ntp-rs.conf` — ntpsec-rs daemon config

### 2. NTS-KE Interop Lab (`tests/docker/docker-compose.nts.yml`)

Proves that `ntpsec-rs` NTS-KE client interoperates with a real chrony NTS
server using TLS 1.3 key establishment (RFC 8915).

```sh
cd ntpsec-rs
docker compose -f tests/docker/docker-compose.nts.yml up --build
docker compose -f tests/docker/docker-compose.nts.yml down
```

**Topology:**
- `chrony-nts` — chronyd with NTS-KE enabled on port 4460
- `ntpsec-rs` — ntpd-rs with NTS client support
- `test-runner` — builds and runs the `nts_ke_chrony_interop` integration test

**Component files:**
- `tests/docker/docker-compose.nts.yml` — NTS-KE interop topology
- `tests/docker/Dockerfile.nts` — chrony NTS server image with self-signed certs
- `tests/docker/Dockerfile.runner` — Rust builder for test binary
- `tests/docker/test-runner.sh` — NTS-KE interop test orchestration
- `tests/docker/nts-test.sh` — chrony server startup script

### 3. Package Swap Test (`tests/docker/docker-compose.swap.yml`)

Proves that `ntpsec-rs` can replace NTPsec on a real Ubuntu 24.04 system.
Starts NTPsec, verifies it, installs `ntpsec-rs` `.deb` packages, stops NTPsec,
starts `ntpd-rs`, and verifies protocol equivalence.

```sh
cd ntpsec-rs
docker compose -f tests/docker/docker-compose.swap.yml up --build
docker compose -f tests/docker/docker-compose.swap.yml down
```

**Test flow:**
1. Install NTPsec from `apt`
2. Start `ntpd` with a test config
3. Verify via `ntpq -c rv` and `ntpq -pn`
4. Install `ntpsec-rs` `.deb` packages (`ntpd-rs`, `ntpq-rs`, `ntpdig-rs`)
5. Stop `ntpd`
6. Start `ntpd-rs` with the same config
7. Verify via reference `ntpq` and native `ntpq-rs`
8. Report pass/fail for every comparison point

**Component files:**
- `tests/docker/docker-compose.swap.yml` — swap test topology
- `tests/docker/Dockerfile.swap` — Ubuntu 24.04 image with NTPsec + ntpsec-rs
- `tests/docker/test-package-swap.sh` — swap test orchestration

## Oracle Matrix (Legacy)

The existing Dockerfiles in this directory (`docker/`) build oracle containers
for specific OS distributions. They are built and run via `build-all.sh` and
`run-matrix.sh`.

These containers build `ntpsec-rs` from local source and test:
1. **Forward court**: real `ntpd` queried by both `ntpq` and `ntpq-rs`
2. **Reverse hardened court**: `ntpd-rs -u ntp --seccomp` queried by real `ntpq`
3. **Lifecycle**: SIGHUP survival, SIGTERM flushes drift and exits 0

```sh
cd docker
./build-all.sh                 # Build all oracle images
./run-matrix.sh                # Run full matrix on all images
./run-matrix.sh alpine         # Run on a single image
```

### OS Matrix

| OS | Dockerfile | ntpsec source | Status |
|----|-----------|---------------|--------|
| Alpine Linux 3.20 | `alpine.dockerfile` | apk | Ready |
| Debian 12 (stable) | `debian-stable.dockerfile` | package | Ready |
| Debian 13 (testing) | `debian-testing.dockerfile` | package | Ready |
| Ubuntu 24.04 LTS | `ubuntu-lts.dockerfile` | package | Ready |
| Fedora 40 | `fedora.dockerfile` | package | Ready |
| Rocky Linux 9 | `rocky.dockerfile` | package | Ready |

## CI Integration

The Docker tests run as part of the CI pipeline (`.github/workflows/ci.yml`):

- **Oracle job**: Builds the oracle topology, runs synthetic packet comparison.
- **NTS-KE job**: Builds the NTS interop topology, runs chrony ↔ ntpsec-rs test.
- **Swap job**: Builds the swap topology, validates NTPsec replacement.
- **Matrix job**: Runs the oracle matrix across all supported distributions.

## Building and Running

### Build all Docker images

```sh
# Legacy oracle images (docker/)
cd docker && ./build-all.sh

# Oracle differential lab (tests/docker/)
docker compose -f tests/docker/docker-compose.yml build

# NTS-KE interop (tests/docker/)
docker compose -f tests/docker/docker-compose.nts.yml build

# Package swap (tests/docker/)
docker compose -f tests/docker/docker-compose.swap.yml build
```

### Run tests

```sh
# Oracle differential lab
docker compose -f tests/docker/docker-compose.yml up --build
docker compose -f tests/docker/docker-compose.yml logs -f oracle

# NTS-KE interop
docker compose -f tests/docker/docker-compose.nts.yml up --build

# Package swap
docker compose -f tests/docker/docker-compose.swap.yml up --build
docker compose -f tests/docker/docker-compose.swap.yml down
```
