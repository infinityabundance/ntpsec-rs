# ntpsec-rs Replacement Contract

**Version:** 0.3.48
**Date:** 2026-07-26
**Oracle:** NTPsec 1.2.4+dfsg-1 (Debian)
**Status:** Release candidate — nearing 100% drop-in replacement

## Definition of 100%

ntpsec-rs is a complete drop-in replacement for NTPsec only when an existing NTPsec
operator can replace the installed package without:
- Redesigning their deployment
- Editing their configuration
- Changing monitoring scripts
- Modifying firewall or service expectations
- Loss of observability or safety

This contract documents every capability required for that claim, its current status,
and the evidence required to close it.

## Contract Surfaces

| Surface | Description | Overall Status |
|---------|-------------|---------------|
| 1. Daemon behavior | Synchronization, serving, survival | 95-97% |
| 2. Configuration | ntp.conf acceptance and semantics | 88-92% |
| 3. Network protocols | NTP, Mode 6, auth, NTS, symmetric, broadcast | 92-95% |
| 4. Operator tools | ntpq, ntpdig, ntpmon, ntpkeygen, ntpleapfetch | 88-92% |
| 5. Runtime integration | Files, paths, users, systemd, signals | 82-88% |
| 6. Observable compatibility | Output formatting, exit codes, packet behavior | 82-88% |

### Surface Notes

**Surface 1 — Daemon behavior (95-97%)**
All core clock-discipline paths are ported and differentially verified: clock
filter, clock select, cluster, combine, and loop filter. Autonomous peer loss
and reacquisition is verified in the soak court. Exactly-once clock boundary
enforcement is verified. Peer lifecycle (pool DNS resolution, server replacement,
manycast discovery) is complete. Remaining gap: edge-case runtime paths not
exercised by the current oracle scenario suite.

**Surface 2 — Configuration (88-92%)**
Configuration directive recognition is near-complete, verified against live
`ntpd -?` output and Doxygen-extracted option tables. The `nom`-based parser
handles the full directive grammar including `pool`, `restrict`, `crypto`,
`nts`, `server`, `peer`, `broadcast`, `manycastserver`, `manycastclient`,
`driftfile`, `statsdir`, `filegen`, `logfile`, `interface`, `discard`,
`mru`, `enable`/`disable`, `tos`, `tinker`, and `trap`. Remaining gap:
obscure/deprecated directive edge cases.

**Surface 3 — Network protocols (92-95%)**
NTP client/server, symmetric peer (active/passive, interleaved), broadcast
client, Mode 6 control protocol, NTS-KE + NTP-over-NTS (RFC 8915), and Autokey
symmetric key auth (MD5, SHA-1, SHA-256, SHA-512, AES-CMAC) are all
implemented and differentially tested. NTS-KE interoperability is verified
against chrony in a dedicated Docker topology. The Mode 6 implementation
successfully serves queries from the reference NTPsec `ntpq` binary.

**Surface 4 — Operator tools (88-92%)**
All 15 NTPsec binary drop-ins are implemented as native Rust binaries. Output
parity for `ntpq`, `ntpdig`, `ntpmon`, `ntpkeygen`, and `ntpleapfetch` is
verified against the real NTPsec counterparts. `ntpq` read and write operations
(Mode 6 `readvar`, `peers`, `associations`, `authinfo`, `sysinfo`, `clockinfo`)
return comparable output. Remaining gap: formatting edge cases and deprecated
CLI flags.

**Surface 5 — Runtime integration (82-88%)**
Systemd service hardening (ProtectSystem, PrivateTmp, NoNewPrivileges, Capability
dropping, seccomp filter), drift file persistence, statistics file generation,
signal handling (SIGHUP reopen, SIGTERM clean shutdown), privilege dropping
(chroot, user transition), and socket binding are all operational. Remaining gap:
full signal-handling coverage and some paths/log-file rotation behaviors.

**Surface 6 — Observable compatibility (82-88%)**
Packet-level byte parity is verified through the Docker oracle (40+ scenarios).
ntpq output parity is verified against reference NTPsec ntpd. The `ntpdig`
output format matches NTPsec. Exit codes follow NTPsec conventions. Remaining
gap: formatted output differences in edge cases and deprecated output modes.

## Key Milestone Evidence

The following concrete evidence supports the surfaces above:

- **Docker oracle (two-sided)**: 40+ scenarios comparing ntpsec-rs against NTPsec
  byte-for-byte in isolated network namespaces. Each scenario exercises a specific
  combination of protocol, configuration, and authentication mode. See
  [`tests/docker/docker-compose.yml`](../tests/docker/docker-compose.yml).

- **Package swap proven**: A CI job (`package-swap`) builds Debian packages,
  starts NTPsec in a container, ntpsec-rs is installed over it, NTPsec is stopped,
  ntpsec-rs-d is started, and protocol equivalence is verified. This proves that
  a live upgrade path works. See
  [`tests/docker/test-package-swap.sh`](../tests/docker/test-package-swap.sh).

- **NTS-KE interop tested**: A dedicated Docker topology validates NTS-KE
  handshake between ntpsec-rs and chrony as the reference NTS-KE server. See
  [`tests/docker/docker-compose.nts.yml`](../tests/docker/docker-compose.nts.yml).

- **Reference ntpq connectivity**: The NTPsec `ntpq` binary (from the oracle)
  successfully queries ntpsec-rs-d via Mode 6, and ntpsec-rs-query queries
  NTPsec ntpd, with output compared for parity.

- **All CI gates are hard**: Every PR must pass all 9 CI jobs (test on stable +
  nightly, cross-compile on aarch64 + musl, oracle, soak, fuzz, package-swap,
  NTS-KE interop). A failure in any job blocks merge.

## Key Dispensations

The following are NOT required for 100% replacement:
- Bit-identical output in all cases (formatting divergence is documented)
- Identical floating-point results to the last ulp (tolerance is defined)
- Bug-for-bug compatibility with NTPsec defects
- Support for deprecated features removed in the pinned oracle version
- Hardware-dependent refclocks without device evidence

## Residual Classification

Every divergence from oracle behavior is classified:
- `OUR_BUG` — Defect to be fixed
- `ORACLE_BUG` — Known NTPsec defect we will not replicate
- `SPEC_AMBIGUITY` — RFC or spec leaves room; our interpretation differs
- `PLATFORM_VARIANCE` — OS or hardware-dependent difference
- `EXPECTED_RANDOMNESS` — Random nonces, ephemeral ports, etc.
- `INTENTIONAL_DIVERGENCE` — Deliberate improvement documented in compat/divergences/
- `UNCLASSIFIED` — Must be classified before release

## Inventory Files

| File | Contents |
|------|----------|
| `config-directives.toml` | Every NTPsec configuration directive and option |
| `command-options.toml` | Every CLI flag for all 15 binaries |
| `mode6-variables.toml` | Every Mode 6 system and peer variable |
| `protocol-behaviors.toml` | Every protocol behavior (auth, selection, filtering, etc.) |
| `files-and-paths.toml` | Every file path, statistics file, and runtime directory |
| `exit-codes.toml` | Every exit code and signal behavior |
| `platform-matrix.toml` | Every supported platform and build target |

## Status Key

| Status | Meaning |
|--------|---------|
| `implemented` | Functionally complete with tests |
| `partial` | Core behavior exists, edges missing |
| `absent` | Not implemented |
| `divergent` | Behavior differs intentionally from NTPsec |
| `sealed` | Differentially tested against oracle, residuals classified |
