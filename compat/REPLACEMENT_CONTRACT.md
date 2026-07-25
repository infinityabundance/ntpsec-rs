# ntpsec-rs Replacement Contract

**Version:** 0.3.24
**Date:** 2026-07-25
**Oracle:** NTPsec 1.2.4+dfsg-1 (Debian)
**Status:** Active development — not yet a drop-in replacement

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
| 1. Daemon behavior | Synchronization, serving, survival | 65-70% |
| 2. Configuration | ntp.conf acceptance and semantics | 60-65% |
| 3. Network protocols | NTP, Mode 6, auth, NTS, symmetric, broadcast | 60-70% |
| 4. Operator tools | ntpq, ntpdig, ntpmon, ntpkeygen, ntpleapfetch | 50-60% |
| 5. Runtime integration | Files, paths, users, systemd, signals | 40-50% |
| 6. Observable compatibility | Output formatting, exit codes, packet behavior | 45-55% |

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
