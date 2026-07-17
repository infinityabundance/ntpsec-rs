# Forensic Parity Court Methodology

ntpsec-rs uses the same **forensic parity court method** proven in chrony-rs.
This document describes the methodology in full detail.

## Core principle: Byte parity, behavior parity, operational-knowledge parity

Every behavior admitted into ntpsec-rs must be backed by a **court** — a
reproducible, documented body of evidence that demonstrates the Rust behavior
matches the real NTPsec C implementation.

## The four pillars

### 1. Deep Doxygen / source archaeology

Every ntpsec C translation unit is indexed using Doxygen to extract:

- Function signatures (name, parameters, return type)
- Static/global variable declarations
- Macro constants and their values
- Enumerations and their discriminants
- Struct layouts and field types
- Control flow between functions

This index is stored in `docs/research/` and serves as the structural oracle.
The Rust implementation is developed from this index — never from reading the C
code directly (to maintain clean-room status).

### 2. Deterministic-trace replay

Real NTPsec `ntpd` packet traces (captured via `tcpdump` / `pcap`) are replayed
through the Rust code. Every received packet is fed to the Rust implementation,
and the resulting state transitions and output packets are compared byte-for-byte
against what the real `ntpd` produced in response.

Trace captures are stored in `docs/courts/traces/` with metadata describing the
capture environment, configuration, and expected behavior.

### 3. Protocol-spec cross-check

NTP RFCs and NIST known-answer tests are used to classify behavior:

- **Protocol truth**: behavior required by RFC 5905 (NTPv4), RFC 8915 (NTS),
  etc. This is the baseline standard.
- **NTPsec policy**: behavior where NTPsec's implementation differs from the
  generic protocol. These are documented as NTPsec-specific choices and are
  cross-checked against the C oracle.
- **Bug compatibility**: known NTPsec bugs (tracked in the NTPsec issue tracker)
  that ntpsec-rs may need to replicate for drop-in replacement parity.

### 4. Court-backed evidence

Every admitted behavior is documented in a **court file** in `docs/courts/`.

Each court file contains:

```markdown
# Court: ntp_fp — dolfptoa format

## Claim
dolfptoa seconds.fraction matches ntpsec's output exactly for
positive, negative, zero, edge case values.

## Evidence
### Test output (ntpsec-rs)
```
$ cargo test -p ntpsec-rs-core dolfptoa
<test output>
```

### Oracle output (ntpsec C)
```
$ ./tests/dolfptoa-test
<ntpsec output>
```

### Byte comparison
<diff showing identical output>

## Witnesses
- RFC 5905 §6 — timestamp format definition
- ntpsec libntp/dolfptoa.c — structural oracle (via Doxygen index)
- Test vector generated from ntpsec 1.3.3

## Verdict
PASS — bytes match.
```

## Clean-room enforcement

Ntpsec-rs enforces a strict clean-room protocol:

1. **No ntpsec C source in the repository**: The `.gitignore` and a CI check
   (`cargo xtask check`) reject any file originating from the ntpsec repository.
2. **Doxygen index only**: The structural oracle is a Doxygen-generated index
   (abstracted function signatures and constants), never verbatim C source.
3. **Oracle VM**: Real ntpsec binaries run in Docker containers for behavioral
   comparison. The binaries are never decompiled or reverse-engineered — only
   observed through their inputs and outputs.
4. **Attribution**: All behavioral knowledge derived from running ntpsec is clearly
   attributed in court files.

## The porting process

For each ntpsec C translation unit:

```
1. Generate Doxygen index ─────────────────────────────┐
                                                        │
2. Create Rust module skeleton with all function        │
   signatures and type definitions from index           │
                                                        │
3. Implement each function using:                       │
   a. Doxygen index (structure)                         │
   b. Protocol spec (behavioral requirements)           │
   c. Differential testing (behavioral verification)    │
                                                        │
4. Create unit tests for each function                  │
                                                        │
5. Run against oracle:                                  │
   a. In-process deterministic replay                   │
   b. Docker oracle VM for end-to-end testing          │
                                                        │
6. Write court file documenting the evidence            │
                                                        │
7. Run `cargo xtask check` to verify freshness          │
```

## The Docker Oracle VM Matrix

The oracle matrix tests across:

| OS | Distribution | ntpsec version | ntpsec-rs version |
|----|--------------|----------------|-------------------|
| Alpine Linux | 3.20 | 1.3.3 | matching |
| Debian | 12 (stable) | 1.3.3 | matching |
| Debian | 13 (testing) | 1.3.3 | matching |
| Ubuntu | 24.04 (LTS) | 1.3.3 | matching |
| Fedora | 40 | 1.3.3 | matching |
| Rocky Linux | 9 | 1.3.3 | matching |

Each matrix cell runs:

1. Real ntpd in the container
2. ntpsec-rs ntpd-rs in the container
3. Client tests (ntpq, ntpdig, ntpmon, etc.) against both
4. Byte-level output comparison

See [docker/README.md](../docker/README.md) for setup instructions.
