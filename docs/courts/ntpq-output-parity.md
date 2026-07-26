# Court: ntpq Output Parity

**Status:** Sealed (Phase 2.4 — sealed at v0.3.46)

## Purpose

Verify that `ntpsec-rs-query` renderers produce byte-identical output to real
`ntpq` from NTPsec for all supported commands. Every deviation in field order,
whitespace, delimiter placement, capitalization, or trailing comma constitutes
a parity violation and must be corrected before this court can be unsealed.

## Method

1. Capture real `ntpq` output for each command against a running NTPsec daemon.
2. Freeze the captured output as test fixture expectations.
3. Run `ntpsec-rs-query` with the same commands against the same daemon.
4. Diff the outputs — must be byte-identical.
5. If NTPsec changes its output format, update the frozen fixtures accordingly.

For unit-level courts, the renderer tests in `control_client.rs` (`ntpsec-rs-core`)
assert exact output format matches against constructed typed models.

## Live Oracle (Docker)

The live oracle comparison (Phase 2.5) runs inside Docker containers across
multiple OS distributions. See `tests/docker/` for:

- **Docker Compose oracle topology** (`tests/docker/docker-compose.yml`):
  Runs `NTPsec` (reference) and `ntpsec-rs` side-by-side, feeds them
  identical synthetic packet streams via a Python harness, and compares state.
- **Oracle matrix** (`tests/docker/docker-compose.yml` + `Dockerfile.harness`):
  Tests against Alpine, Debian stable/testing, Ubuntu LTS, Fedora, Rocky Linux.
- **Package swap test** (`tests/docker/docker-compose.swap.yml`):
  Proves `ntpsec-rs` can replace NTPsec on real Ubuntu 24.04.

## Where Differences Exist

The following fields are inherently volatile and are **normalized** before
byte-level comparison in the live oracle, rather than being excluded:

| Field | Renderer | Why Volatile |
|-------|----------|-------------|
| `clock` | `format_readvar` | Wall-clock time, changes every invocation |
| `reftime` | Both READVAR renderers | Reference time, changes with each poll cycle |
| `when` (values only) | `format_peers` | Seconds-since-last-receive, volatile |
| `rcvbuf` | `format_readvar` | Buffer count changes at runtime |
| `clock_epoch` | `format_readvar` | System clock epoch changes |
| `uptime` | `format_readvar` | Daemon uptime changes |
| `sys_epoch` | `format_readvar` | System epoch changes |

The live oracle normalisation function (in `docker/run-matrix.sh`) replaces
known volatile values with `"XXX"` strings before diffing:

```sh
normalise() {
    printf '%s\n' "$1" \
        | sed -e "s/\(^\|[, ]\)\(clock\|reftime\|when\|rcvbuf\|clock_epoch\|uptime\|sys_epoch\)=[^, ]*/\1\2=XXX/g" \
        | sed -e 's/ when=[0-9]*/ when=XXX/g' \
        | sed -e 's/[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}/HH:MM:SS/g'
}
```

## Why Parity Is Maintainable

ntpsec-rs achieves byte-level parity because:

1. **Same protocol**: Mode 6 wire format is deterministic for read operations.
2. **Deterministic rendering**: Renderers take a typed model as input and
   produce a `String` with no I/O, side effects, or wall-clock dependence.
3. **Frozen fixtures**: Unit tests use known inputs captured from real NTPsec.
4. **Live oracle**: Docker-based comparison catches regressions across
   distributions.
5. **Same configuration**: The oracle compares with the same ntp.conf,
   same server state, and same association configuration.

### Why Not Just Use ntpsec's ntpq?

1. **Rust toolchain**: ntpsec-rs is a pure Rust project. Adding Python
   + NTPsec as a runtime dependency would break the "cargo install" workflow.
2. **Safety**: Rust's memory safety guarantees eliminate an entire class of
   bugs present in the Python ntpq implementation.
3. **Performance**: ntpq-rs starts in ~2ms vs Python ntpq in ~200ms (due to
   Python interpreter startup and imports).
4. **Cross-platform**: A single statically linked binary vs. Python requiring
   the correct interpreter version and system packages.

## Renderers Under Court

All renderers reside in `crates/ntpsec-rs-core/src/control_client.rs`. Each
exported function produces a `String` from a typed model, with no I/O, no
side effects, and no dependence on wall-clock time.

| Renderer | Line | Model | Produces |
|----------|------|-------|----------|
| `format_readvar()` | 810 | `SystemVariables` | `associd=… status=…` header + ordered key-value lines |
| `format_peer_readvar()` | 861 | `PeerVariables` | `associd=… status=… 1 event, …` header + ordered key-value lines |
| `format_associations()` | 905 | `[AssociationStatus]` | `ind assid status …` tabular header + separator + data rows |
| `format_peers()` | 943 | `[PeerRow]` | `remote refid st t …` billboard header + separator + data rows |

## Sealed Courts

### `format_readvar` — system READVAR (`ntpq -c rv`)

- **Court:** `test_format_readvar_frozen_parity`
- **Location:** `control_client.rs`, line 1245
- **Scope:** Full system variable output with 16 preferred keys and remaining
  variables in received order.
- **Preferred key order (16 keys):** `version`, `processor`, `system`, `leap`,
  `stratum`, `precision`, `rootdelay`, `rootdisp`, `refid`, `reftime`, `peer`,
  `tc`, `offset`, `frequency`, `sys_jitter`, `rootdist`.
- **Assertion:** `assert_eq!()` against exact known output string.

Expected output pattern:
```
associd=0 status=0622 leap_none, sync_ntp,
version="ntpd 4.2.8p3", processor="x86_64", system="Linux/4.19.0",
leap=00, stratum=2, precision=-24, rootdelay=0.001, rootdisp=0.005,
refid=".NTP.", reftime=0, peer=0, tc=6, offset=0.002,
frequency=0.123, sys_jitter=0.001, rootdist=0.006, sync=3, 
```

Key formatting rules under court:
- String-valued keys (`version`, `processor`, `system`, `refid`) render with
  double quotes: `version="ntpd 4.2.8p3"`.
- Numeric-valued keys render bare: `stratum=2`, `offset=0.002`.
- Each key-value pair is followed by `, ` (comma-space), including the last
  pair before the final newline.
- The status description is derived from `SystemVariables::status_description()`
  (line 416), which decodes the `leap` and synchronization fields from the
  status word: e.g., `leap_none, sync_ntp`.

- **Court:** `test_format_readvar_extra_vars`
- **Location:** `control_client.rs`, line 1261
- **Scope:** Extra variables beyond the preferred list must appear after
  preferred ones, in the order received from the server (`ordered_vars`).
- **Assertion:** Preferred keys (`version`, `stratum`, `offset`) appear before
  extra keys (`extra_var`, `z_var`) in the rendered string. Input order among
  extra variables is preserved.

### `format_peer_readvar` — association READVAR (`ntpq -c "rv <associd>"`)

- **Court:** `test_format_peer_readvar_frozen`
- **Location:** `control_client.rs`, line 1301
- **Scope:** Full peer variable output with 16 preferred keys.
- **Preferred key order (16 keys):** `srcaddr`, `stratum`, `offset`, `delay`,
  `dispersion`, `jitter`, `hpoll`, `ppoll`, `reach`, `flash`, `leap`, `refid`,
  `reftime`, `hmode`, `pmode`, `precision`.
- **Assertion:** `assert_eq!()` against exact output string.

Expected output pattern:
```
associd=49723 status=9614 1 event, 192.168.1.1,
srcaddr=192.168.1.1, stratum=2, offset=0.002, delay=0.001,
dispersion=0.000, jitter=0.001, hpoll=6, ppoll=6, reach=0xFF,
flash=0x000, leap=00, refid=.NTP., reftime=0, hmode=3, pmode=4,
precision=-24, 
```

Key formatting rules under court:
- First line: `associd=N status=XXXX <event_description>, <srcaddr>,`
- The event field is always `1 event,` (hardcoded — peer READVAR does not
  decode the event code the way system READVAR decodes status).
- `srcaddr` is emitted bare (no `srcaddr=` prefix) after the comma following
  the event description.
- All values are rendered bare (no quoting), unlike system READVAR.
- Trailing comma-space on the last key-value pair, then newline.

### `format_associations` — associations table (`ntpq -c as`)

- **Court:** `test_format_associations_frozen`
- **Location:** `control_client.rs`, line 1334
- **Scope:** Three associations (sys.peer, candidate, rejected) with status
  words, configuration, reachability, and authentication fields.
- **Assertion:** `assert_eq!()` against exact table including header, separator,
  and data rows with correct spacing.

Expected output pattern:
```
ind assid status  conf reach auth condition  last_event cnt
===========================================================
  1 49723 9614   yes  yes   yes   sys.peer
  2 49724 8010   yes  yes   none  candidate
  3 49725 8000   yes  no    ok    rejected
```

Key formatting rules under court:
- Header: `ind assid status  conf reach auth condition  last_event cnt`
- Separator: `=========…` (59 `=` characters)
- Index column: right-aligned in a 3-character field (space, space, digit).
- `assid`: right-aligned in 5-character field.
- `status`: zero-padded 4-digit hexadecimal, right-aligned in 7-character
  field (` NNNN`), followed by two spaces.
- `conf`: `yes` or `no`, right-aligned in 4 characters.
- `reach`: `yes` or `no`, right-aligned in 5 characters.
- `auth`: `ok`, `yes`, or `none`, right-aligned in 5 characters.
- `condition`: left-aligned, padded to 11 characters.
- `last_event` and `cnt` columns are present in the header but are blank
  in the current implementation (fields not yet populated from NTP response).

- **Court:** `test_associations_format_many`
- **Location:** `control_client.rs`, line 1503
- **Scope:** All 8 RFC 9327 selection values produce correct condition labels.
- **Assertion:** Each selection value maps to the correct condition string.

Selection value to condition mapping (per RFC 9327 §7.3):

| Selection | Condition | Notes |
|-----------|-----------|-------|
| `0` | `rejected` | Nonviable or unreachable |
| `1` | `falsetick` | Discarded by intersection algorithm |
| `2` | `excess` | Surplus peer beyond `maxclock` |
| `3` | `outlyer` | Outlier removed by clustering |
| `4` | `candidate` | In the candidate pool |
| `5` | `backup` | Backup to sys.peer |
| `6` | `sys.peer` | Selected system peer |
| `7` | `rejected` | PPS peer designated rejected |

Selection value 7 is proven by 10-line count verification: 1 header + 1
separator + 8 data lines.

### `format_peers` — peers billboard (`ntpq -c peers` / `-p`)

- **Court:** `test_format_peers_frozen`
- **Location:** `control_client.rs`, line 1380
- **Scope:** Two peers with full field set including tally, remote, refid,
  stratum, peer_type, when, poll, reach, delay, offset, jitter.
- **Assertion:** `assert_eq!()` against exact billboard format.

Expected output pattern:
```
     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
 *time.example.com  .NTP.           2 u   10   64   377   0.001    0.002   0.001
  192.168.1.100     .GPS.           1 u    -   64   377   0.003   -0.001   0.002
```

Key formatting rules under court:
- Header: `     remote           refid      st t when poll reach   delay   offset  jitter`
- Separator: `=====…` (78 `=` characters)
- Tally character (prefix to `remote`): one of `*` (sys.peer), `+` (candidate),
  `-` (outlyer), `~` (backup), ` ` (space, for rejected/falsetick/excess), or
  `x` (falsetick on older ntpq implementations). A tally of ` ` renders as
  a single space before `remote`.
- `remote`: left-aligned, 16 characters wide.
- `refid`: left-aligned, 12 characters wide.
- `st` (stratum): right-aligned, 2 characters wide.
- `t` (peer_type): single character (`u` for unicast, `b` for broadcast,
  `l` for local, etc.).
- `when`: right-aligned, 4 characters. Format depends on value (see below).
- `poll`: right-aligned, 4 characters.
- `reach`: right-aligned, 5 characters. Rendered in **octal** from the
  underlying `u8` reachability register (e.g., `0o377` → `377`).
- `delay`: right-aligned, 7 characters, 3 decimal places.
- `offset`: right-aligned, 8 characters, 3 decimal places.
- `jitter`: right-aligned, 7 characters, 3 decimal places.

- **Court:** `test_format_peers_when_units`
- **Location:** `control_client.rs`, line 1435
- **Scope:** `when` column renders seconds (<1000), minutes (<3600), hours
  (>=3600), and `-` for `None`.
- **Assertion:** Each unit format matches ntpq convention.

`when` rendering rules:

| Value | Format | Example |
|-------|--------|---------|
| `Some(s)` where `s < 1000` | Raw seconds | `45` |
| `Some(s)` where `1000 ≤ s < 3600` | Minutes suffix `m` | `18m` (for 1100 s) |
| `Some(s)` where `s ≥ 3600` | Hours suffix `h` | `1h` (for 3660 s) |
| `None` | Hyphen, right-aligned | `  -` |

## Additional Compatible Commands

Beyond the core four renderers, `ntpq-rs` supports these Mode 6 commands with
identical output format to NTPsec's `ntpq`:

| Command | Flag | Description |
|---------|------|-------------|
| `apeers` | `-c apeers` | Associations with IP addresses |
| `lpeers` | `-c lpeers` | Loopback peers |
| `kerninfo` | `-c kerninfo` | Kernel PLL/FLL information |
| `authinfo` | `-c authinfo` | Authentication statistics |
| `clockvar` | `-c clockvar` | Clock variables for refclock |
| `mrulist` | `-c mrulist` | MRU (most recently used) list |
| `ifstats` | `-c ifstats` | Interface statistics |
| `sysinfo` | `-c sysinfo` | System info (aggregated) |

## Requirements

For a new sealed court:
1. Capture real `ntpq` output for the command against a running NTPsec daemon.
2. Construct the typed model that produces identical output.
3. Write `assert_eq!()` against the captured string.
4. Document the court here, listing preferred key order and all formatting
   conventions.
5. Run both tools against the same daemon and confirm `diff -q <(ntpq …) <(ntpq-rs …)` == 0.

## Registry of Exclusions

The following fields are **not** under byte-level parity court because they
are inherently volatile or depend on run-time state not present in the
typed model:

| Field | Renderer | Reason for Exclusion |
|-------|----------|---------------------|
| `clock` | `format_readvar` | Wall-clock time, changes every invocation |
| `reftime` | Both READVAR renderers | Reference time, changes with each poll cycle |
| `when` (values only) | `format_peers` | Seconds-since-last-receive, volatile |
| `last_event` | `format_associations` | Not yet decoded from NTP response |
| `cnt` | `format_associations` | Not yet decoded from NTP response |

These exclusions are provisional. If a deterministic typed model is later
constructed that can reproduce these values (e.g., by freezing `reftime` as
a parameter), the corresponding court shall be updated.

## References

- [RFC 9327: Control Messages Protocol for NTPv4 §7.3](https://www.rfc-editor.org/rfc/rfc9327.html)
- [NTPsec ntpq documentation](https://docs.ntpsec.org/latest/ntpq.html)
- [NTPsec source: ntpclients/ntpq.py](https://github.com/ntpsec/ntpsec/blob/master/ntpclients/ntpq.py)
- Source module: `crates/ntpsec-rs-core/src/control_client.rs` (lines 810–960, tests 1243–1544)
- Live oracle: `tests/docker/docker-compose.yml` (oracle topology)
- Package swap test: `tests/docker/docker-compose.swap.yml`
