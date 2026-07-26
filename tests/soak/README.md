# ntpsec-rs Soak Testing

This directory contains soak (long-duration) tests for the `ntpd-rs` daemon.
Soak tests run the daemon under real elapsed time while collecting metrics,
then report PASS/FAIL based on crash detection, error rate, and process health.

## Prerequisites

- **Root access** (`sudo`): `ntpd-rs` binds to privileged port 123
- **Rust toolchain** installed and on `$PATH`
- **Linux** with `/proc` mounted (for RSS/fd counting)
- `awk`, `grep` (with `-P` / PCRE support), `tee`, `date`

## Quick Start

```bash
# Quick 10-minute validation
sudo tests/soak/24h-daemon-soak.sh --duration 600
```

## Usage

### Full 24-hour soak

```bash
sudo tests/soak/24h-daemon-soak.sh
```

### Shorter test (e.g., 1 hour)

```bash
sudo tests/soak/24h-daemon-soak.sh --duration 3600
```

### Options

| Flag | Description |
|---|---|
| `--duration SECONDS` | Test duration (default: `86400` = 24 hours) |
| `--keep-tmp` | Preserve the temporary directory after the test completes |
| `--help`, `-h` | Show usage information |

### Environment

No environment variables are required. All paths are derived from the project
root (the parent of `tests/soak/`).

## What the Soak Test Does

### Phase 1 — Build

Builds `ntpd-rs` and `ntpq-rs` in release mode:

```bash
cargo build --release -p ntpsec-rs-d -p ntpsec-rs-query
```

### Phase 2 — Configuration & Startup

Creates a temporary directory (`/tmp/ntpsec-soak-XXXXXX/`) containing:

| File | Purpose |
|---|---|
| `ntp.conf` | Minimal config: LOCAL refclock, restrict, driftfile, stats |
| `daemon.log` | Captured stdout/stderr from the daemon |
| `soak-metrics.log` | Structured timestamped metric rows |
| `stats/` | Loopstats, peerstats, clockstats files |
| `ntp.drift` | Persisted drift value |
| `ntpd.pid` | PID file |

The daemon is started in no-fork (`-n`) mode with `-g` (panicgate) and `-x`
(slew) flags for safe refclock operation.

### Phase 3 — Monitoring

For the configured duration, the script polls:

| Interval | Metric | Source |
|---|---|---|
| **60 s** | Process alive, RSS (kB), open FDs | `/proc/PID/status`, `/proc/PID/fd/` |
| **300 s** | offset, frequency, jitter, stratum | `ntpq-rs -c rv` |
| **300 s** | peer reach, stratum, offset, jitter, delay | `ntpq-rs -c peers` |
| **300 s** | Clock adjustment count | `stats/loopstats` line count |
| **continuous** | Panics, errors in daemon log | `daemon.log` |

All data is written to `soak-metrics.log` with ISO-8601 timestamps.

### Phase 4 — Termination & Report

1. Sends `SIGTERM` to the daemon (waits up to 10 s for graceful shutdown)
2. If the daemon does not stop within 10 s, sends `SIGKILL`
3. Collects final stats from the stats directory and drift file
4. Scans the daemon log for panics and ERROR-level messages
5. Prints a **PASS** or **FAIL** verdict

### PASS / FAIL Criteria

**PASS** requires all of the following:

- Daemon ran for the full duration without crashing
- No `panic` or `thread panicked` messages in `daemon.log`
- Fewer than 10 `[ERROR]` messages in `daemon.log`

**FAIL** triggers on any of:

- Daemon exits unexpectedly before the duration expires
- Panic detected in the daemon log
- More than 10 `[ERROR]` messages in the daemon log

## Output Artifacts

After the test completes (unless `--keep-tmp` is used, the temp directory is
removed). The final output includes:

- **PASS/FAIL verdict** with summarized statistics
- Max RSS (kB) and file descriptor count observed
- Total ntpq queries attempted and failed
- Loopstats and peerstats entry counts
- Final drift value (ppm)
- Path to all log files (if `--keep-tmp` was used)

## CI Integration

For CI pipelines, run with a short duration:

```yaml
# GitHub Actions example snippet
- name: Soak test (10 min)
  run: sudo tests/soak/24h-daemon-soak.sh --duration 600
  timeout-minutes: 15
```

The script exits with code 0 on PASS and non-zero on FAIL, so it integrates
naturally with CI exit-code-based pass/fail logic.

### CI Recommendations

| CI Platform | Suggested Duration | Timeout |
|---|---|---|
| PR validation | 10–15 minutes | 20 min |
| Nightly regression | 1–6 hours | 7 h |
| Release candidate | 24 hours | 25 h |

## Troubleshooting

### "Cannot bind to port 123"

Ensure the script is run with `sudo` and no other NTP daemon is running:

```bash
sudo lsof -i :123
sudo systemctl stop ntpd ntp chronyd 2>/dev/null || true
```

### "ntpq-rs query failed"

The daemon may still be initializing. If failures are persistent, check the
daemon log:

```bash
cat /tmp/ntpsec-soak-*/daemon.log
```

### Build failures

Ensure the Rust toolchain is up to date:

```bash
rustup update
```
