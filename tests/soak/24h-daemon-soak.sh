#!/bin/bash
# ──── 24h-daemon-soak.sh ────────────────────────────────────────────────────
# Real elapsed-time soak test for the ntpd-rs daemon.
#
# Runs ntpd-rs with a local refclock for a configurable duration (default 24h),
# collects metrics at regular intervals, and reports PASS/FAIL.
#
# Usage:
#   sudo tests/soak/24h-daemon-soak.sh                    # 24-hour soak
#   sudo tests/soak/24h-daemon-soak.sh --duration 3600    # 1-hour soak
#   sudo tests/soak/24h-daemon-soak.sh --duration 600     # 10-min validation
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ──── Configurable Defaults ──────────────────────────────────────────────────
DURATION=86400          # 24 hours in seconds
NTPQ_INTERVAL=300       # ntpq-rs query interval (seconds)
ALIVE_INTERVAL=60       # process health check interval (seconds)
BUILD_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
KEEP_TMP=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ──── Helpers ────────────────────────────────────────────────────────────────
log_info()  { echo -e "${CYAN}[INFO]${NC}  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $(date '+%Y-%m-%d %H:%M:%S') $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*"; }

# Vars set later, initialized here for cleanup
TMPDIR=""
DAEMON_PID=""
DAEMON_LOG=""
SOAK_LOG=""
STATS_DIR=""
DRIFT_FILE=""
CONFIG_FILE=""
PID_FILE=""
CRASH_DETECTED=0
HAD_ERRORS=0
ALIVE_COUNT=0
NTPQ_COUNT=0
NTPQ_FAIL=0
MAX_RSS=0
MAX_FD=0
RUN_DURATION=$DURATION

# ═══════════════════════════════════════════════════════════════════════════
# cleanup — trap handler for EXIT, SIGINT, SIGTERM
# ═══════════════════════════════════════════════════════════════════════════
cleanup() {
    local exit_code=$?
    set +e
    local ec=0

    echo ""
    log_info "=== Cleanup ==="

    # Kill the daemon if still running
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        log_info "Sending SIGTERM to ntpd-rs (PID $DAEMON_PID)..."
        kill -TERM "$DAEMON_PID" 2>/dev/null
        local waited=0
        while kill -0 "$DAEMON_PID" 2>/dev/null && [ $waited -lt 10 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        if kill -0 "$DAEMON_PID" 2>/dev/null; then
            log_warn "Daemon did not exit after 10s, sending SIGKILL"
            kill -KILL "$DAEMON_PID" 2>/dev/null
            ec=1
        else
            log_ok "Daemon terminated gracefully"
        fi
    fi

    # Collect final stats
    gather_final_stats

    # Report final verdict
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    local verdict="FAIL"
    local vcolor="$RED"
    if [ "$exit_code" -eq 0 ] && [ "$CRASH_DETECTED" -eq 0 ] && [ "$HAD_ERRORS" -eq 0 ]; then
        verdict="PASS"
        vcolor="$GREEN"
    fi
    echo -e "  ${vcolor}${verdict}${NC} — Soak test completed"
    local actual_dur=0
    if [ -n "${START_TIME:-}" ]; then
        actual_dur=$(($(date +%s) - START_TIME))
    fi
    echo "  Duration:       $((RUN_DURATION)) seconds (actual: ${actual_dur})"
    [ "$CRASH_DETECTED" -ne 0 ] && echo "  Crash detected:  yes"
    [ "$HAD_ERRORS" -ne 0 ] && echo "  Errors in log:   yes"
    echo "  Sampling:        ${ALIVE_COUNT} alive checks, ${NTPQ_COUNT} ntpq queries (${NTPQ_FAIL} failed)"
    echo "  Max RSS:         ${MAX_RSS} kB"
    echo "  Max FDs:         ${MAX_FD}"
    echo "  Soak log:        ${SOAK_LOG:-N/A}"
    echo "  Stats dir:       ${STATS_DIR:-N/A}"
    echo "═══════════════════════════════════════════════════════════════════════"

    # Remove temp directory unless --keep-tmp was passed
    if [ "$KEEP_TMP" -eq 0 ] && [ -n "$TMPDIR" ]; then
        rm -rf "$TMPDIR"
        log_info "Removed temporary directory $TMPDIR"
    fi

    exit $ec
}

# ═══════════════════════════════════════════════════════════════════════════
# gather_final_stats — collect and display final statistics
# ═══════════════════════════════════════════════════════════════════════════
gather_final_stats() {
    echo ""
    log_info "=== Final Statistics ==="

    # Loopstats summary
    if [ -n "$STATS_DIR" ] && [ -f "$STATS_DIR/loopstats" ]; then
        local loop_lines adj_count
        loop_lines=$(wc -l < "$STATS_DIR/loopstats" 2>/dev/null || echo 0)
        adj_count=$(awk '$4 != 0 {count++} END {print count+0}' "$STATS_DIR/loopstats" 2>/dev/null || echo 0)
        log_info "Loopstats entries:       $loop_lines"
        log_info "Non-zero adjustments:    $adj_count"
        echo "       (last 5 entries):"
        tail -5 "$STATS_DIR/loopstats" 2>/dev/null | while read -r line; do
            echo "       $line"
        done
    else
        log_warn "No loopstats file found"
    fi

    # Peerstats summary
    if [ -n "$STATS_DIR" ] && [ -f "$STATS_DIR/peerstats" ]; then
        local peer_lines
        peer_lines=$(wc -l < "$STATS_DIR/peerstats" 2>/dev/null || echo 0)
        log_info "Peerstats entries:       $peer_lines"
        echo "       (last 5 entries):"
        tail -5 "$STATS_DIR/peerstats" 2>/dev/null | while read -r line; do
            echo "       $line"
        done
    fi

    # Drift file
    if [ -n "$DRIFT_FILE" ] && [ -f "$DRIFT_FILE" ]; then
        local drift_val
        drift_val=$(cat "$DRIFT_FILE" 2>/dev/null || echo "N/A")
        log_info "Final drift (ppm):       $drift_val"
    else
        log_warn "No drift file found"
    fi

    # Count panics/errors in the daemon log
    if [ -n "$DAEMON_LOG" ] && [ -f "$DAEMON_LOG" ]; then
        local panic_count error_count
        panic_count=$(grep -ci 'panic\|thread.*panicked' "$DAEMON_LOG" 2>/dev/null || echo 0)
        error_count=$(grep -ci '\[ERROR\]' "$DAEMON_LOG" 2>/dev/null || echo 0)
        log_info "Panics in daemon log:    $panic_count"
        log_info "Errors in daemon log:    $error_count"

        if [ "$panic_count" -gt 0 ]; then
            CRASH_DETECTED=1
            echo ""
            log_error "=== CRASH DETECTED ==="
            grep -i 'panic\|thread.*panicked' "$DAEMON_LOG" 2>/dev/null | tail -10 | while read -r line; do
                echo "       $line"
            done
        fi
    fi

    # Sampling summary
    echo ""
    log_info "Sampling summary:"
    echo "       Process checks:      ${ALIVE_COUNT:-0}"
    echo "       ntpq queries:        ${NTPQ_COUNT:-0}"
    echo "       ntpq failures:       ${NTPQ_FAIL:-0}"
    echo "       Max RSS (kB):        ${MAX_RSS:-N/A}"
    echo "       Max FDs:             ${MAX_FD:-N/A}"
}

# ──── Register Trap ──────────────────────────────────────────────────────────
trap cleanup EXIT SIGINT SIGTERM

# ──── Parse Arguments ────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --duration)
            shift
            if [ -z "${1:-}" ] || ! [[ "$1" =~ ^[0-9]+$ ]]; then
                echo "Error: --duration requires a numeric argument (seconds)"
                exit 1
            fi
            DURATION="$1"
            ;;
        --keep-tmp)
            KEEP_TMP=1
            ;;
        --help|-h)
            echo "Usage: sudo $0 [--duration SECONDS] [--keep-tmp]"
            echo ""
            echo "  --duration SECONDS   Test duration (default: 86400 = 24h)"
            echo "  --keep-tmp           Preserve temporary directory after test"
            echo "  --help, -h           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: sudo $0 [--duration SECONDS] [--keep-tmp]"
            exit 1
            ;;
    esac
    shift
done

# Validate root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo) — ntpd-rs needs to bind to port 123"
    exit 1
fi

RUN_DURATION=$DURATION

# Validate project root
if [ ! -f "$BUILD_DIR/Cargo.toml" ]; then
    echo "Error: Cannot find project root (Cargo.toml). Run from the project directory."
    exit 1
fi

# ──── Create Temporary Workspace ─────────────────────────────────────────────
TMPDIR=$(mktemp -d /tmp/ntpsec-soak-XXXXXX)
CONFIG_FILE="$TMPDIR/ntp.conf"
DAEMON_LOG="$TMPDIR/daemon.log"
SOAK_LOG="$TMPDIR/soak-metrics.log"
STATS_DIR="$TMPDIR/stats"
DRIFT_FILE="$TMPDIR/ntp.drift"
PID_FILE="$TMPDIR/ntpd.pid"

mkdir -p "$STATS_DIR"

# ──── Write Config File ─────────────────────────────────────────────────────
# Use LOCAL refclock (driver 1, unit 0 = 127.127.1.0) for deterministic testing.
# The config parser auto-detects 127.127.x.y addresses as refclock directives,
# so "server 127.127.1.0" becomes a Refclock { refclock_type: 1, unit: 0 }.
cat > "$CONFIG_FILE" <<CONFIGEOF
# ── ntpd-rs soak test configuration ──────────────────────────────────────

# Local refclock (driver 1, unit 0) — no external NTP server needed.
# minpoll 4 (16s) and maxpoll 6 (64s) for quick convergence.
server 127.127.1.0 minpoll 4 maxpoll 6

# Fudge the LOCAL refclock: stratum 10, refid LOCAL.
# Field 1 = refclock_type (1), field 2 = unit (0).
fudge 1 0 stratum 10 refid LOCAL

# Allow unrestricted Mode 6 queries from localhost
restrict 127.0.0.1
restrict ::1

# Default restrictions: block everything except basic time service
restrict -4 default kod notrap nomodify nopeer noquery
restrict -6 default kod notrap nomodify nopeer noquery

# Drift and stats paths
driftfile $DRIFT_FILE
statsdir $STATS_DIR

# Enable statistics collection
statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
CONFIGEOF

log_info "Config:          $CONFIG_FILE"
log_info "Stats directory: $STATS_DIR"
log_info "Drift file:      $DRIFT_FILE"
log_info "Daemon log:      $DAEMON_LOG"

# ──── Phase 1: Build in Release Mode ──────────────────────────────────────
echo ""
log_info "=== Phase 1: Building release binaries ==="
log_info "Building ntpd-rs and ntpq-rs..."

BUILD_LOG="$TMPDIR/build.log"
cd "$BUILD_DIR"
cargo build --release -p ntpsec-rs-d -p ntpsec-rs-query 2>&1 | tee "$BUILD_LOG"
BUILD_EXIT=${PIPESTATUS[0]}

if [ "$BUILD_EXIT" -ne 0 ]; then
    log_error "Build failed (exit code $BUILD_EXIT)"
    cat "$BUILD_LOG" >&2
    exit 1
fi

NTPD_BIN="$BUILD_DIR/target/release/ntpd-rs"
NTPQ_BIN="$BUILD_DIR/target/release/ntpq-rs"

if [ ! -x "$NTPD_BIN" ]; then
    log_error "ntpd-rs binary not found at $NTPD_BIN"
    exit 1
fi
if [ ! -x "$NTPQ_BIN" ]; then
    log_error "ntpq-rs binary not found at $NTPQ_BIN"
    exit 1
fi

NTPD_VERSION=$("$NTPD_BIN" --version 2>/dev/null | head -1 || echo "unknown")
NTPQ_VERSION=$("$NTPQ_BIN" --version 2>/dev/null | head -1 || echo "unknown")
log_ok "ntpd-rs: $NTPD_VERSION"
log_ok "ntpq-rs: $NTPQ_VERSION"

# ──── Phase 2: Start the Daemon ───────────────────────────────────────────
echo ""
log_info "=== Phase 2: Starting ntpd-rs ==="

# Start in no-fork (-n) mode so we capture all output.
# Use -g (panicgate) and -x (slew) for safe refclock operation.
"$NTPD_BIN" \
    -c "$CONFIG_FILE" \
    -f "$DRIFT_FILE" \
    -p "$PID_FILE" \
    -n \
    -g \
    -x \
    > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

log_info "ntpd-rs started with PID $DAEMON_PID"

# Wait for the daemon to initialize and bind
sleep 2
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    log_error "ntpd-rs failed to start. Daemon log:"
    cat "$DAEMON_LOG" >&2
    exit 1
fi
log_ok "ntpd-rs is running (PID $DAEMON_PID)"

# Write soak log header
{
    echo "═══════════════════════════════════════════════════════════════════════"
    echo " ntpsec-rs Soak Test — $(date)"
    echo " Duration:       $RUN_DURATION seconds"
    echo " ntpd-rs:        $NTPD_VERSION"
    echo " ntpq-rs:        $NTPQ_VERSION"
    echo " Config:         $CONFIG_FILE"
    echo " Daemon PID:     $DAEMON_PID"
    echo ""
    echo " Timestamped rows:"
    echo "   [ALIVE] time elapsed=rss-kB=fds=   (every ${ALIVE_INTERVAL}s)"
    echo "   [NTPQ]  time elapsed=offset_ms=freq=jitter_ms=stratum=  (every ${NTPQ_INTERVAL}s)"
    echo "   [PEER]  time elapsed=reach=stratum=offset=jitter=delay="
    echo "   [STAT]  time elapsed=adj_count="
    echo "═══════════════════════════════════════════════════════════════════════"
} > "$SOAK_LOG"

# ──── Phase 3: Monitoring Loop ─────────────────────────────────────────────
echo ""
log_info "=== Phase 3: Monitoring (${RUN_DURATION}s) ==="
echo "       Process checks:  every ${ALIVE_INTERVAL}s"
echo "       ntpq queries:    every ${NTPQ_INTERVAL}s"
echo "       Soak log:        $SOAK_LOG"

START_TIME=$(date +%s)
LAST_NTPQ_TIME=0
LAST_ALIVE_TIME=0
RSS_KB=0
FD_COUNT=0

# ──── Monitoring Loop ───────────────────────────────────────────────────
while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TIME))

    # Check if duration has elapsed
    if [ "$ELAPSED" -ge "$RUN_DURATION" ]; then
        log_info "Duration reached (${ELAPSED}s ≥ ${RUN_DURATION}s)"
        break
    fi

    # ── Process Alive Check (every ALIVE_INTERVAL seconds) ─────────
    if [ $((ELAPSED - LAST_ALIVE_TIME)) -ge "$ALIVE_INTERVAL" ] || [ "$ALIVE_COUNT" -eq 0 ]; then
        LAST_ALIVE_TIME=$ELAPSED
        ALIVE_COUNT=$((ALIVE_COUNT + 1))
        TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

        # Check if process is alive
        if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
            log_error "Daemon (PID $DAEMON_PID) is no longer running!"
            wait "$DAEMON_PID" 2>/dev/null || true
            CRASH_DETECTED=1
            break
        fi

        # Gather RSS and FD count from /proc
        RSS_KB=0
        FD_COUNT=0
        if [ -d "/proc/$DAEMON_PID" ]; then
            if [ -f "/proc/$DAEMON_PID/status" ]; then
                RSS_KB=$(grep -i '^VmRSS:' "/proc/$DAEMON_PID/status" 2>/dev/null | awk '{print $2}' || echo 0)
            fi
            FD_COUNT=$(ls -1 "/proc/$DAEMON_PID/fd" 2>/dev/null | wc -l || echo 0)
        fi

        # Track maximums
        [ "$RSS_KB" -gt "$MAX_RSS" ] && MAX_RSS=$RSS_KB
        [ "$FD_COUNT" -gt "$MAX_FD" ] && MAX_FD=$FD_COUNT

        echo "[ALIVE] $(date '+%H:%M:%S') elapsed=${ELAPSED}s rss=${RSS_KB}kB fds=${FD_COUNT}" >> "$SOAK_LOG"
    fi

    # ── ntpq-rs Query (every NTPQ_INTERVAL seconds) ────────────────
    if [ $((ELAPSED - LAST_NTPQ_TIME)) -ge "$NTPQ_INTERVAL" ] || [ "$NTPQ_COUNT" -eq 0 ]; then
        LAST_NTPQ_TIME=$ELAPSED
        NTPQ_COUNT=$((NTPQ_COUNT + 1))
        local_time=$(date '+%H:%M:%S')

        # ── Read system variables (ntpq -c rv) ────────────────────
        RV_OUTPUT=$("$NTPQ_BIN" -c rv 2>&1 || true)
        RV_EXIT=$?

        if [ "$RV_EXIT" -ne 0 ] || [ -z "$RV_OUTPUT" ]; then
            NTPQ_FAIL=$((NTPQ_FAIL + 1))
            echo "[NTPQ] $local_time elapsed=${ELAPSED}s FAIL rv_exit=$RV_EXIT" >> "$SOAK_LOG"
            log_warn "ntpq-rs -c rv failed (attempt $NTPQ_FAIL)"
            OFFSET_MS="N/A"
            FREQ="N/A"
            JITTER_MS="N/A"
            STRATUM="N/A"
        else
            OFFSET=$(echo "$RV_OUTPUT" | grep -oP 'offset=\K[^ ]+' || echo "N/A")
            FREQ=$(echo "$RV_OUTPUT" | grep -oP 'frequency=\K[^ ]+' || echo "N/A")
            JITTER=$(echo "$RV_OUTPUT" | grep -oP '(sys_jitter|jitter)=\K[^ ]+' || echo "N/A")
            STRATUM=$(echo "$RV_OUTPUT" | grep -oP 'stratum=\K[^ ]+' || echo "N/A")
            OFFSET_MS=$(echo "$OFFSET" | awk '{printf "%.6f", $1 * 1000}' 2>/dev/null || echo "N/A")
            JITTER_MS=$(echo "$JITTER" | awk '{printf "%.6f", $1 * 1000}' 2>/dev/null || echo "N/A")

            echo "[NTPQ] $local_time elapsed=${ELAPSED}s offset_ms=${OFFSET_MS} freq=${FREQ} jitter_ms=${JITTER_MS} stratum=${STRATUM}" >> "$SOAK_LOG"
        fi

        # ── Read peers (ntpq -c peers) ────────────────────────────
        PEERS_OUTPUT=$("$NTPQ_BIN" -c peers 2>&1 || true)
        PEERS_EXIT=$?

        if [ "$PEERS_EXIT" -ne 0 ] || [ -z "$PEERS_OUTPUT" ]; then
            echo "[PEER] $local_time elapsed=${ELAPSED}s FAIL exit=$PEERS_EXIT" >> "$SOAK_LOG"
            PEER_REACH="N/A"
            PEER_STRATUM="N/A"
            PEER_OFFSET="N/A"
            PEER_JITTER="N/A"
            PEER_DELAY="N/A"
        else
            # Extract the first data line from peers output (skip header/separator)
            PEER_LINE=$(echo "$PEERS_OUTPUT" \
                | grep -v '^==' \
                | grep -v '^\s*$' \
                | grep -v 'remote' \
                | head -1)

            if [ -n "$PEER_LINE" ]; then
                # peers format: remote refid st t when poll reach delay offset jitter
                PEER_REACH=$(echo "$PEER_LINE" | awk '{print $7}' || echo "N/A")
                PEER_STRATUM=$(echo "$PEER_LINE" | awk '{print $4}' || echo "N/A")
                PEER_OFFSET=$(echo "$PEER_LINE" | awk '{print $9}' || echo "N/A")
                PEER_JITTER=$(echo "$PEER_LINE" | awk '{print $11}' || echo "N/A")
                PEER_DELAY=$(echo "$PEER_LINE" | awk '{print $8}' || echo "N/A")
            fi

            echo "[PEER] $local_time elapsed=${ELAPSED}s reach=${PEER_REACH} stratum=${PEER_STRATUM} offset=${PEER_OFFSET} jitter=${PEER_JITTER} delay=${PEER_DELAY}" >> "$SOAK_LOG"
        fi

        # ── Count loopstats entries (clock adjustments) ────────────
        ADJ_COUNT=0
        if [ -f "$STATS_DIR/loopstats" ]; then
            ADJ_COUNT=$(wc -l < "$STATS_DIR/loopstats" 2>/dev/null || echo 0)
        fi
        echo "[STAT] $local_time elapsed=${ELAPSED}s adj_count=${ADJ_COUNT}" >> "$SOAK_LOG"

        # Periodic progress to stdout
        echo -e "${GREEN}[${ELAPSED}s / ${RUN_DURATION}s]${NC} offset=${OFFSET_MS}ms freq=${FREQ} stratum=${STRATUM} reach=${PEER_REACH} rss=${RSS_KB}kB fds=${FD_COUNT} adj=${ADJ_COUNT}"
    fi

    # ── Abort check: scan daemon log for panics ───────────────────
    if [ -f "$DAEMON_LOG" ] && grep -qi 'panic\|thread.*panicked' "$DAEMON_LOG" 2>/dev/null; then
        log_error "Panic detected in daemon log at t=${ELAPSED}s!"
        CRASH_DETECTED=1
        grep -i 'panic\|thread.*panicked' "$DAEMON_LOG" | tail -5 | while read -r line; do
            echo "       $line"
        done
        break
    fi

    # Track excessive ERROR messages in daemon log
    if [ -f "$DAEMON_LOG" ]; then
        local error_count
        error_count=$(grep -c '\[ERROR\]' "$DAEMON_LOG" 2>/dev/null || echo 0)
        if [ "$error_count" -gt 10 ]; then
            HAD_ERRORS=1
        fi
    fi

    # Short sleep to keep loop responsive without busy-waiting
    sleep 5
done

# Cleanup is called automatically by the EXIT trap
exit 0
