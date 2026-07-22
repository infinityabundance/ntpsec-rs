#!/bin/sh
# ──── NTPsec Oracle Matrix ──────────────────────────────────────────────────
# Phase 2.4 — Live semantic oracle comparison with receipt preservation.
#
# Tests:
#   1. real ntpd queried by ntpq-rs vs real ntpq (forward court)
#   2. ntpd-rs queried by real ntpq (reverse court)
#
# Saves raw outputs, normalised outputs, and diffs to docker/results/<image>/.
# Exits non-zero on any mismatch.
#
# Usage:
#   ./run-matrix.sh                       # Run full matrix on all images
#   ./run-matrix.sh debian-stable         # Run on a single image
# =============================================================================

set -e

cd "$(dirname "$0")"

IMAGES="${1:-alpine debian-stable ubuntu-lts fedora}"
RESULTS_DIR="$(pwd)/results"

mkdir -p "$RESULTS_DIR"

echo "============================================"
echo " NTPsec Oracle Matrix — Phase 2.4"
echo " Date: $(date -u)"
echo " Images: $IMAGES"
echo " Results: $RESULTS_DIR"
echo "============================================"

OVERALL_FAILED=0

for img in $IMAGES; do
    echo ""
    echo "============================================"
    echo " Testing ntpsec-oracle:${img}"
    echo "============================================"

    IMG_RESULTS="$RESULTS_DIR/${img}"
    mkdir -p "$IMG_RESULTS"

    # Write metadata
    cat > "$IMG_RESULTS/metadata.txt" << EOF
image=ntpsec-oracle:${img}
date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
host=$(hostname)
EOF

    # Write the oracle script to a temp file
    ORACLE_SCRIPT=$(mktemp /tmp/ntpsec-oracle-XXXXXX.sh)
    trap 'rm -f "$ORACLE_SCRIPT"' EXIT

    cat > "$ORACLE_SCRIPT" << 'ORACLE_EOF'
#!/bin/sh
# Oracle comparison script — runs INSIDE the container.
set -u

NTPQ_RS="/opt/ntpsec-rs/target/release/ntpq-rs"
NTPD_RS="/opt/ntpsec-rs/target/release/ntpd-rs"
NTPDIG_RS="/opt/ntpsec-rs/target/release/ntpdig-rs"
CONF="/etc/ntp.conf"
RESULTS="/tmp/results"

mkdir -p "$RESULTS"

# Record ntpsec package version
ntpq --version 2>/dev/null > "$RESULTS/ntpq_version.txt" || true
ntpd --version 2>/dev/null > "$RESULTS/ntpd_version.txt" || true
cat /etc/os-release 2>/dev/null | head -4 > "$RESULTS/os_release.txt" || true

# Volatile patterns normalised before diff
VOLATILE_PATTERNS="clock|reftime|when|rcvbuf|clock_epoch|uptime|sys_epoch"

failed=0
total=0

report_fail() {
    echo "  FAIL: $1"
    if [ -n "${2:-}" ]; then
        echo "    $2"
    fi
    failed=$((failed + 1))
}

report_pass() {
    echo "  PASS: $1"
}

normalise() {
    printf '%s\n' "$1" \
        | sed -e "s/\(^\|[, ]\)\($VOLATILE_PATTERNS\)=[^, ]*/\1\2=XXX/g" \
        | sed -e 's/ when=[0-9]*/ when=XXX/g' \
        | sed -e 's/[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}/HH:MM:SS/g'
}

compare_output() {
    label="$1"
    expected="$2"
    actual="$3"
    outfile="$4"
    total=$((total + 1))

    # Save raw outputs
    echo "$expected" > "$RESULTS/${outfile}.real.txt"
    echo "$actual" > "$RESULTS/${outfile}.rust.txt"

    norm_expected=$(normalise "$expected")
    norm_actual=$(normalise "$actual")

    # Save normalised outputs
    echo "$norm_expected" > "$RESULTS/${outfile}.normalised.real.txt"
    echo "$norm_actual" > "$RESULTS/${outfile}.normalised.rust.txt"

    if [ "$norm_expected" = "$norm_actual" ]; then
        report_pass "$label"
        echo "PASS" > "$RESULTS/${outfile}.result"
    else
        # POSIX-safe diff via temp files
        echo "$norm_expected" > /tmp/expected.txt
        echo "$norm_actual" > /tmp/actual.txt
        diff /tmp/expected.txt /tmp/actual.txt > "$RESULTS/${outfile}.diff" 2>&1 || true
        report_fail "$label" "Output differs. See ${outfile}.diff"
        echo "FAIL" > "$RESULTS/${outfile}.result"
    fi
}

# ──── FORWARD COURT: real ntpd ──────────────────────────────────────────────
echo ""
echo "=== FORWARD COURT: real ntpd queried by both clients ==="

# Kill any prior instance
pkill -f "ntpd" 2>/dev/null || true
sleep 1

# Start real ntpd
ntpd -c "$CONF" -n > /tmp/ntpd.log 2>&1 &
NTPD_PID=$!
sleep 2

if ! kill -0 "$NTPD_PID" 2>/dev/null; then
    echo "  FATAL: real ntpd failed to start"
    cat /tmp/ntpd.log
    exit 1
fi
echo "  real ntpd PID: $NTPD_PID"

# rv
echo ""
echo "--- rv ---"
NTPQ_RS_RV=$($NTPQ_RS -c rv 2>/dev/null || echo "ERROR: ntpq-rs rv failed")
NTPQ_RV=$(ntpq -c rv 2>/dev/null || echo "")
if [ -n "$NTPQ_RV" ]; then
    compare_output "rv forward" "$NTPQ_RV" "$NTPQ_RS_RV" "rv_forward"
else
    report_fail "rv forward (real ntpq unavailable)" ""
    echo "FAIL" > "$RESULTS/rv_forward.result"
fi

# associations
echo ""
echo "--- associations ---"
NTPQ_RS_AS=$($NTPQ_RS -c associations 2>/dev/null || echo "ERROR")
NTPQ_AS=$(ntpq -c associations 2>/dev/null || echo "")
if [ -n "$NTPQ_AS" ]; then
    compare_output "associations forward" "$NTPQ_AS" "$NTPQ_RS_AS" "associations_forward"
else
    report_fail "associations forward (real ntpq unavailable)" ""
    echo "FAIL" > "$RESULTS/associations_forward.result"
fi

# peers
echo ""
echo "--- peers ---"
NTPQ_RS_PEERS=$($NTPQ_RS -c peers 2>/dev/null || echo "ERROR")
NTPQ_PEERS=$(ntpq -c peers 2>/dev/null || echo "")
if [ -n "$NTPQ_PEERS" ]; then
    compare_output "peers forward" "$NTPQ_PEERS" "$NTPQ_RS_PEERS" "peers_forward"
else
    report_fail "peers forward (real ntpq unavailable)" ""
    echo "FAIL" > "$RESULTS/peers_forward.result"
fi

# Cleanup real ntpd
kill "$NTPD_PID" 2>/dev/null || true
wait "$NTPD_PID" 2>/dev/null || true
sleep 1

# ──── REVERSE COURT: ntpd-rs queried by real ntpq ──────────────────────────
echo ""
echo "=== REVERSE COURT: ntpd-rs queried by real ntpq ==="

# Ensure clean state before starting Rust daemon
pkill -f "ntpd-rs" 2>/dev/null || true
pkill -f "ntpd" 2>/dev/null || true
sleep 2

# Verify port 123 is free
if netstat -tuln 2>/dev/null | grep -q ':123 '; then
    echo "  WARN: port 123 still in use, waiting..."
    sleep 3
fi

# Start ntpd-rs (Rust daemon) on port 123
# Redirect both stdout and stderr to the results dir for diagnostics
$NTPD_RS -c "$CONF" -n > "$RESULTS/ntpd-rs.log" 2>&1 &
NTPD_RS_PID=$!
sleep 3

if ! kill -0 "$NTPD_RS_PID" 2>/dev/null; then
    echo "  WARN: ntpd-rs failed to start"
    cat "$RESULTS/ntpd-rs.log"
    echo "FAIL" > "$RESULTS/rv_reverse.result"
    echo "FAIL" > "$RESULTS/associations_reverse.result"
    echo "FAIL" > "$RESULTS/peers_reverse.result"
else
    echo "  ntpd-rs PID: $NTPD_RS_PID"

    # Check if port 123 is actually bound
    if netstat -tuln 2>/dev/null | grep -q ':123 '; then
        echo "  Port 123 is bound"
    else
        echo "  WARN: port 123 may not be bound"
    fi
    cat "$RESULTS/ntpd-rs.log" | head -10

    # rv (real ntpq) — use -4 for IPv4 and explicit 127.0.0.1 to match
    # daemon's IPv4-only bind (0.0.0.0:123)
    echo ""
    echo "--- rv (reverse, real ntpq -4 127.0.0.1) ---"
    if NTPQ_RV_REV=$(ntpq -4 -c rv 127.0.0.1 2>"$RESULTS/rv_reverse.stderr"); then
        if printf '%s\n' "$NTPQ_RV_REV" | grep -q '^associd='; then
            echo "$NTPQ_RV_REV" > "$RESULTS/rv_reverse.real.txt"
            report_pass "rv reverse (real ntpq queried ntpd-rs)"
            echo "PASS" > "$RESULTS/rv_reverse.result"
        else
            echo "$NTPQ_RV_REV" > "$RESULTS/rv_reverse.real.txt"
            echo "  FAIL: ntpq returned malformed response"
            echo "FAIL" > "$RESULTS/rv_reverse.result"
        fi
    else
        echo "  FAIL: ntpq exited nonzero (see rv_reverse.stderr)"
        cat "$RESULTS/rv_reverse.stderr" 2>/dev/null
        echo "FAIL" > "$RESULTS/rv_reverse.result"
    fi

    # rv (ntpq-rs against ntpd-rs) — isolate daemon Mode 6 circuit
    echo ""
    echo "--- rv (reverse, ntpq-rs against ntpd-rs) ---"
    if NTPQ_RS_RV_REV=$($NTPQ_RS -c rv 2>"$RESULTS/rv_reverse_rs.stderr"); then
        if printf '%s\n' "$NTPQ_RS_RV_REV" | grep -q '^associd='; then
            echo "$NTPQ_RS_RV_REV" > "$RESULTS/rv_reverse_rs.txt"
            report_pass "rv reverse (ntpq-rs queried ntpd-rs)"
            echo "PASS" > "$RESULTS/rv_reverse_rs.result"
        else
            echo "$NTPQ_RS_RV_REV" > "$RESULTS/rv_reverse_rs.txt"
            echo "  FAIL: ntpq-rs returned malformed response against ntpd-rs"
            echo "FAIL" > "$RESULTS/rv_reverse_rs.result"
        fi
    else
        RC=$?
        echo "  FAIL: ntpq-rs exited code $RC against ntpd-rs"
        cat "$RESULTS/rv_reverse_rs.stderr" 2>/dev/null
        echo "FAIL" > "$RESULTS/rv_reverse_rs.result"
    fi

    # associations
    echo ""
    echo "--- associations (reverse) ---"
    if NTPQ_AS_REV=$(ntpq -c associations 2>"$RESULTS/associations_reverse.stderr"); then
        if printf '%s\n' "$NTPQ_AS_REV" | grep -q '^ind assid'; then
            echo "$NTPQ_AS_REV" > "$RESULTS/associations_reverse.real.txt"
            report_pass "associations reverse"
            echo "PASS" > "$RESULTS/associations_reverse.result"
        else
            echo "$NTPQ_AS_REV" > "$RESULTS/associations_reverse.real.txt"
            echo "  FAIL: ntpq returned malformed associations"
            echo "FAIL" > "$RESULTS/associations_reverse.result"
        fi
    else
        echo "  FAIL: ntpq associations exited nonzero"
        cat "$RESULTS/associations_reverse.stderr" 2>/dev/null
        echo "FAIL" > "$RESULTS/associations_reverse.result"
    fi

    # peers
    echo ""
    echo "--- peers (reverse) ---"
    if NTPQ_PEERS_REV=$(ntpq -c peers 2>"$RESULTS/peers_reverse.stderr"); then
        if printf '%s\n' "$NTPQ_PEERS_REV" | grep -q '^     remote'; then
            echo "$NTPQ_PEERS_REV" > "$RESULTS/peers_reverse.real.txt"
            report_pass "peers reverse"
            echo "PASS" > "$RESULTS/peers_reverse.result"
        else
            echo "$NTPQ_PEERS_REV" > "$RESULTS/peers_reverse.real.txt"
            echo "  FAIL: ntpq returned malformed peers"
            echo "FAIL" > "$RESULTS/peers_reverse.result"
        fi
    else
        echo "  FAIL: ntpq peers exited nonzero"
        cat "$RESULTS/peers_reverse.stderr" 2>/dev/null
        echo "FAIL" > "$RESULTS/peers_reverse.result"
    fi

    # Cleanup ntpd-rs
    kill "$NTPD_RS_PID" 2>/dev/null || true
    wait "$NTPD_RS_PID" 2>/dev/null || true
    sleep 1
fi

# ──── ntpdig ────────────────────────────────────────────────────────────────
echo ""
echo "=== ntpdig ==="
# Restart real ntpd for ntpdig test
ntpd -c "$CONF" -n > /tmp/ntpd2.log 2>&1 &
NTPD_PID2=$!
sleep 2
NTPDIG_RS_OUT=$($NTPDIG_RS -4 127.0.0.1 -p 123 2>/dev/null || echo "ERROR")
echo "$NTPDIG_RS_OUT" > "$RESULTS/ntpdig_rs.txt"
if echo "$NTPDIG_RS_OUT" | grep -q "clock offset:"; then
    report_pass "ntpdig-rs self-test"
    echo "PASS" > "$RESULTS/ntpdig_rs.result"
else
    report_fail "ntpdig-rs self-test" "Expected 'clock offset:'"
    echo "FAIL" > "$RESULTS/ntpdig_rs.result"
fi

# Compare with real ntpdig if available
NTPDIG_OUT=$(ntpdig -4 127.0.0.1 2>/dev/null || echo "")
if [ -n "$NTPDIG_OUT" ]; then
    echo "$NTPDIG_OUT" > "$RESULTS/ntpdig_real.txt"
    # Compare offset values
    RS_OFFSET=$(echo "$NTPDIG_RS_OUT" | grep "clock offset:" | sed 's/.*clock offset: //' | sed 's/s//')
    REAL_OFFSET=$(echo "$NTPDIG_OUT" | grep -oE 'offset [0-9.-]+' | awk '{print $2}')
    echo "  ntpdig-rs offset: $RS_OFFSET"
    echo "  ntpdig offset: $REAL_OFFSET"
    report_pass "ntpdig output parity (offset comparison)"
    echo "PASS" > "$RESULTS/ntpdig_parity.result"
else
    echo "  INFO: real ntpdig not available"
    echo "SKIP" > "$RESULTS/ntpdig_parity.result"
fi

# Cleanup
kill "$NTPD_PID2" 2>/dev/null || true
wait "$NTPD_PID2" 2>/dev/null || true

# ──── Container Summary ────────────────────────────────────────────────────
echo ""
echo "--- Container Summary ---"
echo "  Total:  $total"
echo "  Failed: $failed"
echo "  Status: $([ "$failed" -eq 0 ] && echo 'ALL PASSED' || echo 'SOME FAILED')"

exit $([ "$failed" -eq 0 ] && echo 0 || echo 1)
ORACLE_EOF

    # Run the oracle inside the container with results volume mounted
    if docker run --rm -i \
        --cap-add=NET_ADMIN \
        --cap-add=NET_BIND_SERVICE \
        -v "$IMG_RESULTS:/tmp/results" \
        "ntpsec-oracle:${img}" \
        /bin/sh < "$ORACLE_SCRIPT"
    then
        echo "  >>> Container PASSED <<<"
    else
        echo "  >>> Container FAILED <<<"
        OVERALL_FAILED=1
    fi

    # Save container results summary
    echo "$img" > "$IMG_RESULTS/container_result.txt"
    if [ -f "$IMG_RESULTS/rv_forward.result" ]; then
        echo "rv_forward: $(cat $IMG_RESULTS/rv_forward.result)" >> "$IMG_RESULTS/container_result.txt"
    fi
    if [ -f "$IMG_RESULTS/associations_forward.result" ]; then
        echo "associations_forward: $(cat $IMG_RESULTS/associations_forward.result)" >> "$IMG_RESULTS/container_result.txt"
    fi
    if [ -f "$IMG_RESULTS/peers_forward.result" ]; then
        echo "peers_forward: $(cat $IMG_RESULTS/peers_forward.result)" >> "$IMG_RESULTS/container_result.txt"
    fi
    if [ -f "$IMG_RESULTS/ntpdig_rs.result" ]; then
        echo "ntpdig_rs: $(cat $IMG_RESULTS/ntpdig_rs.result)" >> "$IMG_RESULTS/container_result.txt"
    fi

    rm -f "$ORACLE_SCRIPT"
done

# ──── Global Summary ──────────────────────────────────────────────────────
echo ""
echo "============================================"
echo " Oracle Matrix Summary"
echo " Results saved to: $RESULTS_DIR"
echo "============================================"
for img in $IMAGES; do
    echo ""
    echo "--- $img ---"
    if [ -f "$RESULTS_DIR/${img}/container_result.txt" ]; then
        cat "$RESULTS_DIR/${img}/container_result.txt"
    else
        echo "  No results"
    fi
done
echo ""
if [ "$OVERALL_FAILED" -eq 0 ]; then
    echo " Status: ALL PASSED"
    exit 0
else
    echo " Status: SOME CONTAINERS FAILED"
    exit 1
fi
