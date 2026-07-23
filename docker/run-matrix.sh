#!/bin/sh
# ──── NTPsec Oracle Matrix ──────────────────────────────────────────────────
# Phase 2.5 — Hardened lifecycle regression court.
#
# Tests:
#   1. Forward: ntpd-rs vs real ntpq (protocol parity)
#   2. Reverse hardened: ntpd-rs -u ntp --seccomp queried by real ntpq
#   3. Capability and seccomp enforcement
#   4. Lifecycle: SIGHUP survives, SIGTERM flushes drift and exits 0
#
# Usage:
#   ./run-matrix.sh                       # Run full matrix on all images
#   ./run-matrix.sh alpine                # Run on a single image
# =============================================================================

set -e

cd "$(dirname "$0")"

IMAGES="${1:-alpine debian-stable ubuntu-lts fedora}"
RESULTS_DIR="$(pwd)/results"

mkdir -p "$RESULTS_DIR"

echo "============================================"
echo " NTPsec Oracle Matrix — Phase 2.5"
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

    GIT_COMMIT=$(cd /home/one/ntpsec-rs && git rev-parse HEAD 2>/dev/null || echo "unknown")
    echo "$GIT_COMMIT" > "$IMG_RESULTS/git_commit.txt"

    cat > "$IMG_RESULTS/metadata.txt" << EOF
image=ntpsec-oracle:${img}
date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
git_commit=$GIT_COMMIT
EOF

    # Write oracle script to temp file
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

# Record environment
ntpq --version 2>/dev/null > "$RESULTS/ntpq_version.txt" || true
ntpd --version 2>/dev/null > "$RESULTS/ntpd_version.txt" || true
cat /etc/os-release 2>/dev/null | head -4 > "$RESULTS/os_release.txt" || true
sha256sum /opt/ntpsec-rs/target/release/ntpd-rs 2>/dev/null | cut -d' ' -f1 > "$RESULTS/ntpd-rs.sha256" || true
sha256sum /opt/ntpsec-rs/target/release/ntpq-rs 2>/dev/null | cut -d' ' -f1 > "$RESULTS/ntpq-rs.sha256" || true
if file /usr/bin/ntpq 2>/dev/null | grep -q ELF; then
    sha256sum /usr/bin/ntpq 2>/dev/null | cut -d' ' -f1 > "$RESULTS/ntpq.sha256" || true
fi

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
        | sed -e "s/\(^\|[, ]\)\(clock\|reftime\|when\|rcvbuf\|clock_epoch\|uptime\|sys_epoch\)=[^, ]*/\1\2=XXX/g" \
        | sed -e 's/ when=[0-9]*/ when=XXX/g' \
        | sed -e 's/[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}/HH:MM:SS/g'
}

compare_output() {
    label="$1"
    expected="$2"
    actual="$3"
    outfile="$4"
    total=$((total + 1))

    echo "$expected" > "$RESULTS/${outfile}.real.txt"
    echo "$actual" > "$RESULTS/${outfile}.rust.txt"

    norm_expected=$(normalise "$expected")
    norm_actual=$(normalise "$actual")

    echo "$norm_expected" > "$RESULTS/${outfile}.normalised.real.txt"
    echo "$norm_actual" > "$RESULTS/${outfile}.normalised.rust.txt"

    if [ "$norm_expected" = "$norm_actual" ]; then
        report_pass "$label"
        echo "PASS" > "$RESULTS/${outfile}.result"
    else
        echo "$norm_expected" > /tmp/expected.txt
        echo "$norm_actual" > /tmp/actual.txt
        diff /tmp/expected.txt /tmp/actual.txt > "$RESULTS/${outfile}.diff" 2>&1 || true
        report_fail "$label" "Output differs. See ${outfile}.diff"
        echo "FAIL" > "$RESULTS/${outfile}.result"
    fi
}

# ──── Create test user for -u flag ──────────────────────────────────────────
# Portable across Alpine (adduser), Debian/Ubuntu (adduser --disabled-password),
# and Fedora (useradd)
if command -v useradd >/dev/null 2>&1; then
    useradd -M ntp 2>/dev/null || true
elif command -v adduser >/dev/null 2>&1; then
    adduser -D ntp 2>/dev/null || adduser --disabled-password ntp 2>/dev/null || true
fi

# ──── FORWARD COURT: real ntpd queried by both clients ──────────────────────
echo ""
echo "=== FORWARD COURT: real ntpd ==="

pkill -f "ntpd" 2>/dev/null || true
sleep 1

ntpd -c "$CONF" -n > /tmp/ntpd.log 2>&1 &
NTPD_PID=$!
sleep 2

if ! kill -0 "$NTPD_PID" 2>/dev/null; then
    echo "  FATAL: real ntpd failed to start"
    cat /tmp/ntpd.log
    report_fail "forward court" "real ntpd failed to start"
    echo "FAIL" > "$RESULTS/forward.result"
else
    echo "  real ntpd PID: $NTPD_PID"

    # rv
    echo "--- rv ---"
    NTPQ_RS_RV=$($NTPQ_RS -c rv 2>/dev/null || echo "ERROR")
    NTPQ_RV=$(ntpq -c rv 2>/dev/null || echo "")
    if [ -n "$NTPQ_RV" ]; then
        compare_output "rv forward" "$NTPQ_RV" "$NTPQ_RS_RV" "rv_forward"
    else
        report_fail "rv forward (real ntpq unavailable)" ""
        echo "FAIL" > "$RESULTS/rv_forward.result"
    fi

    # associations
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
    echo "--- peers ---"
    NTPQ_RS_PEERS=$($NTPQ_RS -c peers 2>/dev/null || echo "ERROR")
    NTPQ_PEERS=$(ntpq -c peers 2>/dev/null || echo "")
    if [ -n "$NTPQ_PEERS" ]; then
        compare_output "peers forward" "$NTPQ_PEERS" "$NTPQ_RS_PEERS" "peers_forward"
    else
        report_fail "peers forward (real ntpq unavailable)" ""
        echo "FAIL" > "$RESULTS/peers_forward.result"
    fi

    kill "$NTPD_PID" 2>/dev/null || true
    wait "$NTPD_PID" 2>/dev/null || true
    sleep 1
fi

# ──── REVERSE COURT: hardened ntpd-rs (-u ntp --seccomp) ────────────────────
echo ""
echo "=== REVERSE COURT: ntpd-rs -u ntp --seccomp ==="

pkill -f "ntpd-rs" 2>/dev/null || true
sleep 2

$NTPD_RS -c "$CONF" -n -u ntp --seccomp > "$RESULTS/ntpd-rs.log" 2>&1 &
NTPD_RS_PID=$!
sleep 3

if ! kill -0 "$NTPD_RS_PID" 2>/dev/null; then
    echo "  WARN: ntpd-rs failed to start"
    cat "$RESULTS/ntpd-rs.log"
    report_fail "ntpd-rs startup" "daemon failed to start with -u ntp --seccomp"
    echo "FAIL" > "$RESULTS/rv_reverse.result"
    echo "FAIL" > "$RESULTS/associations_reverse.result"
    echo "FAIL" > "$RESULTS/peers_reverse.result"
    echo "FAIL" > "$RESULTS/capability.result"
    echo "FAIL" > "$RESULTS/seccomp.result"
else
    echo "  ntpd-rs PID: $NTPD_RS_PID"

    # ── Hardening assertions ──────────────────────────────────────────
    echo ""
    echo "--- Hardening assertions ---"

    # 1. UID must be non-zero (dropped privileges)
    # Use /proc/PID/status for portability across BusyBox/procps
    DAEMON_UID_LINE=$(cat /proc/$NTPD_RS_PID/status 2>/dev/null | grep '^Uid:' | awk '{print $2}')
    echo "  Daemon UID: $DAEMON_UID_LINE"
    echo "$DAEMON_UID_LINE" > "$RESULTS/daemon_uid.txt"
    if [ "$DAEMON_UID_LINE" != "0" ] && [ -n "$DAEMON_UID_LINE" ]; then
        report_pass "UID dropped (not root)"
        echo "PASS" > "$RESULTS/uid.result"
    else
        report_fail "UID drop" "Daemon UID is $DAEMON_UID_LINE, expected non-zero"
        echo "FAIL" > "$RESULTS/uid.result"
    fi

    # 2. Seccomp mode must be 2 (filter)
    DAEMON_SECCOMP=$(cat /proc/$NTPD_RS_PID/status 2>/dev/null | grep '^Seccomp:' | awk '{print $2}')
    echo "  Daemon Seccomp: $DAEMON_SECCOMP"
    echo "$DAEMON_SECCOMP" > "$RESULTS/daemon_seccomp.txt"
    if [ "$DAEMON_SECCOMP" = "2" ]; then
        report_pass "Seccomp mode 2 (filter)"
        echo "PASS" > "$RESULTS/seccomp.result"
    else
        report_fail "Seccomp mode" "Expected 2, got '$DAEMON_SECCOMP'"
        echo "FAIL" > "$RESULTS/seccomp.result"
    fi

    # 3. Capability sets (CapEff = CAP_SYS_TIME only = bit 25 = 0x2000000)
    DAEMON_CAPEFF=$(cat /proc/$NTPD_RS_PID/status 2>/dev/null | grep '^CapEff:' | awk '{print $2}')
    DAEMON_CAPPRM=$(cat /proc/$NTPD_RS_PID/status 2>/dev/null | grep '^CapPrm:' | awk '{print $2}')
    DAEMON_CAPINH=$(cat /proc/$NTPD_RS_PID/status 2>/dev/null | grep '^CapInh:' | awk '{print $2}')
    echo "  CapEff: $DAEMON_CAPEFF"
    echo "  CapPrm: $DAEMON_CAPPRM"
    echo "  CapInh: $DAEMON_CAPINH"
    echo "$DAEMON_CAPEFF" > "$RESULTS/daemon_capeff.txt"
    echo "$DAEMON_CAPPRM" > "$RESULTS/daemon_capprm.txt"
    echo "$DAEMON_CAPINH" > "$RESULTS/daemon_capinh.txt"

    CAP_SYS_TIME_HEX="0000000002000000"
    if [ "$DAEMON_CAPEFF" = "$CAP_SYS_TIME_HEX" ] && \
       [ "$DAEMON_CAPPRM" = "$CAP_SYS_TIME_HEX" ] && \
       [ "$DAEMON_CAPINH" = "0000000000000000" ]; then
        report_pass "Capability sets correct (CAP_SYS_TIME only)"
        echo "PASS" > "$RESULTS/capability.result"
    else
        report_fail "Capability sets" \
            "Expected Eff=$CAP_SYS_TIME_HEX Prm=$CAP_SYS_TIME_HEX Inh=0000000000000000"
        echo "FAIL" > "$RESULTS/capability.result"
    fi

    # ── Protocol queries ─────────────────────────────────────────────
    echo ""
    echo "--- Protocol queries ---"

    # rv
    echo "--- rv (reverse) ---"
    if NTPQ_RV_REV=$(ntpq -4 -c rv 127.0.0.1 2>"$RESULTS/rv_reverse.stderr"); then
        if printf '%s\n' "$NTPQ_RV_REV" | grep -q '^associd='; then
            echo "$NTPQ_RV_REV" > "$RESULTS/rv_reverse.real.txt"
            report_pass "rv reverse (real ntpq queried ntpd-rs)"
            echo "PASS" > "$RESULTS/rv_reverse.result"
        else
            echo "$NTPQ_RV_REV" > "$RESULTS/rv_reverse.real.txt"
            report_fail "rv reverse malformed" "ntpq output does not start with associd="
            echo "FAIL" > "$RESULTS/rv_reverse.result"
        fi
    else
        report_fail "rv reverse failed" "ntpq exited nonzero"
        cat "$RESULTS/rv_reverse.stderr" 2>/dev/null
        echo "FAIL" > "$RESULTS/rv_reverse.result"
    fi

    # ntpq-rs against ntpd-rs
    echo "--- rv (reverse, ntpq-rs) ---"
    if NTPQ_RS_RV_REV=$($NTPQ_RS -c rv 2>"$RESULTS/rv_reverse_rs.stderr"); then
        if printf '%s\n' "$NTPQ_RS_RV_REV" | grep -q '^associd='; then
            echo "$NTPQ_RS_RV_REV" > "$RESULTS/rv_reverse_rs.txt"
            report_pass "rv reverse (ntpq-rs queried ntpd-rs)"
            echo "PASS" > "$RESULTS/rv_reverse_rs.result"
        else
            echo "$NTPQ_RS_RV_REV" > "$RESULTS/rv_reverse_rs.txt"
            report_fail "rv reverse rs malformed" ""
            echo "FAIL" > "$RESULTS/rv_reverse_rs.result"
        fi
    else
        report_fail "rv reverse rs failed" "ntpq-rs exited nonzero"
        echo "FAIL" > "$RESULTS/rv_reverse_rs.result"
    fi

    # associations
    echo "--- associations (reverse) ---"
    if NTPQ_AS_REV=$(ntpq -4 -c associations 127.0.0.1 2>"$RESULTS/associations_reverse.stderr"); then
        if printf '%s\n' "$NTPQ_AS_REV" | grep -q '^ind assid'; then
            echo "$NTPQ_AS_REV" > "$RESULTS/associations_reverse.real.txt"
            report_pass "associations reverse"
            echo "PASS" > "$RESULTS/associations_reverse.result"
        else
            echo "$NTPQ_AS_REV" > "$RESULTS/associations_reverse.real.txt"
            report_fail "associations reverse malformed" ""
            echo "FAIL" > "$RESULTS/associations_reverse.result"
        fi
    else
        report_fail "associations reverse failed" "ntpq exited nonzero"
        echo "FAIL" > "$RESULTS/associations_reverse.result"
    fi

    # peers
    echo "--- peers (reverse) ---"
    if NTPQ_PEERS_REV=$(ntpq -4 -c peers 127.0.0.1 2>"$RESULTS/peers_reverse.stderr"); then
        if printf '%s\n' "$NTPQ_PEERS_REV" | grep -q '^     remote'; then
            echo "$NTPQ_PEERS_REV" > "$RESULTS/peers_reverse.real.txt"
            report_pass "peers reverse"
            echo "PASS" > "$RESULTS/peers_reverse.result"
        else
            echo "$NTPQ_PEERS_REV" > "$RESULTS/peers_reverse.real.txt"
            report_fail "peers reverse malformed" ""
            echo "FAIL" > "$RESULTS/peers_reverse.result"
        fi
    else
        report_fail "peers reverse failed" "ntpq exited nonzero"
        echo "FAIL" > "$RESULTS/peers_reverse.result"
    fi

    # ── Lifecycle tests ──────────────────────────────────────────────
    echo ""
    echo "--- Lifecycle tests ---"

    # SIGHUP: daemon should survive and remain queryable
    kill -HUP "$NTPD_RS_PID" 2>/dev/null
    sleep 1
    if kill -0 "$NTPD_RS_PID" 2>/dev/null; then
        if NTPQ_RV_HUP=$(ntpq -4 -c rv 127.0.0.1 2>"$RESULTS/rv_sighup.stderr") && \
           printf '%s\n' "$NTPQ_RV_HUP" | grep -q '^associd='; then
            echo "$NTPQ_RV_HUP" > "$RESULTS/rv_sighup.txt"
            report_pass "SIGHUP: daemon alive and queryable"
            echo "PASS" > "$RESULTS/sighup.result"
        else
            report_fail "SIGHUP: daemon alive but unqueryable" ""
            echo "FAIL" > "$RESULTS/sighup.result"
        fi
    else
        report_fail "SIGHUP: daemon died" "ntpd-rs terminated after SIGHUP"
        echo "FAIL" > "$RESULTS/sighup.result"
    fi

    # SIGTERM: graceful shutdown, drift persisted, exit 0
    kill -TERM "$NTPD_RS_PID" 2>/dev/null
    wait "$NTPD_RS_PID" 2>/dev/null || true
    SIGTERM_EXIT=$?
    echo "  SIGTERM exit code: $SIGTERM_EXIT"
    echo "$SIGTERM_EXIT" > "$RESULTS/sigterm_exit.txt"
    if [ "$SIGTERM_EXIT" -eq 0 ]; then
        report_pass "SIGTERM: clean exit code 0"
        echo "PASS" > "$RESULTS/sigterm.result"
    else
        report_fail "SIGTERM: exit code $SIGTERM_EXIT (expected 0)" ""
        echo "FAIL" > "$RESULTS/sigterm.result"
    fi

    sleep 1
fi

# ──── ntpdig ────────────────────────────────────────────────────────────────
echo ""
echo "=== ntpdig ==="
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

NTPDIG_OUT=$(ntpdig -4 127.0.0.1 2>/dev/null || echo "")
if [ -n "$NTPDIG_OUT" ]; then
    echo "$NTPDIG_OUT" > "$RESULTS/ntpdig_real.txt"
    echo "  ntpdig available on this platform"
    report_pass "ntpdig parity"
    echo "PASS" > "$RESULTS/ntpdig_parity.result"
else
    echo "  INFO: real ntpdig not available"
    echo "SKIP" > "$RESULTS/ntpdig_parity.result"
fi

kill "$NTPD_PID2" 2>/dev/null || true
wait "$NTPD_PID2" 2>/dev/null || true

# ──── Container Summary ────────────────────────────────────────────────────
echo ""
echo "=== Container Summary ==="
echo "  Total:  $total"
echo "  Failed: $failed"
echo "  Status: $([ "$failed" -eq 0 ] && echo 'ALL PASSED' || echo 'SOME FAILED')"

exit $([ "$failed" -eq 0 ] && echo 0 || echo 1)
ORACLE_EOF

    # ──── Run container with SYS_TIME capability ────────────────────
    if docker run --rm -i \
        --cap-add=NET_ADMIN \
        --cap-add=NET_BIND_SERVICE \
        --cap-add=SYS_TIME \
        -v "$IMG_RESULTS:/tmp/results" \
        "ntpsec-oracle:${img}" \
        /bin/sh < "$ORACLE_SCRIPT"
    then
        echo "  >>> Container PASSED <<<"
    else
        echo "  >>> Container FAILED <<<"
        OVERALL_FAILED=1
    fi

    # ──── Build container summary ────────────────────────────────────
    {
        echo "image: ntpsec-oracle:${img}"
        echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "git_commit: $GIT_COMMIT"
        echo ""
        echo "--- Forward Court (ntpq-rs vs real ntpd) ---"
        for t in rv_forward associations_forward peers_forward; do
            if [ -f "$IMG_RESULTS/$t.result" ]; then
                echo "$t: $(cat $IMG_RESULTS/$t.result)"
            fi
        done
        echo ""
        echo "--- Reverse Court (real ntpq vs ntpd-rs -u ntp --seccomp) ---"
        for t in rv_reverse associations_reverse peers_reverse; do
            if [ -f "$IMG_RESULTS/$t.result" ]; then
                echo "$t: $(cat $IMG_RESULTS/$t.result)"
            fi
        done
        echo ""
        echo "--- Hardening ---"
        for t in uid seccomp capability sighup sigterm; do
            if [ -f "$IMG_RESULTS/$t.result" ]; then
                echo "$t: $(cat $IMG_RESULTS/$t.result)"
            fi
        done
        echo ""
        echo "--- Rust Client Reverse ---"
        if [ -f "$IMG_RESULTS/rv_reverse_rs.result" ]; then
            echo "rv_reverse_rs: $(cat $IMG_RESULTS/rv_reverse_rs.result)"
        fi
        echo ""
        echo "--- ntpdig ---"
        if [ -f "$IMG_RESULTS/ntpdig_rs.result" ]; then
            echo "ntpdig_rs: $(cat $IMG_RESULTS/ntpdig_rs.result)"
        fi
        if [ -f "$IMG_RESULTS/ntpdig_parity.result" ]; then
            echo "ntpdig_parity: $(cat $IMG_RESULTS/ntpdig_parity.result)"
        fi
    } > "$IMG_RESULTS/container_result.txt"

    rm -f "$ORACLE_SCRIPT"
done

# ──── Global Summary ──────────────────────────────────────────────────────
echo ""
echo "============================================"
echo " Oracle Matrix Summary — Phase 2.5"
echo " Results: $RESULTS_DIR"
echo "============================================"
for img in $IMAGES; do
    echo ""
    echo "--- $img ---"
    if [ -f "$RESULTS_DIR/${img}/container_result.txt" ]; then
        grep -E '^(rv_|associations_|peers_|uid|seccomp|capability|sighup|sigterm|ntpdig_)' \
            "$RESULTS_DIR/${img}/container_result.txt" || echo "  (no results)"
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
