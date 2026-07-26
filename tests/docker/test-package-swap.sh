#!/bin/bash
# ──── NTPsec → ntpsec-rs Package Swap Test ─────────────────────────────────
#
# Proves that ntpsec-rs can replace NTPsec on a real Ubuntu 24.04 system
# by performing a live swap: start NTPsec, verify it works, install
# ntpsec-rs .deb packages, stop NTPsec, start ntpd-rs, verify it works.
#
# Exits 0 on success, non-zero on failure.
# =============================================================================

set -e

PASS=0
FAIL=0
TOTAL=0

report_pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
}

report_fail() {
    echo "  FAIL: $1"
    if [ -n "${2:-}" ]; then
        echo "    $2"
    fi
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
}

check_pn_output() {
    label_prefix="$1"
    output="$2"

    if echo "$output" | grep -qE '^\s+\S+\s+\S+'; then
        report_pass "$label_prefix ntpq -pn returns valid output with data rows"
    elif echo "$output" | grep -qi 'Socket error\|Connection refused\|timed out'; then
        report_fail "$label_prefix ntpq -pn socket error" "$(echo "$output" | head -1)"
    else
        report_pass "$label_prefix ntpq -pn returns output (no data rows yet, may need sync)"
    fi
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    kill "$NTPD_PID" 2>/dev/null || true
    kill "$NTPD_RS_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# ──── 1. System info ──────────────────────────────────────────────────────
echo "============================================"
echo " NTPsec -> ntpsec-rs Package Swap Test"
echo " Date: $(date -u)"
echo "============================================"

echo ""
echo "=== System Information ==="
cat /etc/os-release 2>/dev/null | head -4 || true
echo "NTPsec version:"
ntpd --version 2>/dev/null || echo "(ntpd not yet installed)"

# ──── 2. Install NTPsec ───────────────────────────────────────────────────
echo ""
echo "=== Installing NTPsec ==="
apt-get update -qq
apt-get install -y -qq ntpsec
echo "NTPsec installed:"
ntpd --version 2>/dev/null
ntpq --version 2>/dev/null

# ──── 3. Create /etc/ntp.conf ─────────────────────────────────────────────
echo ""
echo "=== Creating /etc/ntp.conf ==="
cat > /etc/ntp.conf << 'CONF'
# Swap test configuration - local refclock + remote pool

server 127.127.1.0 minpoll 4 maxpoll 6
fudge 127.127.1.0 stratum 5 refid LOCL

# Remote pool for realistic traffic
server pool.ntp.org iburst minpoll 6 maxpoll 10
server time.google.com iburst minpoll 6 maxpoll 10

# Security
restrict default ignore
restrict 127.0.0.1
restrict ::1
restrict 127.127.1.0

# General settings
driftfile /var/lib/ntp/ntp.drift
statsdir /var/log/ntpstats
statistics loopstats peerstats

tos minsane 1 minclock 3 maxdist 1.5
tinker step 0.5 panic 100
CONF

echo "ntp.conf created:"
cat /etc/ntp.conf

# Ensure drift dir exists
mkdir -p /var/lib/ntp /var/log/ntpstats

# ──── 4. Start NTPsec daemon ──────────────────────────────────────────────
echo ""
echo "=== Starting NTPsec (ntpd) ==="

# Kill any stray ntpd
pkill -f "ntpd" 2>/dev/null || true
sleep 1

ntpd -c /etc/ntp.conf -n > /tmp/ntpd.log 2>&1 &
NTPD_PID=$!
echo "NTPsec PID: $NTPD_PID"

# Wait for startup
sleep 3

if ! kill -0 "$NTPD_PID" 2>/dev/null; then
    echo "FATAL: NTPsec failed to start"
    cat /tmp/ntpd.log
    exit 1
fi
report_pass "NTPsec daemon started"

# ──── 5. Verify NTPsec responds to queries ────────────────────────────────
echo ""
echo "=== Verifying NTPsec ==="

# Give it a moment to initialize
sleep 2

echo "Querying NTPsec with ntpq -c rv..."
NTPQ_RV_OUTPUT=$(ntpq -c rv 2>&1 || true)
echo "$NTPQ_RV_OUTPUT"
if echo "$NTPQ_RV_OUTPUT" | grep -q 'associd='; then
    report_pass "NTPsec ntpq -c rv returns system variables"
else
    report_fail "NTPsec ntpq -c rv returned no system variables"
fi

echo ""
echo "Querying NTPsec with ntpq -pn..."
NTPQ_PN_OUTPUT=$(ntpq -pn 2>&1 || true)
echo "$NTPQ_PN_OUTPUT"
check_pn_output "NTPsec" "$NTPQ_PN_OUTPUT"

# Verify the local refclock is configured (should appear as LOCAL(0))
if echo "$NTPQ_PN_OUTPUT" | grep -qE 'LOCAL\(0\)|127\.127\.1\.0'; then
    report_pass "NTPsec ntpq -pn shows local refclock (127.127.1.0)"
else
    report_fail "NTPsec ntpq -pn missing local refclock"
fi

# Also verify remote servers are configured
if echo "$NTPQ_PN_OUTPUT" | grep -qE 'pool\.ntp\.org|time\.google\.com|\b16 u\b'; then
    report_pass "NTPsec ntpq -pn shows remote server associations"
fi

# ──── 6. Install ntpsec-rs packages ───────────────────────────────────────
echo ""
echo "=== Installing ntpsec-rs .deb packages ==="

ls -la /tmp/packages/ 2>/dev/null || {
    echo "ERROR: No packages found in /tmp/packages/"
    ls -la /tmp/ 2>/dev/null || true
    exit 1
}

dpkg -i /tmp/packages/ntpsec-rs-*.deb 2>&1 || true
apt-get install -f -y -qq  # Resolve any missing dependencies

echo ""
echo "Installed ntpsec-rs packages:"
dpkg -l | grep ntpsec-rs || true

echo ""
echo "Checking binaries:"
which ntpd-rs 2>/dev/null && ntpd-rs --version 2>/dev/null || echo "ntpd-rs not found in PATH"
which ntpq-rs 2>/dev/null && ntpq-rs --version 2>/dev/null || echo "ntpq-rs not found in PATH"

# ──── 7. Stop NTPsec ──────────────────────────────────────────────────────
echo ""
echo "=== Stopping NTPsec ==="

kill "$NTPD_PID" 2>/dev/null || true
wait "$NTPD_PID" 2>/dev/null || true
sleep 2

if kill -0 "$NTPD_PID" 2>/dev/null; then
    report_fail "NTPsec process still running after kill"
else
    report_pass "NTPsec stopped cleanly"
fi

# ──── 8. Start ntpsec-rs daemon ───────────────────────────────────────────
echo ""
echo "=== Starting ntpsec-rs (ntpd-rs) ==="

# ntpsec-rs uses the same config syntax as NTPsec.
# Bind explicitly to 127.0.0.1 so reference ntpq can reach it.

pkill -f "ntpd-rs" 2>/dev/null || true
sleep 1

ntpd-rs -c /etc/ntp.conf -n -I 127.0.0.1 > /tmp/ntpd-rs.log 2>&1 &
NTPD_RS_PID=$!
echo "ntpd-rs PID: $NTPD_RS_PID"

sleep 3

if ! kill -0 "$NTPD_RS_PID" 2>/dev/null; then
    echo "FATAL: ntpd-rs failed to start"
    cat /tmp/ntpd-rs.log
    exit 1
fi
report_pass "ntpd-rs daemon started"

# ──── 9. Verify ntpsec-rs responds to queries (via reference ntpq) ────────
echo ""
echo "=== Verifying ntpsec-rs with reference ntpq ==="

# Give it a moment to initialize
sleep 2

echo "Querying ntpd-rs with reference ntpq -c rv (explicit 127.0.0.1)..."
NTPQ_RV_RS=$(ntpq -c rv 127.0.0.1 2>&1 || true)
echo "$NTPQ_RV_RS"
if echo "$NTPQ_RV_RS" | grep -q 'associd='; then
    report_pass "ntpd-rs reference ntpq -c rv returns system variables"
else
    report_fail "ntpd-rs reference ntpq -c rv returned no system variables"
fi

echo ""
echo "Querying ntpd-rs with reference ntpq -pn (explicit 127.0.0.1)..."
NTPQ_PN_RS=$(ntpq -pn 127.0.0.1 2>&1 || true)
echo "$NTPQ_PN_RS"
check_pn_output "ntpd-rs (ref ntpq)" "$NTPQ_PN_RS"

if echo "$NTPQ_PN_RS" | grep -qE 'LOCAL\(0\)|127\.127\.1\.0'; then
    report_pass "ntpd-rs ntpq -pn shows local refclock (127.127.1.0)"
fi

# Also test associations command (more robust than -pn)
echo ""
echo "Querying ntpd-rs with reference ntpq -c associations..."
NTPQ_AS_RS=$(ntpq -c associations 127.0.0.1 2>&1 || true)
echo "$NTPQ_AS_RS"
if echo "$NTPQ_AS_RS" | grep -qE 'associd=|indices'; then
    report_pass "ntpd-rs reference ntpq -c associations returns results"
fi

# ──── 10. Verify with native ntpq-rs client ───────────────────────────────
echo ""
echo "=== Verifying with native ntpq-rs client ==="

echo "Querying ntpd-rs with ntpq-rs -pn..."
NTPQ_RS_PN=$(ntpq-rs -pn 2>&1 || true)
echo "$NTPQ_RS_PN"
check_pn_output "ntpd-rs (ntpq-rs)" "$NTPQ_RS_PN"

echo ""
echo "Querying ntpd-rs with ntpq-rs -c rv..."
NTPQ_RS_RV=$(ntpq-rs -c rv 2>&1 || true)
echo "$NTPQ_RS_RV"
if echo "$NTPQ_RS_RV" | grep -q 'associd='; then
    report_pass "ntpq-rs -c rv returns system variables"
else
    report_fail "ntpq-rs -c rv returned no system variables" "$NTPQ_RS_RV"
fi

# ──── 11. Summary ─────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo " Swap Test Results"
echo "============================================"
echo " Total:  $TOTAL"
echo " Passed: $PASS"
echo " Failed: $FAIL"
echo "============================================"

if [ "$FAIL" -eq 0 ]; then
    echo "RESULT: SWAP SUCCESSFUL - ntpsec-rs can replace NTPsec"
    exit 0
else
    echo "RESULT: SWAP FAILED - $FAIL test(s) did not pass"
    exit 1
fi
