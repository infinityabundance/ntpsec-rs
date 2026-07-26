#!/bin/bash
set -e

echo "=== 1. Waiting for chrony NTS-KE server ==="
sleep 5

python3 << 'PYEOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
print('Connecting to chrony NTS-KE on 10.200.0.10:4460...')
try:
    s.connect(('10.200.0.10', 4460))
    data = s.recv(4096)
    print(f'NTS-KE port OPEN: received {len(data)} bytes')
    print(f'TLS ServerHello: {data[:20].hex()}')
    s.close()
except Exception as e:
    print(f'NTS-KE connection failed: {e}')
    exit(1)
PYEOF
echo "NTS-KE TCP port verified"

echo ""
echo "=== 2. Extracting chrony self-signed certificate ==="
CERT_SRC="/nts-certs/nts-cert.pem"
CERT_DST="/tmp/chrony-cert.pem"
if [ -f "$CERT_SRC" ]; then
    cp "$CERT_SRC" "$CERT_DST"
    echo "Certificate extracted from shared volume: $(wc -c < "$CERT_DST") bytes"
    openssl x509 -in "$CERT_DST" -noout -subject 2>/dev/null || true
else
    echo "WARNING: Shared certificate not found at $CERT_SRC"
    echo "Falling back to extracting via container name..."
    # Try to extract by running docker exec on the host
    if command -v docker &>/dev/null; then
        docker cp chrony-nts:/etc/chrony/nts-cert.pem "$CERT_DST" 2>/dev/null || \
        docker cp ntpsec-rs-chrony-nts-1:/etc/chrony/nts-cert.pem "$CERT_DST" 2>/dev/null || \
        echo "Could not extract cert via docker cp"
    fi
fi

echo ""
echo "=== 3. Building NTS-KE interop test binary ==="
cd /build
cargo test --test nts_ke_chrony_interop --no-run -p ntpsec-rs-core 2>&1
# Find the built test binary
TEST_BINARY=$(find target/debug -name 'nts_ke_chrony_interop*' -type f 2>/dev/null | head -1)
if [ -n "$TEST_BINARY" ]; then
    echo "Test binary: $TEST_BINARY"
else
    echo "ERROR: Could not find nts_ke_chrony_interop test binary"
    exit 1
fi

echo ""
echo "=== 4. Running NTS-KE interop test against chrony ==="
NTSKE_TEST=1 \
NTSKE_CERT_PATH="$CERT_DST" \
NTSKE_HOST="10.200.0.10" \
NTSKE_PORT="4460" \
"$TEST_BINARY" --nocapture

echo ""
echo "=== 5. Installing ntpq ==="
apt-get update -qq 2>/dev/null | tail -1
apt-get install -y -qq ntpsec 2>&1 | tail -1

echo ""
echo "=== 6. Cross-container ntpq against ntpsec-rs ==="
echo "Testing ntpq -pn ntpsec-rs:"
timeout 5 ntpq -pn ntpsec-rs 2>&1 || echo "(ntpq peers result)"
echo ""
echo "Testing ntpq -c rv ntpsec-rs:"
timeout 5 ntpq -c rv ntpsec-rs 2>&1 || echo "(ntpq rv result)"

echo ""
echo "=== 7. Test harness complete ==="
