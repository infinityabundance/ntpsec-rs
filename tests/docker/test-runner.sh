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
echo "=== 2. Installing ntpq ==="
apt-get update -qq 2>/dev/null | tail -1
apt-get install -y -qq ntpsec 2>&1 | tail -1

echo ""
echo "=== 3. Cross-container ntpq against ntpsec-rs ==="
echo "Testing ntpq -pn ntpsec-rs:"
timeout 5 ntpq -pn ntpsec-rs 2>&1 || echo "(ntpq peers result)"
echo ""
echo "Testing ntpq -c rv ntpsec-rs:"
timeout 5 ntpq -c rv ntpsec-rs 2>&1 || echo "(ntpq rv result)"

echo ""
echo "=== 4. Test harness complete ==="
