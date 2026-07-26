#!/bin/bash
set -e

echo "=== Starting chronyd with NTS ==="

cat > /etc/chrony/chrony.conf << 'CHRONYCONF'
# NTS-KE test configuration
ntsservercert /etc/chrony/nts-cert.pem
ntsserverkey /etc/chrony/nts-key.pem
ntsport 4460

# Make the server authoritative for testing
local stratum 5 orphan
allow all

# Drift file
driftfile /var/lib/chrony/chrony.drift

# Logging
log measurements statistics tracking
logdir /var/log/chrony
CHRONYCONF

echo "chrony.conf written"

# Start chronyd
chronyd -d -s &
CHRONY_PID=$!
echo "chronyd PID: $CHRONY_PID"
sleep 3

# Verify chronyd is running
if kill -0 $CHRONY_PID 2>/dev/null; then
    echo "chronyd running OK"
else
    echo "chronyd FAILED to start"
    exit 1
fi

# Test NTS-KE TCP port
echo "=== Testing NTS-KE port 4460 ==="
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(('127.0.0.1', 4460))
    # Read TLS handshake
    data = s.recv(4096)
    print(f'NTS-KE port 4460: OPEN, received {len(data)} bytes')
    print(f'TLS handshake data: {data[:20].hex()}...')
    s.close()
except Exception as e:
    print(f'NTS-KE port 4460: {e}')
"

# Test the NTS-KE with a proper NTS request
echo "=== Sending NTS-KE request ==="
python3 -c "
import socket, struct

# Connect to NTS-KE port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(('127.0.0.1', 4460))

# After TLS handshake, send NTS-KE records
# Build NTS-KE request: Next Protocol (NTPv4) + AEAD + EOM
# NTS-KE record format: type(2) + length(2) + body(length)
def make_record(rec_type, body, critical=True):
    if critical:
        rec_type |= 0x8000
    length = 4 + len(body)
    # Pad to 4-byte boundary
    padded = (length + 3) & ~3
    pad = padded - length
    return struct.pack('!HH', rec_type, padded) + body + b'\\x00' * pad

# Read TLS server hello
data = s.recv(4096)
print(f'Received {len(data)} bytes from TLS server')

# Build request
next_proto = make_record(0, struct.pack('!H', 0))  # Next Protocol = NTPv4
aead = make_record(1, struct.pack('!H', 15))  # AEAD_AES_SIV_CMAC_256
eom = make_record(6, b'', critical=True)  # End of Message

request = next_proto + aead + eom
print(f'Sending NTS-KE request: {len(request)} bytes')
s.sendall(request)

# Read response
response = b''
s.settimeout(5)
while True:
    try:
        chunk = s.recv(4096)
        if not chunk:
            break
        response += chunk
    except socket.timeout:
        break

print(f'Received NTS-KE response: {len(response)} bytes')
if len(response) > 4:
    # Parse first record
    rec_type, rec_len = struct.unpack_from('!HH', response, 0)
    print(f'  Record 0: type=0x{rec_type:04x} length={rec_len}')
    rec_type2, rec_len2 = struct.unpack_from('!HH', response, rec_len)
    print(f'  Record 1: type=0x{rec_type2:04x} length={rec_len2}')
    if len(response) > rec_len + rec_len2:
        rec_type3, rec_len3 = struct.unpack_from('!HH', response, rec_len + rec_len2)
        print(f'  Record 2: type=0x{rec_type3:04x} length={rec_len3}')

s.close()
print('NTS-KE handshake test completed')
"

# Also run cross-container ntpq test if we have other containers
echo "=== NTS-KE interop test complete ==="

# Keep container running for ntpq test
echo "Checking if ntpsec-rs is available..."
if getent hosts ntpsec-rs >/dev/null 2>&1; then
    echo "ntpsec-rs container reachable, testing ntpq..."
    timeout 5 ntpq -pn ntpsec-rs 2>&1 || echo "ntpq to ntpsec-rs failed"
    timeout 5 ntpq -c rv ntpsec-rs 2>&1 || echo "ntpq rv failed"
fi

# Keep running
wait $CHRONY_PID
