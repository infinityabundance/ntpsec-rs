#!/bin/sh
# Run the full ntpsec oracle matrix
set -e

cd "$(dirname "$0")"

IMAGES="alpine debian-stable ubuntu-lts"

for img in $IMAGES; do
    echo "=== Testing ntpsec-oracle:${img} ==="
    docker run --rm -it "ntpsec-oracle:${img}" /bin/sh -c "
        # Start ntpd-rs in lab mode
        /opt/ntpsec-rs/target/release/ntpd-rs --lab-daemon -c /etc/ntp.conf -n &
        NTPD_PID=\$!
        sleep 2

        # Query with ntpq-rs
        /opt/ntpsec-rs/target/release/ntpq-rs -c peers 2>/dev/null || true
        /opt/ntpsec-rs/target/release/ntpq-rs -c associations 2>/dev/null || true
        /opt/ntpsec-rs/target/release/ntpdig-rs -4 127.0.0.1 2>/dev/null || true

        # Compare with real ntpq if available
        if command -v ntpq >/dev/null 2>&1; then
            echo '=== Real ntpq output for comparison ==='
            ntpq -c peers 2>/dev/null || true
        fi

        kill \$NTPD_PID 2>/dev/null
    "
    echo "=== Done: ${img} ==="
    echo ""
done

echo "=== Full matrix test complete ==="
