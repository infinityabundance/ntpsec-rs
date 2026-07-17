#!/bin/sh
# Build all oracle Docker containers
set -e

cd "$(dirname "$0")"

IMAGES="alpine debian-stable ubuntu-lts"

for img in $IMAGES; do
    echo "=== Building ntpsec-oracle:${img} ==="
    docker build -f "${img}.dockerfile" -t "ntpsec-oracle:${img}" ..
    echo "=== Done: ${img} ==="
    echo ""
done

echo "=== All oracle images built ==="
