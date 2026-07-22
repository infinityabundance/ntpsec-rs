#!/bin/sh
# Build all oracle Docker containers
set -e

cd "$(dirname "$0")"

# Build in order of size (Alpine fastest, Fedora largest)
IMAGES="alpine debian-stable ubuntu-lts fedora"

for img in $IMAGES; do
    echo ""
    echo "=== Building ntpsec-oracle:${img} ==="
    docker build -f "${img}.dockerfile" -t "ntpsec-oracle:${img}" ..
    echo "=== Done: ${img} ==="
done

echo ""
echo "=== All oracle images built ==="
docker images
