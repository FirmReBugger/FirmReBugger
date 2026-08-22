#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
rm -rf "$HERE/cache"

if command -v docker >/dev/null; then
    for image in \
        firmrebugger/p2im-build:ubuntu20.04 \
        firmrebugger/p2im-build:ubuntu22.04
    do
        docker image inspect "$image" >/dev/null 2>&1 || continue
        docker image rm "$image"
    done
fi

echo "Removed P2IM source/tool caches and tagged build images."
