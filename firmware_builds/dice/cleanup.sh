#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
rm -rf "$HERE/cache"
if command -v docker >/dev/null \
   && docker image inspect firmrebugger/dice-build:gcc7-2018q2 >/dev/null 2>&1; then
    docker image rm firmrebugger/dice-build:gcc7-2018q2
fi
echo "Removed DICE source cache and tagged build image; rebuild/out artifacts remain."
