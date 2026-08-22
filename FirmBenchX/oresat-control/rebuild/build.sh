#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec "$here/../../../firmware_builds/oresat-control/build.sh" \
    --config "$here/benchmark.conf" "$@"
