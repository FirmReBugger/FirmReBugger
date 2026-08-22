#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec "$HERE/../../../firmware_builds/dice/build.sh" --config "$HERE/benchmark.conf" "$@"
