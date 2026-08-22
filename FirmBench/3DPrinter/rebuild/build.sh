#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
exec "$ROOT/firmware_builds/marlin/build.sh" --config "$HERE/benchmark.conf" "$@"
