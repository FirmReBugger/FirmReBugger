#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
for recipe in FirmBenchDMA/midi FirmBenchDMA/modbus; do
    "$ROOT/$recipe/rebuild/build.sh" "$@"
done
