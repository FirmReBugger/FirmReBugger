#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
for recipe in \
    FirmBench/CNC FirmBench/Console FirmBench/Gateway FirmBench/PLC \
    FirmBench/Soldering_Iron \
    FirmBenchX/CNC FirmBenchX/Console FirmBenchX/Gateway FirmBenchX/PLC
do
    "$ROOT/$recipe/rebuild/build.sh" "$@"
done
