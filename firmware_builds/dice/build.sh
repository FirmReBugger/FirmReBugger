#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: build.sh --config PATH [--verify] [--install]

Build one recovered DICE DMA benchmark. --verify compares all PT_LOAD bytes
with the checked-in ELF. --install is allowed only after that comparison.
EOF
}

CONFIG=
VERIFY=0
INSTALL=0
while (($#)); do
    case "$1" in
        --config) CONFIG=${2:?missing config path}; shift 2 ;;
        --verify) VERIFY=1; shift ;;
        --install) INSTALL=1; VERIFY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -n "$CONFIG" ]] || { usage >&2; exit 2; }
CONFIG=$(realpath "$CONFIG")
RECIPE_DIR=$(dirname "$CONFIG")
TOOL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$CONFIG"

: "${BENCHMARK_ID:?missing BENCHMARK_ID}"
: "${BUILD_KIND:?missing BUILD_KIND}"
: "${CACHE_NAMESPACE:?missing CACHE_NAMESPACE}"
: "${OUTPUT_ELF:?missing OUTPUT_ELF}"
: "${REFERENCE_REL:?missing REFERENCE_REL}"
: "${PLATFORM:=linux/amd64}"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v flock >/dev/null || { echo "flock is required" >&2; exit 1; }

cache_dir="$TOOL_DIR/cache/$CACHE_NAMESPACE"
source_dir="$cache_dir/source"
out_dir="$RECIPE_DIR/out"
mkdir -p "$source_dir" "$out_dir" "$TOOL_DIR/cache/.docker"
export DOCKER_CONFIG="$TOOL_DIR/cache/.docker"
exec 9>"$cache_dir/.lock"
flock 9

image=firmrebugger/dice-build:gcc7-2018q2
echo "==> Preparing $image"
docker build --platform "$PLATFORM" -t "$image" "$TOOL_DIR"

echo "==> Building $BENCHMARK_ID"
docker run --rm --platform "$PLATFORM" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/dice-home \
    -v "$source_dir:/src" \
    -v "$RECIPE_DIR:/recipe:ro" \
    -v "$TOOL_DIR:/tooling:ro" \
    -v "$out_dir:/out" \
    --workdir /src \
    --entrypoint /bin/bash \
    "$image" /tooling/container-build.sh

reference=$(realpath -m "$RECIPE_DIR/$REFERENCE_REL")
if ((VERIFY)); then
    python3 "$TOOL_DIR/compare_loadable.py" "$out_dir/$OUTPUT_ELF" "$reference"
fi
if ((INSTALL)); then
    install -m 0644 "$out_dir/$OUTPUT_ELF" "$reference"
    echo "Installed $reference"
fi
