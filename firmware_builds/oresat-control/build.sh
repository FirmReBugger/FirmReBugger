#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: build.sh --config PATH [--verify] [--strict] [--install]

Build one OreSat control recipe. --verify checks section and recovered-function
structure. --strict requires identical loadable bytes. --install is permitted
only after a strict match and replaces the checked-in ELF.
EOF
}

CONFIG=
VERIFY=0
STRICT=0
INSTALL=0
while (($#)); do
    case "$1" in
        --config) CONFIG=${2:?missing config path}; shift 2 ;;
        --verify) VERIFY=1; shift ;;
        --strict) STRICT=1; shift ;;
        --install) INSTALL=1; STRICT=1; shift ;;
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
: "${VARIANT_KIND:?missing VARIANT_KIND}"
: "${CACHE_NAMESPACE:?missing CACHE_NAMESPACE}"
: "${OUTPUT_ELF:?missing OUTPUT_ELF}"
: "${REFERENCE_REL:?missing REFERENCE_REL}"
: "${PLATFORM:=linux/amd64}"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v flock >/dev/null || { echo "flock is required" >&2; exit 1; }

docker_image=firmrebugger/oresat-control-build:ubuntu20.04-gcc9
cache_dir="$TOOL_DIR/cache/$CACHE_NAMESPACE"
repo_dir="$cache_dir/oresat-firmware"
out_dir="$RECIPE_DIR/out"
mkdir -p "$repo_dir" "$out_dir"

exec 9>"$cache_dir/.lock"
flock 9

echo "==> Preparing pinned OreSat build image"
docker build --platform "$PLATFORM" -t "$docker_image" "$TOOL_DIR"

echo "==> Building $BENCHMARK_ID ($VARIANT_KIND)"
docker run --rm --platform "$PLATFORM" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/home \
    -v "$repo_dir:/home/user/working-firmrebugger/firmrebugger/binaries/new/oresat-control/oresat-firmware" \
    -v "$RECIPE_DIR:/recipe:ro" \
    -v "$TOOL_DIR:/tooling:ro" \
    -v "$out_dir:/out" \
    --entrypoint /bin/bash \
    "$docker_image" /tooling/container-build.sh

reference=$(realpath -m "$RECIPE_DIR/$REFERENCE_REL")
if ((VERIFY)); then
    docker run --rm --platform "$PLATFORM" \
        -e VARIANT_KIND="$VARIANT_KIND" \
        -e OUTPUT_ELF="$OUTPUT_ELF" \
        -v "$out_dir:/out:ro" \
        -v "$reference:/reference.elf:ro" \
        -v "$TOOL_DIR:/tooling:ro" \
        --entrypoint /bin/bash \
        "$docker_image" /tooling/container-verify.sh
fi

if ((STRICT)); then
    command -v python3 >/dev/null || { echo "python3 is required for --strict" >&2; exit 1; }
    python3 "$TOOL_DIR/compare_loadable.py" "$out_dir/$OUTPUT_ELF" "$reference"
fi

if ((INSTALL)); then
    install -m 0644 "$out_dir/$OUTPUT_ELF" "$reference"
    echo "Installed $reference"
fi
