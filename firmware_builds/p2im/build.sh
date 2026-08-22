#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: build.sh --config PATH [--verify] [--install]

Build one recovered P2IM benchmark variant. --verify compares either loadable
bytes or the recovered function inventory, as selected by the recipe.
--install is allowed only after verification.
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
: "${VARIANT_KIND:?missing VARIANT_KIND}"
: "${CACHE_NAMESPACE:?missing CACHE_NAMESPACE}"
: "${BASE_IMAGE:?missing BASE_IMAGE}"
: "${CONTAINER_SOURCE:?missing CONTAINER_SOURCE}"
: "${OUTPUT_ELF:?missing OUTPUT_ELF}"
: "${REFERENCE_REL:?missing REFERENCE_REL}"
: "${PLATFORM:=linux/amd64}"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v flock >/dev/null || { echo "flock is required" >&2; exit 1; }

cache_dir="$TOOL_DIR/cache/$CACHE_NAMESPACE"
source_dir="$cache_dir/source"
home_dir="$cache_dir/home"
out_dir="$RECIPE_DIR/out"
mkdir -p "$source_dir" "$home_dir" "$out_dir"
export DOCKER_CONFIG="$TOOL_DIR/cache/.docker"
mkdir -p "$DOCKER_CONFIG"
exec 9>"$cache_dir/.lock"
flock 9

case "$BASE_IMAGE" in
    ubuntu:20.04) image=firmrebugger/p2im-build:ubuntu20.04 ;;
    ubuntu:22.04) image=firmrebugger/p2im-build:ubuntu22.04 ;;
    *) echo "Unsupported BASE_IMAGE: $BASE_IMAGE" >&2; exit 2 ;;
esac

echo "==> Preparing $image"
docker build --platform "$PLATFORM" --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    -t "$image" "$TOOL_DIR"

container_home=${CONTAINER_HOME:-/tmp/p2im-home}
echo "==> Building $BENCHMARK_ID ($VARIANT_KIND)"
docker run --rm --platform "$PLATFORM" \
    --user "$(id -u):$(id -g)" \
    -e "HOME=$container_home" \
    -v "$source_dir:$CONTAINER_SOURCE" \
    -v "$home_dir:$container_home" \
    -v "$RECIPE_DIR:/recipe:ro" \
    -v "$TOOL_DIR:/tooling:ro" \
    -v "$out_dir:/out" \
    --workdir "$CONTAINER_SOURCE" \
    --entrypoint /bin/bash \
    "$image" /tooling/container-build.sh

reference=$(realpath -m "$RECIPE_DIR/$REFERENCE_REL")
if ((VERIFY)); then
    case "${VERIFY_MODE:-loadable}" in
        loadable)
            python3 "$TOOL_DIR/compare_loadable.py" "$out_dir/$OUTPUT_ELF" "$reference"
            ;;
        functions)
            python3 "$TOOL_DIR/compare_functions.py" "$out_dir/$OUTPUT_ELF" "$reference"
            ;;
        *)
            echo "Unsupported VERIFY_MODE: $VERIFY_MODE" >&2
            exit 2
            ;;
    esac
fi
if ((INSTALL)); then
    install -m 0644 "$out_dir/$OUTPUT_ELF" "$reference"
    echo "Installed $reference"
fi
