#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: build.sh --config PATH [--install] [--verify]

Build the single benchmark variant described by PATH. Output is written below
that recipe's out/ directory. --install replaces the checked-in ELF only after
a successful build; --verify compares loadable bytes with the checked-in ELF.
EOF
}

CONFIG=
INSTALL=0
VERIFY=0
while (($#)); do
    case "$1" in
        --config) CONFIG=${2:?missing config path}; shift 2 ;;
        --install) INSTALL=1; shift ;;
        --verify) VERIFY=1; shift ;;
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
: "${DOCKER_IMAGE:?missing DOCKER_IMAGE}"
: "${CACHE_NAMESPACE:?missing CACHE_NAMESPACE}"
: "${REFERENCE_REL:?missing REFERENCE_REL}"
: "${PLATFORM:=linux/amd64}"
: "${CONTAINER_REPO:=/workdir/RIOT}"
: "${VERIFY_MODE:=loadable}"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v flock >/dev/null || { echo "flock is required" >&2; exit 1; }

cache_dir="$TOOL_DIR/cache/$CACHE_NAMESPACE"
out_dir="$RECIPE_DIR/out"
mkdir -p "$cache_dir" "$out_dir"

# Recipes sharing a RIOT checkout also share a clone. Serialize them so one
# checkout cannot be reset while another target is compiling.
exec 9>"$cache_dir/.lock"
flock 9

echo "==> Building $BENCHMARK_ID ($VARIANT_KIND)"
if [[ "$CONTAINER_REPO" == /RIOT ]]; then
    # MultiFuzz built with the checkout mounted at /RIOT. Keep that exact path
    # because it is embedded in DWARF and is required for full-file identity.
    repo_cache="$cache_dir/RIOT"
    mkdir -p "$repo_cache"
    source_mount=(-v "$repo_cache:/RIOT")
else
    source_mount=(-v "$cache_dir:/workdir")
fi

docker run --rm --pull=missing --platform "$PLATFORM" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/home \
    "${source_mount[@]}" \
    -v "$RECIPE_DIR:/recipe:ro" \
    -v "$TOOL_DIR:/tooling:ro" \
    -v "$out_dir:/out" \
    --workdir /workdir \
    --entrypoint /bin/bash \
    "$DOCKER_IMAGE" /tooling/container-build.sh

reference=$(realpath -m "$RECIPE_DIR/$REFERENCE_REL")
if ((VERIFY)); then
    case "$VERIFY_MODE" in
        full)
            if ! cmp -s "$out_dir/$OUTPUT_ELF" "$reference"; then
                echo "full ELF verification failed:" >&2
                sha256sum "$out_dir/$OUTPUT_ELF" "$reference" >&2
                exit 1
            fi
            echo "full ELF verification passed: $(sha256sum "$reference" | awk '{print $1}')"
            ;;
        loadable)
            python3 "$TOOL_DIR/compare_loadable.py" "$out_dir/$OUTPUT_ELF" "$reference"
            ;;
        *)
            echo "Unknown VERIFY_MODE: $VERIFY_MODE" >&2
            exit 2
            ;;
    esac
fi

if ((INSTALL)); then
    install -m 0644 "$out_dir/$OUTPUT_ELF" "$reference"
    echo "Installed $reference"
fi
