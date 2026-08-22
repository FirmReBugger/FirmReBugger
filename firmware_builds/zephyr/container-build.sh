#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source /recipe/benchmark.conf
: "${VARIANT_KIND:?missing VARIANT_KIND}"
: "${BUILD_FAMILY:?missing BUILD_FAMILY}"
: "${BASE_COMMIT:?missing BASE_COMMIT}"
: "${BOARD:?missing BOARD}"
: "${SAMPLE_DIR:?missing SAMPLE_DIR}"
: "${OUTPUT_ELF:?missing OUTPUT_ELF}"

export HOME=${HOME:-/tmp/home}
mkdir -p "$HOME" /out

if [[ "$BUILD_FAMILY" == fuzzware ]]; then
    : "${ZEPHYR_VERSION:?missing ZEPHYR_VERSION}"
    workspace="/workdir/workspace-$ZEPHYR_VERSION"
    if [[ ! -d "$workspace/.west" ]]; then
        west init --mr="zephyr-v$ZEPHYR_VERSION" "$workspace"
        (cd "$workspace" && west update)
    fi
    repo="$workspace/zephyr"
elif [[ "$BUILD_FAMILY" == hoedur ]]; then
    : "${ZEPHYR_SDK_INSTALL_DIR:?missing ZEPHYR_SDK_INSTALL_DIR}"
    export ZEPHYR_SDK_INSTALL_DIR
    if [[ -n "${ZEPHYR_SDK_SETUP_URL:-}" && ! -d "$ZEPHYR_SDK_INSTALL_DIR" ]]; then
        # The pinned CI image doesn't bundle this SDK version; CMake's
        # find_package(Zephyr-sdk) enforces an exact minimum, so a nearby
        # bundled version isn't a substitute. Install it once into the
        # shared cache.
        installer=/tmp/zephyr-sdk-setup.run
        curl -sfL -o "$installer" "$ZEPHYR_SDK_SETUP_URL"
        chmod +x "$installer"
        "$installer" -- -d "$ZEPHYR_SDK_INSTALL_DIR" -y -norc
        rm -f "$installer"
    fi
    repo=/workdir/zephyr
    if [[ ! -d "$repo/.git" ]]; then
        git clone https://github.com/zephyrproject-rtos/zephyr "$repo"
    fi
    if [[ ! -d /workdir/.west ]]; then
        git -C "$repo" checkout --detach "$BASE_COMMIT"
        (cd /workdir && west init -l "$repo")
    fi
    if [[ -n "${WEST_MIN_VERSION:-}" ]]; then
        # The pinned CI image's west predates this commit's CMake minimum
        # version check; upgrading system-wide west would need root, so
        # install into $HOME instead.
        export PATH="$HOME/.local/bin:$PATH"
        pip3 install --user --quiet --upgrade "west>=$WEST_MIN_VERSION"
    fi
else
    echo "unknown BUILD_FAMILY: $BUILD_FAMILY" >&2
    exit 2
fi

cd "$repo"
export ZEPHYR_BASE="$repo"
git reset --hard
git clean -df
git checkout --detach "$BASE_COMMIT"

if [[ "$BUILD_FAMILY" == fuzzware ]]; then
    (cd /workdir/"workspace-$ZEPHYR_VERSION" && west update)
    # Required by the original Fuzzware recipe to make old Zephyr revisions
    # build correctly; this is build infrastructure, not a CVE fix.
    git cherry-pick 5b36a01a67dd705248496ef46999f39b43e02da9 --no-commit
else
    (cd /workdir && west update)
fi

for commit in ${REVERT_COMMITS:-}; do
    git revert "$commit" --no-commit
done

for patch in ${PATCHES:-}; do
    echo "Applying $patch"
    git apply "/recipe/patches/$patch"
done

build_args=()
# Old Zephyr probes this flag through a shared compiler-capability cache. That
# probe can retain a false negative, so pass the upstream mapping explicitly.
if [[ "$BUILD_FAMILY" == fuzzware ]]; then
    build_args+=("-DEXTRA_CFLAGS=-fmacro-prefix-map=$workspace=WEST_TOPDIR")
fi
[[ -n "${SHIELD:-}" ]] && build_args+=("-DSHIELD=$SHIELD")
[[ -n "${OVERLAY_CONFIG:-}" ]] && build_args+=("-DOVERLAY_CONFIG=$OVERLAY_CONFIG")
if [[ -n "${EXTRA_DEFINES:-}" ]]; then
    # Intentional word splitting: entries are CMake -D arguments in the config.
    # shellcheck disable=SC2206
    extra=( $EXTRA_DEFINES )
    build_args+=("${extra[@]}")
fi

if [[ "$BUILD_FAMILY" == fuzzware ]]; then
    build_dir="$repo/$SAMPLE_DIR/build"
    rm -rf "$build_dir"
    (cd "$repo/$SAMPLE_DIR" && west build --pristine always -b "$BOARD" . -- "${build_args[@]}")
else
    build_dir=/workdir/build
    rm -rf "$build_dir"
    (cd /workdir && west build --pristine always -b "$BOARD" "$repo/$SAMPLE_DIR" -- "${build_args[@]}")
fi

cp "$build_dir/zephyr/zephyr.elf" "/out/$OUTPUT_ELF"
cp "$build_dir/zephyr/zephyr.bin" "/out/${OUTPUT_ELF%.elf}.bin"

if [[ -n "${EARLY_RETURNS:-}" ]]; then
    python3 /tooling/patch_early_returns.py \
        "/out/$OUTPUT_ELF" "/out/${OUTPUT_ELF%.elf}.bin" $EARLY_RETURNS
fi

sha256sum "/out/$OUTPUT_ELF" "/out/${OUTPUT_ELF%.elf}.bin" > /out/SHA256SUMS
echo "Built /out/$OUTPUT_ELF"
