#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source /recipe/benchmark.conf
: "${BASE_COMMIT:?missing BASE_COMMIT}"
: "${BOARD:?missing BOARD}"
: "${EXAMPLE_DIR:?missing EXAMPLE_DIR}"
: "${APPLICATION:?missing APPLICATION}"
: "${OUTPUT_ELF:?missing OUTPUT_ELF}"
: "${BUILD_PROFILE:=hoedur}"
: "${CONTAINER_REPO:=/workdir/RIOT}"

export HOME=${HOME:-/tmp/home}
mkdir -p "$HOME" /out

repo="$CONTAINER_REPO"
if [[ ! -d "$repo/.git" ]]; then
    git clone https://github.com/RIOT-OS/RIOT "$repo"
fi

cd "$repo"
git fetch origin "$BASE_COMMIT"
git reset --hard
git clean -xdf
if [[ "$BUILD_PROFILE" == multifuzz-default ]]; then
    # MultiFuzz used `git reset` on the default branch. An attached HEAD is
    # significant: RIOT otherwise appends "-HEAD" to its embedded version.
    git checkout -B master "$BASE_COMMIT"
    git reset --hard "$BASE_COMMIT"
else
    git checkout --detach "$BASE_COMMIT"
fi
git config user.email "build@localhost"
git config user.name "build"

for commit in ${REVERT_COMMITS:-}; do
    git revert "$commit" --no-commit
done

for commit in ${BACKPORT_COMMITS:-}; do
    git cherry-pick "$commit" --no-commit
done

for patch in ${PATCHES:-}; do
    echo "Applying $patch"
    git apply "/recipe/patches/$patch"
done

build_dir="$repo/$EXAMPLE_DIR/bin/$BOARD"
rm -rf "$build_dir"
if [[ "$BUILD_PROFILE" == multifuzz-default ]]; then
    : "${DISABLE_MODULES:?missing DISABLE_MODULES}"
    : "${MAKE_JOBS:=8}"
    # Preserve the artifact's stock RIOT flags and exact command-line module
    # exclusion. The checkout was cleaned above, so no separate clean target
    # is needed and package builds start from an empty build/ directory.
    unset CFLAGS
    make -j"$MAKE_JOBS" -C "$repo/$EXAMPLE_DIR" \
        DISABLE_MODULE="$DISABLE_MODULES" BOARD="$BOARD"
else
    # CFLAGS must come from the environment, not the make command line: RIOT's
    # own Makefiles append arch/feature-test flags with `CFLAGS +=`, which a
    # command-line-origin CFLAGS would shadow entirely (breaking newlib headers).
    export CFLAGS="-gdwarf-4 -gstrict-dwarf"
    make -C "$repo/$EXAMPLE_DIR" BOARD="$BOARD" clean all
fi

cp "$build_dir/$APPLICATION.elf" "/out/$OUTPUT_ELF"
cp "$build_dir/$APPLICATION.bin" "/out/${OUTPUT_ELF%.elf}.bin"

sha256sum "/out/$OUTPUT_ELF" "/out/${OUTPUT_ELF%.elf}.bin" > /out/SHA256SUMS
echo "Built /out/$OUTPUT_ELF"
