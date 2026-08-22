#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source /recipe/benchmark.conf
: "${BASE_COMMIT:?missing BASE_COMMIT}"
: "${EXAMPLE:?missing EXAMPLE}"
: "${APPLICATION:?missing APPLICATION}"
: "${TARGET:?missing TARGET}"
: "${OUTPUT_ELF:?missing OUTPUT_ELF}"
: "${BUILD_SUBPATH:=$TARGET}"

export HOME=${HOME:-/tmp/home}
mkdir -p "$HOME" /out

repo=/workdir/contiki-ng
if [[ ! -d "$repo/.git" ]]; then
    git clone https://github.com/contiki-ng/contiki-ng "$repo"
fi

cd "$repo"
git fetch origin "$BASE_COMMIT"
git reset --hard
git clean -xdf
git checkout --detach "$BASE_COMMIT"
git config user.email "build@localhost"
git config user.name "build"
git submodule update --init --recursive

# Entries may be "commit" or "commit@mainline-parent" for reverting a merge.
for entry in ${REVERT_COMMITS:-}; do
    commit=${entry%@*}
    if [[ "$entry" == *@* ]]; then
        git revert "$commit" --no-commit -m "${entry#*@}"
    else
        git revert "$commit" --no-commit
    fi
done

for commit in ${BACKPORT_COMMITS:-}; do
    git cherry-pick "$commit" --no-commit
done

for patch in ${PATCHES:-}; do
    echo "Applying $patch"
    git apply "/recipe/patches/$patch"
done

example_dir="$repo/examples/$EXAMPLE"
rm -rf "$example_dir/build"
make -C "$example_dir" TARGET="$TARGET" distclean all

build_dir="$example_dir/build/$BUILD_SUBPATH"
if [[ ! -f "$build_dir/$APPLICATION.bin" ]]; then
    # Some Contiki-NG versions' `all` target does not chain to `.bin`; ask
    # for it explicitly. The pattern rule only matches the full build path.
    make -C "$example_dir" TARGET="$TARGET" "build/$BUILD_SUBPATH/$APPLICATION.bin"
fi

cp "$build_dir/$APPLICATION.elf" "/out/$OUTPUT_ELF"
cp "$build_dir/$APPLICATION.bin" "/out/${OUTPUT_ELF%.elf}.bin"

if [[ -n "${EARLY_RETURNS:-}" ]]; then
    python3 /tooling/patch_early_returns.py \
        "/out/$OUTPUT_ELF" "/out/${OUTPUT_ELF%.elf}.bin" $EARLY_RETURNS
fi

sha256sum "/out/$OUTPUT_ELF" "/out/${OUTPUT_ELF%.elf}.bin" > /out/SHA256SUMS
echo "Built /out/$OUTPUT_ELF"
