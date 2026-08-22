#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source /recipe/benchmark.conf
: "${BASE_COMMIT:?missing BASE_COMMIT}"
: "${PROJECT_DIR:?missing PROJECT_DIR}"
: "${PROJECT_NAME:?missing PROJECT_NAME}"
: "${GCC_ARM_URL:?missing GCC_ARM_URL}"
: "${OUTPUT_ELF:?missing OUTPUT_ELF}"

export HOME=${HOME:-/tmp/home}
mkdir -p "$HOME" /out

toolchain=/workdir/gcc-arm
if [[ ! -x "$toolchain/bin/arm-none-eabi-gcc" ]]; then
    mkdir -p "$toolchain"
    curl -sfL "$GCC_ARM_URL" | tar xj -C "$toolchain" --strip-components=1
fi
export PATH="$toolchain/bin:$PATH"

repo=/workdir/pretender
if [[ ! -d "$repo/.git" ]]; then
    git clone --filter=blob:none --sparse https://github.com/ucsb-seclab/pretender "$repo"
fi

cd "$repo"
git sparse-checkout set "$PROJECT_DIR"
git fetch origin "$BASE_COMMIT"
git reset --hard
git clean -xdf
git checkout --detach "$BASE_COMMIT"
git sparse-checkout set "$PROJECT_DIR"

for patch in ${PATCHES:-}; do
    echo "Applying $patch"
    git apply "/recipe/patches/$patch"
done

project_dir="$repo/$PROJECT_DIR"
rm -rf "$project_dir/BUILD"
make -C "$project_dir"

cp "$project_dir/BUILD/$PROJECT_NAME.elf" "/out/$OUTPUT_ELF"
cp "$project_dir/BUILD/$PROJECT_NAME.bin" "/out/${OUTPUT_ELF%.elf}.bin"

sha256sum "/out/$OUTPUT_ELF" "/out/${OUTPUT_ELF%.elf}.bin" > /out/SHA256SUMS
echo "Built /out/$OUTPUT_ELF"
