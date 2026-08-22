#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source /recipe/benchmark.conf
: "${BASE_COMMIT:?missing BASE_COMMIT}"
: "${PIO_ENV:?missing PIO_ENV}"
: "${PIO_VERSION:?missing PIO_VERSION}"
: "${OUTPUT_ELF:?missing OUTPUT_ELF}"

export HOME=${HOME:-/tmp/home}
mkdir -p "$HOME" /out
export PATH="$HOME/.local/bin:$PATH"

pip install --user --quiet "platformio==$PIO_VERSION"

repo=/workdir/Marlin
if [[ ! -d "$repo/.git" ]]; then
    git clone https://github.com/MarlinFirmware/Marlin "$repo"
fi

cd "$repo"
git fetch origin "$BASE_COMMIT"
git reset --hard
git clean -xdf
git checkout --detach "$BASE_COMMIT"
git config user.email "build@localhost"
git config user.name "build"

for patch in ${PATCHES:-}; do
    echo "Applying $patch"
    git apply "/recipe/patches/$patch"
done

rm -rf ".pio/build/$PIO_ENV"
pio run -e "$PIO_ENV"

build_dir="$repo/.pio/build/$PIO_ENV"
cp "$build_dir/firmware.elf" "/out/$OUTPUT_ELF"
cp "$build_dir/firmware.bin" "/out/${OUTPUT_ELF%.elf}.bin"

if [[ -n "${EARLY_RETURNS:-}" ]]; then
    python3 /tooling/patch_early_returns.py \
        "/out/$OUTPUT_ELF" "/out/${OUTPUT_ELF%.elf}.bin" $EARLY_RETURNS
fi

sha256sum "/out/$OUTPUT_ELF" "/out/${OUTPUT_ELF%.elf}.bin" > /out/SHA256SUMS
echo "Built /out/$OUTPUT_ELF"
