#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source /recipe/benchmark.conf

: "${UPSTREAM_URL:?missing UPSTREAM_URL}"
: "${BASE_COMMIT:?missing BASE_COMMIT}"
: "${OPENCCSDS_COMMIT:?missing OPENCCSDS_COMMIT}"
: "${SOURCE_DATE_EPOCH:?missing SOURCE_DATE_EPOCH}"
: "${PATCHES:=}"
: "${OUTPUT_ELF:?missing OUTPUT_ELF}"
: "${OUTPUT_BIN:?missing OUTPUT_BIN}"

repo=/home/user/working-firmrebugger/firmrebugger/binaries/new/oresat-control/oresat-firmware
app="$repo/src/f4/app_control"

mkdir -p "$HOME" /out
if [[ ! -d "$repo/.git" ]]; then
    git clone "$UPSTREAM_URL" "$repo"
fi

git -C "$repo" fetch --force origin "$BASE_COMMIT"
git -C "$repo" checkout --detach "$BASE_COMMIT"
git -C "$repo" reset --hard "$BASE_COMMIT"
git -C "$repo" clean -ffd
git -C "$repo" submodule sync --recursive
git -C "$repo" submodule update --init --recursive --force

# The reference source tree used a newer OpenCCSDS checkout than the OreSat
# superproject pin. This override is required for exact USLP function sizes.
git -C "$repo/ext/OpenCCSDS" fetch --force origin "$OPENCCSDS_COMMIT"
git -C "$repo/ext/OpenCCSDS" checkout --detach "$OPENCCSDS_COMMIT"

patch --batch --forward -d "$repo/ext/ChibiOS" -p0 \
    -i /recipe/patches/chibios-stm32f42x_43x-efl.patch

# GNU patch cannot match an LF unified diff against this CRLF ChibiOS source.
# Normalizing line endings is source-neutral and keeps the checked-in patch
# readable on Unix hosts.
sed -i 's/\r$//' "$repo/ext/ChibiOS/os/rt/src/chvt.c"

for patch_name in $PATCHES; do
    patch --batch --forward -d "$repo" -p1 -i "/recipe/patches/$patch_name"
done

export TZ=UTC
export LC_ALL=C
export SOURCE_DATE_EPOCH
make -C "$app" clean
make -C "$app" -j2

cp "$app/build/app_control.elf" "/out/$OUTPUT_ELF"
cp "$app/build/app_control.bin" "/out/$OUTPUT_BIN"
cp "$app/build/app_control.map" "/out/${OUTPUT_ELF%.elf}.map"
sha256sum "/out/$OUTPUT_ELF" "/out/$OUTPUT_BIN" > /out/SHA256SUMS
