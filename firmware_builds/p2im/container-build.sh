#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source /recipe/benchmark.conf

checkout() {
    local url=$1 commit=$2
    if [[ ! -d .git ]]; then
        git init
        git remote add origin "$url"
    fi
    git fetch --depth 1 origin "$commit"
    git reset --hard FETCH_HEAD
    git clean -ffdqx
}

apply_source_patches() {
    local name
    for name in ${PATCHES:-}; do
        git apply "/recipe/patches/$name"
    done
}

prepare_arduino() {
    local cli="$CONTAINER_SOURCE/deps/arduino-cli/arduino-cli"
    # Arduino CLI 0.5 predates the current Board Manager layout.  The 1.3.0
    # package is still described by the project's historical master index.
    local index=https://raw.githubusercontent.com/stm32duino/BoardManagerFiles/master/STM32/package_stm_index.json
    chmod +x "$cli"
    if [[ ! -d "$HOME/.arduino15/packages/STM32/hardware/stm32/1.3.0" ]]; then
        "$cli" core update-index --additional-urls "$index"
        "$cli" core install STM32:stm32@1.3.0 --additional-urls "$index"
    fi
    if [[ "$BUILD_KIND" == gateway && ! -d "$HOME/Arduino/libraries/Firmata/.git" ]]; then
        mkdir -p "$HOME/Arduino/libraries"
        git clone "$FIRMATA_URL" "$HOME/Arduino/libraries/Firmata"
        git -C "$HOME/Arduino/libraries/Firmata" checkout --detach "$FIRMATA_COMMIT"
    fi
    # The historical STM32 package mixes CRLF and LF source files. Normalize
    # the two files touched by recovered patches so GNU patch is deterministic.
    sed -i 's/\r$//' \
        "$HOME/.arduino15/packages/STM32/hardware/stm32/1.3.0/cores/arduino/HardwareSerial.h" \
        "$HOME/.arduino15/packages/STM32/hardware/stm32/1.3.0/system/Drivers/STM32F1xx_HAL_Driver/Src/stm32f1xx_hal_rcc.c"
    local core_patch
    for core_patch in ${CORE_PATCHES:-}; do
        if patch --dry-run -d "$HOME/.arduino15/packages/STM32/hardware/stm32/1.3.0" \
            -p1 < "/recipe/patches/$core_patch" >/dev/null; then
            patch -d "$HOME/.arduino15/packages/STM32/hardware/stm32/1.3.0" \
                -p1 < "/recipe/patches/$core_patch"
        elif patch --dry-run -R -d "$HOME/.arduino15/packages/STM32/hardware/stm32/1.3.0" \
            -p1 < "/recipe/patches/$core_patch" >/dev/null; then
            echo "Core patch already applied: $core_patch"
        else
            echo "Core patch does not apply cleanly: $core_patch" >&2
            exit 1
        fi
    done
}

checkout "$UPSTREAM_URL" "$BASE_COMMIT"
for normalized in ${NORMALIZE_CRLF:-}; do
    sed -i 's/\r$//' "$normalized"
done
apply_source_patches
rm -rf /out/*

case "$BUILD_KIND" in
    cnc)
        if [[ "$TOOLCHAIN" == gcc6 ]]; then
            tools=$GCC6_ROOT
        else
            tools=/usr
        fi
        make -C CNC XTOOLS_DIR="$tools/" clean
        make -C CNC XTOOLS_DIR="$tools/" -j"$(nproc)"
        cp CNC/grbl_stm32f4 "/out/$OUTPUT_ELF"
        cp CNC/grbl_stm32f4.bin "/out/$OUTPUT_BIN"
        ;;
    console)
        export PATH
        if [[ "$TOOLCHAIN" == gcc6 ]]; then
            PATH="$GCC6_ROOT/bin:$PATH"
        fi
        make -C examples/default WERROR=0 \
            RIOT_VERSION_OVERRIDE="$RIOT_VERSION_OVERRIDE" -j"$(nproc)"
        cp examples/default/bin/frdm-k64f/default.elf "/out/$OUTPUT_ELF"
        arm-none-eabi-objcopy -O binary "/out/$OUTPUT_ELF" "/out/$OUTPUT_BIN"
        ;;
    gateway|plc)
        prepare_arduino
        cli="$CONTAINER_SOURCE/deps/arduino-cli/arduino-cli"
        sketch_dir="$CONTAINER_SOURCE/${SOURCE_SUBDIR}"
        mkdir -p "$sketch_dir/build"
        "$cli" compile -b "$FQBN" "$sketch_dir/$SKETCH" \
            --build-path "$sketch_dir/build" -o firmware
        cp "$sketch_dir/build/${SKETCH}.elf" "/out/$OUTPUT_ELF"
        cp "$sketch_dir/build/${SKETCH}.bin" "/out/$OUTPUT_BIN"
        ;;
    soldering)
        export PATH="$GCC6_ROOT/bin:$PATH"
        make -C workspace/TS100 clean
        make -C workspace/TS100 lang=EN -j"$(nproc)"
        cp workspace/TS100/Hexfile/TS100_EN.elf "/out/$OUTPUT_ELF"
        cp workspace/TS100/Hexfile/TS100_EN.bin "/out/$OUTPUT_BIN"
        ;;
    *)
        echo "Unknown BUILD_KIND: $BUILD_KIND" >&2
        exit 2
        ;;
esac

sha256sum "/out/$OUTPUT_ELF" "/out/$OUTPUT_BIN" > /out/SHA256SUMS
arm-none-eabi-size "/out/$OUTPUT_ELF"
