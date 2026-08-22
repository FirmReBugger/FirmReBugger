#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/dev/null
source /recipe/benchmark.conf

if [[ ! -d .git ]]; then
    git init
    git remote add origin "$UPSTREAM_URL"
fi
git fetch --depth 1 origin "$BASE_COMMIT"
git reset --hard FETCH_HEAD
git clean -ffdqx
for source_patch in ${PATCHES:-}; do
    git apply "/recipe/patches/$source_patch"
done
rm -rf /out/*

common=(-mcpu=cortex-m4 -mthumb -mfloat-abi=soft -g3 -O0 \
        -fmessage-length=0 -ffunction-sections)
project="/src/$PROJECT_SUBDIR"
build=/tmp/dice-build
rm -rf "$build"
mkdir -p "$build/obj"

case "$BUILD_KIND" in
    midi)
        defs=(-DSTM32 -DSTM32F4 -DSTM32F429ZITx -DNUCLEO_F429ZI \
              -DDEBUG -DSTM32F429_439xx -DUSE_STDPERIPH_DRIVER)
        includes=(-I"$project/mmmidi/inc" -I"$project/StdPeriph_Driver/inc" \
                  -I"$project/inc" -I"$project/CMSIS/device" -I"$project/CMSIS/core")
        sources=(
            StdPeriph_Driver/src/stm32f4xx_dma.c
            StdPeriph_Driver/src/stm32f4xx_gpio.c
            StdPeriph_Driver/src/stm32f4xx_rcc.c
            StdPeriph_Driver/src/stm32f4xx_tim.c
            StdPeriph_Driver/src/stm32f4xx_usart.c
            mmmidi/src/mm_midiccrouter.c
            mmmidi/src/mm_midimsg.c
            mmmidi/src/mm_midimsgbuilder.c
            mmmidi/src/mm_midirouter.c
            mmmidi/src/mm_midirouter_standard.c
            src/afl_call.c src/leds.c src/main.c src/midi_lowlevel.c
            src/stm32f4xx_it.c src/syscalls.c src/system_stm32f4xx.c
        )
        startup=startup/startup_stm32.s
        ;;
    modbus)
        defs=(-DSTM32 -DSTM32F3 -DSTM32F30 -DSTM32F303RETx \
              -DNUCLEO_F303RE -DDEBUG -DSTM32F303xE -DUSE_HAL_DRIVER \
              -DUSE_RTOS_SYSTICK -DUSE_FULL_LL_DRIVER)
        includes=(-I"$project/HAL_Driver/Inc/Legacy" \
                  -I"$project/Middlewares/Third_Party/FreeRTOS/Source/portable/GCC/ARM_CM3" \
                  -I"$project/Middlewares/Third_Party/FreeRTOS/Source/include" \
                  -I"$project/inc" -I"$project/Utilities/STM32F3xx-Nucleo" \
                  -I"$project/CMSIS/device" -I"$project/CMSIS/core" \
                  -I"$project/Middlewares/Third_Party/FreeRTOS/Source/CMSIS_RTOS" \
                  -I"$project/HAL_Driver/Inc")
        sources=(
            HAL_Driver/Src/stm32f3xx_hal.c
            HAL_Driver/Src/stm32f3xx_hal_cortex.c
            HAL_Driver/Src/stm32f3xx_ll_rcc.c
            Middlewares/Third_Party/FreeRTOS/Source/CMSIS_RTOS/cmsis_os.c
            Middlewares/Third_Party/FreeRTOS/Source/list.c
            Middlewares/Third_Party/FreeRTOS/Source/queue.c
            Middlewares/Third_Party/FreeRTOS/Source/tasks.c
            Middlewares/Third_Party/FreeRTOS/Source/portable/GCC/ARM_CM3/port.c
            Middlewares/Third_Party/FreeRTOS/Source/portable/MemMang/heap_4.c
            src/afl_call.c src/main.c src/modbus_rtu.c src/stm32f3xx_it.c
            src/system_stm32f3xx.c
        )
        startup=startup/startup_stm32f303xe.s
        ;;
    *) echo "Unknown BUILD_KIND: $BUILD_KIND" >&2; exit 2 ;;
esac

objects=()
for source in "${sources[@]}"; do
    object="$build/obj/${source%.c}.o"
    mkdir -p "$(dirname "$object")"
    arm-none-eabi-gcc "${common[@]}" "${defs[@]}" "${includes[@]}" \
        -c "$project/$source" -o "$object"
    objects+=("$object")
done

# Workbench appended startup/subdir.mk after the C subdirectories. Keeping the
# startup object last is required for the historical vector and text addresses.
startup_object="$build/obj/${startup%.s}.o"
mkdir -p "$(dirname "$startup_object")"
arm-none-eabi-gcc "${common[@]}" "${includes[@]}" \
    -c "$project/$startup" -o "$startup_object"
objects+=("$startup_object")

arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -mfloat-abi=soft \
    -T"$project/LinkerScript.ld" -Wl,-Map="$build/$OUTPUT_MAP" \
    -Wl,--gc-sections -static --specs=nosys.specs -Wl,--start-group \
    "${objects[@]}" -lc -lm -Wl,--end-group -o "$build/$OUTPUT_ELF"
arm-none-eabi-objcopy -O binary "$build/$OUTPUT_ELF" "$build/$OUTPUT_BIN"
cp "$build/$OUTPUT_ELF" "$build/$OUTPUT_BIN" "$build/$OUTPUT_MAP" /out/
sha256sum "/out/$OUTPUT_ELF" "/out/$OUTPUT_BIN" > /out/SHA256SUMS
arm-none-eabi-size "/out/$OUTPUT_ELF"
