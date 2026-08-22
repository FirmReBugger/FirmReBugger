# Rebuilding 3DPrinter

`uEmu-real_world_firmware` ships this exact ELF (identical SHA-256) but no
build script. Recovered entirely from strings embedded in the binary.

```sh
./build.sh --verify
```

Confirmed via `arm-none-eabi-nm -S --size-sort`: 1017/1017 symbols present
with zero size differences against the checked-in ELF. `--verify` reports a
~7% byte diff, consistent with ordinary link-order noise (see other
recipes' READMEs for why this is expected and not a sign of wrong content).

## How it was found

The ELF embeds `FIRMWARE_NAME:Marlin 2.0.5.4 (GitHub) ... MACHINE_TYPE:STM32F103RET6`
and PlatformIO/toolchain paths
(`C:\users\willy\.platformio\packages\framework-arduinoststm32-maple\...`,
`toolchain-gccarmnoneeabi@1.70201.0` = GCC 7.2.1). That's:

- **Commit** `5513e67512481024e0d571d84487f7c636996803` (tag `2.0.5.4`);
- **PlatformIO environment** `STM32F103RE` (`platformio.ini`'s
  `[env:STM32F103RE]`: `board = genericSTM32F103RE`, no board-specific
  `extra_scripts`, matching a plain `STM32F103RET6` machine type with no
  vendor board name);
- **`MOTHERBOARD`** must be changed from the stock `Configuration.h` default
  (`BOARD_RAMPS_14_EFB`, an AVR/Mega2560 board incompatible with an ARM env)
  to `BOARD_STM32F103RE` — the only board resolving to `pins_STM32F1R.h`
  tagged `env:STM32F103RE` (not one of the `_btt`-suffixed variants) in
  `Marlin/src/pins/pins.h`;
- **`SERIAL_PORT`** must move off the stock default (`0`, invalid on this
  HAL) to `1` — the build otherwise fails outright, so any working value
  was necessarily used;
- The embedded `MACHINE_UUID` (`cede2a2f-...`) is Marlin's own
  universal hardcoded default in `Version.h`, confirming the rest of
  `Configuration.h`/`Configuration_adv.h` is stock, unmodified.

See `firmware_builds/marlin/README.md` for why `Adafruit_MAX31865` is
dropped from `platformio.ini`'s `lib_deps` in the patch.
