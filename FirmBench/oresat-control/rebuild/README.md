# Rebuilding OreSat control (FirmBench)

This recipe reconstructs the regular `app_control.elf` from OreSat commit
`e41286df4fb19904a0cc67c556e9ab588c7180df`, with the recovered OpenCCSDS
override and GCC 9.2.1 toolchain.

```sh
./build.sh --verify
```

## Applied patches

Required in both variants:

- `chibios-stm32f42x_43x-efl.patch`: upstream OreSat compatibility support for
  the STM32F429/439 embedded flash driver;
- `nonshared-buses.patch`: builds FRAM, MAX7310, and AX5043 without shared-bus
  acquisition, matching the emulation-oriented ELF;
- `ax5043-no-rx-copy.patch`: omits the SPI receive-buffer copy, a retained DMA
  workaround also present in X.

Regular-only vulnerability-easing changes:

- `chvt-empty-list.patch`: returns from `chVTDoTickI` when no timer is armed;
- `ax5043-mmio-emulation.patch`: replaces AX5043 exchange/status DMA activity
  with reads from fuzzing MMIO addresses `0x40001000` and `0x40001004`.

The resulting critical function sizes match the checked-in ELF:
`chVTDoTickI=0xc8`, `ax5043GetStatus=0x28`, and
`ax5043Exchange=0x3c`; `ax5043SPIExchange` is eliminated by LTO.

The old summary's `Early return to Delay` entry is not represented in this
ELF, so no delay patch is included. See the shared `SOURCES.md` for evidence and
the one known historical LTO placement difference.
