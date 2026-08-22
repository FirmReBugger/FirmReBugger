# Rebuilding OreSat control (FirmBenchX)

This recipe reconstructs `app_controlX.elf` from OreSat commit
`e41286df4fb19904a0cc67c556e9ab588c7180df`, with the recovered OpenCCSDS
override and GCC 9.2.1 toolchain.

```sh
./build.sh --verify
```

X deliberately omits the regular benchmark's virtual-timer empty-list guard
and AX5043 MMIO exchange/status replacements. It retains only the changes that
the reference proves were common to both variants:

- the upstream STM32F429/439 ChibiOS flash compatibility patch;
- non-shared FRAM, MAX7310, and AX5043 buses;
- omission of the AX5043 SPI receive-buffer copy.

The resulting critical function sizes match the checked-in ELF:
`chVTDoTickI=0xc0`, `ax5043SPIExchange=0x5e`,
`ax5043GetStatus=0x68`, and `ax5043Exchange=0x70`.

No delay early return is applied because the checked-in X ELF contains the full
`delay_deploy` body. See the shared `SOURCES.md` for the forensic details and
the one known historical LTO placement difference.
