# Rebuilding utasker_USB — not reproducible here (closed-source toolchain)

Same as `FirmBench/utasker_MODBUS` — see that recipe's README for the full
writeup. The checked-in ELF's `.comment` section shows the identical build
line (`IAR ELF Linker V8.50.4.261/W32 for ARM`,
`IAR8_STM32/settings/STM32_F4_Flash_BM.icf`, output `uTaskerV1.4_BM.out`) and
the **exact same linked object list** as `utasker_MODBUS` — both binaries
come from the same all-modules-compiled-in uTasker build, not two different
feature builds.

Blocked on IAR Embedded Workbench for ARM (commercial, licensed, Windows) —
not reproducible with the tooling available here.
