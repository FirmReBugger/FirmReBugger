# Rebuilding utasker_MODBUS — not reproducible here (closed-source toolchain)

**Blocked on a proprietary toolchain, left unresolved.** The checked-in ELF's
`.comment` section is unambiguous:

```
IAR ELF Linker V8.50.4.261/W32 for ARM
-f C:\Users\willy\...\Obj\application.o ... --config
    F:\IoTS2E\newtestcases\utasker\uTasker-GIT-Kinetis\Applications\uTaskerV1.4\
    IAR8_STM32\settings\STM32_F4_Flash_BM.icf
    --entry __iar_program_start --inline --vfe
-o "...\IAR8_STM32\Release BM STM32\Exe\uTaskerV1.4_BM.out"
```

This is **IAR Embedded Workbench for ARM V8.50.4.261** — a commercial,
licensed Windows IDE, not GCC. `firmware_builds/`'s whole verification
approach (pin a Docker image, build, confirm via `arm-none-eabi-nm`
symbol-size comparison) doesn't transfer to a different compiler family:
IAR and GCC produce genuinely different code layout/sizes for identical
source, so a GCC build could never be confirmed correct the same way every
other recipe in this project was — only "the same modules are linked in,"
never "byte-for-byte right."

## What's confirmed anyway

- **Source**: [`uTasker/uTasker-Kinetis`](https://github.com/uTasker/uTasker-Kinetis)
  (v1.4.x). Both `utasker_MODBUS` and `utasker_USB` link the *exact same*
  object list (`MODBUS.o`, `modbus_app.o`, `usb_application.o`, `USB_drv.o`,
  full TCP/IP stack, etc.) — these are the same build configuration, not two
  different feature builds.
- **IAR project**: `Applications/uTaskerV1.4/IAR8_STM32/`, configuration
  **"Release BM STM32"**, board `NUCLEO_F429ZI` (`config.h`, commented out
  by default).
- uTasker also ships an official GCC path
  (`Applications/uTaskerV1.4/GNU_STM32/`, linker script
  `uTaskerSTM32_F429ZI.ld`) that does build and link on this MCU once
  `config.h`'s default `BLINKY` demo mode is disabled — confirmed working,
  but not pursued further here, for the reason above: even a fully
  feature-matched GCC build can't be verified against an IAR-linked
  reference, so it wouldn't reach the confidence bar the rest of this
  project holds to.

`SOFTWARE_VERSION "V1.4.012"` embedded in the ELF has never existed in
`uTasker/uTasker-Kinetis`'s git history (hardcoded `"V1.4.011"` since the
repo's 2017 first commit, never changed) — uTasker's primary distribution is
periodic ZIPs from utasker.com, and this GitHub org looks like a
slower-cadence mirror, so the exact revision used likely isn't on GitHub at
all regardless of toolchain.
