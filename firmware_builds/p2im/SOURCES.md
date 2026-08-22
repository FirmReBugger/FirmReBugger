# Recovered provenance

The regular CNC, Console, Gateway, PLC, and Soldering Iron ELFs are identical
to the copies in Fuzzware's P2IM comparison experiment. P2IM published source
for the first four but did not commit its Soldering Iron source; its top-level
README still labels that target as unfinished cleanup.

Recovered source pins:

| Target | Source | Commit/tag |
| --- | --- | --- |
| CNC, Gateway, PLC | `RiS3-Lab/p2im-real_firmware` | `d4c7456574ce2c2ed038e6f14fea8e3142b3c1f7` |
| Console | `RIOT-OS/RIOT` | `99b170d8e8788edc49aa23248effbaeb1a1183d5` (`2018.04`) |
| Gateway library | `firmata/arduino` | `8cbe99be5890296d330b990f3ec078a4fba3a980` (`2.5.8`) |
| Gateway/PLC core | `stm32duino/Arduino_Core_STM32` package | `1.3.0` |
| Soldering Iron | `Ralim/IronOS` | `f7165781380cc3c1910727ce40457896b63105b1` (between `v2.05` and `v2.05.01`) |

The pins were recovered from P2IM's build notes, ELF DWARF producers and source
paths, function sizes/disassembly, version strings, and controlled rebuilds.
The regular binaries use Arm GNU 6-2017-q2-update. CNCX uses the Ubuntu 22.04
GCC 10 package; ConsoleX uses Ubuntu 20.04 GCC 9; the Arduino X targets still
use GNU 6.

The P2IM Arduino archive differs from the public 1.3.0 package in one material
place: its F429ZI board flags are soft-float. `arduino-f429-soft-float.patch`
records that recovered toolchain edit locally in each PLC recipe.

Patch classification:

- CNC regular skips the serial-drain call, bypasses delays and accepts a
  missing PLL-ready flag. CNCX restores those paths and removes the
  benchmark-control call. The drain function itself remains intact in both.
- Console regular prevents the idle thread from sleeping. ConsoleX restores
  `pm_set_lowest()`. Both retain `-O0` because that is present in both ELFs.
- Gateway regular stubs `delay()`; GatewayX restores it. Both omit P2IM's AFL
  call because neither checked-in ELF contains it.
- PLC regular disables CRC validation and replaces timing-based receive
  completion with an eight-byte availability gate. PLCX restores CRC but keeps
  the availability gate because it is required for deterministic emulation.
- Soldering Iron is regular-only. Its patch selects `-O0`, restores the full
  flash address range, avoids emulated flash writes and host-blocking timing,
  ADC, and I2C waits, and restores the no-op `controlSanitizer()` boundaries in
  `main`, the FreeRTOS heap, and task-list initialization. All 403 recovered
  function names and sizes match the checked-in ELF. Its loadable byte layout
  does not: the upstream Makefile generated its LTO input list with unsorted
  `find`, so the original filesystem-dependent link order is not recoverable.

Some source changes were already committed in P2IM's final repository. The
recipes keep explicit reverse/forward patches where needed so the difference
between regular and X remains reviewable.
