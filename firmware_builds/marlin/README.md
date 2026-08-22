# Shared Marlin (PlatformIO) firmware build tooling

The Marlin recipe beside each ELF under `FirmBench/`/`FirmBenchX/` calls this
tooling. `build.sh` runs the build container. `container-build.sh` clones
Marlin, resets to the pinned commit, applies the declared patches, installs
the pinned PlatformIO Core version, and runs `pio run` for the declared
environment. `compare_loadable.py` compares the bytes the emulator actually
loads.

Unlike the RIOT/Zephyr/Contiki-NG tooling, there is no upstream fuzzer build
script to recover here — `uEmu`'s companion firmware repo only ships prebuilt
ELFs. Everything in these recipes was reconstructed from strings and symbols
embedded in the checked-in binary itself; see each recipe's own README for
the specific evidence trail.

## Known limitation: floating PlatformIO library dependencies

Marlin's own `platformio.ini` pins several `lib_deps` entries directly to a
GitHub branch (`.../archive/master.zip`), not a commit. A fresh clone today
fetches whatever is on that branch *today*, which can be a materially
different, incompatible library than what existed when the reference binary
was built years ago — this is Marlin's own upstream non-determinism, not
something introduced by these recipes.

`FirmBench/3DPrinter`'s `stm32f103re_board.patch` drops the
`Adafruit_MAX31865` line entirely (confirmed absent from the checked-in ELF's
symbol table — it requires `MAX6675_IS_MAX31865`, not enabled by default) —
today's `master` `Adafruit_MAX31865`/`Adafruit_BusIO` no longer builds against
this old `framework-arduinoststm32-maple` core's `Wire`/`SPI` API, and even
pinning both libraries to their commits as of the tag's release date didn't
fix it (same API mismatch existed then too, i.e. this library was already
effectively unbuildable against this HAL and only "worked" because
`lib_ldf_mode` correctly never compiled it when unreferenced). If a future
recipe hits an unrelated floating dependency, check the checked-in ELF's
symbol table first — if the library's symbols aren't present, it's dead code
safe to drop instead of pin.
