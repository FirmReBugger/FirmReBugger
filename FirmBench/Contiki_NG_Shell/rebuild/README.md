# Rebuilding contiki-ng-shell

SplITS never published a build script for this one — unlike every other
recipe in this benchmark, everything here was reconstructed from the binary
itself plus a real source checkout the user located on another machine
(`/home/user/internal_firmrebugger/contiki-ng`), which turned out to be
pinned at `release/v4.4` for the *other* Contiki-NG recipes and didn't
directly cover this target, but ruled out several early guesses.

```sh
./build.sh --verify
```

## What it is

`examples/libs/shell` (`CONTIKI_PROJECT = example`, `MODULES += os/services/shell`)
on `TARGET=cc2538dk`, at Contiki-NG commit `c20b12cd2db707d6c07918f8b26cfeb52cf298ca`
(`release/v4.9`), with only `cc2538_norom.patch` applied — no `cc2538_read.patch`
or `transparent_mac.patch` like the other cc2538 recipes here.

## How the commit was pinned down

The checked-in ELF's `.comment` section reads
`GCC: (GNU Arm Embedded Toolchain 10.3-2021.10) 10.3.1 20210824 (release)`,
not the GCC 5.2.1 every other Contiki-NG recipe here was built with (the
toolchain baked into `contiker/contiki-ng:f823e6a1`). Tracing Contiki-NG's own
`tools/docker/Dockerfile` history to the commit that upgraded to that exact
toolchain version (`f4c4bb5a9d39`, "Updated gcc on Dockerfile") gave the
matching CI image tag: `contiker/contiki-ng:f4c4bb5a9` — note it's
**`linux/386`, not `linux/amd64`** (that CI image bundles an i386 host
toolchain), hence `PLATFORM=linux/386` here and nowhere else.

With the right toolchain, symbol-table comparison (`arm-none-eabi-nm -S`)
against candidate commits narrowed the source revision:

- `release/v4.4`/`v4.5` are ruled out: `os/dev/button-hal.c`'s
  `button_event_handlers` (plural, an array) only exists from commit
  `384f1cd39` onward, which lands in `release/v4.6`+.
- `release/v4.6`/`v4.8` are close but wrong: the built ELF is missing
  `mac_sequence_set_dsn`/`mac_sequence_init` as separate symbols, which only
  exist from commit `3fbf94d95` (2022-12-10) onward — after `v4.8`
  (2022-07-14) but before `v4.9` (2023-07-12, matching the SplITS paper's
  August 2023 publication).
- At `release/v4.9`, dropping `cc2538_read.patch` (the reference's `read()`
  matches the stock 232-byte DMA-based radio driver, not the ~48-byte
  simplified version that patch installs) brings the symbol table to 782/782
  symbols present with only 6 differing in size, and total loadable size
  within 0.3% of the reference.

`--verify` still reports a large byte diff (Contiki-NG's unsorted
module-source `wildcard()` makes link order non-reproducible across
machines — see `firmware_builds/contiki/README.md`), and it's a much bigger
percentage than the other five Contiki-NG recipes here because this example
pulls in the full default module set (IPv6 router, RPL-lite, shell, radio),
giving the unsorted per-directory `wildcard()` far more opportunities to
reorder than the smaller null-MAC examples do. The near-exact symbol-table
and total-size match is the signal that this is genuinely the right source,
not the byte diff.

## Still not pinned to the bit

Six symbols (`cmd_rpl_set_root`, `dao_input`, `dio_input`, `frag_info`,
`get_value`, `process_thread_tcpip_process`) differ in size by a handful of
bytes each — likely a small config/CFLAGS difference (logging level, RPL
timing constants, or similar) rather than a different commit, since v4.9 is
also exactly where the SplITS paper's timeline points. `cmd_rpl_set_root`
(the function `S06`'s raven hooks) still contains the same unchecked
`strcmp` call regardless of the 4-byte size difference. Not chased further.
