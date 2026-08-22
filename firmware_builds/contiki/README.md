# Shared Contiki-NG firmware build tooling

The Contiki-NG recipe beside each ELF under `FirmBench/` calls this tooling.
Each recipe describes exactly one variant and pins its Contiki-NG commit,
Docker image digest, board (`TARGET=`), example application, revert/backport
commits, and complete patch set.

`build.sh` runs the build container. `container-build.sh` clones Contiki-NG,
resets to the pinned commit, initializes submodules, applies the declared
reverts/backports/patches, and builds the example with `make`.
`compare_loadable.py` compares the bytes the emulator actually loads.
`patch_early_returns.py` (shared with the Zephyr tooling) applies each
recipe's `EARLY_RETURNS` list as post-link `bx lr` patches by symbol.

## `FirmBench` vs `FirmBenchX`

Every Contiki-NG `FirmBench` recipe here patches `fade` (and, except for
`Contiki_NG_Shell`, `lpm_enter` too) to `bx lr` via `EARLY_RETURNS` — this is
invisible to a symbol-size diff, since a post-link patch doesn't change a
function's declared size, only its first two bytes. Its `FirmBenchX`
counterpart drops `EARLY_RETURNS` entirely and drops whichever source patches
made the base recipe easier to fuzz (`cc2538_read.patch` everywhere it
appears, plus `enc28j60_read.patch`/`ipv6_checksums.patch` for
`contiki-router`), keeping the stock, harder-to-reach implementations
instead. Check a checked-in ELF's `fade`/`lpm_enter` bytes directly
(`arm-none-eabi-objdump -d --start-address=... --stop-address=...`) before
assuming a new recipe needs the same patches — a symbol-size match alone does
not confirm the early-return patch state.

## Known limitation: link order is not reproducible

Contiki-NG's `Makefile.include` enumerates each module directory's sources
with a bare `$(wildcard $(d)/*.c)` (no `$(sort ...)`), so the final link order
— and therefore where each function and global ends up in flash/RAM — depends
on the host filesystem's raw directory-entry order, not on anything the
recipe controls. Two rebuilds on this same machine from a clean clone are
byte-identical (verified), but they do not match a reference ELF built on a
different machine/filesystem years ago, even with the exact right commit and
patches.

This was confirmed on `contiki-6lowpan` and `contiki-router`: `--verify`
reports thousands of differing bytes, but `arm-none-eabi-nm -S --size-sort`
shows every symbol has an identical size, and diffing the (size, type)
multiset of the two symbol tables shows zero differences — the compiled code
is provably identical, just relocated. A rebuild is a correctness check on
the recipe (commit + patches), not a byte-for-byte replacement for the
checked-in ELF. If you replace a checked-in ELF with a rebuilt one, any
hardcoded addresses in that binary's `bug_descriptor.c` must be regenerated
against the new layout (e.g. via `frb_symbolize`), since the raw hex
addresses `frb_add_reflection_point` uses will point at the wrong functions
after a relink.

Contiki-NG checkouts are shared by compatible recipes below `cache/` here.
Builds take an exclusive lock before resetting the shared checkout. Delete
the relevant cache namespace for a completely cold rebuild.
