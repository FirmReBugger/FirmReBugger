# Rebuilding RF_Door_lock

Unlike the `uEmu` targets, this one has real, findable source: Pretender's own
GitHub repo ships the exact application, `PROJECT := max32_rf_door_lock`,
matching the checked-in `Pretender.max32_rf_door_lock.elf` name exactly —
[`ucsb-seclab/pretender`](https://github.com/ucsb-seclab/pretender),
`test_programs/max32600/rf_lock/`.

```sh
./build.sh --verify
```

## What it is

A plain `mbed` "classic" (pre-mbed-OS, `.mbed`/`mbed.bld`) GCC Makefile
project for the MAX32600MBED board (Maxim MAX32600, Cortex-M3). Unusually,
the repo checks in **pre-vendored, precompiled `.o` files** for the mbed HAL
(`mbed/TARGET_MAX32600MBED/TOOLCHAIN_GCC_ARM/*.o`) — these came from mbed.org's
online compiler service (embedded debug paths show
`/home/jenkins/build_node_4_1/workspace/bm_wrap/.../mbed-os/...`), not from
source in this repo. `main.cpp` is compiled fresh and linked against those.

## Toolchain

The checked-in ELF's `.comment` section has two different GCC version
strings: `4.9.3 (prerelease)` (baked into the vendored `.o` files, not
reproduced here) and `GNU Tools for ARM Embedded Processors 6-2017-q1-update)
6.3.1` for `main.cpp`. The default `arm-none-eabi-gcc` on a modern system
(observed: 10.3.1) does **not** match — pulled in 16 extra newlib
`__retarget_lock_*`/locale symbols not in the reference and used different
long-division intrinsics (`__udivmoddi4`/`__unorddf2` instead of
`__divdi3`/`__udivdi3`). `GCC_ARM_URL` pins the exact
`6-2017-q1-update-linux.tar.bz2` release from ARM's own archive.

## Residual gap

Even with the matching compiler, 16 newlib-internal symbols still differ
(`__retarget_lock_*`, locale/`_ctype_`, division helpers) and three
functions — `reset_rf_config`, `max_tx_power`, `set_code` — are 4-8 bytes
larger than the reference, all `str*()`-calling functions. This looks like a
newlib version/configuration difference bundled with this exact toolchain
release rather than a wrong recipe. It doesn't reach the application logic
that matters: `configure_rf`, `unlock`, `read_code`, and `mbed_die` all match
the reference **exactly** in size, including the two functions the tracked
bugs (`FW29` in `set_code`, `FRB09`) actually hook.
