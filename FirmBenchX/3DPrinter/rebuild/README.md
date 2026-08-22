# Rebuilding 3Dprinter (X)

Identical recipe to `FirmBench/3Dprinter` — `bug_descriptor.c` is byte-for-byte
identical between the two variants, and comparing the checked-in
`uEmu.3Dprinter.elf` against the checked-in `3DprinterX.elf` shows the same
small-scattered-diff, zero-symbol-size-difference signature as ordinary
link-order noise (846 tiny ranges, mostly single bytes). This is simply an
independently-linked build of the same source, not a different configuration.

```sh
./build.sh --verify
```

Confirmed via `arm-none-eabi-nm -S --size-sort`: 1017/1017 symbols, zero size
differences against the checked-in `3DprinterX.elf`.
