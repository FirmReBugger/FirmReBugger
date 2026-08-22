# Rebuilding contiki-ng-shell (X)

Same recipe as `FirmBench/Contiki_NG_Shell` (`examples/libs/shell`,
`release/v4.9`, `cc2538_norom.patch` only — see that recipe's README for how
the exact commit and toolchain were pinned down) with one difference: no
`EARLY_RETURNS`. `fade` keeps its real body instead of being patched to
`bx lr`. `lpm_enter` is never patched in either variant of this binary,
unlike every other cc2538 recipe here.

```sh
./build.sh --verify
```

Confirmed via `arm-none-eabi-nm -S --size-sort`: 782/782 symbols present,
matching the same small residual gap (6 symbols differing by a handful of
bytes each) already documented in `FirmBench/Contiki_NG_Shell/rebuild/README.md`
as unresolved but likely a minor config/CFLAGS difference rather than a wrong
commit. `--verify` still reports a large byte diff for the link-order reason
in `firmware_builds/contiki/README.md`.
