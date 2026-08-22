# OreSat control reproducible builds

These recipes reconstruct `app_control.elf` and `app_controlX.elf` from pinned
OreSat and submodule revisions in Ubuntu 20.04 with GCC 9.2.1. The recipe for
each benchmark lives beside its checked-in ELF and owns the patches it applies.

Build either variant from its `rebuild/` directory:

```sh
./build.sh --verify
```

`--verify` checks the ELF section totals and the sizes of the functions affected
by the recovered patches. `--strict` additionally requires identical loadable
bytes. The current clean reconstruction is structurally exact but intentionally
does not claim strict identity; the historical ELF has one unexplained GCC LTO
ordering difference described in `SOURCES.md`.

The first run builds the pinned toolchain image and downloads the upstream Git
repositories. Later runs reuse `cache/`. `--install` is guarded by strict
verification so the checked-in benchmark cannot be replaced by a merely
structural match.
