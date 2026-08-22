# Shared RIOT firmware build tooling

The RIOT recipe beside each ELF under `FirmBench/` calls this tooling. Each
recipe describes exactly one variant and pins its RIOT commit, Docker image
digest, board, example application, revert/backport commits, and complete
patch set.

`build.sh` runs the build container. `container-build.sh` clones RIOT,
resets to the pinned commit, applies the declared reverts/backports/patches,
and builds the example with `make`. `compare_loadable.py` ignores DWARF/path
metadata and compares the bytes the emulator actually loads.

RIOT checkouts are shared by compatible recipes below `cache/` here. Builds
take an exclusive lock before resetting the shared checkout. Delete the
relevant cache namespace for a completely cold rebuild.

The MultiFuzz recipes use the same driver with a dedicated profile that
preserves the original `/RIOT` compilation path, attached Git branch, stock
compiler flags, eight-way build, and `DISABLE_MODULE=cortexm_fpu` argument.
Those details are required for full, byte-for-byte ELF identity. The older
Hoedur recipe keeps its existing detached-checkout and DWARF-4 behavior.
