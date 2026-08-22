# Shared Zephyr firmware build tooling

The Zephyr recipes beside each ELF under `FirmBench/` and `FirmBenchX/` call
this tooling. Each recipe describes exactly one variant and pins its Zephyr
commit, Docker image digest, board, sample, fix reverts, and complete patch set.

`build.sh` runs the build container. `container-build.sh` reconstructs the
Zephyr west workspace and applies the declared source patches.
`patch_early_returns.py` reproduces the ordinary benchmark's post-link Thumb
`bx lr` patches by symbol. `compare_loadable.py` ignores DWARF/path metadata and
compares the bytes the emulator actually loads.

The container wrapper also passes Zephyr's original
`-fmacro-prefix-map=<workspace>=WEST_TOPDIR` explicitly. Old Zephyr caches its
compiler-capability probe; a cached false negative otherwise leaks the absolute
workspace into loadable assertion strings and changes the firmware image.

West workspaces are shared by compatible recipes below `cache/` here. Builds
take an exclusive lock before resetting the shared checkout. Delete the
relevant cache namespace for a completely cold rebuild.
