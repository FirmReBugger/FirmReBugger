# P2IM firmware rebuild tooling

This directory contains the shared Docker runner for the P2IM-derived
FirmBench targets. The target-specific source edits deliberately live beside
each binary under `FirmBench/<target>/rebuild/patches` or
`FirmBenchX/<target>/rebuild/patches`.

Build every recovered variant from the repository root:

```sh
./firmware_builds/p2im/build-all.sh
```

Pass `--verify` to compare each result with its checked-in binary. Eight recipes
compare loadable bytes. Soldering Iron compares all recovered function names
and sizes because the original Makefile used filesystem-dependent, unsorted
`find` output as its LTO link order. Individual target wrappers accept the same
flag. Docker downloads only pinned source commits and fixed toolchain/core
releases; temporary source/tool caches are kept below
`firmware_builds/p2im/cache/`.

The Docker images and cache are build tools, not benchmark artifacts. After a
build, the `rebuild/out/` ELF and BIN files are sufficient to keep. To remove
the local source cache and the two tagged build images:

```sh
./firmware_builds/p2im/cleanup.sh
```

Docker BuildKit can also retain untagged layers. `docker builder prune` removes
those globally, including layers from unrelated projects, so the cleanup script
deliberately does not run it.

No `Soldering_IronX` recipe is generated because FirmBenchX does not contain
that target.
