# Shared Pretender firmware build tooling

The Pretender recipe beside its ELF under `FirmBench/` calls this tooling.
`build.sh` runs the build container. `container-build.sh` sparse-checks-out
the named project directory from `ucsb-seclab/pretender`, installs the pinned
ARM GNU Toolchain release (`GCC_ARM_URL`) into the shared cache, and runs the
project's own vendored `make`. `compare_loadable.py` compares the bytes the
emulator actually loads.

Pretender's repo vendors precompiled `.o` files for its mbed HAL layer
(from mbed.org's online compiler) alongside the actual application source, so
there's nothing to patch or reconstruct there — only the toolchain used to
compile the one source file (`main.cpp`) needs to be pinned, by matching the
second GCC version string in the checked-in ELF's `.comment` section.
