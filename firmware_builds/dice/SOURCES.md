# Provenance

- Upstream: `https://github.com/RiS3-Lab/DICE-DMA-Emulation.git`
- Pinned commit: `2b3b8c8b722abdbd7ff9e35fc7b02914fddf75df`
- Initial public source commit: `1d84abe264baffba7063f036e9554bd3aadacec4`
- Toolchain: GNU Arm Embedded 7-2018-q2-update (GCC 7.3.1, revision 261907)
- Toolchain SHA-256: `bb17109f0ee697254a5d4ae6e5e01440e3ea8f0277f2e8169bf95d07c7d5fe69`
- Paper: `https://arxiv.org/pdf/2007.01502`

The repository's `.cproject`, linker scripts, startup assembly, CMSIS trees,
drivers, middleware, and application sources are complete. The checked-in
ELFs identify the same compiler revision and `-O0`, soft-float Cortex-M4 flags.

Recovery found later source-only edits in `modbus_rtu.c` and one commented
MIDI free. The small per-benchmark patches restore what is proven by the
checked-in machine code. See each recipe README for the exact evidence.
