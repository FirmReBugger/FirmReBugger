# DICE DMA firmware rebuilds

This tooling reconstructs the MIDI and MODBUS ELFs in `FirmBenchDMA` from the
complete System Workbench projects published by DICE. It pins both the source
commit and GNU Arm Embedded 7-2018-q2, then reproduces Workbench's object order
without installing the historical Eclipse IDE.

Build and verify both benchmarks:

```sh
./firmware_builds/dice/build-all.sh --verify
```

Build one benchmark from its own directory:

```sh
cd FirmBenchDMA/midi/rebuild
./build.sh --verify
```

Results are retained in each `rebuild/out/` directory. Full ELFs normally have
different hashes because DWARF embeds build paths. Verification therefore
compares every file-backed `PT_LOAD` byte, which is the executable firmware
image consumed by the benchmark. `--install` replaces a checked-in reference
only after this comparison succeeds.

`cleanup.sh` removes the source cache and tagged Docker image, but deliberately
keeps the recipes and build outputs.
