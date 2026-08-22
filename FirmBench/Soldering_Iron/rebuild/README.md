# Rebuilding Soldering_Iron (FirmBench)

```sh
./build.sh --verify
```

P2IM never committed this target's source. Version strings, DWARF paths and line
numbers, commit-by-commit rebuilds, and disassembly identify IronOS commit
`f7165781380cc3c1910727ce40457896b63105b1` (between `v2.05` and `v2.05.01`).
The local patch selects `-O0`, restores the full-flash linker layout, removes
host-blocking flash/timing/ADC/I2C operations, and reconstructs the no-op
`controlSanitizer()` boundaries visible in the checked-in ELF. GNU Arm
6-2017-q2 matches its producer metadata.

`--verify` compares the complete 403-function name/size inventory. It does not
claim byte-identical layout: the old Makefile fed unsorted, filesystem-dependent
`find` output to GCC LTO, and the historical directory order was not recorded.
No X binary exists, so no X recipe is created.
