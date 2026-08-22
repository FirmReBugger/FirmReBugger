# Rebuilding CNC (FirmBench)

```sh
./build.sh --verify
```

This pins P2IM commit `d4c74565` and GNU Arm 6-2017-q2. P2IM's final source
already contains two regular emulation edits: immediate returns from
`delay_ms`/`delay_us` and acceptance of a missing PLL-ready flag.
`benchmark-control.patch` reconstructs the checked-in ELF: it skips the call
that drains the serial receive buffer and adds the no-op
`controlSanitizer(1)` entry point.
