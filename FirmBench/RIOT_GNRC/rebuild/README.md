# Rebuilding RIOT_GNRC

This recipe reproduces MultiFuzz's unmodified RIOT `gnrc_networking` example
for the `stm32f3discovery` board.

```sh
./build.sh --verify
```

`--verify` requires the complete rebuilt ELF to be byte-for-byte identical to
`../gnrc_networking.elf`. The expected SHA-256 is
`444e9576e8b85f985643738ffb7358e4e7857c5ed389b302a05cd04a1ab21425`.

## Patch policy

No source patches, reverts, or backports are applied. MultiFuzz built RIOT's
stock `examples/gnrc_networking` at commit
`9142d9c37597c665fa704fe00ec8e377b35cf0d0`. The only non-default make
argument is `DISABLE_MODULE=cortexm_fpu`, which the artifact identifies as
necessary for comparison with Fuzzware.

The build uses board `stm32f3discovery` and preserves the original `/RIOT`
compilation path and attached Git state. See the shared
`firmware_builds/riot/SOURCES.md` for the container and toolchain pins.
