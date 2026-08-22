# Rebuilding RIOT_CCN_LITE

This recipe reproduces MultiFuzz's unmodified RIOT `ccn-lite-relay` example
for the `nrf52dk` board.

```sh
./build.sh --verify
```

`--verify` requires the complete rebuilt ELF to be byte-for-byte identical to
`../ccn-lite-relay.elf`. The expected SHA-256 is
`b422ea45c960705ce28d5f41f2e9aef972c8afcb2cbdb057de202aaaed14304f`.

## Patch policy

No source patches, reverts, or backports are applied. MultiFuzz built RIOT's
stock `examples/ccn-lite-relay` at commit
`9142d9c37597c665fa704fe00ec8e377b35cf0d0`. The only non-default make
argument is `DISABLE_MODULE=cortexm_fpu`, which the artifact identifies as
necessary for comparison with Fuzzware.

The build uses board `nrf52dk`, keeps the original `/RIOT` compilation path,
and downloads the package revisions pinned by RIOT. See the shared
`firmware_builds/riot/SOURCES.md` for the image and package digests.
