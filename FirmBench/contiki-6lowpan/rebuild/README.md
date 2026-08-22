# Rebuilding contiki-6lowpan

This is Fuzzware's `build_sample_HALucinator_CVE-2019-9183.sh` recipe,
unmodified: `examples/hello-world` on Contiki-NG `release/v4.4`
(`f156c231de80d32f8e1d60e43ffbdad5bb152d58`), `TARGET=cc2538dk`, with the
6LoWPAN reassembly fix reverted to reintroduce HALucinator's CVE-2019-9183
(`HAL02`), plus `HAL01` which is reachable in this exact same unmodified
binary.

```sh
./build.sh --verify
```

`--verify` will report a byte diff — see `firmware_builds/contiki/README.md`
for why (Contiki-NG's unsorted module-source `wildcard()` makes link order,
not code, non-reproducible across machines). Confirmed via
`arm-none-eabi-nm -S --size-sort`: every symbol in a rebuild has the same
size as the checked-in ELF, just a different address.

## Patch policy

- `cc2538_norom.patch` / `cc2538_read.patch` replace ROM-routine and DMA-based
  radio reads so the emulator sees a plain register-mapped read path;
- `transparent_mac.patch` lets the MAC layer's max packet size follow the
  network layer's configured buffer size instead of the 127-byte radio
  default;
- `6lowpan_sample.patch` configures `hello-world` with a null MAC/routing
  stack so 6LoWPAN input reaches `sicslowpan` directly.

The revert (`5884a12d7d71c5bce0d97b1a387aeb7928189b04`, mainline parent 1) is
PR #972 "sicslowpan vulnerability fixes", merged five weeks before the
`release/v4.4` tag was cut — it is already applied at that tag and must be
reverted to reopen CVE-2019-9183.
