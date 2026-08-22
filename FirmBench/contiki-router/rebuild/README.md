# Rebuilding contiki-router

This is Hoedur's `CVE-2023-31129` target from
`04-prev-unknown-vulns/building/contiki-ng/build.py` in `hoedur-experiments`,
unmodified: `examples/ip64-router` on Contiki-NG commit
`9771e9aaebbfbb5633ce69eb9876e0fc70bbcd6f` (within `release/v4.8`),
`TARGET=zoul` (board `orion`). No `backport_commits` — the fix for
CVE-2023-31129 (a missing null check in `rs_input`'s Neighbor Discovery path,
`H13`) postdates this commit, so it is naturally open without reverting
anything.

```sh
./build.sh --verify
```

`--verify` will report a byte diff for the same link-order reason documented
in `firmware_builds/contiki/README.md` — confirmed via
`arm-none-eabi-nm -S --size-sort`: every symbol has an identical size to the
checked-in ELF, just a different address (`zoul`/CMSIS needs
`git submodule update --init --recursive`, which `container-build.sh` does
before applying patches).

## Patch policy

- `cc2538_norom.patch` / `cc2538_read.patch`: see `contiki-6lowpan`'s README;
- `enc28j60_read.patch` neutralizes the Ethernet driver's watchdog process
  and DMA-style send/receive for the emulator;
- `transparent_mac.patch`: see `contiki-6lowpan`'s README;
- `ip64_sample.patch` configures `ip64-router` with a null MAC/routing stack;
- `link_address_granularity.patch` coarsens link-address comparison so the
  fuzzer can address multiple simulated neighbors without exact-match
  addresses;
- `ipv6_checksums.patch` disables checksum validation so generated packets
  reach parsing code;
- `0001-...` / `0002-...ip64-dns64...patch` are Hoedur's own upstreamed
  bounds-check fixes for an unrelated IP64 DNS64 bug, applied here as
  harness-stability patches (not part of this binary's tracked bug set).
