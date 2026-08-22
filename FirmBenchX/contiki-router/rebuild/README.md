# Rebuilding contiki-router (X)

Same recipe as `FirmBench/contiki-router` (Hoedur's CVE-2023-31129
`ip64-router` build, unmodified) with three differences that make this the
harder variant:

- no `cc2538_read.patch` — keeps the stock DMA-based radio `read()`;
- no `enc28j60_read.patch` — keeps the stock Ethernet driver, including its
  watchdog process, instead of the neutralized version;
- no `ipv6_checksums.patch` — packets need real, valid checksums instead of
  the harness's unconditional `0xffff`;
- no `EARLY_RETURNS` — `fade` and `lpm_enter` keep their real bodies instead
  of being patched to `bx lr`.

```sh
./build.sh --verify
```

Confirmed via `arm-none-eabi-nm -S --size-sort`: 689/689 symbols present with
zero size differences against the checked-in ELF. `--verify` still reports a
byte diff for the link-order reason in `firmware_builds/contiki/README.md`.
