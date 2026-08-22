# Rebuilding contiki-6lowpan (X)

Same recipe as `FirmBench/contiki-6lowpan` (Fuzzware's HALucinator
CVE-2019-9183 build, unmodified) with two differences that make this the
harder variant:

- no `cc2538_read.patch` — keeps the stock DMA-based radio `read()` instead
  of the simplified version;
- no `EARLY_RETURNS` — `fade` and `lpm_enter` keep their real bodies instead
  of being patched to `bx lr`.

```sh
./build.sh --verify
```

Confirmed via `arm-none-eabi-nm -S --size-sort`: 558/558 symbols present with
zero size differences against the checked-in ELF. `--verify` still reports a
byte diff for the link-order reason in `firmware_builds/contiki/README.md`.
