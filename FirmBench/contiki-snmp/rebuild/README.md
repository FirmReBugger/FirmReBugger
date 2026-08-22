# Rebuilding contiki-snmp

This is Fuzzware's `build_sample_CVE-2020-12141.sh` recipe, unmodified:
`examples/snmp-server` on Contiki-NG `release/v4.4`
(`f156c231de80d32f8e1d60e43ffbdad5bb152d58`), `TARGET=cc2538dk`.

```sh
./build.sh --verify
```

`--verify` will report a byte diff for the same link-order reason documented
in `firmware_builds/contiki/README.md` — the code content is identical
(confirmed via `arm-none-eabi-nm -S --size-sort`: the rebuild's symbol table
has the exact same (size, type) multiset as the checked-in ELF).

## Why four bugs, one unmodified binary

No source patching combined anything here, the same as `contiki-hello-4-4`.
`FW59` is Fuzzware's own tracked bug (CVE-2020-12141,
`snmp_ber_decode_string_len_buffer`, fixed by
[PR #1355](https://github.com/contiki-ng/contiki-ng/pull/1355), which
postdates `release/v4.4`). `H15` (CVE-2020-14936,
[issue #1351](https://github.com/contiki-ng/contiki-ng/issues/1351),
`snmp_oid_decode_oid`) and `H16` (CVE-2020-14935,
[issue #1353](https://github.com/contiki-ng/contiki-ng/issues/1353),
`snmp_engine_get_bulk`) are two more Contiki-NG SNMP bugs from the same era
that remain open upstream *to this day* — they were never part of either
Fuzzware's or Hoedur's research, they're simply still-unfixed bugs reachable
in the same unmodified binary. `H17` (no CVE assigned) is very likely the
same class of unbounded OID-array write, also unfixed.

## Patch policy

- `cc2538_norom.patch` / `cc2538_read.patch`: see `contiki-6lowpan`'s README;
- `transparent_mac.patch`: see `contiki-6lowpan`'s README;
- `snmp_sample.patch` wires the SNMP engine up to a null-network transport so
  fuzzer input reaches `snmp_engine` directly.
