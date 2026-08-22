# Rebuilding contiki-hello-4-8

This builds Hoedur's `hello-world` target (`examples/hello-world`,
`TARGET=cc2538dk`) at commit `9771e9aaebbfbb5633ce69eb9876e0fc70bbcd6f`
(within `release/v4.8`), from `04-prev-unknown-vulns/building/contiki-ng/build.py`
in `hoedur-experiments`, with `l2cap_sample.patch` and neither BLE-L2CAP CVE
fix backported. Hoedur's own configs backport the other known fixes while
building each single-CVE target. Leaving all of those backports out combines
the open defects in the original 4.8 source into one binary.

```sh
./build.sh --verify
```

`--verify` will report a byte diff — see `firmware_builds/contiki/README.md`
for why (Contiki-NG's unsorted module-source `wildcard()` makes link order,
not code, non-reproducible across machines). Confirmed via
`arm-none-eabi-nm -S --size-sort`: the rebuild has the same 662 symbols as
the checked-in ELF with an identical (size, type) multiset and identical
per-name sizes — the code is content-identical, just relocated.

## Bugs present in the combined 4.8 binary

An ancestry check against the exact base commit establishes five open bugs:

- `H03` / CVE-2023-23609: unchecked completed L2CAP SDU copy to `packetbuf`;
- `H04` / CVE-2023-29001: self-directed IPv6 SRH recursion;
- `H06` / CVE-2023-28116: BLE MTU and `packetbuf` capacity mismatch;
- `H11` / CVE-2022-41873: truncated L2CAP channel-index bounds check;
- `H12` / CVE-2022-41972: missing NULL check in `input_l2cap_credit`.

The later fixes for `FW58`, `H07`, `H08`, `H09`, and `H10` are already
ancestors of the 4.8 base commit, so their ravens must not be installed in
this binary. No extra `project-conf.h` or nine-channel configuration is
required for any of the five retained bugs.
