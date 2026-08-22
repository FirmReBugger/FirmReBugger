# Rebuilding contiki-hello-4-4

This is Fuzzware's `build_sample_CVE-2020-12140.sh` recipe, unmodified:
`examples/hello-world` on Contiki-NG `release/v4.4`
(`f156c231de80d32f8e1d60e43ffbdad5bb152d58`), `TARGET=cc2538dk`, with BLE
L2CAP configured as the MAC layer for CVE-2020-12140.

```sh
./build.sh --verify
```

`--verify` will report a byte diff for the same link-order reason documented
in `firmware_builds/contiki/README.md` — the code content is identical
(confirmed: the rebuild's symbol table has the exact same (size, type)
multiset as the checked-in ELF).

## Why eight bugs, one unmodified binary

No source patching combined anything here. Hoedur later re-fuzzed this exact,
unpatched Fuzzware binary as part of a bug-finding-ability study
(`01-bug-finding-ability/results/bug-reproducers/hoedur/Fuzzware/contiki-ng/CVE-2020-12140/`
in `hoedur-experiments`). The exact source revision contains all eight defects
covered by the combined descriptor:

- `CVE-2020-12140` (`FW58`): unchecked L2CAP fragment extents overflow the
  1280-byte reassembly buffer;
- `new-Bug-unchecked_sdu_length` / CVE-2023-23609 (`H03`): a completed SDU
  can overflow the 128-byte `packetbuf`;
- `new-Bug-ipv6_routing_infinite_recursion` / CVE-2023-29001 (`H04`): an SRH
  next hop can point back to the node and recursively re-enter IPv6 input;
- `new-Bug-l2cap_mtu_6lo_output_packetbuf_oob_write` / CVE-2023-28116 (`H06`):
  BLE reports a 1280-byte MAC payload while `packetbuf` has only 128 bytes;
- `fixed-Bug-uncompress_hdr_iphc_oob_write` (`H07`) and
  `fixed-Bug-6lo_firstfrag_oob_write` (`H08`): the old 6LoWPAN decompression
  and first-fragment copy paths lack the later upstream bounds checks;
- `fixed-Bug-SRH_too_many_segments_left` (`H09`) and
  `fixed-Bug-invalid_SRH_address_pointer` (`H10`): the old RPL SRH parser lacks
  the later segment-count and derived-range validation.

Hoedur's `fixed-Bug-*` label means that its oracle was based on a known
upstream fix. Those fixes are not ancestors of this old 4.4 revision, so the
corresponding bugs are present here.

`fix-l2cap-issues.patch` is Fuzzware's own post-paper patch fixing two
*different* L2CAP bugs (channel-index truncation and a missing null check)
that were later independently rediscovered and assigned CVE-2022-41873 and
CVE-2022-41972. Those two stay fixed here, which is why they are absent
from this binary and only appear in `contiki-hello-4-8`.

## Patch policy

- `cc2538_norom.patch` / `cc2538_read.patch`: see `contiki-6lowpan`'s README;
- `l2cap_sample.patch` configures `hello-world` with BLE L2CAP as the MAC
  layer;
- `fix-l2cap-issues.patch`: Fuzzware's own harness-stability patch, described
  above.
