# Rebuilding riot-gnrc-networking

This recipe rebuilds the `examples/gnrc_networking` sample from
[RIOT-OS/RIOT](https://github.com/RIOT-OS/RIOT), pinned at commit
`68b89e77b3b8521fe614ca5100dde59ee831466a` (tag `2022.07`), for the
`cc2538dk` board, using the pinned `riot/riotbuild:2022.07` image digest.

```sh
./build.sh --verify
```

## Provenance

Hoedur's [`hoedur-experiments`](https://github.com/fuzzware-fuzzer/hoedur-experiments/tree/main/04-prev-unknown-vulns/building/riot)
built one single-CVE-open variant of this firmware per RIOT GNRC CVE, with
every other tracked CVE's fix commit backported so exactly one bug remained
reachable per binary:

- CVE-2023-24817 (`H19`), CVE-2023-24818 (`H20`), CVE-2023-24819 (`H21`),
  CVE-2023-24820 (`H22`), CVE-2023-24821 (`H23`), CVE-2023-24822 (`H24`),
  CVE-2023-24823 (`H25`), CVE-2023-24825 (`H26`), CVE-2023-24826 (`H27`).

This benchmark instead wants one monolithic binary exposing all nine bugs at
once, matched against `bug_descriptor.c`'s reflection points. This recipe
therefore never backports any of Hoedur's nine per-CVE fix commits, and drops
`fix_CVE-2023-24826.patch` (the one fix that is a hand patch rather than a
cherry-pick) from the patch set.

`fix_CVE-2023-33973.patch`, `fix_CVE-2023-33974.patch`, and
`fix_CVE-2023-33975.patch` fix three additional RIOT CVEs that are not part of
this benchmark's tracked bug set, so they stay applied in every Hoedur
variant, including this one. Likewise, `BACKPORT_COMMITS` in `benchmark.conf`
always cherry-picks Hoedur's two always-applied driver fixes (an ethos and a
slipdev off-by-one) that aren't tied to any tracked CVE either.

## Patch policy

- `base.patch` guards two CC2538 peripheral ISRs (`gpio`, `timer`) against a
  null callback, and zero-initializes the timer ISR context array;
- `increase_stack_size.patch` raises the default thread stack size RIOT needs
  for the fuller module set below;
- `gnrc_networking_activate_modules.patch` swaps the routing module for a
  border-router one and enables the additional GNRC/6LoWPAN modules
  (fragmentation, RPL source routing, extension headers, sockets, `ethos`
  stdio) that the tracked bugs live in, and raises `RAM_LEN` to fit them;
- `remove_checksums.patch` disables ICMPv6/TCP checksum validation so
  fuzzer-generated packets reach the parsing code the bugs are in;
- `prevent_null_deref_gnrc_sixlowpan_frag_sfr_arq_timeout.patch` asserts
  instead of silently accepting a null packet in an unrelated SFR error path.
