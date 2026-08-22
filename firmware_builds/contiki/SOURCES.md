# Upstream provenance

Recipes here draw on two upstream research repos, combined per-binary:

- [`fuzzware-fuzzer/fuzzware-experiments`](https://github.com/fuzzware-fuzzer/fuzzware-experiments),
  `03-fuzzing-new-targets/contiki-ng/` — the original Fuzzware paper's three
  Contiki-NG samples (`hello-world` + BLE-L2CAP for CVE-2020-12140,
  `hello-world` + 6LoWPAN reverted to reintroduce HALucinator's
  CVE-2019-9183, `snmp-server` for CVE-2020-12141), all on `release/v4.4`
  (commit `f156c231de80d32f8e1d60e43ffbdad5bb152d58`), Docker image
  `contiker/contiki-ng:f823e6a1`.
- [`fuzzware-fuzzer/hoedur-experiments`](https://github.com/fuzzware-fuzzer/hoedur-experiments),
  `04-prev-unknown-vulns/building/contiki-ng/build.py` — Hoedur's own
  per-CVE `hello-world` (CVE-2022-41873, CVE-2022-41972) and `ip64-router`
  (CVE-2023-31129) targets, all on commit
  `9771e9aaebbfbb5633ce69eb9876e0fc70bbcd6f` (within `release/v4.8`), same
  Docker image tag/digest.

## Container pin

- `docker.io/contiker/contiki-ng@sha256:0b6df3584cec7cc9991c0e3752ffc99863f044adf4405f231580083c8f1553ed`
  (original tag `f823e6a1`, used by both repos above).

## The "combination" the benchmark asked about

Fuzzware and Hoedur never combined binaries at the source level themselves —
each of their own recipes tracks exactly one CVE. Two different kinds of
combination produced this benchmark's monolithic binaries instead:

1. **Free extra bugs from re-fuzzing an unmodified Fuzzware binary.**
   Hoedur's own bug-finding-ability study (`01-bug-finding-ability/results/bug-reproducers/hoedur/Fuzzware/contiki-ng/CVE-2020-12140/`)
   re-fuzzed Fuzzware's *exact, unpatched* CVE-2020-12140 build and found three
   more bugs already reachable in it, later assigned CVE-2023-29001,
   CVE-2023-28116, and CVE-2023-23609. No patch changed — Fuzzware's original
   binary already contained all of them. `contiki-6lowpan` and
   `contiki-snmp` are similarly just Fuzzware's unmodified builds: Contiki-NG
   GitHub issues [#1351](https://github.com/contiki-ng/contiki-ng/issues/1351)
   (CVE-2020-14936) and [#1353](https://github.com/contiki-ng/contiki-ng/issues/1353)
   (CVE-2020-14935) are, as of this writing, still open upstream, so they are
   present in any `release/v4.4`-or-later `snmp-server` build without any
   extra revert.
2. **A real merge of Hoedur's per-CVE variants.** Hoedur's `build.py` builds
   one `hello-world` binary per CVE, backporting every *other* tracked fix so
   only the target CVE stays open. `contiki-hello-4-8` backports neither
   target fix, so both (CVE-2022-41873, CVE-2022-41972) stay open at once —
   confirmed content-identical to the checked-in ELF via symbol-table
   comparison.
