# Upstream provenance

The RIOT recipes and patches were recovered from
[`fuzzware-fuzzer/hoedur-experiments`](https://github.com/fuzzware-fuzzer/hoedur-experiments/tree/main/04-prev-unknown-vulns/building/riot)
at repository commit `2babc78b72b1331b3122c11f170e9367132b8aa2`.

The recipes clone RIOT from [`RIOT-OS/RIOT`](https://github.com/RIOT-OS/RIOT)
and detach at the full commit recorded in each `benchmark.conf`.

## Container pins

- The build uses the amd64 manifest digest
  `docker.io/riot/riotbuild@sha256:bd3a1e4d5bd7c930551aad2ec42e84b3a604acd1b2695232c915cd99c5e8c196`
  (the original tag was `2022.07`).

Digest pins avoid silently receiving a different toolchain if a registry tag
is changed. A first build still requires the registry and GitHub to retain
these historical objects.

## MultiFuzz RIOT targets

The `RIOT_CCN_LITE` and `RIOT_GNRC` recipes were recovered from the official
[`MultiFuzz/MultiFuzz-benchmarks`](https://github.com/MultiFuzz/MultiFuzz-benchmarks/tree/usenix2024-ae/benchmarks)
artifact at commit `92051caf3770fe0578b248f17a941038eb6c4c49`.
Its `build_new_binaries.sh` identifies the RIOT revision, boards, examples,
container tag, and required module exclusion, and publishes the same SHA-256
values as FirmReBugger's checked-in ELFs.

Pinned common inputs:

- RIOT: `9142d9c37597c665fa704fe00ec8e377b35cf0d0`
  (`2023.04-devel-651-g9142d`);
- container: `riot/riotbuild:2023.01`, pinned here as amd64 image digest
  `sha256:691413d2b0deb59dbd11d812de205f6f0c1898fc343551e83076b0b19e026422`;
- GNU Arm Embedded Toolchain `10.3-2021.10` (GCC `10.3.1`, binutils `2.36.1`);
- build checkout path `/RIOT`, attached to branch `master`;
- `DISABLE_MODULE=cortexm_fpu`, required by MultiFuzz for comparison with
  Fuzzware.

CCN-Lite additionally obtains the package revisions pinned by that RIOT tree:
CCN-Lite `da0d9de8d82349dff845acc62d37242dd09b3d3d`, NimBLE
`719bd3c435b728f07ce7aaffaf6cebbd9c659a46`, nrfx
`3521c97df0b9549daecf867fb588f62819c317b4`, and tinycrypt
`5969b0e0f572a15ed95dc272e57104faeb5eb6b0`.

No firmware source patches are applied to either MultiFuzz target. Clean
builds reproduce both complete ELF files byte-for-byte, not only their
loadable sections.
