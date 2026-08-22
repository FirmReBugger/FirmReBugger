# Upstream provenance

The Fuzzware recipes and patches were recovered from
[`fuzzware-fuzzer/fuzzware-experiments`](https://github.com/fuzzware-fuzzer/fuzzware-experiments/tree/main/03-fuzzing-new-targets/zephyr-os/building)
at repository commit `1b03b728ea660b777571bf2a6c1ecfa9072f0bf5`.

The F429ZI recipe and patches were recovered from
[`fuzzware-fuzzer/hoedur-experiments`](https://github.com/fuzzware-fuzzer/hoedur-experiments/tree/main/04-prev-unknown-vulns/building/zephyr-os)
at repository commit `2babc78b72b1331b3122c11f170e9367132b8aa2`.

The recipes clone Zephyr from
[`zephyrproject-rtos/zephyr`](https://github.com/zephyrproject-rtos/zephyr)
and detach at the full commit recorded in each `benchmark.conf`. West then uses
that revision's manifest to fetch pinned module revisions.

## Container pins

- Fuzzware-derived builds use the amd64 manifest digest
  `docker.io/zephyrprojectrtos/zephyr-build@sha256:09d20690920a4ada89c08cccd6f555e4f48fbb00e9b0bf0462568071df96b55d`
  (the original tag was `v0.13.1`).
- The Hoedur build uses multi-platform manifest digest
  `docker.io/zephyrprojectrtos/ci@sha256:bc1bd27844ceb9661a1b7232980529a1a676dc10bacc613dd5fa8d859c986c7c`
  with `linux/amd64` selected (the original tag was `v0.26.4`). Its recipe
  explicitly selects the bundled SDK at
  `/opt/toolchains/zephyr-sdk-0.16.1`; the image does not export that location.

Digest pins avoid silently receiving a different toolchain if a registry tag is
changed. A first build still requires the registry and GitHub to retain these
historical objects.
