# Rebuilding zephyr-bt X

This recipe matches Fuzzware's original CVE-2020-10066 Zephyr 2.2 target. It
reverts the CVE-2020-10066 fix, retains `fix-CVE-2020-10065.patch`, and leaves
logging, sleeps, and halt behavior intact. The checked-in X ELF is an exact
copy of Fuzzware's upstream CVE-2020-10066 ELF.

```sh
./build.sh --verify
```

The ordinary combined target is under `FirmBench/zephyr-bt/rebuild/`; it omits
the CVE-2020-10065 fix so both Bluetooth CVEs coexist.
