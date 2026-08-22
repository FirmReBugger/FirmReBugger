# Rebuilding zephyr-3330 X

This harder CVE-2021-3330 variant reverts the vulnerability fix but retains the
CVE-2021-3323 fix, RF2xx frame-size bound, and watchdog callback safety check.
It removes the deterministic SPI read, infinite reassembly lifetime, and
post-link early returns used by the ordinary FirmBench target.

```sh
./build.sh --verify
```

The ordinary variant is documented in `FirmBench/zephyr-3330/rebuild/`.
