# Rebuilding zephyr-sam4s X

This harder SAM4S variant matches Fuzzware's original CVE-2021-3322 loadable
image. It retains the CVE-2021-3323 and common 802.15.4 safety patches, but does
not apply the CVE-2021-3321 combining patch or FirmBench's post-link early
returns.

```sh
./build.sh --verify
```

The combined ordinary target is documented in `FirmBench/zephyr-sam4s/rebuild/`.
