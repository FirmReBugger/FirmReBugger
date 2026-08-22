# Rebuilding zephyr-sampro

This recipe reconstructs the combined SAM4E 802.15.4 benchmark at Zephyr commit
`38970c07abfcddcfc6a5958189f096a55c49594a`. It is derived from Fuzzware's
`build_sample_CVE-2020-10064.sh` and uses the `echo_server` sample on
`sam4e_xpro` with `overlay-802154.conf`.

Run from this directory:

```sh
./build.sh --verify
```

Results go to `out/`. Add `--install` only when you intentionally want to
replace the checked-in benchmark ELF. The X recipe lives beside its ELF under
`FirmBenchX/zephyr-sampro/rebuild/`.

## Patch policy

Both variants revert the base commit (the CVE fix), apply Fuzzware's old-Zephyr
device-binding backport, and retain two implicit patches from Fuzzware's common
802.15.4 wrapper:

- `ieee802154_rf2xx_size_check.patch`: bounds the emulated radio frame read.
- `wdt_sam_watchdog_callback_check.patch`: avoids calling a null watchdog callback.

Those two patches were absent from the summary table because the upstream
wrapper appended them automatically. The `firmbench` variant then overwrites
available logging/sleep/halt function entries with Thumb `bx lr`; `x` does not.

The Docker image is pinned by digest. The west workspace is cached under
`cache/`; remove it for a cold rebuild. Network access is needed on the first
build to fetch Zephyr modules.
