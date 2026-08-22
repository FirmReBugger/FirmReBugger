# Rebuilding zephyr-3330

This recipe follows Fuzzware's CVE-2021-3330 Zephyr 2.4 build at commit
`a980762f70d7048825e6ce9e42ceb6b5f87a5e44`, using `echo_server` on
`sam4s_xplained` with the `atmel_rf2xx_xplained` shield.

```sh
./build.sh --verify
```

## Patch policy

Both variants revert the CVE-2021-3330 fix and retain three focus/safety
patches: the CVE-2021-3323 fix, the RF2xx frame-size bound, and the watchdog
callback null check. `firmbench` additionally applies:

- `ieee802154_reass_timeout.patch`, preventing the reassembly cache from
  expiring while fuzzed input is being supplied;
- `spi_sam_flat_read.patch`, replacing peripheral-driven SPI progress with a
  deterministic flat receive-buffer fill;
- the standard post-link early returns.

The `x` variant removes those three difficulty-reducing changes while retaining
the safety/focus patches needed to reach CVE-2021-3330 cleanly.
