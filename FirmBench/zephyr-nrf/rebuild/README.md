# Rebuilding zephyr-nrf

This is Fuzzware's CVE-2021-3329 Bluetooth host-only target at Zephyr commit
`e1dddf7befa7309bd2afc567b2e00d2e7362f7c4`, built for
`nrf52840dk_nrf52840`.

```sh
./build.sh --verify
```

## Patch policy

Both variants retain:

- `fix-CVE-2020-10065.patch`, so an unrelated SPI HCI overflow does not mask
  CVE-2021-3329;
- `bt_hostonly_build.patch`, which disables the in-tree controller and makes
  the external/emulated HCI path reachable.

Only `firmbench` applies `bt_hci_cmd_timeout.patch` (`K_FOREVER`) and the
post-link logging/sleep/halt early returns. Unlike the other ordinary targets,
its checked-in ELF leaves `z_tick_sleep` intact; the exact symbol list is in
`benchmark.conf`. `x` restores the finite HCI command timeout and all normal
functions. The current ELFs confirm this exact split.
