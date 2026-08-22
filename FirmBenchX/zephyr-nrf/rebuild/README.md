# Rebuilding zephyr-nrf X

This harder CVE-2021-3329 variant retains the unrelated CVE-2020-10065 safety
fix and the host-only HCI configuration required for emulation. It removes
`bt_hci_cmd_timeout.patch` and all post-link early returns, restoring the finite
HCI command timeout and normal Zephyr runtime paths.

```sh
./build.sh --verify
```

The ordinary variant is documented in `FirmBench/zephyr-nrf/rebuild/`.
