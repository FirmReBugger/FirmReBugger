# Rebuilding zephyr-f429zi

This recipe is derived from Hoedur's CVE-2022-3806 build. It pins Zephyr commit
`4256cd41df6c60f1832fd2deb14edc30ac7debab`, the `nucleo_f429zi` board,
`x_nucleo_idb05a1` shield, and Hoedur's Zephyr CI image digest.

```sh
./build.sh --verify
```

## Patch policy

Both variants retain four patches required for the emulated host-only setup:

- `bluetooth_hci_overlay.patch` enables HCI in a dedicated overlay;
- `bt_hostonly_build.patch` disables the controller and relocates flash;
- `stm32f4_cap_flash_region_sizes.patch` makes the settings backend's page-size
  assumption hold;
- `arm_generic_atomic.patch` selects the C atomic implementation so exclusive
  access instructions are not required from the emulator.

`firmbench` additionally disables HCI/L2CAP/advertising timeouts with
`bt_hci_cmd_timeout.patch` and applies the post-link early returns. For this
Zephyr generation the fatal path includes `z_do_kernel_oops` and
`z_fatal_error`, which are recorded explicitly in `benchmark.conf`. `x` removes
those difficulty reductions. The X variant is under
`FirmBenchX/zephyr-f429zi/rebuild/`.
