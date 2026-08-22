# Rebuilding zephyr-f429zi X

This harder Hoedur-derived CVE-2022-3806 target retains the HCI overlay,
host-only configuration, capped STM32 flash layout, and generic C atomics needed
for emulation. It removes Hoedur's infinite Bluetooth timeouts and all post-link
early returns.

```sh
./build.sh --verify
```

The ordinary target is under `FirmBench/zephyr-f429zi/rebuild/`.
