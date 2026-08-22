# Rebuilding Zepyhr_SocketCan

`uEmu`/`uEmu-real_world_firmware` never published a build script for this one —
the checked-in `uEmu.zephyrsocketcan.elf` is identical (same SHA-256) to the
copy in [`MCUSec/uEmu-real_world_firmware`](https://github.com/MCUSec/uEmu-real_world_firmware),
but that repo only ships the prebuilt ELF, not the recipe. Everything below
was recovered from strings embedded in the ELF itself.

```sh
./build.sh --verify
```

**Verifies byte-for-byte.**

## How it was found

The ELF's debug paths embed `*** Booting Zephyr OS build zephyr-v2.3.0-857-g157f6f65d920 ***`
and `/home/willy/zephyrproject/zephyr/samples/net/sockets/can/src` — an exact
Zephyr commit and sample. That resolves to:

- **Commit** `157f6f65d920656d0f375a2df26e8c60b3f84347` (`zephyr-v2.3.0-857-g157f6f65d920`);
- **Sample** `samples/net/sockets/can`, **board** `nucleo_l432kc` (STM32L432KC,
  matches `sample.yaml`'s `platform_whitelist`);
- **Toolchain** `zephyr-sdk-0.11.3` — also in the debug paths.

`bug_descriptor.c` hooks `canbus` and `pwm` shell subcommands
(`cmd_attach`/`cmd_config`/`cmd_detach`, `pwm ... usec/nsec/cycle`) that
aren't part of this sample's own source. Both `CAN_SHELL` and `PWM_SHELL`
default to `y` whenever `SHELL` is enabled in Zephyr's `drivers/can/Kconfig`
and `drivers/pwm/Kconfig`, and the sample's `prj.conf` sets
`CONFIG_NET_SHELL=y` (which implies `CONFIG_SHELL=y`) while
`nucleo_l432kc_defconfig` sets `CONFIG_PWM=y` — so both shells are pulled in
automatically with no extra config needed.

## Toolchain plumbing

This exact commit's `cmake/toolchain/zephyr/host-tools.cmake` hard-requires
`MINIMUM_REQUIRED_SDK_VERSION 0.11.3` via `find_package(Zephyr-sdk 0.11.3 ...)`
— a bundled 0.11.1 (same GCC 9.2.0, just older SDK metadata) does not satisfy
it despite being functionally identical. The pinned CI image
(`zephyrprojectrtos/ci:v0.11.3`) doesn't bundle 0.11.3 either (only 0.10.3 and
0.11.1), so `container-build.sh` installs the real 0.11.3 SDK into the shared
cache via `ZEPHYR_SDK_SETUP_URL` the first time this recipe builds. Separately,
that CI image's `west` (0.7.0) predates this commit's minimum-version check
(0.7.1), so `WEST_MIN_VERSION` triggers a `pip install --user --upgrade west`
before the build.
