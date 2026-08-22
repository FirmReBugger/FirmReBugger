# Rebuilding zephyr-bt

This recipe reconstructs the combined Bluetooth benchmark from Fuzzware's
Zephyr 2.2 `peripheral_dis` target on `disco_l475_iot1`. It pins commit
`e1dddf7befa7309bd2afc567b2e00d2e7362f7c4` and reverts that commit to expose
CVE-2020-10066.

```sh
./build.sh --verify
```

Output is placed in `out/`; `--install` replaces the checked-in ELF after a
successful build. The X recipe is in `FirmBenchX/zephyr-bt/rebuild/`.

## Patch policy

- `firmbench` deliberately omits `fix-CVE-2020-10065.patch`, so the one image
  contains both CVE-2020-10065 and CVE-2020-10066. It also applies the post-link
  early returns used by FirmReBugger.
- `x` matches Fuzzware's original CVE-2020-10066 target: it keeps the
  CVE-2020-10065 safety fix and removes the post-link early returns.

That asymmetry is present in the checked-in binaries: the X ELF is byte-for-byte
the upstream Fuzzware CVE-2020-10066 ELF. It is documented explicitly here
rather than hidden in wrapper defaults.
