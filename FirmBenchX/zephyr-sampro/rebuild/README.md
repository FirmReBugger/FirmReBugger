# Rebuilding zephyr-sampro X

This is the harder SAMPRO variant beside this ELF. It uses Zephyr 2.2 commit
`38970c07abfcddcfc6a5958189f096a55c49594a`, reverts the CVE fix, and retains
Fuzzware's RF2xx frame-size and watchdog callback safety patches. It does not
apply FirmBench's post-link logging/sleep/halt early returns.

```sh
./build.sh --verify
```

Output goes to `out/`; `--install` replaces the checked-in X ELF. The ordinary
variant and its difficulty-reducing changes are documented in
`FirmBench/zephyr-sampro/rebuild/`.
