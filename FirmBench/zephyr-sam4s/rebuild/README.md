# Rebuilding zephyr-sam4s

This combined SAM4S 802.15.4 image starts at commit
`2a423bc6d37f916771bce65672efadf30e6ea74c`. It reverts the four fixes
recorded for the combined FirmBench target:

- `2a423bc6d37f916771bce65672efadf30e6ea74c`
- `6917d268482afc2da617a57456e1cdf4dd9c75d4`
- `0ebd30000113f87a1f6090dd050974c1e540b42a`
- `6f1ab93c66c59cf267bb2b974cf76a3b9b306e32`

The first two match Fuzzware's isolated CVE-2021-3322 recipe. The latter two
remove the ACK-frame rejection and missing-address validation fixes so that the
additional CVE-2021-3320/CVE-2021-3319 behavior is present in this combined
binary.

```sh
./build.sh --verify
```

## Patch policy

Both variants retain Fuzzware's implicit RF2xx frame-size and
watchdog-callback safety patches. The X variant also retains
`fix-CVE-2021-3323.patch`, matching Fuzzware's isolated CVE-2021-3322 target.
The combined `firmbench` image deliberately omits that fix and applies
`backport-CVE-2021-3321.patch`; despite its name, the latter removes the new
fragment-header length check. This makes CVE-2021-3323 and CVE-2021-3321
coexist with CVE-2021-3322. Together with the two additional commit reverts,
this reproduces the five-CVE combined target. It also applies the usual
post-link early returns.

This distinction was verified against the checked-in ELFs: the regular image
matches the combined FirmBench binary, while the X loadable image matches
Fuzzware's original CVE-2021-3322 binary.
