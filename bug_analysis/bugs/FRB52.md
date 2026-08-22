---
bug_id: FRB52
binary: betaflight
mcu: AT32F435G
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: cliLed passes a missing LED configuration argument to parseLedStripConfig, which immediately dereferences the NULL pointer.
---

# Bug Description

`cliLed` parses the LED index and then obtains the configuration string with `nextArg`. A command containing a valid index but no following configuration makes `nextArg` return NULL. The caller passes that result directly to `parseLedStripConfig` without checking it, and the parser immediately reads the first byte through the NULL pointer.

This is reachable through ordinary CLI input and does not depend on a synthetic interrupt or peripheral value. Betaflight tracks the source defect as [issue #13704](https://github.com/betaflight/betaflight/issues/13704); the [reported source revision](https://github.com/betaflight/betaflight/blob/660018b1de0c32ee60d8321f301d36fb1fd097f9/src/main/cli/cli.c#L1947-L1971) contains the unchecked call. The proper fix is to reject a NULL result from `nextArg` before invoking the parser.
