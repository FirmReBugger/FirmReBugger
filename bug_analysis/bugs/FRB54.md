---
bug_id: FRB54
binary: betaflight
mcu: AT32F435G
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: cliColor passes a missing color specification to parseColor, whose numeric parser dereferences the NULL pointer.
---

# Bug Description

`cliColor` parses a color-table index and then obtains the following color specification with `nextArg`. When the command contains an index but no specification, `nextArg` returns NULL.

The handler does not test that result. It passes the NULL pointer directly to `parseColor`, which treats the argument as a numeric text string and advances through it while parsing channel values. The first character access therefore dereferences NULL.

The caller must reject a missing specification before entering `parseColor`, and the parser can defensively validate its own argument as well. This malformed-command path is tracked in [Betaflight issue #13702](https://github.com/betaflight/betaflight/issues/13702), and the [affected source](https://github.com/betaflight/betaflight/blob/660018b1de0c32ee60d8321f301d36fb1fd097f9/src/main/cli/cli.c#L1990-L2010) contains the unchecked call.
