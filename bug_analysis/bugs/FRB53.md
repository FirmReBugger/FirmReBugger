---
bug_id: FRB53
binary: betaflight
mcu: AT32F435G
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: cliHelp passes a NULL command description to strcasestr when the command name does not match the requested help filter.
---

# Bug Description

Several entries in Betaflight's CLI command table intentionally have no description. When filtered help does not match such an entry's command name, `cliHelp` nevertheless calls `strcasestr` on the NULL description. `strcasestr` subsequently scans its first string argument, producing a NULL-pointer dereference instead of simply treating the missing description as a non-match.

The path is driven solely by an ordinary CLI help filter. Betaflight records the defect as [issue #13703](https://github.com/betaflight/betaflight/issues/13703), and the [reported source revision](https://github.com/betaflight/betaflight/blob/660018b1de0c32ee60d8321f301d36fb1fd097f9/src/main/cli/cli.c#L6617-L6633) shows the unchecked description search. The command description must be checked for NULL before calling `strcasestr`.
