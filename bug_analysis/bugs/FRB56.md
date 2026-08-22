---
bug_id: FRB56
binary: betaflight
mcu: AT32F435G
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: cliAux calls nextArg a second time after its first argument search has already returned NULL.
---

# Bug Description

`cliAux` advances through a sequence of optional-looking arguments with repeated calls to `nextArg`. It conditionally parses the first returned pointer, but after that block it calls `nextArg` again unconditionally. When the initial search found no next argument, the second call receives NULL and forwards it to `strchr`, which expects a valid string.

The malformed argument sequence is supplied through the normal CLI and is independent of peripheral emulation. Betaflight tracks the undefined NULL access as [issue #13701](https://github.com/betaflight/betaflight/issues/13701); the [reported source revision](https://github.com/betaflight/betaflight/blob/660018b1de0c32ee60d8321f301d36fb1fd097f9/src/main/cli/cli.c#L1193-L1225) shows the unconditional second call. The function must stop or report an argument-count error when the first search returns NULL.
