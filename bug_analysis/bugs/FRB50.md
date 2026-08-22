---
bug_id: FRB50
binary: oresat-control
mcu: STM32F439VI
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: The time scet shell branch dereferences argv[1] with strcmp after checking only that the scet mode argument exists.
---

# Bug Description

The ChibiOS shell supplies `cmd_time` with a NULL-terminated argument array. The incomplete command `time scet` reaches the handler with one argument: the mode string at `argv[0]` and NULL at `argv[1]`.

Although `cmd_time` verifies that `argv[0]` exists, the SCET branch calls `strcmp(argv[1], "get")` before verifying that a subcommand was supplied. The library comparison consumes the NULL pointer before the later argument-count checks can reject the command.

The SCET branch must require at least two arguments before reading `argv[1]`, then validate the extra operands needed by `set`. The unchecked expression appears in the [upstream source](https://github.com/oresat/oresat-firmware/blob/5c158a2da99f6e3d49ad401a1f9c9ecf04ec7554/src/f4/app_control/source/test/test_time.c#L32).
