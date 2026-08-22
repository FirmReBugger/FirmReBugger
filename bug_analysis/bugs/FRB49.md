---
bug_id: FRB49
binary: oresat-control
mcu: STM32F439VI
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: The time utc shell branch dereferences argv[1] with strcmp after checking only that the utc mode argument exists.
---

# Bug Description

The ChibiOS shell invokes `cmd_time` with a count of tokens following the command name and places NULL at `argv[argc]`. The input `time utc` therefore yields `argc == 1`, `argv[0] == "utc"`, and `argv[1] == NULL`.

`cmd_time` checks only that the mode argument exists. After matching the UTC branch, it immediately evaluates `strcmp(argv[1], "get")` before the later count checks used by the set operation. The first string access therefore dereferences NULL for a syntactically valid but incomplete command.

The UTC branch must require `argc >= 2` before reading `argv[1]`, and require any additional value arguments separately. The [upstream source](https://github.com/oresat/oresat-firmware/blob/5c158a2da99f6e3d49ad401a1f9c9ecf04ec7554/src/f4/app_control/source/test/test_time.c#L43) contains the unchecked comparison.
