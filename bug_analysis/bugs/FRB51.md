---
bug_id: FRB51
binary: oresat-control
mcu: STM32F439VI
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: The time unix shell branch dereferences argv[1] with strcmp after checking only that the unix mode argument exists.
---

# Bug Description

The ChibiOS shell writes a NULL terminator after the last supplied argument. The incomplete command `time unix` therefore enters `cmd_time` with `argc == 1` and `argv[1] == NULL`.

The handler's initial check proves only that the Unix mode string exists at `argv[0]`. Once that branch matches, it immediately compares `argv[1]` with `"get"` before applying the later count check for the set operation. `strcmp` dereferences the missing argument and faults.

The Unix branch must require `argc >= 2` before reading `argv[1]`. Its additional set operands should be validated independently. The [upstream source](https://github.com/oresat/oresat-firmware/blob/5c158a2da99f6e3d49ad401a1f9c9ecf04ec7554/src/f4/app_control/source/test/test_time.c#L20) shows the unchecked access.
