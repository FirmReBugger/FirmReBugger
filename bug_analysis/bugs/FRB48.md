---
bug_id: FRB48
binary: oresat-control
mcu: STM32F439VI
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: The lfs shell command dereferences argv[0] with strcmp before checking that any subcommand argument exists.
---

# Bug Description

The ChibiOS shell parses the command name separately from its remaining arguments. It passes each handler an `argc` count for those remaining tokens and stores a NULL terminator at `argv[argc]`.

`cmd_lfs` immediately evaluates `strcmp(argv[0], "ls")` without first checking that `argc` is at least one. Entering the valid command name `lfs` with no subcommand gives the handler `argc == 0`, so `argv[0]` is the shell-installed NULL terminator. `strcmp` dereferences it as its first string.

The handler must reject `argc < 1` or display usage before examining `argv[0]`. The unchecked expression is visible in the [upstream command implementation](https://github.com/oresat/oresat-firmware/blob/5c158a2da99f6e3d49ad401a1f9c9ecf04ec7554/src/f4/app_control/source/test/test_lfs.c#L19).
