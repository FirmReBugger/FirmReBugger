---
bug_id: FRB38
binary: hoverboard
mcu: STM32F103RC
cwes: [CWE-252]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: line_read_memory ignores sscanf's conversion result and dereferences the unchanged address when the command supplies no valid address.
---

# Bug Description

`line_read_memory` initializes its address to NULL, asks `sscanf` to parse an address and optional length from the ASCII command, and then enters the memory-reading loop without checking whether the address conversion succeeded. An empty or malformed address therefore leaves the destination unchanged and makes the loop consume an address that the command never validly supplied.

The unchecked return is present in the [reported firmware revision](https://github.com/bipropellant/bipropellant-hoverboard-firmware/blob/21bd06076e01c6d2b458a8d5870873ecc1bb1399/src/ascii_proto_funcs.c#L618-L642) and was reported as [bipropellant-hoverboard-firmware issue #129](https://github.com/bipropellant/bipropellant-hoverboard-firmware/issues/129). Correct behavior is to require at least one successful conversion before reading memory and to reject malformed commands otherwise.
