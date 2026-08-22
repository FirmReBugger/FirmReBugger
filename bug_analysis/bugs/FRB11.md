---
bug_id: FRB11
binary: Zepyhr_SocketCan
mcu: STM32L432KC
cwes: [CWE-369]
benchmarks: [FirmBench]
status: confirmed
summary: Shell cursor calculations divide by an unvalidated terminal width, and this firmware enables the Cortex-M4 divide-by-zero trap.
---

# Bug Description

`shell_multiline_data_calc` uses `cons->terminal_wid` as the divisor for
cursor row and column calculations without checking it for zero. The terminal
resize response parser assigns a reported horizontal position directly to this
field, so a zero-width response can reach the division.

During ARM fault initialization the firmware sets `SCB->CCR.DIV_0_TRP`.
Consequently a zero divisor raises a UsageFault on this STM32L432KC rather than
silently producing zero. Reject a reported width of zero or retain the prior
valid width.

