---
bug_id: FRB12
binary: Zepyhr_SocketCan
mcu: STM32L432KC
cwes: [CWE-369]
benchmarks: [FirmBench]
status: confirmed
summary: Tab-completion formatting can compute zero columns from a narrow terminal width and then use that value as a divisor while divide-by-zero trapping is enabled.
---

# Bug Description

`tab_item_print` computes
`columns = (terminal_wid - 2) / longest_option` and immediately evaluates
`printed_cmd % columns` without checking that `columns` is nonzero. A validly
parsed but narrow terminal-width response can make the quotient zero when an
option is wider than the available line.

This firmware sets `SCB->CCR.DIV_0_TRP` during fault initialization, so the
zero divisor raises a Cortex-M4 UsageFault. Clamp the column count to at least
one before the modulo operation.

