---
bug_id: FRB07
binary: utasker_USB
mcu: STM32F429ZI
cwes: [CWE-129, CWE-125]
benchmarks: [FirmBench]
status: false_positive
summary: fnMsgs shares Driver.c's unchecked (driver_id-1)*20 table-walk with fnRead/fnFlush/fnDriver; for an out-of-range driver_id that still lands on mapped RAM (rather than faulting outright), the "function pointer" it reads back is unrelated data, and the unconditional indirect call to it crashes with an illegal instruction.
---

# Bug Description

`fnMsgs` belongs to the same uTasker driver-dispatch family but selects the message callback. It derives `index = (driver_id - 1) * 20`, adds that unchecked index to the fixed driver table, loads a word from the calculated record as a function pointer, and executes an unconditional indirect call through it.

An out-of-range identifier does not always fail at the table read. If the calculated address falls inside mapped RAM, the load succeeds but returns ordinary data from an unrelated object. `fnMsgs` then treats that word as executable code. Depending on its value, control can jump into data memory, an invalid instruction stream, or an unintended valid routine.

# False Positive Reason

Identifiers reaching `fnMsgs` are assigned by driver-registration code from a small fixed set. External protocol bytes do not directly control this internal identifier. Producing a value outside the registered set requires corruption or synthetic modification of task and queue state, so the invalid dispatch is not reachable through normal firmware inputs.
