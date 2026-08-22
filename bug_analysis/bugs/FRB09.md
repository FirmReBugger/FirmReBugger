---
bug_id: FRB09
binary: RF_Door_lock
mcu: MAX32600
cwes: [CWE-120]
benchmarks: [FirmBench]
status: confirmed
summary: read_code copies a NUL-terminated serial code into a fixed-size stack buffer without enforcing its 16-byte capacity, allowing input to overwrite saved control data.
---

# Bug Description

`read_code` receives an access code one byte at a time from the serial
interface. It advances a pointer after every byte and stops only when it sees a
NUL terminator; it never checks that the pointer remains inside the 16-byte
local buffer.

A sufficiently long code therefore continues through the function's stack
frame and overwrites saved registers, including the saved return address. When
`read_code` returns, the function epilogue loads the attacker-controlled value
into the program counter and transfers execution away from the legitimate
caller. The trigger consists only of ordinary serial bytes and does not depend
on a synthetic interrupt or an impossible peripheral state.

