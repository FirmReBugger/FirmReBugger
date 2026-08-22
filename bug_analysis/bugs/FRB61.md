---
bug_id: FRB61
binary: utasker_MODBUS
mcu: STM32F429ZI
cwes: [CWE-129, CWE-125]
benchmarks: [FirmBench]
status: confirmed
summary: fnMODBUS maps an input-derived request field to an index into the two-byte SerialHandle array without a bounds check, so an out-of-range byte is consumed as a driver ID and can redirect control through an invalid callback.
---

# Bug Description

`fnMODBUS` reads a five-byte request from its serial queue and uses the byte at request offset four in the expression `10 - field`. It consumes the result as an index into `SerialHandle`, even though that ELF object contains only two one-byte handles.

No check restricts the calculated index to zero or one. Values such as zero in the request field produce an index of ten, causing the array load to read a byte from a neighboring global object. The loaded byte is then treated as a one-based driver identifier and passed to the generic dispatch layer.

The dispatch code subtracts one again, selects a record from the driver table, loads a callback, and calls it. Thus one unchecked request-derived array index can redirect control through unrelated memory. `fnMODBUS` must validate the mapping before reading `SerialHandle`, and the driver layer should independently reject identifiers outside its registered range.
