---
bug_id: FRB39
binary: hoverboard
mcu: STM32F103RC
cwes: [CWE-665]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: line_generic_var invokes parameter read callbacks without copying the selected parameter code into the zeroed protocol message.
---

# Bug Description

The read branches of `line_generic_var` clear a local protocol message and pass it to the selected parameter callback, but they do not assign the selected parameter's code. A callback such as `protocol_process_ReadValue` consequently indexes the parameter table with the message's zero default rather than with the parameter the command selected, and can consume a missing or unrelated table entry.

The omission is present in both generic-read paths in the [reported firmware revision](https://github.com/bipropellant/bipropellant-hoverboard-firmware/blob/21bd06076e01c6d2b458a8d5870873ecc1bb1399/src/ascii_proto_funcs.c#L357-L424) and was reported as [bipropellant-hoverboard-firmware issue #128](https://github.com/bipropellant/bipropellant-hoverboard-firmware/issues/128). The message must receive the selected parameter code before the callback is invoked.
