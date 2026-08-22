---
bug_id: FRB62
binary: utasker_MODBUS
mcu: STM32F429ZI
cwes: [CWE-125, CWE-200]
benchmarks: [FirmBench]
status: confirmed
summary: The debug console's memory-display command parses an address from input and performs an unrestricted raw byte, halfword, or word load through it, providing an arbitrary-memory-read primitive.
---

# Bug Description

The debug console's memory-display command passes its address token to `fnHexStrHex` and stores the parsed value as the current display address. Its byte, halfword, and word display modes then dereference that address directly in a repeated output loop.

No readable-region allowlist, privilege check, alignment validation, or upper/lower bound constrains the address. A console user can therefore read arbitrary mapped RAM, Flash, or peripheral state. An unmapped selection causes a fault, while a carefully chosen mapped address discloses memory without any failure.

One command variant passes the same input-derived address to `fnGetParsFile`, which forwards it to `uMemcpy` and exposes the same unrestricted read through a shared copy helper. The fix is to limit the console command to explicitly authorized ranges and lengths before performing either direct loads or helper-based copies.
