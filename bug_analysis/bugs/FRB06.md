---
bug_id: FRB06
binary: utasker_USB
mcu: STM32F429ZI
cwes: [CWE-129, CWE-125]
benchmarks: [FirmBench]
status: false_positive
summary: fnRead computes its driver-dispatch-table pointer as table_base+(driver_id-1)*20 with no bounds check; called with driver_id=255 (uTasker's "no driver bound" sentinel) via an unbound MODBUS port, the index walks far past the table into unmapped memory.
---

# Bug Description

`fnRead` is uTasker's generic driver-read dispatcher. It converts its one-based `driver_id` into a record offset with `(driver_id - 1) * 20`, adds that offset to the global driver-table base, and immediately reads the record's flags byte. If that succeeds, it loads the record's read callback and calls it indirectly. Neither access validates the identifier against the table's actual entry count.

The value `0xff` is used elsewhere as the “no driver bound” sentinel. If an unbound MODBUS port passes that sentinel to `fnRead`, the subtraction and multiplication select a record thousands of bytes beyond the table. The first field read can fault when the address is unmapped; if it lands in mapped memory, unrelated data can instead be consumed as a callback.

# False Positive Reason

Normal port initialization replaces the sentinel with a registered, in-range driver identifier before the MODBUS read path becomes active. A remote MODBUS request controls request data but does not assign the internal driver identifier. The failure therefore requires an inconsistent internal port state that normal initialization and protocol control flow do not expose.
