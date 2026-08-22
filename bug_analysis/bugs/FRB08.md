---
bug_id: FRB08
binary: utasker_USB
mcu: STM32F429ZI
cwes: [CWE-824]
benchmarks: [FirmBench]
status: false_positive
summary: fnDriver builds a per-driver record pointer from the global driver-table base (que_ids) and driver_id with no check that que_ids has been initialized; called during MODBUS port setup before que_ids is populated, the table-base read returns leftover garbage.
---

# Bug Description

`fnDriver` handles generic driver-control operations. For every identifier other than the explicit `0xff` sentinel, it loads the global `que_ids` driver-table base, computes `table_base + (driver_id - 1) * 20`, and dereferences the resulting record. The function checks neither that `que_ids` has been initialized nor that the selected record lies inside the table.

If MODBUS setup invokes `fnDriver` before the table base is populated, the BSS slot can contain zero or stale data. Even a plausible driver identifier then produces a record pointer derived from an invalid base. The first flags-field read can fault, or a mapped result can propagate unrelated data into the later callback dispatch.

# False Positive Reason

The deployed firmware has a fixed startup order that constructs the driver table before registered driver operations can execute. Protocol input cannot schedule MODBUS initialization ahead of that prerequisite. The invalid base requires a startup ordering not produced by the firmware's real scheduler and initialization sequence.
