---
bug_id: FRB18
binary: zephyr-sampro
mcu: ATSAM4E16E
cwes: [CWE-665]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: Instruction-count-based rehosting advances the Ethernet monitor timeout before network initialization completes, allowing DAD work to be scheduled before its handler is installed.
---

# Bug Description

During device initialization, the Ethernet driver schedules a delayed PHY-monitor work item. When the monitor runs, it can bring the interface up and submit the IPv6 duplicate-address-detection work object. That second work object is initialized at a later network initialization level.

If the PHY delay expires before the later initialization level has installed the DAD handler, the monitor submits an object whose handler and timeout links still contain zeroed BSS state. The work queue can then call a NULL handler. A competing initialization path can also clear the timeout node while it is linked, leaving timeout removal to follow NULL list pointers. Both outcomes originate from the same premature PHY-monitor execution.

# False Positive Reason

The requested PHY delay is one second, and the ATSAM4E16E SysTick advances according to real processor clock cycles. The later network initialization finishes before that physical delay can expire. The premature ordering requires an instruction-count-driven synthetic timer that advances disproportionately during boot, so it is not reachable with the target's real timing.
