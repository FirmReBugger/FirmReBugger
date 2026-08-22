---
bug_id: FRB58
binary: loramac
mcu: STM32WLE5JC
cwes: [CWE-703]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: The tracked McpsIndication path merely logs an ordinary non-OK LoRaMAC indication status and is not a memory-safety defect.
---

# Bug Description

`McpsIndication` receives a LoRaMAC indication and tests its status before processing successful receive data. When the status is not `LORAMAC_EVENT_INFO_STATUS_OK`, it emits an error-level diagnostic describing the rejected event.

Non-OK statuses are expected protocol outcomes. They include invalid message authentication codes, stale frame counters, malformed downlinks, radio reception errors, and other conditions that the stack must report and discard safely. This branch does not dereference an invalid pointer, write outside a buffer, or continue processing rejected payload data.

# False Positive Reason

The tracked event is ordinary error handling rather than a source-level defect. Logging a non-OK indication does not establish memory corruption and does not cause a later failure. Any fault occurring after this diagnostic must be attributed to its own causal operation, not to the fact that LoRaMAC rejected an earlier frame.
