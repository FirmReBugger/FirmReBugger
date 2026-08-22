---
bug_id: FRB69
binary: loramac
mcu: STM32WLE5JC
cwes: [CWE-362, CWE-416, CWE-787]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: Zephyr's overwrite-mode logging packet buffer can recycle a message while the consumer still owns it, so concurrently produced data is decoded as log metadata and drives invalid reads, writes, or indirect calls.
---

# Bug Description

Zephyr's `mpsc_pbuf` logging queue does not correctly synchronize overwrite-mode
producers with a preempted consumer. While the consumer holds a pointer returned
by the claim operation, a producer can drop and reuse that same storage; the
consumer can also resume with a pointer into the middle of a newly written
message instead of at a valid package boundary. This violates the queue's
ownership invariant and leaves the consumer decoding concurrently replaced
bytes as log metadata.

The corrupted metadata can select beyond the logging severity table, supply an
invalid format or string pointer, or declare package extents that make the
packaged-printf decoder write outside the message. Those outcomes permit
out-of-bounds memory access and corruption of kernel objects and callback
pointers, causing denial of service or control-flow corruption. The concurrency
defect is documented by Zephyr's upstream
[`mpsc_pbuf` fix](https://github.com/zephyrproject-rtos/zephyr/commit/accaebb7080fefbde82e8daf147f23c74f641738).
