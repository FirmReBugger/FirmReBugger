---
bug_id: FRB60
binary: loramac
mcu: STM32WLE5JC
cwes: [CWE-787]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: Zephyr's packaged printf decoder trusts an inline-string index without checking it against the package's argument slots, allowing stale network-controlled log-pool data to drive an out-of-bounds pointer write.
---

# Bug Description

`cbpprintf_external` decodes a deferred printf package whose first header byte
declares the number of argument words. For every appended string it reads a
one-byte argument index and stores the string pointer at
`package + index * sizeof(int)`, but never verifies that the index is smaller
than the declared argument-word count.

Under log-pool reuse, bytes retained from a received-payload hexdump can overlap
a later package and be interpreted as its header and inline-string indexes. An
out-of-range index then makes the pointer-patching store leave the package and
overwrite unrelated RAM, including callbacks or kernel list state. Because the
overlapping hexdump contains received LoRaWAN data, a remote sender can
influence the corrupting value and cause denial of service or control-flow
corruption.
