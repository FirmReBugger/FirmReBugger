---
bug_id: HAL01
binary: contiki-6lowpan
mcu: CC2538SF53
cwes: [CWE-787]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: The 6LoWPAN reassembly path in input() copies a fragment's payload into a fixed-size reassembly buffer using a length computed from the packet, with no check that the write stays inside the buffer.
---

# Bug Description

While reassembling incoming 6LoWPAN fragments, `input()` computes how much
of the current fragment still needs to be copied into the reassembly buffer
and calls `memcpy` with a destination and length derived from the packet's
own header fields, without checking that destination-plus-length actually
stays within the reassembly buffer's real bounds.

A fragment whose declared offset and length push the write past the end of
that buffer overflows into whatever global state happens to sit right after
it. That overflow doesn't crash immediately — the corruption lands quietly
in the middle of an unrelated adjacent data structure, and the firmware only
crashes later, on the next unrelated code path, when it tries to use the
now-corrupted memory.

This is reachable by any device that can send 6LoWPAN fragments to the
node — a fragment whose offset and payload length push the reassembly write
past the buffer's end is enough to trigger it.
