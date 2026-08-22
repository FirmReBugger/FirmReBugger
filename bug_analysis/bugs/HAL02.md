---
bug_id: HAL02
binary: contiki-6lowpan
mcu: CC2538SF53
cwes: [CWE-787]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: store_fragment copies an incoming 6LoWPAN fragment's payload into a fixed-size per-fragment slot using a length derived straight from the packet, with no check that it fits (CVE-2019-9183).
---

# Bug Description

When a new 6LoWPAN fragment arrives, `store_fragment` claims a free slot in
a small fixed-size table of in-progress reassemblies and copies the
fragment's payload into that slot's data area. The copy length is computed
directly from the incoming packet's buffered length, with nothing capping
it to the amount of space actually left in the slot.

An oversized fragment payload therefore overflows the slot's data area and
writes into whatever follows it — the neighboring reassembly-table entries,
in this fixed-size global table. This is the well-known 6LoWPAN fragment
reassembly buffer overflow tracked as CVE-2019-9183.

This is reachable by any device that can send 6LoWPAN fragments to the
node — an oversized first fragment is enough to trigger the overflow, no
malformed or unusual framing required beyond the payload length itself.
