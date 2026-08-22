---
bug_id: FRB32
binary: riot_gnrc_networking
mcu: CC2538NF53
cwes: [CWE-479, CWE-416]
benchmarks: [FirmBench]
status: confirmed
summary: The RF-core RXUNDERF interrupt handler performs blocking stdio, allowing a contended ETHOS mutex acquisition to enqueue the interrupted IPv6 thread as a waiter while that thread remains executable; a later unlock spuriously resumes it with stale message state and leads to use-after-free packet access.
---

# Bug Description

The RF-core error interrupt handles `RXUNDERF` by entering
`RFCORE_ASSERT_failure`, which calls `printf` from interrupt context. When the
ETHOS output mutex is contended, the mutex path inserts `active_thread`—the
thread interrupted by the ISR—into the waiter list even though that thread has
not actually blocked and will resume normally after the interrupt.

The stale waiter entry lets a later mutex unlock mark the still-executable
thread pending a second time. If the thread is then waiting for a message, this
spurious wakeup can resume its event loop with stale message state and make it
reuse a packet snippet after the send path freed it. Allocator metadata may
then be interpreted as packet fields and dereferenced.

The defect is blocking stdio from the hardware ISR. The first
invariant-breaking effect occurs when the contended mutex path links the
interrupted thread into its waiter queue. Ordinary thread-context waits and
uncontended ISR logging do not create this state.
