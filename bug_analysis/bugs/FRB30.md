---
bug_id: FRB30
binary: zephyr-sampro
mcu: ATSAM4E16E
cwes: [CWE-665]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: Round-robin rehosting injects the ATSAM4E GMAC interrupt before Ethernet initialization, causing the ISR to give an all-zero transmit semaphore.
---

# Bug Description

The ATSAM4E GMAC queue-zero interrupt handler processes transmit completion and transmit-error conditions. Both paths signal the queue's transmit semaphore. Before Ethernet initialization, that semaphore is still its zeroed BSS representation: its limit is zero and its wait and poll-list links are NULL.

If the interrupt handler gives the semaphore in that state, the Zephyr synchronization code assumes the internal lists are initialized and passes the NULL poll-list head into its event-processing logic. The resulting list access faults before any legitimate transmit operation has occurred.

# False Positive Reason

The GMAC interrupt source is disabled at reset and requires peripheral configuration plus NVIC enablement. The Ethernet driver initializes the queue semaphore before performing those enable steps. Physical hardware therefore cannot deliver queue-zero completion while the semaphore is uninitialized. The ordering requires synthetic interrupt dispatch that ignores the hardware enable state.
