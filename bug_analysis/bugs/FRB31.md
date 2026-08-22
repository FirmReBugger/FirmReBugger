---
bug_id: FRB31
binary: riot_gnrc_networking
mcu: CC2538NF53
cwes: [CWE-1246]
benchmarks: [FirmBench]
status: false_positive
summary: Synthetic CC2538 RF event flags violate the driver's radio-state contract, enter an ISR assertion, and exhaust the ISR stack during panic diagnostics.
---

# Bug Description

The CC2538 RF interrupt handler interprets `TXDONE` as completion of an active transmission and asserts that the software radio state is `CC2538_STATE_TX_BUSY`. If the event appears while the state is merely ready, the driver treats the combination as impossible and enters its assertion path.

The assertion invokes panic diagnostics inside the RF interrupt context. Those diagnostics enumerate tasks and format output through the debug transport. Their nested calls exceed the small interrupt stack, so a later function prologue pushes below the stack boundary. The observable memory fault is therefore a consequence of panic processing after the impossible radio-state combination.

# False Positive Reason

The CC2538 hardware generates `TXDONE` only after transmitting a complete frame, and the driver sets its state to transmit-busy when that operation begins. An idle-ready state paired with `TXDONE` requires the event bits to be synthesized independently of the radio operation. The event contract is documented in the [CC2538 user guide](https://www.ti.com/lit/ug/swru319c/swru319c.pdf).
