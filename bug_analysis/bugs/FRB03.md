---
bug_id: FRB03
binary: Gateway
mcu: STM32F103RB
cwes: [CWE-787, CWE-680]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: I2C_ITError advances and writes through hi2c->pBuffPtr on repeated error-status interrupts without bounding it against the transfer's declared size, letting the pointer walk out of Wire's receive buffer and corrupt adjacent globals.
---

# Bug Description

`HAL_I2C_Slave_Sequential_Receive_IT` arms a slave receive by pointing
`hi2c->pBuffPtr` at the caller-supplied buffer and recording the transfer's
byte count. In this firmware that buffer lives inside the `Wire` (`TwoWire`)
object's own storage — a fixed, small window.

STM32 HAL's `I2C_ITError`, on qualifying I2C error-status interrupts (a bus
error / ack failure / arbitration-loss class condition, gated on the I2C
peripheral's status register and the handle's internal error-code byte),
appends a status byte through `hi2c->pBuffPtr` and advances the pointer by
one — but never checks the advance against the transfer's declared
size/count. If the bus keeps producing qualifying error interrupts after the
declared receive window has already closed, each one walks `pBuffPtr`
one byte further past the end of its buffer, with no bound to stop it.

Given enough such interrupts, `pBuffPtr` eventually leaves `Wire`'s own
storage entirely and starts writing into whatever global happens to sit
next in memory. In this firmware's layout that neighbor is the unrelated
`Firmata` object (`Arduino Firmata` protocol handler): the stray byte store
lands on the low byte of `Firmata._firmataStream`, corrupting a valid
`Stream*` pointer (`&Serial2`) into a wild pointer that happens to fall
inside a third, also-unrelated global array (`timer_handles[]`). The next
time the main loop calls `Firmata.available()`, it dereferences the
corrupted pointer as if it were a `Stream` object, reads a "vtable pointer"
that is zero at that location, and crashes on the resulting NULL+8 read.

The defect is entirely in `I2C_ITError`'s missing bounds check; everything
downstream (the specific byte corrupted, the specific object it belongs to,
the specific crash site three layers of indirection away in an unrelated
Arduino library) is incidental to where the firmware's globals happen to be
laid out in `.bss`.
