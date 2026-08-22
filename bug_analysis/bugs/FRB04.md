---
bug_id: FRB04
binary: Gateway
mcu: STM32F103RB
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: I2C_MasterReceive_BTF writes through pBuffPtr without a NULL check, but the transfer-starting path always initializes that cursor before the interrupt receive state becomes reachable.
---

# Bug Description

`I2C_MasterReceive_BTF` handles the two-byte receive state in the STM32 HAL. It loads `hi2c->pBuffPtr`, fetches a byte from the I2C data register, stores that byte through the cursor, and then advances the cursor for the next receive operation. Because the store itself has no NULL check, a NULL `pBuffPtr` would become a write through address zero.

The cursor is not an independent input. The transfer-starting routine assigns it to the driver's fixed internal receive buffer before it programs the transfer and enables the interrupt-driven receive states. Once the handler is active, it consumes and advances that initialized cursor; no intervening branch clears it before the byte store.

# False Positive Reason

The suspected state requires the receive interrupt path to execute without the transfer-starting path having initialized `pBuffPtr`. The firmware's I2C state machine does not provide such an entry: the same operation that makes the receive state reachable also installs the cursor. Consequently, the unchecked store is concerning in isolation but its NULL-pointer precondition is unreachable in this binary.
