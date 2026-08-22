---
bug_id: FRB02
binary: Gateway
mcu: STM32F103RB
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: I2C_ITError dereferences hi2c->hdmarx without a NULL check when a CR2 DMA-enable-like bit is set, but this firmware never performs DMA-based I2C transfers, so that bit can only get set by direct MMIO/register fuzzing.
---

# Bug Description

STM32 HAL's `I2C_ITError`, on an I2C error interrupt, checks a DMA-related
bit in `I2Cx->CR2`. If set, it clears the bit and then dereferences
`hi2c->hdmarx` with no check that the DMA receive handle is set.

# False Positive Reason

`hdmarx` is only ever populated by a DMA-transfer function, and none are
linked into this firmware — this I2C
driver never performs DMA transfers at all. Since `hdmarx` stays unset for
the program's entire life, and the `CR2` bit this handler gates on can only
become set by directly writing to the MMIO register, no sequence of real
I2C bus traffic reaches this error-interrupt path.
