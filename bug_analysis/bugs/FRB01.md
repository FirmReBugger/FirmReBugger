---
bug_id: FRB01
binary: Gateway
mcu: STM32F103RB
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: I2C_Slave_STOPF dereferences hi2c->hdmarx without a NULL check, but this firmware never performs DMA-based I2C transfers, so the guarding CR2 LAST bit can only get set by direct MMIO/register fuzzing, not by any real code path.
---

# Bug Description

STM32 HAL's `I2C_Slave_STOPF`, on a slave STOP interrupt, checks whether
`I2Cx->CR2`'s `LAST` bit is set (meant to indicate an in-progress DMA
transfer). If it is, and the handle's internal state doesn't match one of
two specific DMA-busy values, the handler falls through to
`hi2c->hdmarx` — the DMA receive handle — with no check that it's actually
set.

# False Positive Reason

`hdmarx` is only ever populated by a DMA-transfer function (e.g.
`HAL_I2C_Master_Receive_DMA`), and this firmware never calls one — its I2C
driver only ever does interrupt-based transfers, confirmed by the complete
absence of any DMA-transfer-starter symbol in the compiled firmware (only
DMA abort/cleanup helpers are linked in). Since `hdmarx` never gets set, and
the `CR2.LAST` bit this path is gated on is likewise only ever set by those
same DMA functions, this whole path is unreachable through any real I2C bus
traffic — it only fires when something pokes the `CR2` register directly,
which real I2C protocol interaction with this firmware can't do.
