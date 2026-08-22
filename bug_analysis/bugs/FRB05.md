---
bug_id: FRB05
binary: Soldering_Iron
mcu: STM32F103RB
cwes: [CWE-191]
benchmarks: [FirmBench]
status: false_positive
summary: Fuzzed I2C status sequencing can keep HAL_I2C_Mem_Read active until XferCount underflows, but this depends on peripheral flag combinations that real STM32F103RB receive sequencing does not produce.
---

# Bug Description

`HAL_I2C_Mem_Read` installs the requested byte count in the two-byte `XferCount` field and then enters a blocking receive loop. Several flag-dependent branches read a byte from the peripheral, store it through `pBuffPtr`, advance that pointer, and decrement `XferCount`.

If peripheral status continues to select one of those receive-byte branches after `XferCount` has reached zero, the decrement wraps the unsigned field to `0xffff`. The loop then treats the completed transfer as though tens of thousands of bytes remain and continues writing beyond the caller's buffer. Those stores can overwrite later stack variables, saved registers, or return state.

# False Positive Reason

The STM32F103RB I2C peripheral controls the status flags that select these receive branches. Its documented receive sequencing does not produce additional byte-ready states after the programmed transfer count has been consumed. Reaching the underflow requires mutually inconsistent or repeated status combinations synthesized independently of the peripheral state machine. The applicable sequencing is documented in the [STM32F103x8/xB datasheet](https://www.st.com/resource/en/datasheet/stm32f103rb.pdf) and [RM0008](https://www.st.com/resource/en/reference_manual/rm0008-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-armbased-32bit-mcus-stmicroelectronics.pdf).
