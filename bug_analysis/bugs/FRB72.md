---
bug_id: FRB72
binary: oresat-control
mcu: STM32F439VI
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: Synthetic ADC/DMA interrupt delivery before adcStart enters Vector88 with ADCD1.dmastp NULL, causing the handler's first DMA-stream dereference to fault.
---

# Bug Description

The ADC/DMA completion handler loads the DMA stream pointer from `ADCD1.dmastp` and immediately reads stream state through it. It assumes that `adcStart` and conversion setup have already acquired a DMA stream and attached it to the driver.

Before those steps, `ADCD1` remains in `ADC_STOP`; its configuration, sample buffer, conversion group, and `dmastp` fields are NULL. An early completion-handler entry therefore dereferences NULL before any ADC conversion exists.

# False Positive Reason

The STM32F439VI cannot produce an ADC/DMA completion before software configures and enables the DMA stream, its interrupt source, and NVIC delivery. Those same setup steps populate `ADCD1.dmastp`. The pre-start handler entry requires synthetic interrupt dispatch that bypasses all hardware prerequisites described in [RM0090](https://www.st.com/resource/en/reference_manual/dm00031020-stm32f405-415-stm32f407-417-and-stm32f429-439-advanced-arm-based-32bit-mcus-stmicroelectronics.pdf).
