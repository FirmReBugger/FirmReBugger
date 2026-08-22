---
bug_id: FRB70
binary: hoverboard
mcu: STM32F103RC
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: protocol_process_ReadValue can follow a NULL parameter-table entry, but the resulting low-address read is mapped to boot memory on the STM32F103RC.
---

# Bug Description

`protocol_process_ReadValue` derives a parameter-table index from the incoming message code and loads the selected entry without validating it. Some codes select a NULL table slot. The routine then accesses a structure field through that entry, turning the NULL base into a read at a small positive address.

In an address space where the low page is absent, this field access appears as a NULL-adjacent read fault. The software still lacks an explicit table-entry check, but the registered terminal condition depends on how the MCU maps the low address.

# False Positive Reason

The STM32F103RC maps its selected boot memory at address zero. Because this firmware boots from internal Flash, the low-offset access resolves to the Flash alias on the physical MCU instead of raising an unmapped-read exception. The hardware behavior is documented in [RM0008](https://www.st.com/resource/en/reference_manual/cd00171190-stm32f101-103-105-107-stm32f100-series-armbased-32bit-mcus-stmicroelectronics.pdf).
