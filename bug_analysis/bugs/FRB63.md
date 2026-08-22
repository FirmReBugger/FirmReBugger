---
bug_id: FRB63
binary: utasker_MODBUS
mcu: STM32F429ZI
cwes: [CWE-824]
benchmarks: [FirmBench]
status: false_positive
summary: The rehosting-only synthetic Ethernet path can call fnSimulateEthernetIn before the emulated DMA descriptor-list register is initialized, causing it to dereference a non-SRAM descriptor and derive invalid packet-buffer accesses.
---

# Bug Description

The firmware includes a simulation-only input path in `fnApplication` that calls `fnSimulateEthernetIn` with a synthetic frame. The simulator loads the receive-descriptor base from the Ethernet DMA descriptor-list register and immediately reads descriptor fields through it. It does not verify that Ethernet setup has installed a descriptor ring.

If the register is still zero or contains a non-SRAM value, descriptor-field reads occur through an invalid base. Values obtained from those reads are then used to select a destination packet buffer and passed to `uMemcpy`, turning the uninitialized descriptor into an invalid copy destination.

# False Positive Reason

A physical STM32F429ZI receive requires software to install a descriptor list and explicitly start Ethernet receive DMA before hardware can deliver a frame. Hardware cannot present a frame through an uninitialized descriptor base. Only the firmware's synthetic simulation path bypasses that sequencing, as opposed to the real receive process specified by [RM0090](https://www.st.com/resource/en/reference_manual/dm00031020-stm32f405-415-stm32f407-417-and-stm32f429-439-advanced-arm-based-32bit-mcus-stmicroelectronics.pdf).
