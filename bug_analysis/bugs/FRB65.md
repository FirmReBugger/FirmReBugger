---
bug_id: FRB65
binary: oresat-control
mcu: STM32F439VI
cwes: [CWE-1282]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: MultiFuzz mutates the immutable STM32 flash-size field to an impossible value, making efl_lld_init reject every supported geometry and deliberately halt.
---

# Bug Description

During early HAL initialization, `efl_lld_init` reads the STM32 factory flash-size halfword. It compares the reported capacity with the flash geometries compiled into its descriptor table, including the supported 1 MiB and 2 MiB layouts. If every comparison fails, the initializer cannot select an erase/program geometry and deliberately calls the system halt routine.

This is defensive behavior for an unsupported device, not an accidental NULL dereference. The problematic outcome begins only when the electronic-signature field claims a capacity that is incompatible with every descriptor compiled for the board.

# False Positive Reason

The target is an STM32F439VI whose order code fixes the internal Flash capacity at 2 MiB. Its flash-size electronic-signature field is factory programmed and cannot vary at runtime or be influenced by application input. The unsupported values required to exhaust the descriptor table are therefore impossible on this physical MCU. The geometry is specified by the [STM32F439VI datasheet](https://www.st.com/resource/en/datasheet/stm32f439vi.pdf), and [RM0090](https://www.st.com/resource/en/reference_manual/dm00031020-stm32f405-415-stm32f407-417-and-stm32f429-439-advanced-arm-based-32bit-mcus-stmicroelectronics.pdf) defines the field.
