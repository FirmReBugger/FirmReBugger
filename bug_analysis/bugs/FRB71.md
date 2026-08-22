---
bug_id: FRB71
binary: oresat-control
mcu: STM32F439VI
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: Synthetic CAN1 transmit-interrupt delivery before canStart enters CO_CANtx_cb while CAND1.config is NULL, causing the callback's first configuration access to fault.
---

# Bug Description

The CAN1 transmit-complete callback `CO_CANtx_cb` receives the global CAN driver object and loads its `config` pointer. It immediately accesses configuration fields through that pointer without checking whether the driver has been started.

Before `canStart`, the driver remains in `CAN_STOP` and `CAND1.config` is NULL. Entering the transmit-complete callback in that state therefore turns its first configuration-field store into a NULL-pointer write.

# False Positive Reason

The STM32F439VI bxCAN peripheral cannot report a transmit completion for a stopped, unconfigured driver. Software must configure the controller, enable the relevant peripheral interrupt source, and enable NVIC delivery before the callback can run; those steps occur after `canStart` installs the configuration. The pre-start handler entry requires synthetic interrupt dispatch that bypasses the physical interrupt contract documented in [RM0090](https://www.st.com/resource/en/reference_manual/dm00031020-stm32f405-415-stm32f407-417-and-stm32f429-439-advanced-arm-based-32bit-mcus-stmicroelectronics.pdf).
