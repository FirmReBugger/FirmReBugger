---
bug_id: FRB46
binary: hoverboard
mcu: STM32F103RC
cwes: [CWE-125]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: The debug-memory command can read low addresses that rehosting treats as unmapped, but the STM32F103RC aliases its 256 KiB boot Flash across that range.
---

# Bug Description

`line_read_memory` is a diagnostic command that accepts an address and length, converts the address text to an integer, and reads bytes directly from that location. It does not restrict the read to application objects or an approved memory range. A failed conversion can leave the address at zero, while a small explicit value selects another low address.

A simplified memory map can treat those addresses as unmapped and turn the first byte access into a fault. This entry concerns that low-address terminal behavior; the command's broader unrestricted-read capability remains a separate security consideration.

# False Positive Reason

The target is an STM32F103RC booting from its 256 KiB internal Flash. This MCU aliases the selected boot memory at the bottom of the address space, so the low addresses associated with the reported condition resolve to Flash rather than unmapped memory. They therefore do not produce the modeled read fault on the physical device. The alias is documented in [RM0008](https://www.st.com/resource/en/reference_manual/cd00171190-stm32f101-103-105-107-stm32f100-series-armbased-32bit-mcus-stmicroelectronics.pdf).
