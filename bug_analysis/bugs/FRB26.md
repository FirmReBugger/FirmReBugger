---
bug_id: FRB26
binary: loramac
mcu: STM32WLE5JC
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: Downlink frame-counter lookup dereferences an uninitialized CryptoNvm context, but the observed NULL context requires synthetic RX processing before LoRaMAC crypto initialization.
---

# Bug Description

`GetLastFcntDown` selects one of several downlink frame-counter fields from the global `CryptoNvm` context. It calculates the chosen field address and reads it without validating the context pointer. Downlink validation calls this routine while deciding whether a received frame counter is acceptable.

If receive processing occurs before crypto initialization, `CryptoNvm` is NULL. The selected field offset then becomes a low invalid address, and the counter lookup dereferences it before the frame can be rejected.

# False Positive Reason

A real joined session cannot process downlink counters until LoRaMAC crypto initialization has allocated and populated `CryptoNvm`. Radio reception is enabled only after that prerequisite. The failure requires synthetic receive processing before initialization completes and is not reachable through normal LoRaWAN traffic.
