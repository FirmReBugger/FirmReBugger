---
bug_id: FRB25
binary: loramac
mcu: STM32WLE5JC
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: false_positive
summary: Join-accept processing can dereference a joinEUI derived from an uninitialized secure-element context, but the observed NULL context requires synthetic RX completion before radio and stack initialization.
---

# Bug Description

`SecureElementGetJoinEui` obtains the global secure-element context `SeNvm`, adds the offset of its `JoinEui` field, and returns the resulting address without first checking whether the context exists. `ProcessRadioRxDone` uses that result while handling a join-accept frame and passes it to `LoRaMacCryptoHandleJoinAccept`, which dereferences the EUI data.

If receive processing starts while `SeNvm` is still NULL, adding the field offset produces a small non-NULL address rather than a valid object pointer. The crypto routine then reads through that low address while validating the join accept.

# False Positive Reason

The normal startup sequence initializes the secure element and LoRaMAC state before enabling reception and accepting join responses. Real radio traffic cannot invoke join-accept processing before `SecureElementInit` establishes `SeNvm`. The NULL context requires a synthetic receive-complete event injected ahead of radio and stack initialization.
