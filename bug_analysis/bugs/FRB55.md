---
bug_id: FRB55
binary: betaflight
mcu: AT32F435G
cwes: [CWE-476]
benchmarks: [FirmBench, FirmBenchX]
status: confirmed
summary: gpsEnablePassthrough uses the uninitialized gpsPort when GPS is disabled, dereferencing NULL through the serial-port interface.
---

# Bug Description

`gpsPort` remains NULL until GPS initialization successfully opens the configured serial port. The CLI `gpspassthrough` command calls `gpsEnablePassthrough` without checking that initialization occurred. The passthrough routine first waits for the GPS transmit buffer by dispatching through the serial-port interface, which dereferences the NULL port; later mode access and passthrough operations repeat the same invalid assumption.

Disabling GPS while retaining the compiled GPS CLI is a supported software configuration, so the trigger does not require synthetic hardware state. Betaflight records the defect and the required NULL guard in [issue #13700](https://github.com/betaflight/betaflight/issues/13700); the [reported source revision](https://github.com/betaflight/betaflight/blob/660018b1de0c32ee60d8321f301d36fb1fd097f9/src/main/io/gps.c#L2489-L2505) shows the unchecked use. Passthrough must abort unless `gpsPort` is open.
