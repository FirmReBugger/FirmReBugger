# Rebuilding PLC (FirmBench)

```sh
./build.sh --verify
```

This pins P2IM `d4c74565`, STM32 Arduino core `1.3.0`, and GNU Arm 6-2017-q2.
The regular source disables Modbus CRC validation and replaces timeout-based
frame completion with an eight-byte availability gate. P2IM's AFL call is
removed to match the checked-in ELF. The soft-float board patch reconstructs
P2IM's archived F429ZI core configuration.
