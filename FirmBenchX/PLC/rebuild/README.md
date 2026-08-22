# Rebuilding PLCX (FirmBenchX)

```sh
./build.sh --verify
```

PLCX restores Modbus request CRC validation and removes P2IM's AFL call. It
deliberately retains the eight-byte availability gate: the ELF proves this is
present in both variants, and it is required to delimit frames under emulation.
The local soft-float board patch records the recovered P2IM core configuration.
