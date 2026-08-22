# Rebuilding Gateway (FirmBench)

```sh
./build.sh --verify
```

This pins P2IM `d4c74565`, STM32 Arduino core `1.3.0`, Firmata `2.5.8`, and GNU
Arm 6-2017-q2. `remove-p2im-afl.patch` reflects the checked-in ELF (which has no
AFL call). `arduino-delay-return.patch` is regular-only and makes Arduino
`delay()` return immediately for emulation.
