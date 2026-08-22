# Rebuilding MODBUS

```sh
./build.sh --verify
```

The checked-in ELF is the DICE repository's published STM32F303RE MODBUS ELF.
Its machine code predates three source-only changes: four buffer canaries are
absent, the CRC routine returns zero on mismatch, and the caller invokes the
CRC calculation without branching on its return. The local patch restores
those three independently verified details.

The output has entry point `0x08002a91`, size
`text=11544 data=1096 bss=18084`, and matches every loadable byte of
`../Modbus.elf`. That reference's whole-file SHA-256 is
`46dec0d991380f947644f2875f96ea965ae250bbafea511781afb72d4cb678b1`.
