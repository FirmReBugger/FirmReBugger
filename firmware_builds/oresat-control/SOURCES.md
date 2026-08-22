# Recovered OreSat build provenance

## Pinned inputs

- OreSat firmware: `e41286df4fb19904a0cc67c556e9ab588c7180df`
- CANopenNode: `8c7d852902b2d307e8b91a43332c14e366641e00`
- ChibiOS: `d96c2af163e53c456bdd885c52056d20545b6dde`
- OpenCCSDS override: `87cae72ec21cc553bdd19666fdf55cace6b95c4b`
- littlefs: `1863dc7883d82bd6ca79faa164b65341064d1c16`
- Ubuntu base image:
  `ubuntu@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214`
- GCC `9.2.1` (`gcc-arm-none-eabi` package
  `15:9-2019-q4-0ubuntu1`) and GNU binutils `2.34`

The superproject normally pins OpenCCSDS `1d57be1e...`; the checked-in ELFs
instead have the function sizes produced by `87cae72e...`. In particular,
`uslp_recv`, `uslp_fecf_gen`, and `uslp_map_send` match only after that override.

Upstream repositories:

- https://github.com/oresat/oresat-firmware
- https://github.com/oresat/OpenCCSDS
- https://github.com/ChibiOS/ChibiOS

## Evidence recovered from the ELFs

Both files contain GCC 9.2.1/binutils 2.34 metadata and the original compilation
directory `/home/user/working-firmrebugger/firmrebugger/binaries/new/oresat-control/oresat-firmware/src/f4/app_control`.
Their embedded build timestamps correspond to the `SOURCE_DATE_EPOCH` values in
the two recipe configurations.

Both variants require the STM32F42x/F43x ChibiOS flash patch already shipped in
the OreSat tree. Both also use non-shared FRAM, MAX7310, and AX5043 buses and omit
the AX5043 receive-buffer copy. The regular variant additionally has an empty
virtual-timer-list guard and MMIO stand-ins for the AX5043 exchange/status DMA
paths. The X variant removes those two vulnerability-easing changes.

The old top-level benchmark note also said `Early return to Delay`. That patch is
not present: `delay_deploy` is a complete 0x4c-byte function in both checked-in
ELFs, with the same instruction body. No delay patch is therefore applied.

## Verification boundary

A clean build has the exact reference text/data/BSS totals and exact sizes for
all recovered functions. It is not loadable-byte-identical because the old ELF
places the otherwise identical 0x64-byte `cmd_deploy` function at `0x08010a30`,
while a clean GCC LTO build places it later. Moving that one function accounts
for the 0x70 address delta before `chVTDoTickI`; addresses converge again at
`ax5043SPIExchange`. This is consistent with historical incremental/LTO state,
not a remaining emulation patch. The recipe reports this honestly and reserves
`--strict`/`--install` for a future exact reconstruction.
