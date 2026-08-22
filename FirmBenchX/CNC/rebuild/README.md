# Rebuilding CNCX (FirmBenchX)

```sh
./build.sh --verify
```

`x-restore-runtime.patch` removes P2IM benchmark control and restores the serial
drain, real delays, and PLL-ready error path. This uses GCC 10.3.1, matching the
checked-in X ELF's producer metadata.
