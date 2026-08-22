# Rebuilding Console (FirmBench)

```sh
./build.sh --verify
```

The source is RIOT `2018.04` on `frdm-k64f`, built at `-O0` with GNU Arm
6-2017-q2. The regular-only behavioral edit keeps the idle thread awake instead
of entering the CPU's lowest power state. The recovered ELF contains no P2IM
AFL call, so that part of P2IM's published patch is intentionally omitted.
