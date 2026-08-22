# Rebuilding ConsoleX (FirmBenchX)

```sh
./build.sh --verify
```

This uses uninstrumented RIOT `2018.04`, `frdm-k64f`, `-O0`, and Ubuntu 20.04's
GNU Arm 9.2.1. Unlike regular Console, X retains `pm_set_lowest()` in the idle
thread and does not add `-fno-optimize-sibling-calls`.
