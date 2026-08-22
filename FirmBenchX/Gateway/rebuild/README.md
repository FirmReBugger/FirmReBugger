# Rebuilding GatewayX (FirmBenchX)

```sh
./build.sh --verify
```

GatewayX uses the same pinned P2IM, STM32 core, Firmata library, and GNU Arm 6
toolchain as regular Gateway. It omits P2IM's AFL call but keeps the core's real
`delay()` implementation; therefore there is no regular delay patch here.
