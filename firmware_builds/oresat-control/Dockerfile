FROM ubuntu@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      binutils-arm-none-eabi=2.34-4ubuntu1+13ubuntu1 \
      ca-certificates=20240203~20.04.1 \
      gcc-arm-none-eabi=15:9-2019-q4-0ubuntu1 \
      git=1:2.25.1-1ubuntu3.14 \
      libnewlib-arm-none-eabi=3.3.0-0ubuntu1 \
      libnewlib-dev=3.3.0-0ubuntu1 \
      make=4.2.1-1.2 \
      patch=2.7.6-6 \
 && rm -rf /var/lib/apt/lists/* \
 && test "$(arm-none-eabi-gcc -dumpfullversion)" = 9.2.1 \
 && test "$(arm-none-eabi-ld --version | sed -n '1s/.* //p')" = 2.34
