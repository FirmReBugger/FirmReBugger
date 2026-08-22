ARG BASE_IMAGE=ubuntu:20.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       binutils-arm-none-eabi bzip2 ca-certificates curl file \
       gcc-arm-none-eabi git libnewlib-arm-none-eabi make patch python3 unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

ARG GCC6_URL=https://github.com/stm32duino/arm-none-eabi-gcc/releases/download/6-2017-q2-update/gcc-arm-none-eabi-6-2017-q2-update-linux64.tar.bz2
ARG GCC6_SHA256=81c5b83fd134a34a2f1dd1bd93ece223d4a511134932d41e5dd54a00943c0402
RUN curl -L --fail --retry 4 "$GCC6_URL" -o /tmp/gcc6.tar.bz2 \
    && echo "$GCC6_SHA256  /tmp/gcc6.tar.bz2" | sha256sum -c - \
    && tar -xjf /tmp/gcc6.tar.bz2 -C /opt \
    && rm /tmp/gcc6.tar.bz2

ENV GCC6_ROOT=/opt/gcc-arm-none-eabi-6-2017-q2-update
