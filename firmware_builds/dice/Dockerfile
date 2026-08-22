FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bzip2 ca-certificates curl git make patch python3 \
    && rm -rf /var/lib/apt/lists/*

ARG GCC_URL=https://developer.arm.com/-/media/Files/downloads/gnu-rm/7-2018q2/gcc-arm-none-eabi-7-2018-q2-update-linux.tar.bz2
ARG GCC_SHA256=bb17109f0ee697254a5d4ae6e5e01440e3ea8f0277f2e8169bf95d07c7d5fe69
RUN curl -L --fail --retry 4 "$GCC_URL" -o /tmp/gcc.tar.bz2 \
    && echo "$GCC_SHA256  /tmp/gcc.tar.bz2" | sha256sum -c - \
    && tar -xjf /tmp/gcc.tar.bz2 -C /opt \
    && rm /tmp/gcc.tar.bz2

ENV GCC_ROOT=/opt/gcc-arm-none-eabi-7-2018-q2-update
ENV PATH=$GCC_ROOT/bin:$PATH
