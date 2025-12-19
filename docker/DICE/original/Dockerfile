FROM ubuntu:22.04 as fuzzer-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN apt-get update
RUN apt-get install -y make wget xz-utils unzip git cmake python3 python3-pip curl automake texinfo coreutils gcc-arm-none-eabi nano patchelf

ENV FUZZER=/home/user/DICE
ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

USER user

COPY --chown=user:user ./docker/DICE/original/DICE-DMA-Emulation $FUZZER/build/DICE-DMA-Emulation
WORKDIR $FUZZER/build/DICE-DMA-Emulation/p2im/
RUN make -C afl/

WORKDIR $FUZZER/build/DICE-DMA-Emulation/p2im/qemu/src/install/debian64/qemu/bin
RUN patchelf --replace-needed librt.so.1 /lib/x86_64-linux-gnu/librt.so.1 qemu-system-gnuarmeclipse

USER user:user
ENV DICE_BASE_DIR=$FUZZER/build/DICE-DMA-Emulation
WORKDIR /benchmark