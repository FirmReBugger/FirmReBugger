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

COPY --chown=user:user docker/DICE/frb/DICE-DMA-Emulation $FUZZER/build/DICE-DMA-Emulation
WORKDIR $FUZZER/build/DICE-DMA-Emulation/p2im/
RUN make -C afl/

WORKDIR $FUZZER/build/DICE-DMA-Emulation/p2im/qemu/src/install/debian64/qemu/bin
RUN patchelf --replace-needed librt.so.1 /lib/x86_64-linux-gnu/librt.so.1 qemu-system-gnuarmeclipse

# Install FirmReBugger
USER user
# Install `uv`
RUN pip3 install --user uv
ENV PATH=$PATH:/home/user/.local/bin

# Copy FirmReBugger source files to the FUZZER directory
COPY --chown=user ./src /firmrebugger/
COPY --chown=user ./pyproject.toml /firmrebugger/
COPY --chown=user ./uv.lock /firmrebugger/
COPY --chown=user ./README.md /firmrebugger/
COPY --chown=user ./.python-version /firmrebugger/

# Install UV and run FirmReBugger installation script
WORKDIR /firmrebugger/target
RUN uv run frb -h

ENV DICE_BASE_DIR=$FUZZER/build/DICE-DMA-Emulation
ENV DICE_QEMU=/home/user/DICE/build/DICE-DMA-Emulation/p2im/qemu/src/install/debian64/qemu/bin/qemu-system-gnuarmeclipse 
ENV FIRMREBUGGER_BASE_DIR=/firmrebugger

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]