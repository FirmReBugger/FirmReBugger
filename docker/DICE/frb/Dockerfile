FROM ubuntu:22.04 AS fuzzer-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=1

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

# Copy local FirmReBugger source directly so uncommitted changes are always
# picked up. We skip firmrebugger-web/ since the containers only need fuzz,
# build, bug-analyzer, and charting-tool.
RUN mkdir -p /home/user/firmrebugger/src/firmrebugger/bug_analyzer_utils \
             /home/user/firmrebugger/src/firmrebugger/charting_tool_utils \
             /home/user/firmrebugger/src/firmrebugger/commands \
             /home/user/firmrebugger/src/firmrebugger/fuzzer_runners
COPY --chown=user pyproject.toml uv.lock .python-version README.md /home/user/firmrebugger/
COPY --chown=user src/firmrebugger/__init__.py   /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/cli.py        /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/common.py     /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/app_utils.py  /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/fuzzer.py     /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/manager.py    /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/task.py       /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/bug_analyzer_utils/   /home/user/firmrebugger/src/firmrebugger/bug_analyzer_utils/
COPY --chown=user src/firmrebugger/charting_tool_utils/  /home/user/firmrebugger/src/firmrebugger/charting_tool_utils/
COPY --chown=user src/firmrebugger/fuzzer_runners/       /home/user/firmrebugger/src/firmrebugger/fuzzer_runners/
COPY --chown=user src/firmrebugger/commands/                  /home/user/firmrebugger/src/firmrebugger/commands/
WORKDIR /home/user/firmrebugger
RUN uv run frb -h
WORKDIR /home/user/firmrebugger/target

ENV DICE_BASE_DIR=$FUZZER/build/DICE-DMA-Emulation
ENV DICE_QEMU=/home/user/DICE/build/DICE-DMA-Emulation/p2im/qemu/src/install/debian64/qemu/bin/qemu-system-gnuarmeclipse
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
