FROM frb_original:GDMA AS fuzzer-base

ENV FUZZER=/home/user/GDMA
ENV WORKON_HOME=/home/user/.virtualenvs
ENV PIP_NO_CACHE_DIR=1

# ---- Stage 1: Building TinyCC ----
FROM fuzzer-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc
WORKDIR /tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/GDMA/frb/frb_patches/frb_tcc.patch .
RUN git apply /tinycc/frb_tcc.patch
RUN ./configure && \
    make


# ---- Stage 2: Extend fuzzer FirmReBugger ----
FROM frb_original:GDMA AS gdma-firmrebugger
USER root

USER user
# Install FirmReBugger first
WORKDIR $FUZZER/emulator/unicorn/fuzzware-unicorn
COPY --chown=user docker/GDMA/frb/frb_patches/firmrebugger.c qemu/include/qemu/firmrebugger.c
COPY --chown=user docker/GDMA/frb/frb_patches/firmrebugger.h qemu/include/qemu/firmrebugger.h
COPY --chown=user docker/GDMA/frb/frb_patches/frb_GDMA.patch .
RUN patch -p1 < frb_GDMA.patch
COPY --from=tcc-build /tinycc $FUZZER/tinycc
WORKDIR $FUZZER/emulator

RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZER/emulator/afl clean all && \
    AFL_NO_X86=1 make -f GNUmakefile -C $FUZZER/emulator/AFLplusplus clean test_shm test_python ready afl-fuzz afl-showmap afl-tmin afl-gotcpu && \
    cd $FUZZER/emulator/unicorn && \
    ./build_unicorn.sh

RUN make -C $FUZZER/emulator/harness/fuzzware_harness/native clean all

USER root
RUN pip3 install -e $FUZZER/emulator/harness && \
pip3 install -e $FUZZER/pipeline

# ---- Install FirmReBugger ----
USER user
RUN pip3 install --user uv
ENV PATH=$PATH:/home/user/.local/bin

# Copy local FirmReBugger source directly so uncommitted changes are always
# picked up. We skip firmrebugger-web/ and commands/web_app.py since the
# containers only need fuzz, build, bug-analyzer, and charting-tool.
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

# ---- Final Setup ----
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger
ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
