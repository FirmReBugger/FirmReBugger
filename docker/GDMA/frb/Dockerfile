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
RUN pip3 install --user uv && \
    git clone --depth 1 https://github.com/FirmReBugger/FirmReBugger.git /home/user/firmrebugger
ENV PATH=$PATH:/home/user/.local/bin

WORKDIR /home/user/firmrebugger/target
RUN uv run frb -h

# ---- Final Setup ----
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger
ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]