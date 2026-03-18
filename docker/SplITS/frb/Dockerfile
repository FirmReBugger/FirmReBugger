FROM frb_original:SplITS AS fuzzer-base

ENV FUZZER=/home/user/splits
ENV WORKON_HOME=/home/user/.virtualenvs
ENV PIP_NO_CACHE_DIR=1

# ---- Stage 1: Building TinyCC ----
FROM fuzzer-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc
WORKDIR /tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/SplITS/frb/frb_patches/frb_tcc.patch .
RUN git apply /tinycc/frb_tcc.patch
RUN ./configure && \
    make


# ---- Stage 2: Extend fuzzer FirmReBugger ----
FROM frb_original:SplITS AS splits-firmrebugger
USER user
# Install FirmReBugger first
WORKDIR $FUZZER/repo/fuzzware/emulator
COPY --chown=user docker/SplITS/frb/frb_patches/firmrebugger.c unicorn/fuzzware-unicorn/qemu/include/qemu/firmrebugger.c
COPY --chown=user docker/SplITS/frb/frb_patches/firmrebugger.h unicorn/fuzzware-unicorn/qemu/include/qemu/firmrebugger.h
WORKDIR $FUZZER/repo/fuzzware/emulator/unicorn/fuzzware-unicorn
COPY --chown=user docker/SplITS/frb/frb_patches/frb_fuzzware.patch .
RUN git apply frb_fuzzware.patch
COPY --from=tcc-build /tinycc $FUZZER/tinycc
WORKDIR $FUZZER/repo/fuzzware/emulator
RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZER/repo/fuzzware/emulator/afl clean all && \
    make -C $FUZZER/repo/fuzzware/emulator/AFLplusplus clean all && \
    cd $FUZZER/repo/fuzzware/emulator/unicorn && \
    ./build_unicorn.sh

# Build harness
RUN make -C $FUZZER/repo/fuzzware/emulator/harness/fuzzware_harness/native clean all

# Install the emulator and pipeline
USER root
RUN pip3 install -e $FUZZER/repo/fuzzware/emulator/harness && \
    pip3 install -e $FUZZER/repo/fuzzware/pipeline

# Install FirmReBugger
USER user
RUN pip3 install --user uv
ENV PATH=$PATH:/home/user/.local/bin

COPY --chown=user pyproject.toml uv.lock .python-version README.md /home/user/firmrebugger/
RUN mkdir -p /home/user/firmrebugger/src/firmrebugger /home/user/firmrebugger/target
WORKDIR /home/user/firmrebugger/target

# ---- Final Setup ----
USER root
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger
ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
