FROM frb_original:Fuzzware AS fuzzer-base

ENV FUZZER=/home/user/fuzzware
ENV WORKON_HOME=/home/user/.virtualenvs

# ---- Stage 1: Building TinyCC ----
FROM fuzzer-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc && \
    cd /tinycc && \
    git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user ./docker/Fuzzware/frb/frb_patches/frb_tcc.patch /tinycc/frb_tcc.patch
RUN cd /tinycc && git apply /tinycc/frb_tcc.patch
RUN cd /tinycc && ./configure && make


# ---- Stage 2: Extend fuzzer FirmReBugger ----
FROM frb_original:Fuzzware AS fuzzware-firmrebugger

USER user
WORKDIR $FUZZER/repo/emulator
COPY --chown=user ./docker/Fuzzware/frb/frb_patches/firmrebugger.c unicorn/fuzzware-unicorn/qemu/include/qemu/firmrebugger.c
COPY --chown=user ./docker/Fuzzware/frb/frb_patches/firmrebugger.h unicorn/fuzzware-unicorn/qemu/include/qemu/firmrebugger.h
WORKDIR $FUZZER/repo/emulator/unicorn/fuzzware-unicorn
COPY --chown=user ./docker/Fuzzware/frb/frb_patches/frb_fuzzware.patch .
RUN git apply frb_fuzzware.patch

COPY --from=tcc-build /tinycc $FUZZER/tinycc

# Build the emulator
WORKDIR $FUZZER/repo/emulator
RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZER/repo/emulator/afl clean all && \
    make -C $FUZZER/repo/emulator/AFLplusplus clean all && \
    cd $FUZZER/repo/emulator/unicorn && \
    ./build_unicorn.sh

# Build the harness
RUN make -C $FUZZER/repo/emulator/harness/fuzzware_harness/native clean all

# Install the emulator and pipeline
USER root
RUN pip3 install -e $FUZZER/repo/emulator/harness && \
    pip3 install -e $FUZZER/repo/pipeline
RUN pip3 install watchdog

# ---- Install FirmReBugger ----
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

# ---- Final Setup ----
ENV FIRMREBUGGER_BASE_DIR=/firmrebugger

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]