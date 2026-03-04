FROM frb_original:MultiFuzz AS fuzzer-base

ENV FUZZER=/home/user/multifuzz
ENV PIP_NO_CACHE_DIR=1

# ---- Stage 1: Building TinyCC ----
FROM fuzzer-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc
WORKDIR /tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/MultiFuzz/frb/frb_patches/frb_tcc.patch .
RUN git apply /tinycc/frb_tcc.patch
RUN ./configure && \
    make

# ---- Stage 2: Extend fuzzer FirmReBugger ----
FROM frb_original:MultiFuzz AS multifuzz-firmrebugger
ENV PATH="${PATH}:/home/user/.cargo/bin"
ENV FUZZER=/home/user/multifuzz
WORKDIR $FUZZER/MultiFuzz
COPY --chown=user docker/MultiFuzz/frb/frb_patches/firmrebugger firmrebugger
COPY --chown=user docker/MultiFuzz/frb/frb_patches/frb_multifuzz.patch .
RUN git apply frb_multifuzz.patch
COPY --from=tcc-build /tinycc $FUZZER/tinycc
RUN cargo build --release

# ---- Install FirmReBugger ----
USER user

# Install `uv`
RUN pip3 install --user uv && \
    git clone --depth 1 https://github.com/FirmReBugger/FirmReBugger.git /home/user/firmrebugger
ENV PATH=$PATH:/home/user/.local/bin

# Install UV and run FirmReBugger installation script
WORKDIR /home/user/firmrebugger/target
RUN uv run frb -h

ENV GHIDRA_SRC=$FUZZER/MultiFuzz/ghidra
ENV MULTIFUZZ_DIR=$FUZZER/MultiFuzz
ENV MULTIFUZZ_BASE_DIR=$FUZZER/MultiFuzz/
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]