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
COPY --chown=user docker/MultiFuzz/frb/frb_patches/replay_worker.rs $FUZZER/MultiFuzz/hail-fuzz/src/replay_worker.rs
COPY --chown=user docker/MultiFuzz/frb/frb_patches/frb_multifuzz.patch .
RUN git apply frb_multifuzz.patch
COPY --from=tcc-build /tinycc $FUZZER/tinycc
RUN cargo build --release

# ---- Install FirmReBugger ----
USER user

# Install `uv`
RUN pip3 install --user uv
ENV PATH=$PATH:/home/user/.local/bin

COPY --chown=user pyproject.toml uv.lock .python-version README.md /home/user/firmrebugger/
RUN mkdir -p /home/user/firmrebugger/src/firmrebugger /home/user/firmrebugger/target
WORKDIR /home/user/firmrebugger/target

ENV GHIDRA_SRC=$FUZZER/MultiFuzz/ghidra
ENV MULTIFUZZ_DIR=$FUZZER/MultiFuzz
ENV MULTIFUZZ_BASE_DIR=$FUZZER/MultiFuzz/
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger
ENV FRB_REPLAY_WORKER_COMMAND="$FUZZER/MultiFuzz/target/release/hail-fuzz"

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
