FROM frb_original:MultiFuzz AS fuzzer-base

ENV FUZZER=/home/user/multifuzz

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

ENV GHIDRA_SRC=$FUZZER/MultiFuzz/ghidra
ENV MULTIFUZZ_DIR=$FUZZER/MultiFuzz
ENV MULTIFUZZ_BASE_DIR=$FUZZER/MultiFuzz/
ENV FIRMREBUGGER_BASE_DIR=/firmrebugger

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]