FROM frb_original:Hoedur AS fuzzer-base
ENV PIP_NO_CACHE_DIR=1

# ---- Stage 1: Building TinyCC ----
FROM fuzzer-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc && \
    cd /tinycc && \
    git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user ./docker/Hoedur/frb/frb_patches/frb_tcc.patch /tinycc/frb_tcc.patch
RUN cd /tinycc && git apply /tinycc/frb_tcc.patch
RUN cd /tinycc && ./configure && make


# ---- Stage 2: Extend fuzzer FirmReBugger ----
FROM frb_original:Hoedur AS hoedur-firmrebugger
ENV FUZZER=/home/user/hoedur
ENV PATH="${PATH}:/home/user/.cargo/bin"
ENV LD_LIBRARY_PATH="/home/user/.cargo/bin/"
WORKDIR $FUZZER
COPY --from=tcc-build /tinycc $FUZZER/tinycc
COPY --chown=user docker/Hoedur/frb/frb_patches/ $FUZZER/frb_patches/
RUN git apply $FUZZER/frb_patches/firmrebugger_hoedur_rust.patch
RUN cargo install --path $FUZZER/hoedur \
    --bin hoedur-arm && \
    cp $FUZZER/target/release/libqemu-system-arm.release.so $HOME/.cargo/bin/ && \
    cp $FUZZER/target/release/hoedur-arm $HOME/.cargo/bin/hoedur-dict-arm && \
    cargo clean

# ---- Install FirmReBugger ----
USER user
RUN pip3 install --user uv && \
    git clone --depth 1 https://github.com/FirmReBugger/FirmReBugger.git /home/user/firmrebugger
ENV PATH=$PATH:/home/user/.local/bin
WORKDIR /home/user/firmrebugger/target
RUN uv run frb -h

# ---- Final Setup ----
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger
ENV HOEDUR_BASE_DIR=$FUZZER/hoedur
ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]