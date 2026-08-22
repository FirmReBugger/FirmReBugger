FROM frb_original:Fuzzware-Icicle AS fuzzer-base

ENV FUZZER=/home/user/fuzzware-icicle
ENV WORKON_HOME=/home/user/.virtualenvs
ENV PIP_NO_CACHE_DIR=1

# ---- Stage 1: Building TinyCC ----
FROM fuzzer-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc && \
    cd /tinycc && \
    git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user ./docker/Fuzzware-Icicle/frb/frb_patches/frb_tcc.patch /tinycc/frb_tcc.patch
RUN cd /tinycc && git apply /tinycc/frb_tcc.patch
RUN cd /tinycc && ./configure && make


# ---- Stage 2: Extend fuzzer FirmReBugger ----
FROM frb_original:Fuzzware-Icicle AS fuzzware-icicle-firmrebugger
WORKDIR $FUZZER/repo/emulator
USER user
# Install FirmReBugger first
COPY --chown=user docker/Fuzzware-Icicle/frb/frb_patches/firmrebugger firmrebugger/
COPY --chown=user docker/Fuzzware-Icicle/frb/frb_patches/frb_icicle.patch .
RUN git apply frb_icicle.patch
COPY --from=tcc-build /tinycc $FUZZER/tinycc

# Build the emulator
WORKDIR $FUZZER/repo/emulator
RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZER/repo/emulator/afl clean all && \
    make -C $FUZZER/repo/emulator/AFLplusplus clean all

WORKDIR $FUZZER/repo/emulator/icicle
RUN maturin build --release && \
    pip3 install --force-reinstall target/wheels/icicle-0.1.0*.whl
WORKDIR $FUZZER/repo/emulator

RUN make -C $FUZZER/repo/emulator/harness/fuzzware_harness/native clean all
USER root
RUN pip3 install -e $FUZZER/repo/emulator/harness && \
    pip3 install -e $FUZZER/repo/pipeline
RUN pip3 install watchdog
COPY --chown=user docker/Fuzzware-Icicle/frb/frb_patches/persistent_worker.py $FUZZER/repo/emulator/harness/fuzzware_harness/persistent_worker.py


# Install FirmReBugger
USER user

RUN pip3 install --user uv
ENV PATH=$PATH:/home/user/.local/bin

COPY --chown=user pyproject.toml uv.lock .python-version README.md /home/user/firmrebugger/
RUN mkdir -p /home/user/firmrebugger/src/firmrebugger /home/user/firmrebugger/target
WORKDIR /home/user/firmrebugger/target

ENV GHIDRA_SRC=$FUZZER/ghidra
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger
ENV FRB_REPLAY_WORKER_COMMAND="/usr/bin/python3 -m fuzzware_harness.persistent_worker"

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
