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


# Install FirmReBugger
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

ENV GHIDRA_SRC=$FUZZER/ghidra
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
