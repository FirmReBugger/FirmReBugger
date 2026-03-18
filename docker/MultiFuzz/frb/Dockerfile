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

ENV GHIDRA_SRC=$FUZZER/MultiFuzz/ghidra
ENV MULTIFUZZ_DIR=$FUZZER/MultiFuzz
ENV MULTIFUZZ_BASE_DIR=$FUZZER/MultiFuzz/
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
