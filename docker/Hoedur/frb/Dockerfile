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

# ---- Final Setup ----
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger
ENV HOEDUR_BASE_DIR=$FUZZER/hoedur
ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
