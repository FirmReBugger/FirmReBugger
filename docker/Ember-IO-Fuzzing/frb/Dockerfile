FROM frb_original:Ember-IO-Fuzzing AS fuzzer-base

ENV FUZZER=/home/user/ember
ENV PIP_NO_CACHE_DIR=1

# ---- Stage 1: Building TinyCC ----
FROM fuzzer-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc && \
    cd /tinycc && \
    git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user ./docker/Ember-IO-Fuzzing/frb/frb_patches/frb_tcc.patch /tinycc/frb_tcc.patch
RUN cd /tinycc && git apply /tinycc/frb_tcc.patch
RUN cd /tinycc && ./configure && make

# ---- Stage 2: Extend fuzzer FirmReBugger ----
FROM frb_original:Ember-IO-Fuzzing AS ember-firmrebugger
USER root
# Apply FirmReBugger patches
COPY --chown=user docker/Ember-IO-Fuzzing/frb/frb_patches/frb_ember.patch $FUZZER/Ember-IO-Fuzzing/
WORKDIR $FUZZER/Ember-IO-Fuzzing/AFLplusplus/qemu_mode/qemuafl
RUN git apply $FUZZER/Ember-IO-Fuzzing/frb_ember.patch

COPY --from=tcc-build /tinycc $FUZZER/tinycc

# Copy FirmReBugger files
COPY --chown=user docker/Ember-IO-Fuzzing/frb/frb_patches/firmrebugger.c $FUZZER/Ember-IO-Fuzzing/AFLplusplus/qemu_mode/qemuafl/target/arm/firmrebugger.c
COPY --chown=user docker/Ember-IO-Fuzzing/frb/frb_patches/firmrebugger.h $FUZZER/Ember-IO-Fuzzing/AFLplusplus/qemu_mode/qemuafl/qemuafl/firmrebugger.h


# Build Ember-IO-Fuzzing
WORKDIR $FUZZER/Ember-IO-Fuzzing/AFLplusplus
RUN make
WORKDIR $FUZZER/Ember-IO-Fuzzing/AFLplusplus/qemu_mode
RUN ./build_qemu_support.sh

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

# ---- Final Setup ----
ENV EMBER_BASE_DIR=$FUZZER/Ember-IO-Fuzzing
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger
ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
