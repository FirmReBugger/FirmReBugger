FROM frb_original:Ember-IO-Fuzzing AS fuzzer-base

ENV FUZZER=/home/user/ember

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
ENV EMBER_BASE_DIR=$FUZZER/Ember-IO-Fuzzing
ENV FIRMREBUGGER_BASE_DIR=/firmrebugger
ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]