FROM ubuntu:22.04 AS fuzzer-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y && \
    apt-get install -y python3 python3-pip tmux build-essential clang  ninja-build pkg-config libglib2.0-dev libpixman-1-dev git wget && \
    pip3 install setuptools

ENV FUZZER=/home/user/ember

ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

# TinyCC build 
FROM fuzzer-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc
WORKDIR /tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/Ember-IO-Fuzzing/frb/frb_patches/frb_tcc.patch .
RUN git apply /tinycc/frb_tcc.patch
RUN ./configure && \
    make

FROM fuzzer-base AS build-ember
USER root
WORKDIR $FUZZER
RUN git clone https://github.com/Ember-IO/Ember-IO-Fuzzing.git Ember-IO-Fuzzing
WORKDIR $FUZZER/Ember-IO-Fuzzing
ENV EMBER_BASE_DIR=$FUZZER/Ember-IO-Fuzzing

RUN git submodule update --init
WORKDIR AFLplusplus
RUN git submodule update --init 
WORKDIR qemu_mode
RUN git submodule update --init 
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

# Install FirmReBugger
USER root
RUN pip3 install uv
COPY --chown=user src $FUZZER/firmrebugger/
COPY --chown=user pyproject.toml $FUZZER/firmrebugger/
COPY --chown=user uv.lock $FUZZER/firmrebugger/
COPY --chown=user README.md $FUZZER/firmrebugger/
COPY --chown=user .python-version $FUZZER/firmrebugger/
WORKDIR $FUZZER/firmrebugger
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:/home/user/.local/bin:$PATH"
RUN uv run frb -h

USER user:user
ENV EMBER_BASE_DIR=$FUZZER/Ember-IO-Fuzzing
ENV FIRMREBUGGER_BASE_DIR=$FUZZER/firmrebugger
WORKDIR /benchmark