FROM ubuntu:22.04 AS fuzzer-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y && \
    apt-get install -y python3 python3-pip tmux build-essential git wget curl && \
    pip3 install setuptools

ENV FUZZER=/home/user/multifuzz

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
COPY --chown=user docker/MultiFuzz/frb/frb_patches/frb_tcc.patch .
RUN git apply /tinycc/frb_tcc.patch
RUN ./configure && \
    make

FROM rust:1.88 AS build-multifuzz
USER root
ENV FUZZER=/home/user/multifuzz
RUN apt-get update && \
    apt-get install -y clang llvm-dev libclang-dev pkg-config libglib2.0-dev libpixman-1-dev git
WORKDIR $FUZZER
RUN git clone https://github.com/MultiFuzz/MultiFuzz MultiFuzz
WORKDIR $FUZZER/MultiFuzz
RUN git checkout 1214d15725b06d072b6456e7a25b9a0f922c5f33
RUN git submodule update --init --recursive
COPY --chown=user docker/MultiFuzz/frb/frb_patches/firmrebugger firmrebugger
COPY --chown=user docker/MultiFuzz/frb/frb_patches/frb_multifuzz.patch .
RUN git apply frb_multifuzz.patch
RUN git submodule update --init ghidra
COPY --from=tcc-build /tinycc $FUZZER/tinycc
RUN ls $FUZZER/tinycc
RUN cargo build --release

FROM fuzzer-base
ENV FUZZER=/home/user/multifuzz
COPY --from=tcc-build /tinycc $FUZZER/tinycc
COPY --from=build-multifuzz $FUZZER/MultiFuzz/target/release/hail-fuzz $FUZZER/MultiFuzz/target/release/hail-fuzz
COPY --from=build-multifuzz $FUZZER/MultiFuzz/ghidra $FUZZER/MultiFuzz/ghidra
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
ENV PATH="/root/.local/bin:$PATH"
RUN uv run frb -h

USER user:user
ENV GHIDRA_SRC=$FUZZER/MultiFuzz/ghidra
ENV MULTIFUZZ_DIR=$FUZZER/MultiFuzz
ENV MULTIFUZZ_BASE_DIR=$FUZZER/MultiFuzz/
ENV FIRMREBUGGER_BASE_DIR=$FUZZER/firmrebugger
WORKDIR $FUZZER/firmbench_target
