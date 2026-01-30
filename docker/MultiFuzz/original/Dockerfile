FROM ubuntu:22.04 AS fuzzer-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y && \
    apt-get install -y python3 python3-pip tmux build-essential git wget curl clang llvm-dev libclang-dev pkg-config libglib2.0-dev libpixman-1-dev git && \
    pip3 install setuptools

ENV FUZZER=/home/user/multifuzz

ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

# install Rust
USER user
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path && \
    ~/.cargo/bin/rustup install 1.88.0 && \
    ~/.cargo/bin/rustup default 1.88.0
ENV PATH="${PATH}:/home/user/.cargo/bin"

ENV FUZZER=/home/user/multifuzz

WORKDIR $FUZZER
RUN git clone https://github.com/MultiFuzz/MultiFuzz MultiFuzz
WORKDIR $FUZZER/MultiFuzz
RUN git submodule update --init --recursive
RUN git submodule update --init ghidra
RUN cargo build --release


ENV GHIDRA_SRC=$FUZZER/MultiFuzz/ghidra

USER user:user
WORKDIR $FUZZER/firmbench_target
