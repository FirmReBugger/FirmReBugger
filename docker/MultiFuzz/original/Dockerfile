FROM ubuntu:22.04 AS fuzzer-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y && \
    apt-get install -y python3 python3-pip tmux build-essential git wget && \
    pip3 install setuptools

ENV FUZZER=/home/user/multifuzz

ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

FROM rust:latest AS build-multifuzz
USER root
ENV FUZZER=/home/user/multifuzz
RUN apt-get update && \
    apt-get install -y clang llvm-dev libclang-dev pkg-config libglib2.0-dev libpixman-1-dev git
WORKDIR $FUZZER
RUN git clone https://github.com/MultiFuzz/MultiFuzz MultiFuzz
WORKDIR $FUZZER/MultiFuzz
RUN git submodule update --init --recursive
RUN git submodule update --init ghidra
RUN cargo build --release

FROM fuzzer-base
ENV FUZZER=/home/user/multifuzz
COPY --from=build-multifuzz $FUZZER/MultiFuzz/target/release/hail-fuzz $FUZZER/MultiFuzz/target/release/hail-fuzz
COPY --from=build-multifuzz $FUZZER/MultiFuzz/ghidra $FUZZER/MultiFuzz/ghidra
ENV GHIDRA_SRC=$FUZZER/MultiFuzz/ghidra

ENV MULTI=$FUZZER/MultiFuzz/target/release//hail-fuzz
USER user:user
WORKDIR $FUZZER/firmbench_target
