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

WORKDIR $FUZZER/Ember-IO-Fuzzing/AFLplusplus
RUN make
WORKDIR $FUZZER/Ember-IO-Fuzzing/AFLplusplus/qemu_mode
RUN ./build_qemu_support.sh

USER user:user
ENV EMBER_BASE_DIR=$FUZZER/Ember-IO-Fuzzing
WORKDIR $FUZZER/firmbench_target
