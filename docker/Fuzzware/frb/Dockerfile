FROM ubuntu:22.04 AS fuzzware-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip automake tmux redis wget autoconf sudo htop cmake clang vim unzip git binutils-arm-none-eabi && \
    pip3 install virtualenv virtualenvwrapper cython setuptools

ENV FUZZER=/home/user/fuzzware
ENV WORKON_HOME=/home/user/.virtualenvs
ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

# Modeling container
FROM fuzzware-base AS fuzzware-modeling
USER user
# Install requirements first (from the repo)
RUN git clone https://github.com/fuzzware-fuzzer/fuzzware.git /tmp/fuzzware
RUN python3 -m virtualenv --python=/usr/bin/python3 $WORKON_HOME/fuzzware-modeling && \
    . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip3 install -r /tmp/fuzzware/modeling/requirements.txt
RUN . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip3 install /tmp/fuzzware/modeling

# TinyCC build 
FROM fuzzware-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc
WORKDIR /tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/Fuzzware/frb/frb_patches/frb_tcc.patch .
RUN git apply /tinycc/frb_tcc.patch
RUN ./configure && \
    make

# Main container
FROM fuzzware-base AS fuzzware
USER user
# Clone the source code from GitHub
RUN git clone https://github.com/fuzzware-fuzzer/fuzzware.git $FUZZER/repo
WORKDIR $FUZZER/repo
RUN git checkout e43dfbd38185ef4a374e1e9a6c9d930a9cc40653
RUN git submodule update --init --recursive
USER root
# Install requirements from the repo
RUN pip3 install -r $FUZZER/repo/pipeline/requirements.txt -r $FUZZER/repo/emulator/requirements.txt

USER user
# Install FirmReBugger first
WORKDIR $FUZZER/repo/emulator
COPY --chown=user docker/Fuzzware/frb/frb_patches/firmrebugger.c unicorn/fuzzware-unicorn/qemu/include/qemu/firmrebugger.c
COPY --chown=user docker/Fuzzware/frb/frb_patches/firmrebugger.h unicorn/fuzzware-unicorn/qemu/include/qemu/firmrebugger.h
WORKDIR $FUZZER/repo/emulator/unicorn/fuzzware-unicorn
COPY --chown=user docker/Fuzzware/frb/frb_patches/frb_fuzzware.patch .
RUN git apply frb_fuzzware.patch
COPY --from=tcc-build /tinycc $FUZZER/tinycc
WORKDIR $FUZZER/repo/emulator
# Build the emulator
RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZER/repo/emulator/afl clean all && \
    make -C $FUZZER/repo/emulator/AFLplusplus clean all && \
    cd $FUZZER/repo/emulator/unicorn && \
    ./build_unicorn.sh

# Build harness
RUN make -C $FUZZER/repo/emulator/harness/fuzzware_harness/native clean all

# Install the emulator and pipeline 
USER root
RUN pip3 install -e $FUZZER/repo/emulator/harness && \
    pip3 install -e $FUZZER/repo/pipeline

COPY --chown=user --from=fuzzware-modeling $WORKON_HOME/ $WORKON_HOME/
# Install FirmReBugger
USER root
RUN pip3 install uv
RUN pip3 install --upgrade pip setuptools wheel
COPY --chown=user src $FUZZER/firmrebugger/
COPY --chown=user pyproject.toml $FUZZER/firmrebugger/
COPY --chown=user uv.lock $FUZZER/firmrebugger/
WORKDIR $FUZZER/firmrebugger
RUN pip3 install -e .

USER user:user
ENV FIRMREBUGGER_BASE_DIR=$FUZZER/firmrebugger
WORKDIR /benchmark

