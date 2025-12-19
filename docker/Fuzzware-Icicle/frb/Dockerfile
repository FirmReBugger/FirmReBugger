FROM ubuntu:20.04 AS fuzzware-icicle-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip automake tmux redis wget autoconf sudo htop cmake clang vim unzip git binutils-arm-none-eabi curl && \
    pip3 install virtualenv virtualenvwrapper cython setuptools
RUN pip3 install -U maturin==0.12.0


ENV FUZZER=/home/user/fuzzware-icicle
ENV WORKON_HOME=/home/user/.virtualenvs
ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

USER user
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/home/user/.cargo/bin:${PATH}"

# TinyCC build 
FROM fuzzware-icicle-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc
WORKDIR /tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/Fuzzware-Icicle/frb/frb_patches/frb_tcc.patch .
RUN git apply /tinycc/frb_tcc.patch
RUN ./configure && \
    make

# Modeling container
FROM fuzzware-icicle-base AS fuzzware-icicle-modeling
USER user
RUN git clone https://github.com/icicle-emu/fuzzware.git/ /tmp/fuzzware-icicle
WORKDIR /tmp/fuzzware-icicle
RUN git checkout 149ca48df9ba74bd4c4049e6bdb07d83634c3f24
RUN git submodule update --init --recursive
RUN python3 -m virtualenv --python=/usr/bin/python3 $WORKON_HOME/fuzzware-modeling && \
    . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip3 install -r /tmp/fuzzware-icicle/modeling/requirements.txt
RUN . $WORKON_HOME/fuzzware-modeling/bin/activate && \
pip3 install /tmp/fuzzware-icicle/modeling 'rq==1.14' 'capstone==5.0.3' 'six' 'protobuf<4.21'

# Main container
FROM fuzzware-icicle-base AS fuzzware-icicle
USER user
RUN git clone https://github.com/icicle-emu/fuzzware.git/ $FUZZER/repo
WORKDIR $FUZZER/repo
RUN git checkout 149ca48df9ba74bd4c4049e6bdb07d83634c3f24
RUN git submodule update --init --recursive
RUN pip3 install -r $FUZZER/repo/pipeline/requirements.txt -r $FUZZER/repo/emulator/requirements.txt
RUN pip3 install 'rq==1.14' 'capstone==5.0.3' 'six' 'protobuf<4.21'

WORKDIR $FUZZER/repo/emulator
USER user
# Install FirmReBugger first
COPY --chown=user docker/Fuzzware-Icicle/frb/frb_patches/firmrebugger firmrebugger/
COPY --chown=user docker/Fuzzware-Icicle/frb/frb_patches/frb_icicle.patch .
RUN git apply frb_icicle.patch
COPY --from=tcc-build /tinycc $FUZZER/tinycc

# Build the emulator
WORKDIR $FUZZER/repo/emulator
RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZER/repo/emulator/afl clean all && \
    make -C $FUZZER/repo/emulator/AFLplusplus clean all

WORKDIR $FUZZER/repo/emulator/icicle
RUN maturin build --release && \
    pip3 install --force-reinstall target/wheels/icicle-0.1.0*.whl
WORKDIR $FUZZER/repo/emulator

RUN make -C $FUZZER/repo/emulator/harness/fuzzware_harness/native clean all
USER root
RUN pip3 install -e $FUZZER/repo/emulator/harness && \
    pip3 install -e $FUZZER/repo/pipeline

RUN git clone https://github.com/icicle-emu/ghidra.git $FUZZER/ghidra
# Finally copy the modeling venv
COPY --chown=user --from=fuzzware-icicle-modeling $WORKON_HOME/ $WORKON_HOME/

# Install FirmReBugger
USER root
RUN pip3 install uv
COPY --chown=user src $FUZZER/firmrebugger/
COPY --chown=user pyproject.toml $FUZZER/firmrebugger/
COPY --chown=user uv.lock $FUZZER/firmrebugger/
COPY --chown=user README.md $FUZZER/firmrebugger/
COPY --chown=user .python-version $FUZZER/firmrebugger/
WORKDIR $FUZZER/firmrebugger
RUN uv run frb -h

USER user:user
ENV GHIDRA_SRC=$FUZZER/ghidra
ENV FIRMREBUGGER_BASE_DIR=$FUZZER/firmrebugger
WORKDIR /benchmark