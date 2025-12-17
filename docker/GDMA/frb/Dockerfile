FROM ubuntu:22.04 AS fuzzware-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip automake tmux redis wget autoconf sudo htop cmake clang vim unzip git binutils-arm-none-eabi curl && \
    pip3 install virtualenv virtualenvwrapper cython setuptools

ENV FUZZER=/home/user/GDMA
ENV WORKON_HOME=/home/user/.virtualenvs
ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

# Install cargo for user
USER user
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path --default-toolchain 1.81.0
ENV PATH="${PATH}:/home/user/.cargo/bin"
ENV LD_LIBRARY_PATH="/home/user/.cargo/bin/"

# Modeling container
FROM fuzzware-base as fuzzware-modeling
USER root
# First copy and install requirements
RUN git clone -b DMA --recurse-submodules https://github.com/fuzzware-fuzzer/fuzzware.git /tmp/fuzzware
# f5979d009f18ce0069c7e57c9f557766b5f977c8 is the commit

RUN cp /tmp/fuzzware/modeling/requirements.txt /requirements-modeling.txt
RUN python3 -m virtualenv --python=/usr/bin/python3 $WORKON_HOME/fuzzware-modeling && \
    . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip install -r /requirements-modeling.txt
# Then copy and install modeling, then we don't need to install the requirements on each code change
RUN cp -r /tmp/fuzzware/modeling $FUZZER/modeling
RUN . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip install $FUZZER/modeling


# TinyCC build 
FROM fuzzware-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc
WORKDIR /tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/GDMA/frb/frb_patches/frb_tcc.patch .
RUN git apply /tinycc/frb_tcc.patch
RUN ./configure && \
    make


# Main container
FROM fuzzware-base AS fuzzware
USER root
# As above install requirements first
COPY --from=fuzzware-modeling --chown=user /tmp/fuzzware/pipeline/requirements.txt /requirements-pipeline.txt

COPY --from=fuzzware-modeling --chown=user /tmp/fuzzware/emulator/requirements.txt /requirements-emulator.txt
RUN pip3 install -r /requirements-emulator.txt -r /requirements-pipeline.txt

# Build pipeline components
USER user
COPY --from=fuzzware-modeling --chown=user /tmp/fuzzware/pipeline $FUZZER/pipeline
RUN cargo build --release --manifest-path $FUZZER/pipeline/dma_modeling/Cargo.toml

# Build and install emulator dependencies: afl, unicorn
COPY --from=fuzzware-modeling --chown=user /tmp/fuzzware/emulator/get_afl.sh /tmp/fuzzware/emulator/afl.patch $FUZZER/emulator/

COPY --from=fuzzware-modeling --chown=user /tmp/fuzzware/emulator/unicorn/ $FUZZER/emulator/unicorn
USER user
# Install FirmReBugger first
WORKDIR $FUZZER/emulator/unicorn/fuzzware-unicorn
COPY --chown=user docker/GDMA/frb/frb_patches/firmrebugger.c qemu/include/qemu/firmrebugger.c
COPY --chown=user docker/GDMA/frb/frb_patches/firmrebugger.h qemu/include/qemu/firmrebugger.h
COPY --chown=user docker/GDMA/frb/frb_patches/frb_GDMA.patch .
RUN patch -p1 < frb_GDMA.patch
COPY --from=tcc-build /tinycc $FUZZER/tinycc
WORKDIR $FUZZER/emulator

RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZER/emulator/afl clean all && \
    AFL_NO_X86=1 make -f GNUmakefile -C $FUZZER/emulator/AFLplusplus clean test_shm test_python ready afl-fuzz afl-showmap afl-tmin afl-gotcpu && \
    cd $FUZZER/emulator/unicorn && \
    ./build_unicorn.sh

# Then copy and install emulator and pipeline
COPY --from=fuzzware-modeling --chown=user /tmp/fuzzware/emulator $FUZZER/emulator
RUN make -C $FUZZER/emulator/harness/fuzzware_harness/native clean all

USER root
RUN pip3 install -e $FUZZER/emulator/harness && \
    pip3 install -e $FUZZER/pipeline

# Finally copy the modeling venv
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