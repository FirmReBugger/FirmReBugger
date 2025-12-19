FROM ubuntu:20.04 AS splits-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip automake tmux redis wget autoconf sudo htop cmake clang vim unzip git binutils-arm-none-eabi && \
    pip3 install virtualenv virtualenvwrapper cython setuptools

ENV FUZZER=/home/user/splits
ENV WORKON_HOME=/home/user/.virtualenvs
ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers


# TinyCC build 
FROM splits-base AS tcc-build
USER root
RUN git clone https://github.com/TinyCC/tinycc.git /tinycc
WORKDIR /tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/SplITS/frb/frb_patches/frb_tcc.patch .
RUN git apply /tinycc/frb_tcc.patch
RUN ./configure && \
    make

# Modeling container
FROM splits-base AS fuzzware-modeling
USER user
# Install requirements first (from the repo)
RUN git clone https://github.com/SplITS-Fuzzer/SplITS.git /tmp/splits
WORKDIR /tmp/splits
RUN git checkout b78f98a32196fd0ee4eba8035c880967737a1b29
RUN git submodule update --init --recursive
RUN sed -i 's/^protobuf<=3\.20\.\*/protobuf<3.21/' /tmp/splits/fuzzware/modeling/requirements.txt
RUN python3 -m virtualenv --python=/usr/bin/python3 $WORKON_HOME/fuzzware-modeling && \
    . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip3 install -r /tmp/splits/fuzzware/modeling/requirements.txt
RUN . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip3 install /tmp/splits/fuzzware/modeling 'rq==1.14' 'capstone==5.0.3' 'six' 'protobuf<4.21'

# Main container
FROM splits-base AS splits
USER user
# Clone the source code from GitHub
RUN git clone https://github.com/SplITS-Fuzzer/SplITS.git $FUZZER/repo
WORKDIR $FUZZER/repo
RUN git checkout b78f98a32196fd0ee4eba8035c880967737a1b29
RUN git submodule update --init --recursive
RUN sed -i 's/^PyYAML.*/PyYAML<6.0,>=5.3/' $FUZZER/repo/fuzzware/pipeline/requirements.txt \
 && sed -i 's/^PyYAML.*/PyYAML<6.0,>=5.3/' $FUZZER/repo/fuzzware/emulator/requirements.txt
USER root
# Install requirements from the repo
RUN pip3 install -r $FUZZER/repo/fuzzware/pipeline/requirements.txt -r $FUZZER/repo/fuzzware/emulator/requirements.txt

# Build and install emulator dependencies: afl, unicorn
USER user
# Install FirmReBugger first
WORKDIR $FUZZER/repo/fuzzware/emulator
COPY --chown=user docker/SplITS/frb/frb_patches/firmrebugger.c unicorn/fuzzware-unicorn/qemu/include/qemu/firmrebugger.c
COPY --chown=user docker/SplITS/frb/frb_patches/firmrebugger.h unicorn/fuzzware-unicorn/qemu/include/qemu/firmrebugger.h
WORKDIR $FUZZER/repo/fuzzware/emulator/unicorn/fuzzware-unicorn
COPY --chown=user docker/SplITS/frb/frb_patches/frb_fuzzware.patch .
RUN git apply frb_fuzzware.patch
COPY --from=tcc-build /tinycc $FUZZER/tinycc
WORKDIR $FUZZER/repo/fuzzware/emulator
RUN ./get_afl.sh && \
    UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C $FUZZER/repo/fuzzware/emulator/afl clean all && \
    make -C $FUZZER/repo/fuzzware/emulator/AFLplusplus clean all && \
    cd $FUZZER/repo/fuzzware/emulator/unicorn && \
    ./build_unicorn.sh

# Build harness
RUN make -C $FUZZER/repo/fuzzware/emulator/harness/fuzzware_harness/native clean all

# Install the emulator and pipeline 
USER root
RUN pip3 install -e $FUZZER/repo/fuzzware/emulator/harness && \
    pip3 install -e $FUZZER/repo/fuzzware/pipeline

COPY --chown=user --from=fuzzware-modeling $WORKON_HOME/ $WORKON_HOME/

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
ENV FIRMREBUGGER_BASE_DIR=$FUZZER/firmrebugger
WORKDIR /benchmark