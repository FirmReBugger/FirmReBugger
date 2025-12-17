FROM ubuntu:20.04 AS icicle-fuzzware-base
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip automake tmux redis wget autoconf sudo htop cmake clang vim unzip git binutils-arm-none-eabi curl && \
    pip3 install virtualenv virtualenvwrapper cython setuptools
RUN pip3 install -U maturin==0.12.0


ENV FUZZER=/home/user/icicle-fuzzware
ENV WORKON_HOME=/home/user/.virtualenvs
ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

USER user
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/home/user/.cargo/bin:${PATH}"

# Modeling container
FROM icicle-fuzzware-base AS icicle-fuzzware-modeling
USER user
RUN git clone https://github.com/icicle-emu/fuzzware.git/ /tmp/icicle-fuzzware
WORKDIR /tmp/icicle-fuzzware
RUN git submodule update --init --recursive
RUN python3 -m virtualenv --python=/usr/bin/python3 $WORKON_HOME/fuzzware-modeling && \
    . $WORKON_HOME/fuzzware-modeling/bin/activate && \
    pip3 install -r /tmp/icicle-fuzzware/modeling/requirements.txt
RUN . $WORKON_HOME/fuzzware-modeling/bin/activate && \
pip3 install /tmp/icicle-fuzzware/modeling 'rq==1.14' 'capstone==5.0.3' 'six' 'protobuf<4.21'

# Main container
FROM icicle-fuzzware-base AS icicle-fuzzware
USER user
RUN git clone https://github.com/icicle-emu/fuzzware.git/ $FUZZER/repo
WORKDIR $FUZZER/repo
RUN git submodule update --init --recursive
RUN pip3 install -r $FUZZER/repo/pipeline/requirements.txt -r $FUZZER/repo/emulator/requirements.txt
RUN pip3 install 'rq==1.14' 'capstone==5.0.3' 'six' 'protobuf<4.21'

WORKDIR $FUZZER/repo/emulator
USER user
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
ENV GHIDRA_SRC=$FUZZER/ghidra
# Finally copy the modeling venv
COPY --chown=user --from=icicle-fuzzware-modeling $WORKON_HOME/ $WORKON_HOME/

USER user:user
WORKDIR $FUZZER/firmbench_target

