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


# Main container
FROM fuzzware-base AS fuzzware
USER user
# Clone the source code from GitHub
RUN git clone https://github.com/fuzzware-fuzzer/fuzzware.git $FUZZER/repo
WORKDIR $FUZZER/repo
RUN git submodule update --init --recursive
USER root
# Install requirements from the repo
RUN pip3 install -r $FUZZER/repo/pipeline/requirements.txt -r $FUZZER/repo/emulator/requirements.txt

# Build and install emulator dependencies: afl, unicorn
USER user
WORKDIR $FUZZER/repo/emulator
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

USER user:user
WORKDIR $FUZZER/firmbench_target
