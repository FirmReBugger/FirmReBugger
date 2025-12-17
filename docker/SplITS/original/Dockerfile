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

# Modeling container
FROM splits-base AS fuzzware-modeling
USER user
# Install requirements first (from the repo)
RUN git clone https://github.com/SplITS-Fuzzer/SplITS.git /tmp/splits
WORKDIR /tmp/splits
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
RUN git submodule update --init --recursive
RUN sed -i 's/^PyYAML.*/PyYAML<6.0,>=5.3/' $FUZZER/repo/fuzzware/pipeline/requirements.txt \
 && sed -i 's/^PyYAML.*/PyYAML<6.0,>=5.3/' $FUZZER/repo/fuzzware/emulator/requirements.txt
USER root
# Install requirements from the repo
RUN pip3 install -r $FUZZER/repo/fuzzware/pipeline/requirements.txt -r $FUZZER/repo/fuzzware/emulator/requirements.txt

# Build and install emulator dependencies: afl, unicorn
USER user
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

USER user:user
WORKDIR $FUZZER/firmbench_target
