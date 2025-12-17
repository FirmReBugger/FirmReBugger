FROM ubuntu:22.04
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

RUN apt-get update
RUN apt-get install -y python3-pip automake sudo git vim clang cmake llvm wget unzip build-essential
RUN apt-get install -y gnuplot binutils-arm-none-eabi
RUN apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
RUN apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || apt-get install -y lld llvm llvm-dev clang
RUN apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
RUN apt-get install -y ninja-build

# Prepare non-root user
ENV FUZZER=/home/user/SEmu-Fuzz
ARG USERID=1000
RUN useradd -l -u $USERID -d /home/user user && \
    mkdir -p $FUZZER /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers

WORKDIR /opt
RUN git config --global core.longpaths true && \
    git clone https://github.com/IoTS-P/AFLplusplus.git

WORKDIR /opt/AFLplusplus
RUN make || exit 1
RUN make install || exit 1

WORKDIR /opt/AFLplusplus/unicorn_mode
RUN git clone https://github.com/IoTS-P/unicornafl.git

WORKDIR /opt/AFLplusplus/unicorn_mode/unicornafl
RUN git clone https://github.com/IoTS-P/unicorn.git


RUN cp ../../include/config.h ./include && \
    make clean && \
    rm -rf build_python && \
    make -j1 || exit 1 && \
    cd bindings/python && \
    pip install .

WORKDIR /opt/AFLplusplus/unicorn_mode/unicornafl/unicorn
RUN mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j8 || exit 1 && \
    make install || exit 1

RUN rm -rf build_python && \
    cd bindings/python && \
    rm -rf prebuilt build && \
    pip install .

RUN echo "[+] Success to build AFL!"

RUN git clone https://github.com/IoTS-P/SEmu-Fuzz.git $FUZZER/build/SEmu-Fuzz

RUN chown -R user:user /home/user

USER user
ENV PATH="$PATH:/home/user/.local/bin"
RUN pip3 install --user intelhex
RUN pip3 install --user $FUZZER/build/SEmu-Fuzz/

WORKDIR /home/user/SEmu-Fuzz/firmbench_target
