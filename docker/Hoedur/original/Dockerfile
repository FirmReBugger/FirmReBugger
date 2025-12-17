FROM frb_original:Fuzzware

USER root
RUN apt update -q
RUN apt install -qy \
clang \
curl \
git \
libfdt-dev \
libglib2.0-dev \
libpixman-1-dev \
libxcb-shape0-dev \
libxcb-xfixes0-dev \
ninja-build \
patchelf \
pkg-config \
python3-psutil \
zstd

# set git user
ENV GIT_COMMITTER_NAME=Hoedur
ENV GIT_COMMITTER_EMAIL=user@hoedur
# install Rust
USER user
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path
ENV PATH="${PATH}:/home/user/.cargo/bin"
ENV LD_LIBRARY_PATH="/home/user/.cargo/bin/"

# get hoedur + add eval patches
ENV FUZZER=/home/user/hoedur
RUN git clone https://github.com/fuzzware-fuzzer/hoedur.git $FUZZER/
RUN git clone https://github.com/fuzzware-fuzzer/hoedur-experiments.git         $FUZZER/hoedur-experiments 
WORKDIR $FUZZER
RUN git am $FUZZER/hoedur-experiments/scripts/hoedur/patches/dict/0001-enable-dictionary.patch
# install hoedur (emulator + fuzzer)
RUN cargo install --path $FUZZER/hoedur \
    --bin hoedur-arm && \
    cp $FUZZER/target/release/libqemu-system-arm.release.so $HOME/.cargo/bin/ && \
    cp $FUZZER/target/release/hoedur-arm $HOME/.cargo/bin/hoedur-dict-arm && \
    cargo clean

USER user:user
WORKDIR $FUZZER/firmbench_target