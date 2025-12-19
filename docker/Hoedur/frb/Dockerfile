FROM frb:Fuzzware

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

ENV FUZZER=/home/user/hoedur
RUN git clone https://github.com/TinyCC/tinycc.git $FUZZER/tinycc
WORKDIR $FUZZER/tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/Hoedur/frb/frb_patches/frb_tcc.patch .
RUN git apply $FUZZER/tinycc/frb_tcc.patch
RUN ./configure && \
    make


# get hoedur + add eval patches
ENV FUZZER=/home/user/hoedur
RUN git clone https://github.com/fuzzware-fuzzer/hoedur.git $FUZZER/hoedur
RUN git clone https://github.com/fuzzware-fuzzer/hoedur-experiments.git         $FUZZER/hoedur-experiments 
WORKDIR $FUZZER/hoedur
RUN git checkout a021fd064e5d831a427a25b17975779eef05c45b
RUN git am $FUZZER/hoedur-experiments/scripts/hoedur/patches/dict/0001-enable-dictionary.patch
COPY --chown=user docker/Hoedur/frb/frb_patches/ $FUZZER/frb_patches/
RUN git apply $FUZZER/frb_patches/firmrebugger_hoedur_rust.patch
# USER user
# install hoedur (emulator + fuzzer)
RUN cargo install --path $FUZZER/hoedur/hoedur \
    --bin hoedur-arm && \
    cp $FUZZER/hoedur/target/release/libqemu-system-arm.release.so $HOME/.cargo/bin/ && \
    cp $FUZZER/hoedur/target/release/hoedur-arm $HOME/.cargo/bin/hoedur-dict-arm && \
    cargo clean

# Install FirmReBugger
USER root
RUN pip3 install uv
COPY --chown=user src $FUZZER/firmrebugger/
COPY --chown=user pyproject.toml $FUZZER/firmrebugger/
COPY --chown=user uv.lock $FUZZER/firmrebugger/
COPY --chown=user README.md $FUZZER/firmrebugger/
COPY --chown=user .python-version $FUZZER/firmrebugger/
WORKDIR $FUZZER/firmrebugger
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"
RUN uv run frb -h

USER user:user
ENV FIRMREBUGGER_BASE_DIR=$FUZZER/firmrebugger
ENV HOEDUR_BASE_DIR=$FUZZER/hoedur
WORKDIR /benchmark
