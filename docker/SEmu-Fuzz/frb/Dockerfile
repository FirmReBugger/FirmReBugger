FROM frb_original:SEmu-Fuzz AS fuzzer-base

ENV FUZZER=/home/user/SEmu-Fuzz

FROM frb_original:SEmu-Fuzz AS semu-firmrebugger
USER root
RUN git clone https://github.com/TinyCC/tinycc.git $FUZZER/tinycc
WORKDIR $FUZZER/tinycc
RUN git checkout 7c23c48a936d2bf2ea181af58d698d1816a52e6f
COPY --chown=user docker/SEmu-Fuzz/frb/frb_patches/frb_tcc.patch .
RUN git apply $FUZZER/tinycc/frb_tcc.patch
RUN ./configure && \
    make
RUN make install

WORKDIR /opt/AFLplusplus/unicorn_mode/unicornafl
# FirmRebugger installation
COPY --chown=user docker/SEmu-Fuzz/frb/frb_patches/firmrebugger.c unicorn/qemu/include/qemu/firmrebugger.c
COPY --chown=user docker/SEmu-Fuzz/frb/frb_patches/firmrebugger.h unicorn/qemu/include/qemu/firmrebugger.h

WORKDIR /opt/AFLplusplus/unicorn_mode/unicornafl
RUN cp ../../include/config.h ./include && \
    make clean && \
    rm -rf build_python && \
    make unicorn -j1 || exit 1 && \
    cd bindings/python && \
    pip install .

WORKDIR /opt/AFLplusplus/unicorn_mode/unicornafl/unicorn
COPY --chown=user docker/SEmu-Fuzz/frb/frb_patches/semu.patch .
RUN rm CMakeLists.txt
COPY --chown=user docker/SEmu-Fuzz/frb/frb_patches/CMakeLists.txt .
RUN git apply semu.patch
RUN mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DUNICORN_BUILD_TESTS=OFF && \
    make unicorn -j8 && \
    make install

RUN rm -rf build_python && \
    cd bindings/python && \
    rm -rf prebuilt build && \
    pip install .

RUN echo "[+] Success to build AFL!"

RUN chown -R user:user /home/user
# Install FirmReBugger
USER user
RUN pip3 install --user uv
ENV PATH=$PATH:/home/user/.local/bin
COPY --chown=user ./src /firmrebugger/
COPY --chown=user ./pyproject.toml /firmrebugger/
COPY --chown=user ./uv.lock /firmrebugger/
COPY --chown=user ./README.md /firmrebugger/
COPY --chown=user ./.python-version /firmrebugger/
WORKDIR /firmrebugger/target
RUN uv run frb -h

ENV PATH="$PATH:/home/user/.local/bin"
RUN pip3 install --user intelhex
RUN pip3 install --user $FUZZER/build/SEmu-Fuzz/
ENV FIRMREBUGGER_BASE_DIR=/firmrebugger

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]

