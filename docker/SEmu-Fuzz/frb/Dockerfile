FROM frb_original:SEmu-Fuzz AS fuzzer-base

ENV FUZZER=/home/user/SEmu-Fuzz
ENV PIP_NO_CACHE_DIR=1

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

# Copy local FirmReBugger source directly so uncommitted changes are always
# picked up. We skip firmrebugger-web/ and commands/web_app.py since the
# containers only need fuzz, build, bug-analyzer, and charting-tool.
RUN mkdir -p /home/user/firmrebugger/src/firmrebugger/bug_analyzer_utils \
             /home/user/firmrebugger/src/firmrebugger/charting_tool_utils \
             /home/user/firmrebugger/src/firmrebugger/commands \
             /home/user/firmrebugger/src/firmrebugger/fuzzer_runners
COPY --chown=user pyproject.toml uv.lock .python-version README.md /home/user/firmrebugger/
COPY --chown=user src/firmrebugger/__init__.py   /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/cli.py        /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/common.py     /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/app_utils.py  /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/fuzzer.py     /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/manager.py    /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/task.py       /home/user/firmrebugger/src/firmrebugger/
COPY --chown=user src/firmrebugger/bug_analyzer_utils/   /home/user/firmrebugger/src/firmrebugger/bug_analyzer_utils/
COPY --chown=user src/firmrebugger/charting_tool_utils/  /home/user/firmrebugger/src/firmrebugger/charting_tool_utils/
COPY --chown=user src/firmrebugger/fuzzer_runners/       /home/user/firmrebugger/src/firmrebugger/fuzzer_runners/
COPY --chown=user src/firmrebugger/commands/                  /home/user/firmrebugger/src/firmrebugger/commands/
WORKDIR /home/user/firmrebugger
RUN uv run frb -h
WORKDIR /home/user/firmrebugger/target

ENV PATH="$PATH:/home/user/.local/bin"
RUN pip3 install --user intelhex
RUN pip3 install --user $FUZZER/build/SEmu-Fuzz/
ENV FIRMREBUGGER_BASE_DIR=/home/user/firmrebugger

ENTRYPOINT ["uv", "run", "frb", "bug-analyzer", "."]
