#!/bin/bash
FUZZER_IMAGE="frb_original:SplITS"

docker buildx build --tag "$FUZZER_IMAGE" --load -f $FIRMREBUGGER_BASE_DIR/docker/SplITS/original/Dockerfile . || { echo "Failed to build Docker image '$FUZZER_IMAGE'"; exit 1; }

echo "[+] Docker image '$FUZZER_IMAGE' built successfully."