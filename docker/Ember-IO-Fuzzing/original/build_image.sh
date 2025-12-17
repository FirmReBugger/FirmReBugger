#!/bin/bash
FUZZER_IMAGE="frb_original:Ember-IO-Fuzzing"

docker buildx build --tag "$FUZZER_IMAGE" --load -f $FIRMREBUGGER_BASE_DIR/docker/Ember-IO-Fuzzing/original/Dockerfile . || { echo "Failed to build Docker image '$FUZZER_IMAGE'"; exit 1; }

echo "[+] Docker image '$FUZZER_IMAGE' built successfully."