#!/bin/bash
FUZZER_IMAGE="frb:MultiFuzz"

docker buildx build  \
  --tag "$FUZZER_IMAGE" \
  --load \
  -f docker/MultiFuzz/frb/Dockerfile \
  . \
  || { echo "Failed to build Docker image '$FUZZER_IMAGE'"; exit 1; }

echo "[+] Docker image '$FUZZER_IMAGE' built successfully."