#!/bin/bash
FUZZER_IMAGE="frb:Fuzzware"

docker buildx build \
  --tag "$FUZZER_IMAGE" \
  --load \
  \
  --build-arg USERID="${USERID:-1000}" \
  -f docker/Fuzzware/frb/Dockerfile \
  . \
  || { echo "Failed to build Docker image '$FUZZER_IMAGE'"; exit 1; }

echo "[+] Docker image '$FUZZER_IMAGE' built successfully."
