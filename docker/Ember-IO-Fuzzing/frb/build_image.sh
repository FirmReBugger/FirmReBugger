#!/bin/bash
FUZZER_IMAGE="frb:Ember-IO-Fuzzing"

docker buildx build \
  --tag "$FUZZER_IMAGE" \
  --load \
  -f docker/Ember-IO-Fuzzing/frb/Dockerfile \
  . \
  || { echo "Failed to build Docker image '$FUZZER_IMAGE'"; exit 1; }

echo "[+] Docker image '$FUZZER_IMAGE' built successfully."
