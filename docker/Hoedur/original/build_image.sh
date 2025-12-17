#!/bin/bash
FUZZWARE_IMAGE="frb_original:Fuzzware"
HOEDUR_IMAGE="frb_original:Hoedur"

if docker image inspect "$FUZZWARE_IMAGE" > /dev/null 2>&1; then
  echo "Docker image '$FUZZWARE_IMAGE' exists locally."
else
  echo "Docker image '$FUZZWARE_IMAGE' does NOT exist locally."

  docker buildx build --tag "$FUZZWARE_IMAGE" --load -f $FIRMREBUGGER_BASE_DIR/docker/Fuzzware/original/Dockerfile . || { echo "Failed to build Docker image '$FUZZWARE_IMAGE'"; exit 1; }
fi

docker buildx build --tag "$HOEDUR_IMAGE" --load -f $FIRMREBUGGER_BASE_DIR/docker/Hoedur/original/Dockerfile . || { echo "Failed to build Docker image '$HOEDUR_IMAGE'"; exit 1; }

echo "[+] Docker image '$HOEDUR_IMAGE' built successfully."