#!/bin/bash

# Function to check if a package is installed
check_pkg_installed() {
  if dpkg -s "$1" >/dev/null 2>&1; then
    echo "[+] $1 is installed."
  else
    echo "[!] $1 is NOT installed."
    MISSING_PKGS="$MISSING_PKGS $1"
  fi
}

# Function to check if docker is usable without sudo
check_docker_nosudo() {
  if docker info >/dev/null 2>&1; then
    echo "[+] Docker can be run without sudo."
  else
    echo "[!] Docker cannot be run without sudo."
    echo "    To fix this, run: sudo usermod -aG docker $USER and restart your session."
  fi
}

# List of required packages
REQUIRED_PKGS="curl git automake texinfo"
MISSING_PKGS=""

echo "Checking for required packages..."
for pkg in $REQUIRED_PKGS; do
  check_pkg_installed "$pkg"
done

if [ -n "$MISSING_PKGS" ]; then
  echo "[!] The following packages are missing and can be installed with:"
  echo "    sudo apt-get install$MISSING_PKGS"
else
  echo "[+] All required packages are installed."
fi

echo
echo "Checking docker permissions..."
check_docker_nosudo

#  Start building DICE image

FUZZER_IMAGE="frb_original:DICE"
QEMU_BIN="$FIRMREBUGGER_BASE_DIR/docker/DICE/original/DICE-DMA-Emulation/p2im/qemu/src/install/debian64/qemu/bin/qemu-system-gnuarmeclipse"

if [ -f "$QEMU_BIN" ]; then
  echo "[+] '$QEMU_BIN' already exists. Skipping QEMU build."
else
  echo "[+] '$QEMU_BIN' not found. Starting QEMU build..."
    # Build the docker image for p2im qemu build 
    cd "$FIRMREBUGGER_BASE_DIR/docker/DICE/original" || { echo "Failed to change directory to '$FIRMREBUGGER_BASE_DIR/docker/DICE/original'"; exit 1; }

    if [ ! -d "DICE-DMA-Emulation" ]; then
    git clone https://github.com/RiS3-Lab/DICE-DMA-Emulation.git || { echo "Failed to clone DICE-DMA-Emulation repo"; exit 1; }
    else
    echo "[+] 'DICE-DMA-Emulation' already exists, skipping git clone."
    fi

    cd DICE-DMA-Emulation || { echo "Failed to change directory to 'DICE-DMA-Emulation'"; exit 1; }
    git submodule update --init --recursive p2im

    git apply ./DICE-Patches/DICE-P2IM.patch --unsafe-paths --directory ./p2im/qemu/src/qemu.git/
    cd p2im/qemu || { echo "Failed to change directory to 'p2im/qemu'"; exit 1; }

    # Get fixes for debian build 
    git clone https://github.com/xgandiaga/DRIVERS.git
    mv DRIVERS/* ./build_scripts/ && rm -rf DRIVERS

    WORK_FOLDER_PATH=`pwd`/src ./build_scripts/build-qemu.sh --deb64 --no-strip

fi

docker buildx build --tag "$FUZZER_IMAGE" --load -f $FIRMREBUGGER_BASE_DIR/docker/DICE/original/Dockerfile . || { echo "Failed to build Docker image '$FUZZER_IMAGE'"; exit 1; }
echo "[+] Docker image '$FUZZER_IMAGE' built successfully."