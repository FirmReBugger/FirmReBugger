#!/bin/bash
time_duration=$1
trial_name=$2

mkdir -p "$trial_name"

MAX_I2S_BYTES=1024 TARGET_CONFIG=./config.yml WORKDIR="$trial_name" \
timeout "$time_duration" "/home/user/multifuzz/MultiFuzz/target/release/hail-fuzz"

exit_code=$?

exit $exit_code
