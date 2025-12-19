#!/bin/bash
time_duration=$1
trial_name=$2

mkdir -p "$trial_name"

MAX_I2S_BYTES=1024 TARGET_CONFIG=./config.yml WORKDIR="$trial_name" \
timeout "$time_duration" "/home/user/multifuzz/MultiFuzz/target/release/hail-fuzz" > "$trial_name/fuzzer.log" 2>&1

exit_code=$?

if [ $exit_code -eq 124 ]; then
  echo "hail-fuzz timed out after $time_duration seconds." >> "$trial_name/fuzzer.log"
fi

exit $exit_code