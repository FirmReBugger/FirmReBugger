#!/bin/bash
export AFL_NO_AFFINITY=1
export AFL_NO_UI=1

time_duration=$1
trial_name=$2
config_file=./config

mkdir -p "$trial_name"

mapfile -t CONFIG_ARGS < "$config_file"

timeout "$time_duration" "$EMBER_BASE_DIR/AFLplusplus/afl-fuzz" \
  -i ./seeds \
  -o "$trial_name" \
  -t 200 \
  -Q \
  "${CONFIG_ARGS[@]}"

exit_code=$?

exit $exit_code
