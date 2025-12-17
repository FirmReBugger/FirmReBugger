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
  -t 150 \
  -Q \
  "${CONFIG_ARGS[@]}" > "$trial_name/fuzzer.log" 2>&1

exit_code=$?

if [ $exit_code -eq 124 ]; then
  echo "afl-fuzz timed out after $time_duration seconds." >> "$trial_name/fuzzer.log"
fi

exit $exit_code