#!/bin/bash
time_duration=$1
trial_name=$2

export LD_LIBRARY_PATH="$HOME/.cargo/bin/"

mkdir -p "$trial_name"

timeout "$time_duration" hoedur-dict-arm --fuzzware --config config.yml fuzz --archive-dir "$trial_name" > "$trial_name/fuzzer.log" 2>&1
exit_code=$?

if [ $exit_code -eq 124 ]; then
  echo "hoedur-dict-arm timed out after $time_duration seconds." >> "$trial_name/fuzzer.log"
fi

exit $exit_code