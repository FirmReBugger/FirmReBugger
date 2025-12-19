#!/bin/bash
time_duration=$1
trial_name=$2

export AFL_NO_AFFINITY=1
export AFL_NO_UI=1

mkdir -p "$trial_name"

timeout "$time_duration"  afl-fuzz -U -m none -i ./seeds -o "$trial_name" -t 10000 -- semu-fuzz @@ ./config.yml > "$trial_name/fuzzer.log" 2>&1

exit_code=$?
if [ $exit_code -eq 124 ]; then
  echo "afl-fuzz timed out after $time_duration seconds." >> "$trial_name/fuzzer.log"
fi

exit $exit_code