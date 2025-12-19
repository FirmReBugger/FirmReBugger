#!/bin/bash
time_duration="$1"
trial_name="$2"
export AFL_NO_AFFINITY=1

AFL_COMPCOV_LEVEL=1 timeout "$time_duration" fuzzware pipeline -p "$trial_name" > "$trial_name".log 2>&1
exit_code=$?

mv "$trial_name".log "$trial_name"/fuzzer.log

if [ $exit_code -eq 124 ]; then
  echo "Fuzzware timed out after $time_duration seconds."
fi

exit $exit_code