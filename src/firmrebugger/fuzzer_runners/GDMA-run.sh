#!/bin/bash
time_duration="$1"
trial_name="$2"
export AFL_NO_AFFINITY=1

timeout "$time_duration" fuzzware pipeline --dma -p "$trial_name"
exit_code=$?

exit $exit_code
