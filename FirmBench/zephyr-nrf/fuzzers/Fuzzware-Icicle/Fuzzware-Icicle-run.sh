#!/bin/bash
time_duration="$1"
trial_name="$2"
export AFL_NO_AFFINITY=1

AFL_COMPCOV_LEVEL=1 timeout "$time_duration" fuzzware pipeline -p "$trial_name" --base-inputs ./seeds/
exit_code=$?

exit $exit_code
