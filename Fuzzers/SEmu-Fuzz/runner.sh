#!/bin/bash
time_duration=$1
trial_name=$2

export AFL_NO_AFFINITY=1
export AFL_NO_UI=1

mkdir -p "$trial_name"

timeout "$time_duration"  afl-fuzz -U -m none -i ./seeds -o "$trial_name" -t 10000 -- semu-fuzz @@ ./config.yml

exit_code=$?

exit $exit_code
