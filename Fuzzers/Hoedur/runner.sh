#!/bin/bash
time_duration=$1
trial_name=$2

export LD_LIBRARY_PATH="$HOME/.cargo/bin/"

mkdir -p "$trial_name"

timeout "$time_duration" hoedur-dict-arm --fuzzware --config config.yml fuzz --archive-dir "$trial_name"
exit_code=$?

exit $exit_code
