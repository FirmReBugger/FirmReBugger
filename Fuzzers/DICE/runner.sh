#!/bin/bash
export AFL_NO_AFFINITY=1
export AFL_NO_UI=1

time_duration=$1
trial_name=$2

mkdir -p "$trial_name"
cp -r inputs "$trial_name/inputs"
mkdir -p "$trial_name/outputs"

export FUZZDIR="$trial_name"
program=$(sed -n 's/^[[:space:]]*program[[:space:]]*=[[:space:]]*//p' config.cfg)
# echo "$program"

sed -i "s|^\(run[[:space:]]*=[[:space:]]*\).*|\1$trial_name|" config.cfg

timeout --foreground "$time_duration" python3 -u "$DICE_BASE_DIR/DICE-Evaluation/ARM/Fuzzing/fuzz.py" -c config.cfg
pkill -9 -f afl-fuzz

exit_code=$?

exit $exit_code
