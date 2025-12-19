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

sed -i "s/^\(run[[:space:]]*=[[:space:]]*\).*/\1$trial_name/" config.cfg

timeout --foreground "$time_duration" python3 "$DICE_BASE_DIR/DICE-Evaluation/ARM/Fuzzing/fuzz.py" -c config.cfg > "$trial_name/fuzzer.log" 2>&1
pkill -9 -f afl-fuzz

exit_code=$?

if [ $exit_code -eq 124 ]; then
  echo "afl-fuzz timed out after $time_duration seconds." >> "$trial_name/fuzzer.log"
fi

exit $exit_code