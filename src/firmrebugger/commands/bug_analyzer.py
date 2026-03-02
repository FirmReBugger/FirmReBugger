from firmrebugger.bug_analyzer_utils.common import (
    init_run,
    add_execution_time,
    init_bug_info,
    get_bench_info,
    print_bug_info,
    extract_bug_ids,
)
from firmrebugger.common import get_working_dirs
from firmrebugger.bug_analyzer_utils.ember_analyzer import ember_analyzer
from firmrebugger.bug_analyzer_utils.fuzzware_analyzer import fuzzware_analyzer
from firmrebugger.bug_analyzer_utils.hoedur_analyzer import hoedur_analyzer
from firmrebugger.bug_analyzer_utils.multifuzz_analyzer import multifuzzer_analyzer
from firmrebugger.charting_tool_utils.summarize_data import summarize_data
from firmrebugger.bug_analyzer_utils.semu_analyzer import semu_analyzer
from firmrebugger.bug_analyzer_utils.dice_analyzer import dice_analyzer

import os
import sys
import re
import json
import shutil
import tarfile
from concurrent.futures import ThreadPoolExecutor, as_completed

fuzzer_function_mapping = {
    "Ember-IO-Fuzzing": ember_analyzer,
    "Fuzzware": fuzzware_analyzer,
    "Fuzzware-Icicle": fuzzware_analyzer,
    "SplITS": fuzzware_analyzer,
    "Hoedur": hoedur_analyzer,
    "MultiFuzz": multifuzzer_analyzer,
    "SEmu-Fuzz": semu_analyzer,
    "GDMA": fuzzware_analyzer,
    "DICE": dice_analyzer,
}


def get_run_number(output):
    output = os.path.basename(output)
    match = re.search(r"output-(\d+)", output)
    if not match:
        print(
            f"Error: '{output}' does not match the expected pattern 'output-<number>'"
        )
        sys.exit(1)
    else:
        number = int(match.group(1))
        return number


def get_fuzzer_function(fuzzer):
    if fuzzer in fuzzer_function_mapping:
        return fuzzer_function_mapping[fuzzer]
    else:
        print(f"Error: No analysis function defined for fuzzer '{fuzzer}'")
        sys.exit(1)


def generate_frb_report(fuzzing_results_dir, descriptor_path):
    output_dirs = get_working_dirs(fuzzing_results_dir)
    bug_list = extract_bug_ids(descriptor_path)
    bench_info = get_bench_info(fuzzing_results_dir)
    fuzzer = bench_info["fuzzer"]
    target = bench_info["target"]
    data = {
        "Fuzzer": fuzzer,
        "Target": target,
        "Number-Trials": bench_info["num_trials"],
        "Trial-Time": bench_info["total_time"],
        "Campaign": {},
    }

    data_to_print = {k: v for k, v in data.items() if k != "Campaign"}
    print(json.dumps(data_to_print, indent=4))
    all_times = []

    for output in output_dirs:
        run_count = get_run_number(output)
        print(f"---- run{run_count} ----")
        data["Campaign"] = init_run(data["Campaign"], f"run-{run_count}")
        for bug_id in bug_list:
            data["Campaign"][f"run-{run_count}"] = init_bug_info(
                data["Campaign"][f"run-{run_count}"], bug_id
            )

        analyzer_function = get_fuzzer_function(fuzzer)
        run_data, time_inputs = analyzer_function(
            bench_info,
            output,
            run_data=data["Campaign"][f"run-{run_count}"],
            Crash=False,
            run_name=f"run-{run_count}",
            descriptor_path=descriptor_path,
        )
        run_data, time_crashes = analyzer_function(
            bench_info,
            output,
            run_data=data["Campaign"][f"run-{run_count}"],
            Crash=True,
            run_name=f"run-{run_count}",
            descriptor_path=descriptor_path,
        )

        all_times.extend(time_inputs)
        all_times.extend(time_crashes)
        print_bug_info(run_data)

    add_execution_time(all_times, data)

    # print(data)

    with open(f"{fuzzing_results_dir}/frb_report.json", "w") as json_file:
        json.dump(data, json_file, indent=4)

    print("Summary of the analysis:")
    summary_df = summarize_data(f"{fuzzing_results_dir}/frb_report.json")
    print(summary_df[["BugID", "MedianDetectedTime", "DetectedCount"]])
    print("\n")


def run_bug_analyzer(fuzzing_results_dir, descriptor_path):
    print("Starting Bug Analyzer...")
    descriptor_path = os.path.abspath(descriptor_path)

    if not os.path.isfile(descriptor_path):
        print(f"Descriptor file not found: {descriptor_path}")
        sys.exit(1)
    generate_frb_report(fuzzing_results_dir, descriptor_path)
