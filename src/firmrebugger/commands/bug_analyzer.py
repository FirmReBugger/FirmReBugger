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


def tar_folder(folder_paths):
    print("Archiving folders to tar.gz files...")

    def process_folder(path):
        if not os.path.isdir(path):
            print(f"Error: {path} is not a valid directory.")
            return None

        archive_name = path.rstrip(os.sep).split(os.sep)[-1] + ".tar.gz"
        try:
            # print(f"Creating archive for {path}: {archive_name}")
            with tarfile.open(archive_name, "w:gz") as tar:
                tar.add(path, arcname=os.path.basename(path))
            print(f"Archive {archive_name} created successfully. at {path}")
            return path
        except Exception as e:
            print(f"Error while creating tar.gz archive for {path}: {e}")
            return None

    completed = []
    try:
        with ThreadPoolExecutor() as executor:
            futures = {
                executor.submit(process_folder, path): path for path in folder_paths
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    completed.append(result)
    except KeyboardInterrupt:
        print("Interrupted! Not deleting any folders.")
        return

    if len(completed) == len(folder_paths):
        for path in completed:
            shutil.rmtree(path)
    else:
        print("Not all folders were archived successfully.")


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
        "Trial-Time": bench_info["total_time"],  # time in seconds
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
        json.dump(data, json_file, indent=4)  # Save the JSON data to the file

    print("Summary of the analysis:")
    print(summarize_data(f"{fuzzing_results_dir}/frb_report.json"))
    print("\n")

    # Tar the output directories for fuzzers that use alot of space
    if (
        "Fuzzware-Icicle" in fuzzer
        or "SplITS" in fuzzer
        or "Fuzzware" in fuzzer
        or "GDMA" in fuzzer
        or "DICE" in fuzzer
    ):
        tar_folder(output_dirs)


def run_bug_analyzer(fuzzing_results_dir):
    print("Starting Bug Analyzer...")
    descriptor_path = f"{fuzzing_results_dir}/../../../../bug_descriptor.c"
    descriptor_path = os.path.abspath(descriptor_path)

    if not os.path.isfile(descriptor_path):
        print(f"Descriptor file not found: {descriptor_path}")
        sys.exit(1)
    generate_frb_report(fuzzing_results_dir, descriptor_path)
