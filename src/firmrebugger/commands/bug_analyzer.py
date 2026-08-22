import glob
import importlib.util
import json
import os
import re
import sys

from firmrebugger.bug_analyzer_utils.common import (
    add_execution_time,
    extract_bug_ids,
    get_bench_info,
    init_bug_info,
    init_run,
    print_bug_info,
)
from firmrebugger.charting_tool_utils.summarize_data import summarize_data
from firmrebugger.commands.gen_symbols import run_gen_symbols
from firmrebugger.common import get_frb_base_dir, get_working_dirs


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
    """Load the `analyze` function from Fuzzers/<fuzzer>/analyzer.py.

    Every integrated fuzzer registers its results parser this way, so adding
    a new fuzzer never requires touching this file — just drop an
    analyzer.py next to its runner.sh.
    """
    base_dir = get_frb_base_dir()
    analyzer_path = os.path.join(base_dir, "Fuzzers", fuzzer, "analyzer.py")
    if not os.path.isfile(analyzer_path):
        print(
            f"Error: no analyzer.py found for fuzzer '{fuzzer}' "
            f"(expected at {analyzer_path})"
        )
        sys.exit(1)

    spec = importlib.util.spec_from_file_location(
        f"firmrebugger._fuzzer_analyzer_{fuzzer}", analyzer_path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    analyze = getattr(module, "analyze", None)
    if analyze is None:
        print(f"Error: {analyzer_path} does not define an 'analyze' function")
        sys.exit(1)

    return analyze


def generate_frb_report(fuzzing_results_dir, descriptor_path):
    output_dirs = get_working_dirs(fuzzing_results_dir)
    bug_list = extract_bug_ids(descriptor_path)
    bench_info = get_bench_info(fuzzing_results_dir)

    symbols_path = os.path.join(fuzzing_results_dir, "symbols.txt")
    if os.path.isfile(symbols_path):
        print(f"Found symbols file: {symbols_path}")
        os.environ["FIRMREBUGGER_SYMBOLS"] = symbols_path
    else:
        elf_files = glob.glob(os.path.join(fuzzing_results_dir, "*.elf"))
        if elf_files:
            elf_path = elf_files[0]
            print(f"symbols.txt not found, generating from ELF: {elf_path}")
            run_gen_symbols(elf_path, symbols_path)
            os.environ["FIRMREBUGGER_SYMBOLS"] = symbols_path
        else:
            print(
                "Warning: symbols.txt not found and no ELF file found in results directory. frb_symbolize() will not work."
            )
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
    summary_view = summary_df[["BugID", "MedianDetectedTime", "DetectedCount"]]
    print(summary_view.to_string(index=False))
    print("\n")


def run_bug_analyzer(fuzzing_results_dir, descriptor_path):
    print("Starting Bug Analyzer...")
    descriptor_path = os.path.abspath(descriptor_path)

    if not os.path.isfile(descriptor_path):
        print(f"Descriptor file not found: {descriptor_path}")
        sys.exit(1)
    generate_frb_report(fuzzing_results_dir, descriptor_path)
