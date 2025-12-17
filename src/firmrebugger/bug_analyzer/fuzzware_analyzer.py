import os
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from firmrebugger.bug_analyzer.common import (
    update_bug_data,
    run_command,
    periodic_printer,
)
import threading
from firmrebugger.utils.common import get_working_dirs
import glob


def get_time_data_fuzzware(crash_timing_path):
    time_data = []
    with open(crash_timing_path, "r") as f:
        for line in f:
            time, crash_path = line.strip().split(None, 1)
            time_data.append((time, crash_path))

    return time_data


def replace_main_config(output_path):
    for main_dir in glob.glob(os.path.join(output_path, "main*")):
        config_path = os.path.join(main_dir, "config.yml")

        if os.path.exists(config_path):
            # Read only the first line to check if it's already commented
            with open(config_path, "r") as f:
                first_line = f.readline().strip()

            if not first_line.startswith("#"):
                # Apply sed only if the first line is NOT commented
                subprocess.run(["sed", "-i", "1s/^/# /", config_path])


def gen_fuzzware_stats(RESULT_DIR, fuzzer):
    def process_output_dir(output):
        if fuzzer == "Fuzzware-Icicle":
            replace_main_config(output)

        command = ["fuzzware", "genstats", "crashtimings", "-p", f"{output}"]

        try:
            result = subprocess.run(
                command,
                check=True,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.stderr:
                print(f"Command error output for {output}:")
                print(result.stderr)
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while running fuzzware for {output}: {e.stderr}")
            return False
        return True

    output_dirs = get_working_dirs(RESULT_DIR)

    with ThreadPoolExecutor(
        max_workers=min(len(output_dirs), os.cpu_count())
    ) as executor:
        future_to_output = {
            executor.submit(process_output_dir, output): output
            for output in output_dirs
        }

        failed_outputs = []
        for future in as_completed(future_to_output):
            output = future_to_output[future]
            try:
                success = future.result()
                if not success:
                    failed_outputs.append(output)
            except Exception as exc:
                print(f"Output {output} generated an exception: {exc}")
                failed_outputs.append(output)

    if failed_outputs:
        print(
            f"Failed to generate fuzzware stats the following outputs: {failed_outputs}"
        )
        sys.exit(1)


def fuzzware_analyzer(
    bench_info,
    output_path,
    run_data=None,
    Crash=False,
    run_name=None,
    descriptor_path=None,
):
    os.environ["FIRMREBUGGER_CONFIG"] = descriptor_path
    execution_times = []
    fuzzer = bench_info["fuzzer"]
    GHIDRA_SRC = os.environ.get("GHIDRA_SRC", None)

    if fuzzer == "Fuzzware-Icicle":
        os.environ["GHIDRA_SRC"] = GHIDRA_SRC
        if os.environ.get("GHIDRA_SRC") is None:
            print(
                "The environment variable 'GHIDRA_SRC' is not set for Fuzzware-Icicle."
            )
            sys.exit(1)

    gen_fuzzware_stats(f"{output_path}/../", fuzzer)
    crash_timing_path = os.path.join(output_path, "stats", "crash_creation_timings.txt")
    input_timing_path = os.path.join(output_path, "stats", "input_creation_timings.txt")

    if not os.path.exists(crash_timing_path) or not os.path.exists(input_timing_path):
        print(f"Timing files not found in {output_path}.")
        sys.exit(1)
    if Crash:
        seed_info = get_time_data_fuzzware(crash_timing_path)
    else:
        seed_info = get_time_data_fuzzware(input_timing_path)

    num_cores = os.cpu_count()
    num_workers = max(1, int(num_cores) - 1)

    progress = {
        "completed": 0,
        "total": len(seed_info),
        "run_name": run_name,
        "ungrouped_crashes": 0,
        "Fuzzer": bench_info["fuzzer"],
        "Target": bench_info["target"],
    }
    stop_event = threading.Event()

    printer_thread = threading.Thread(
        target=periodic_printer, args=(run_data, stop_event, progress, Crash)
    )
    printer_thread.start()

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for time_val, seed_path in seed_info:
            full_seed_path = os.path.join(output_path, seed_path)
            command = f"fuzzware replay -v {full_seed_path}"
            futures.append(
                executor.submit(run_command, command, seed_path, time_val, Crash)
            )

        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            seed_path, bugs_triggered, bugs_reached, time_val, elapsed, errors = result
            execution_times.append(elapsed)
            if errors:
                continue

            run_data = update_bug_data(
                run_data,
                time_val,
                seed_path,
                bugs_triggered=bugs_triggered,
                bugs_reached=bugs_reached,
                Crash=Crash,
            )
            progress["completed"] += 1
            progress["ungrouped_crashes"] = len(run_data[0]["ungrouped_crashes"])

    stop_event.set()
    printer_thread.join()

    return run_data, execution_times
