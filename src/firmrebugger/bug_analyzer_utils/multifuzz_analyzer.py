import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from firmrebugger.bug_analyzer_utils.common import (
    update_bug_data,
    run_command,
    periodic_printer,
)
import threading


def get_multifuzz_env():
    if "MULTIFUZZ_BASE_DIR" not in os.environ:
        raise EnvironmentError(
            "The environment variable 'MULTIFUZZ_BASE_DIR' is not set."
        )
        sys.exit(1)

    multifuzzer_env = os.environ["MULTIFUZZ_BASE_DIR"]
    return multifuzzer_env


def get_time_input(seed_path):
    output_path = os.path.normpath(os.path.join(seed_path, "..", ".."))
    try:
        crash_creation_time = os.path.getmtime(seed_path)

        cmplog_path = os.path.join(output_path, "cmplog")
        cmplog_creation_time = os.path.getmtime(cmplog_path)

        time_difference = crash_creation_time - cmplog_creation_time

        # Return the result with zero decimal points
        return int(time_difference)
    except Exception as e:
        print(f"Error: {e}")
        return None


def multifuzzer_analyzer(
    bench_info,
    output_path,
    run_data=None,
    Crash=False,
    run_name=None,
    descriptor_path=None,
):
    # Set the environment variable for the entire process
    os.environ["FIRMREBUGGER_CONFIG"] = descriptor_path
    GHIDRA_SRC = os.environ.get("GHIDRA_SRC", None)
    if not GHIDRA_SRC:
        raise EnvironmentError(
            "The environment variable 'GHIDRA_SRC' is not set for MultiFuzz."
        )
    os.environ["GHIDRA_SRC"] = GHIDRA_SRC

    execution_times = []
    multifuzzer_env = get_multifuzz_env()

    if not Crash:
        working_folder = os.path.join(output_path, "queue")
        if not os.path.isdir(working_folder):
            raise FileNotFoundError(
                f"The 'Queue' folder does not exist at: {working_folder}"
            )
    else:
        working_folder = os.path.join(output_path, "crashes")
        if not os.path.isdir(working_folder):
            raise FileNotFoundError(
                f"The 'Crashes' folder does not exist at: {working_folder}"
            )
    seeds = [
        os.path.join(working_folder, seed)
        for seed in sorted(os.listdir(working_folder))
        if "README" not in seed
    ]
    num_cores = os.cpu_count()
    num_workers = max(1, int(num_cores) - 1)
    config_path = f"{output_path}/../config.yml"

    progress = {
        "completed": 0,
        "total": len(seeds),
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
        for seed_path in seeds:
            command = f"REPLAY={seed_path} TARGET_CONFIG={config_path} {multifuzzer_env}/target/release/hail-fuzz"
            futures.append(
                executor.submit(
                    run_command, command, seed_path, get_time_input(seed_path), Crash
                )
            )

        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            seed_path, bugs_triggered, bugs_reached, time_val, elapsed, errors = result
            execution_times.append(elapsed)

            run_data = update_bug_data(
                run_data,
                time_val,
                seed_path,
                bugs_triggered=bugs_triggered,
                bugs_reached=bugs_reached,
                Crash=Crash,
            )
            # print(run_data)

            progress["completed"] += 1
            progress["ungrouped_crashes"] = len(run_data[0]["ungrouped_crashes"])

    stop_event.set()
    printer_thread.join()

    return run_data, execution_times
