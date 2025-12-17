import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from firmrebugger.bug_analyzer.common import (
    update_bug_data,
    run_command,
    periodic_printer,
)
import re


def get_time_input(seed_path):
    match = re.search(r"time[_:](\d+)", seed_path)
    if match:
        time_value = round(int(match.group(1)) / 1000)
        return time_value
    else:
        print(seed_path)
        return None


def semu_analyzer(
    bench_info,
    output_path,
    run_data=None,
    Crash=False,
    run_name=None,
    descriptor_path=None,
):
    os.environ["FIRMREBUGGER_CONFIG"] = descriptor_path
    execution_times = []
    if not Crash:
        working_folder = os.path.join(output_path, "default", "queue")
        if not os.path.isdir(working_folder):
            raise FileNotFoundError(
                f"The 'Queue' folder does not exist at: {working_folder}"
            )
    else:
        working_folder = os.path.join(output_path, "default", "crashes")
        if not os.path.isdir(working_folder):
            raise FileNotFoundError(
                f"The 'Crashes' folder does not exist at: {working_folder}"
            )

    seeds = [
        os.path.join(working_folder, seed)
        for seed in sorted(os.listdir(working_folder))
        if "README" not in seed and os.path.basename(seed).startswith("id")
    ]
    config_path = os.path.abspath("./config.yml")
    num_cores = os.cpu_count()
    num_workers = max(1, int(num_cores) - 1)

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
            command = f"stdbuf -oL -eL semu-fuzz {seed_path} {config_path}"
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

            progress["completed"] += 1
            progress["ungrouped_crashes"] = len(run_data[0]["ungrouped_crashes"])

    stop_event.set()
    printer_thread.join()

    return run_data, execution_times
