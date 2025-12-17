import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from firmrebugger.bug_analyzer.common import (
    update_bug_data,
    run_command,
    periodic_printer,
)
import re


def final_model(path="."):
    max_num = None
    for name in os.listdir(path):
        folder_path = os.path.join(path, name)
        if os.path.isdir(folder_path) and name.isdigit():
            n = int(name)
            if (max_num is None) or (n > max_num):
                max_num = n
    return max_num


def get_time_input(seed_path, fuzzer_stats_path="default/fuzzer_stats"):
    try:
        file_mtime = int(os.path.getmtime(seed_path))
    except Exception as e:
        raise RuntimeError(f"Could not get mtime for {seed_path}: {e}")

    try:
        with open(fuzzer_stats_path, "r") as f:
            for line in f:
                if line.startswith("start_time"):
                    match = re.search(r"\d+", line)
                    if match:
                        start_time = int(match.group())
                        break
            else:
                raise RuntimeError(f"start_time not found in {fuzzer_stats_path}")
    except Exception as e:
        raise RuntimeError(f"Could not read {fuzzer_stats_path}: {e}")

    return file_mtime - start_time


def get_run_parameters(output_path):
    file_info = ""
    file_return = []

    cmdline_path = os.path.join(output_path, "default", "cmdline")
    if not os.path.isfile(cmdline_path):
        raise FileNotFoundError(f"The 'cmdline' file does not exist at: {cmdline_path}")

    with open(cmdline_path, "r") as file:
        filename = ""
        for line in file:
            line = line.strip()
            if line.endswith(".elf"):
                filename = line.rsplit("/", 1)[-1]
            elif filename == "":
                sys.exit(f"Error: No ELF file found in cmdline at {cmdline_path}")
            else:
                if "@@" in line:
                    file_return.append(filename)
                    file_return.append(file_info)
                    return file_return
                file_info += line + " "


def dice_analyzer(
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
    original_dir = os.getcwd()

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        # change dir
        os.chdir(output_path)
        model = final_model()
        for seed_path in seeds:
            command = f"stdbuf -oL -eL ./run_fw.py {model} {seed_path}"
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
    os.chdir(original_dir)
    return run_data, execution_times
