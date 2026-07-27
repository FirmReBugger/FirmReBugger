import glob
import os
import shlex
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from firmrebugger.bug_analyzer_utils.common import (
    get_available_cpu_count,
    periodic_printer,
    run_command,
    update_bug_data,
)
from firmrebugger.common import get_working_dirs


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

    if not output_dirs:
        return

    with ThreadPoolExecutor(
        max_workers=min(len(output_dirs), get_available_cpu_count())
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

    progress = {
        "completed": 0,
        "total": len(seed_info),
        "run_name": run_name,
        "ungrouped_crashes": 0,
        "Fuzzer": bench_info["fuzzer"],
        "Target": bench_info["target"],
        "failed": False,
        "failure_message": None,
    }
    stop_event = threading.Event()

    printer_thread = threading.Thread(
        target=periodic_printer, args=(run_data, stop_event, progress, Crash)
    )
    printer_thread.start()

    failure_exc = None
    failure_tb = None
    try:
        # Use all visible CPUs, capped by replay items to avoid thread oversubscription.
        num_workers = max(1, min(len(seed_info), get_available_cpu_count()))

        def _process_seed(seed_tuple):
            time_val, seed_path = seed_tuple
            full_seed_path = os.path.join(output_path, seed_path)
            command = f"fuzzware replay -v {shlex.quote(full_seed_path)}"
            return run_command(command, seed_path, time_val, Crash, 10)

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_process_seed, item) for item in seed_info]

            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    for pending in futures:
                        pending.cancel()
                    raise exc

                if result is None:
                    progress["completed"] += 1
                    continue

                (
                    seed_path,
                    bugs_triggered,
                    bugs_reached,
                    time_val,
                    elapsed,
                    errors,
                ) = result
                execution_times.append(elapsed)

                if not errors:
                    run_data = update_bug_data(
                        run_data,
                        time_val,
                        seed_path,
                        bugs_triggered=bugs_triggered,
                        bugs_reached=bugs_reached,
                        Crash=Crash,
                    )
                    progress["ungrouped_crashes"] = len(
                        run_data[0]["ungrouped_crashes"]
                    )

                progress["completed"] += 1
    except Exception as exc:
        progress["failed"] = True
        progress["failure_message"] = str(exc)
        failure_exc = exc
        failure_tb = exc.__traceback__
    finally:
        stop_event.set()
        printer_thread.join()

    if failure_exc is not None:
        print(
            "\n[ERROR Fuzzware Triaging] Triaging aborted due to replay error.\n"
            f"{progress['failure_message']}\n",
            file=sys.stderr,
            flush=True,
        )
        raise failure_exc.with_traceback(failure_tb)

    return run_data, execution_times
