import os
import re
import subprocess
import sys
import threading

from firmrebugger.bug_analyzer_utils.common import (
    periodic_printer,
    update_bug_data,
)


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
        "failed": False,
        "failure_message": None,
    }
    stop_event = threading.Event()

    printer_thread = threading.Thread(
        target=periodic_printer, args=(run_data, stop_event, progress, Crash)
    )
    printer_thread.start()

    def run_multifuzz_command(seed_path, time_val, crash_mode):
        command = (
            f"ICICLE_DISABLE_JIT=1 REPLAY={seed_path} TARGET_CONFIG={config_path} "
            f"{multifuzzer_env}/target/release/hail-fuzz"
        )

        start = os.times()[4]
        try:
            result = subprocess.run(
                command, shell=True, text=True, capture_output=True, timeout=10
            )
        except subprocess.TimeoutExpired:
            elapsed = os.times()[4] - start
            print(
                f"[run_multifuzz_command] Timeout (10s) exceeded for seed: {seed_path} — skipping."
            )
            return seed_path, [], [], time_val, elapsed, []
        elapsed = os.times()[4] - start

        bugs_triggered = []
        bugs_reached = []
        errors = []
        triggered_found = False

        for line in result.stdout.splitlines():
            if not triggered_found and "REACHED:" in line:
                bug_id = line.split(":", 1)[1].strip()
                if bug_id not in bugs_reached:
                    bugs_reached.append(bug_id)
            if "TRIGGERED:" in line:
                triggered_found = True
                bug_id = line.split(":", 1)[1].strip()
                if bug_id not in bugs_triggered:
                    bugs_triggered.append(bug_id)

            if crash_mode:
                if "SYSCTL_AIRCR" in line:
                    errors.append(seed_path)
                if "input file not read until end" in result.stderr:
                    errors.append(seed_path)

        combined_output = f"{result.stdout or ''}\n{result.stderr or ''}"
        combined_lower = combined_output.lower()
        has_frb_config_init = "firmrebugger config" in combined_lower
        has_c_parse_error = (
            re.search(r":\d+:\s*error:", combined_output, re.IGNORECASE) is not None
        )
        has_missing_config_error = (
            "please set firmrebugger_config path" in combined_lower
        )
        descriptor_error = (
            has_frb_config_init and has_c_parse_error
        ) or has_missing_config_error

        if result.returncode != 0 or descriptor_error:
            output_tail = "\n".join(combined_output.splitlines()[-30:])
            raise RuntimeError(
                "MultiFuzz triaging failed during replay "
                f"(seed: {seed_path}, exit code: {result.returncode}).\n"
                f"output (tail):\n{output_tail}"
            )

        return seed_path, bugs_triggered, bugs_reached, time_val, elapsed, errors

    failure_exc = None
    failure_tb = None
    try:
        for seed_path in seeds:
            result = run_multifuzz_command(seed_path, get_time_input(seed_path), Crash)
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
            "\n[ERROR MultiFuzz Triaging] Triaging aborted due to replay error.\n"
            f"{progress['failure_message']}\n",
            file=sys.stderr,
            flush=True,
        )
        raise failure_exc.with_traceback(failure_tb)

    return run_data, execution_times
