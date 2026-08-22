import os
import shutil
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from firmrebugger.bug_analyzer_utils.common import (
    get_available_cpu_count,
    periodic_printer,
    update_bug_data,
)
from firmrebugger.bug_analyzer_utils.replay_worker import PersistentReplayPool


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

    configured_workers = int(
        os.environ.get("MULTIFUZZ_REPLAY_WORKERS", str(get_available_cpu_count()))
    )
    num_workers = max(1, min(len(seeds), configured_workers, get_available_cpu_count()))
    config_path = f"{output_path}/../config.yml"
    hail_fuzz = os.path.join(multifuzzer_env, "target", "release", "hail-fuzz")

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

    def replay_env(workdir):
        env = os.environ.copy()
        env.update(
            {
                "ICICLE_DISABLE_JIT": "1",
                "TARGET_CONFIG": config_path,
                "WORKDIR": workdir,
            }
        )
        return env

    def check_replay_result(result, context):
        combined_output = f"{result.stdout or ''}\n{result.stderr or ''}"
        if result.returncode == 0:
            return

        output_tail = "\n".join(combined_output.splitlines()[-30:])
        raise RuntimeError(
            "MultiFuzz triaging failed during replay "
            f"({context}, exit code: {result.returncode}).\n"
            f"output (tail):\n{output_tail}"
        )

    def parse_seed_output(
        seed_path,
        stdout_lines,
        stderr_lines,
        time_val,
        elapsed,
        crash_mode,
        reached_ids=(),
        triggered_ids=(),
    ):
        stdout_lines = list(stdout_lines)
        stdout_lines.extend(f"REACHED: {bug_id}" for bug_id in reached_ids)
        stdout_lines.extend(f"TRIGGERED: {bug_id}" for bug_id in triggered_ids)
        bugs_triggered = []
        bugs_reached = []
        errors = []
        triggered_found = False

        for line in stdout_lines:
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
            terminal_lines = stdout_lines + stderr_lines
            if any(
                "exited with:" in line and ("ReadWatch" in line or "Halt" in line)
                for line in terminal_lines
            ):
                errors.append("NON_REPRODUCING")
            if any("SYSCTL_AIRCR" in line for line in stdout_lines):
                errors.append(seed_path)
            if any("input file not read until end" in line for line in stderr_lines):
                errors.append(seed_path)

        return seed_path, bugs_triggered, bugs_reached, time_val, elapsed, errors

    def run_multifuzz_command(seed_path, time_val, crash_mode):
        workdir = tempfile.mkdtemp(prefix="hail-fuzz-replay-")
        env = replay_env(workdir)
        env["REPLAY"] = seed_path

        try:
            result = replay_pool.replay(
                [hail_fuzz],
                seed_path,
                10,
                env=env,
                mode="crash" if crash_mode else "queue",
                timing=time_val,
            )
            if result.timed_out:
                elapsed = result.elapsed
                print(
                    f"[replay_worker] Timeout (10s) exceeded for seed: {seed_path} — skipping."
                )
                errors = ["NON_REPRODUCING"] if crash_mode else []
                return seed_path, [], [], time_val, elapsed, errors
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        elapsed = result.elapsed

        check_replay_result(result, f"seed: {seed_path}")
        return parse_seed_output(
            seed_path,
            result.stdout.splitlines(),
            result.stderr.splitlines(),
            time_val,
            elapsed,
            crash_mode,
            result.reached_ids,
            result.triggered_ids,
        )

    failure_exc = None
    failure_tb = None
    try:
        with PersistentReplayPool(
            num_workers, descriptor_path=descriptor_path
        ) as replay_pool:
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = [
                    executor.submit(
                        run_multifuzz_command,
                        seed_path,
                        get_time_input(seed_path),
                        Crash,
                    )
                    for seed_path in seeds
                ]

                for future in as_completed(futures):
                    try:
                        replay_result = future.result()
                    except Exception as exc:
                        for pending in futures:
                            pending.cancel()
                        raise exc

                    (
                        seed_path,
                        bugs_triggered,
                        bugs_reached,
                        time_val,
                        elapsed,
                        errors,
                    ) = replay_result
                    execution_times.append(elapsed)

                    if "NON_REPRODUCING" in errors:
                        progress["completed"] += 1
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
                    progress["ungrouped_crashes"] = len(
                        run_data[0]["ungrouped_crashes"]
                    )
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
