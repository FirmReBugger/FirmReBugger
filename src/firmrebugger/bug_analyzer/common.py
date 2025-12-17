import os
import yaml
import time
import subprocess
import re
import sys
import io


def extract_bug_ids(file_path):
    pattern = re.compile(r'report_detected_triggered\("([^"]+)"\);')
    bug_ids = set()
    try:
        with open(file_path, "r") as file:
            content = file.read()
            content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
            content = re.sub(r"//.*", "", content)
            for line in content.splitlines():
                matches = pattern.findall(line)
                for bug_id in matches:
                    bug_ids.add(bug_id)
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
    except IOError:
        print(f"Error: An IOError occurred while reading the file {file_path}.")

    return bug_ids


# Initialize the run data structure
def init_run(campaign_data, run_name):
    if run_name not in campaign_data:
        campaign_data[run_name] = []
        campaign_data[run_name].append({"ungrouped_crashes": []})
        campaign_data[run_name].append({"multi_bugs_triggered": []})
    return campaign_data


# Initialize bug information in the run data
def init_bug_info(run_data, bug_id):
    run_data.append(
        {
            "bug_id": bug_id,
            "reached": None,
            "triggered": None,
            "detected": None,
            "raw_crash_data": [],
        }
    )
    return run_data


# Print bug information
def print_bug_info(run_data):
    for bug in run_data:
        if "bug_id" in bug:
            print(
                f"Bug ID: {bug['bug_id']}, Reached: {bug['reached']}, Triggered: {bug['triggered']}, Detected: {bug['detected']}"
            )
            if bug["reached"] is None and bug["triggered"] is not None:
                print(
                    f"Bug ID: {bug['bug_id']} has no reached time but has triggered time: {bug['triggered']} check Raven"
                )
                os._exit(1)


# Update execution time for a seed during bug analysis
def add_execution_time(all_times, data):
    if all_times:
        overall_avg = sum(all_times) / len(all_times)
    else:
        overall_avg = 0
    data["execution_time"] = {
        "input average": round(overall_avg, 2),
        "count": len(all_times),
    }


# Update bugs that are ungrouped
def append_to_ungrouped_crashes(run_data, crash_path):
    print(f"Appending ungrouped crash: {crash_path}")
    # _os.exit(1)
    for entry in run_data:
        if "ungrouped_crashes" in entry:
            entry["ungrouped_crashes"].append(crash_path)
            return run_data
    return run_data


def count_lines_of_bug_info(run_data):
    buf = io.StringIO()
    sys_stdout = sys.stdout
    sys.stdout = buf
    print_bug_info(run_data)
    sys.stdout = sys_stdout
    bug_info_output = buf.getvalue()
    return bug_info_output.count("\n")


# Print progress of bug analsis
def periodic_printer(run_data, stop_event, progress, crash):
    import sys

    crash_str = "Crash" if crash else "Reached"
    prev_lines_printed = 0
    while not stop_event.is_set() and progress["completed"] < progress["total"]:
        lines_to_print = 1 + count_lines_of_bug_info(run_data)

        for _ in range(prev_lines_printed):
            sys.stdout.write("\x1b[1A")
        for _ in range(prev_lines_printed):
            sys.stdout.write("\x1b[2K")
            sys.stdout.write("\x1b[1B")
        for _ in range(prev_lines_printed):
            sys.stdout.write("\x1b[1A")
        sys.stdout.flush()

        print(
            f"[Progress {crash_str}] Completed: {progress['completed']}/{progress['total']} | "
            f"{progress['Fuzzer']} | "
            f"{progress['Target']} | "
            f"{progress['run_name']} | "
            f"Total Ungrouped crashes: {progress['ungrouped_crashes']} |"
        )
        print_bug_info(run_data)
        sys.stdout.flush()
        prev_lines_printed = lines_to_print
        stop_event.wait(5)

    for _ in range(prev_lines_printed):
        sys.stdout.write("\x1b[1A")
    for _ in range(prev_lines_printed):
        sys.stdout.write("\x1b[2K")
        sys.stdout.write("\x1b[1B")
    for _ in range(prev_lines_printed):
        sys.stdout.write("\x1b[1A")
    sys.stdout.flush()

    # Print the final summary
    print(
        f"[Progress {crash_str}] Completed: {progress['total']}/{progress['total']} | "
        f"{progress['Fuzzer']} | "
        f"{progress['Target']} | "
        f"{progress['run_name']} | "
        f"Total Ungrouped crashes: {progress['ungrouped_crashes']} |"
    )
    print_bug_info(run_data)
    sys.stdout.flush()


# Update if mutliple bugs were triggered
def append_to_multi_bugs_triggered(run_data, seed_path):
    for entry in run_data:
        if "multi_bugs_triggered" in entry:
            entry["multi_bugs_triggered"].append(seed_path)
            return run_data
    return run_data


# Update bug triggered time
def update_triggered_time(run_data, bug_id, time):
    for bug in run_data:
        if bug.get("bug_id") == bug_id:
            if bug["triggered"] is None or (
                time is not None and time < bug["triggered"]
            ):
                bug["triggered"] = time
                return run_data
    return run_data


# Update bug reached time
def update_reached_time(run_data, bug_id, time):
    for bug in run_data:
        if bug.get("bug_id") == bug_id:
            if bug["reached"] is None or (time is not None and time < bug["reached"]):
                bug["reached"] = time
                return run_data
    return run_data


# Update bug detected time
def update_detected_time(run_data, bug_id, time):
    for bug in run_data:
        if bug.get("bug_id") == bug_id:
            if bug["detected"] is None or (time is not None and time < bug["detected"]):
                bug["detected"] = time
                return run_data
    return run_data


# Update raw crash data for a bug
def append_raw_crash_data(run_data, bug_id, seed_path):
    for bug in run_data:
        if bug.get("bug_id") == bug_id:
            if seed_path not in bug["raw_crash_data"]:
                bug["raw_crash_data"].append(seed_path)
            return run_data
    return run_data


# Update bug data function
def update_bug_data(
    run_data, time_val, seed_path, bugs_reached=None, bugs_triggered=None, Crash=False
):
    time_val = int(time_val)
    if bugs_triggered is None:
        bugs_triggered = []
    if bugs_reached is None:
        bugs_reached = []
    for bug in bugs_reached:
        run_data = update_reached_time(run_data, bug, time_val)
    if len(bugs_triggered) > 0:
        run_data = update_triggered_time(run_data, bugs_triggered[0], time_val)
        if Crash:
            run_data = append_raw_crash_data(run_data, bugs_triggered[0], seed_path)
            run_data = update_detected_time(run_data, bugs_triggered[0], time_val)
    if len(bugs_triggered) > 1 and Crash:
        run_data = append_to_multi_bugs_triggered(run_data, seed_path)
    if len(bugs_triggered) == 0 and Crash:
        run_data = append_to_ungrouped_crashes(run_data, seed_path)
    return run_data


# Get benchmark information from the result directory
def get_bench_info(result_dir):
    frb_bench_info = os.path.join(result_dir, "frb_bench_info.yml")
    with open(frb_bench_info, "r") as f:
        bench_info = yaml.safe_load(f)
    result = {}
    mapping = {
        "Fuzzer": "fuzzer",
        "Target": "target",
        "Num_Trials": "num_trials",
        "Total_Time": "total_time",
    }
    for k, v in mapping.items():
        # Find matching key ignoring case and underscores
        for key in bench_info:
            if key.lower().replace("_", "") == k.lower().replace("_", ""):
                val = bench_info[key]
                # Convert to int if appropriate
                if v in ["num_trials", "total_time"]:
                    try:
                        val = int(val)
                    except Exception:
                        pass
                result[v] = val
    return result


# Run seed to get time and reached/triggered info
def run_command(command, seed_path, time_val, Crash):
    start = time.time()
    result = subprocess.run(command, shell=True, text=True, capture_output=True)
    end = time.time()
    elapsed = end - start

    bugs_triggered = []
    bugs_reached = []
    errors = []
    triggered_found = False

    # output = result.stdout + "\n" + result.stderr
    # print(output)
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
        if Crash:
            if "SYSCTL_AIRCR" in line:
                errors.append(seed_path)
            if "input file not read until end" in result.stderr:
                # print(f"Warning: {seed_path} was not read until the end.")
                errors.append(seed_path)

    return seed_path, bugs_triggered, bugs_reached, time_val, elapsed, errors
