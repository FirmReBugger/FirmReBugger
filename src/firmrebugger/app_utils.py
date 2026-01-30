import os
import re
import glob
import psutil
import json
from collections import defaultdict
from firmrebugger.common import get_frb_base_dir
from lifelines.utils import restricted_mean_survival_time as rmst
from lifelines import KaplanMeierFitter
import numpy as np

def convert_numpy_types(obj):
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    return obj


def check_fuzzers(benchmark):
    """For a given benchmark, return a list of valid fuzzers to select"""
    base_dir = get_frb_base_dir()
    benchmark_dir = os.path.join(base_dir, benchmark)
    valid_fuzzers = set()
    fuzzer_dirs = glob.glob(f"{benchmark_dir}/*/fuzzers/")

    for fuzzer_dir in fuzzer_dirs:
        if os.path.isdir(fuzzer_dir):
            for item in os.listdir(fuzzer_dir):
                item_path = os.path.join(fuzzer_dir, item)
                if os.path.isdir(item_path):
                    valid_fuzzers.add(item)

    valid_fuzzers = sorted(list(valid_fuzzers))
    print(f"Valid fuzzers found: {valid_fuzzers}")

    return valid_fuzzers

def check_binaries(benchmark, fuzzers_selected):
    base_dir = get_frb_base_dir()
    benchmark_dir = os.path.join(base_dir, benchmark)
    valid_binaries = []

    fuzzer_dirs = glob.glob(f"{benchmark_dir}/*/fuzzers")
    print(f"Fuzzer directories found: {fuzzer_dirs}")


    for fuzzer_dir in fuzzer_dirs:
        binary_name = os.path.basename(os.path.dirname(fuzzer_dir))

        has_all_fuzzers = True
        for selected_fuzzer in fuzzers_selected:
            fuzzer_path = os.path.join(fuzzer_dir, selected_fuzzer)
            if not (os.path.exists(fuzzer_path) and os.path.isdir(fuzzer_path)):
                has_all_fuzzers = False
                break

        if has_all_fuzzers:
            valid_binaries.append(binary_name)

    print(f"Valid binaries found: {valid_binaries}")
    return valid_binaries

def get_reports(benchmark, fuzzers_selected):
    base_dir = get_frb_base_dir()
    benchmark_dir = os.path.join(base_dir, benchmark)

    valid_reports = []
    fuzzer_dirs = glob.glob(f"{benchmark_dir}/*/fuzzers")

    for fuzzer_dir in fuzzer_dirs:
        binary_name = os.path.basename(os.path.dirname(fuzzer_dir))

        all_fuzzers_reports = []
        all_fuzzers_have_reports = True

        # Check each selected fuzzer for reports
        for selected_fuzzer in fuzzers_selected:
            report_path = os.path.join(
                fuzzer_dir, selected_fuzzer, "fuzzing_out", "*", "frb_report.json"
            )
            matching_reports = glob.glob(report_path)
            if matching_reports:
                all_fuzzers_reports.extend(matching_reports)
            else:
                all_fuzzers_have_reports = False
                break

        if all_fuzzers_have_reports:
            valid_reports.extend(all_fuzzers_reports)

    print(f"Valid reports found: {valid_reports}")
    return valid_reports

def check_output_name(benchmark, binary_name, fuzzers_selected, output_name):
    """Check if the output dir exists"""
    for fuzzer in fuzzers_selected:
        base_dir = get_frb_base_dir()
        fuzzer_path = os.path.join(base_dir, benchmark, binary_name, "fuzzers", fuzzer, "fuzzing_out")
        output_path = os.path.join(fuzzer_path, output_name)
        print("Checking path:", output_path)
        if os.path.exists(output_path) and os.path.isdir(output_path):
            return False
    return True


def cpu_usage(cpu_num):
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1, percpu=True)

        if isinstance(cpu_num, list):
            total_usage = 0.0
            for num in cpu_num:
                if 0 <= num < len(cpu_percent):
                    total_usage += cpu_percent[num]
                else:
                    print(f"Invalid CPU number: {num}. Valid range: 0-{len(cpu_percent)-1}")
            return round(total_usage, 2)

        if 0 <= cpu_num < len(cpu_percent):
            return round(cpu_percent[cpu_num], 2)
        else:
            print(f"Invalid CPU number: {cpu_num}. Valid range: 0-{len(cpu_percent)-1}")
            return 0.0
    except Exception as e:
        print(f"Error getting CPU usage: {e}")
        return 0.0

def all_cpu_usage():
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1, percpu=True)
        return [round(percent, 2) for percent in cpu_percent]
    except Exception as e:
        print(f"Error getting CPU usage: {e}")
        return []

def get_all_frb_reports(benchmark):
    """Get all FirmReBugger reports for a given benchmark."""
    base_dir = get_frb_base_dir()
    benchmark_dir = os.path.join(base_dir, benchmark)
    report_files = glob.glob(f"{benchmark_dir}/*/fuzzers/*/fuzzing_out/*/frb_report.json")

    valid_reports = []
    for report_file in report_files:
        if os.path.isfile(report_file):
            valid_reports.append(report_file)

    valid_reports.sort()
    return valid_reports


def prep_upset_data(frb_reports, bug_status):
    raw_data = []
    annotations = {
        "columns": {
            "id": "id",
            "Name": "label",
            "MeanSurvivalTime": "number",
            "MeanCount": "number",
            "FP/TP": "category"
        }
    }

    fuzzer_set = set()
    aggregated_data = defaultdict(lambda: {
        "bug_id": "",
        "successful_events": [],
        "event_observed": [],
        "total_trials": 0,
        "successful_runs": 0,
        "bug_type": "",
        "trial_time": 0,
        "fuzzers": defaultdict(lambda: {"successful_runs": 0}),
    })

    for report_path in frb_reports:
        try:
            with open(report_path, "r") as f:
                report_data = json.load(f)

            fuzzer_name = report_data.get("Fuzzer", "Unknown-Fuzzer")
            fuzzer_set.add(fuzzer_name)

            num_trials = report_data.get("Number-Trials", 0)
            trial_time = report_data.get("Trial-Time", 0)

            for run, run_data in report_data["Campaign"].items():
                for bug in run_data:
                    if "bug_id" not in bug:
                        continue

                    bug_id = bug.get("bug_id")
                    reached = bug.get("reached", None)
                    triggered = bug.get("triggered", None)
                    detected = bug.get("detected", None)

                    status_value = {"reached": reached, "triggered": triggered, "detected": detected}[bug_status]

                    success = status_value is not None

                    aggregated_data[bug_id]["bug_id"] = bug_id
                    aggregated_data[bug_id]["total_trials"] = num_trials
                    aggregated_data[bug_id]["trial_time"] = trial_time
                    aggregated_data[bug_id]["bug_type"] = "False Positive" if bug_id.startswith("FP_") else "True Positive"

                    aggregated_data[bug_id]["successful_events"].append(status_value if success else trial_time)
                    aggregated_data[bug_id]["event_observed"].append(1 if success else 0)

                    if success:
                        aggregated_data[bug_id]["successful_runs"] += 1

                    aggregated_data[bug_id]["fuzzers"][fuzzer_name]["successful_runs"] += 1 if success else 0
        except Exception as e:
            print(f"Error processing {report_path}: {e}")
            continue

    item_id = 0
    for bug_id, data in aggregated_data.items():
        kmf = KaplanMeierFitter()
        survival_mean_time = 0

        if len(data["successful_events"]) > 0:
            kmf.fit(data["successful_events"], event_observed=data["event_observed"])

            survival_mean_time = rmst(kmf, t=data["trial_time"])

        total_trials = data["total_trials"]
        avg_status_count = data["successful_runs"] / total_trials if total_trials > 0 else 0

        bug_entry = {
            "id": item_id,
            "Name": bug_id,
            "MeanSurvivalTime": survival_mean_time,
            "MeanCount": avg_status_count,
            "FP/TP": data["bug_type"],
        }

        for fuzzer in fuzzer_set:
            bug_entry[fuzzer] = aggregated_data[bug_id]["fuzzers"][fuzzer]["successful_runs"] > 0

        raw_data.append(bug_entry)
        item_id += 1

    for fuzzer in fuzzer_set:
        annotations["columns"][fuzzer] = "boolean"

    print("--- Prepared UpSet Data ---")
    print("Raw Data:", raw_data)
    print("Annotations:", annotations)

    raw_data = convert_numpy_types(raw_data)

    return {"raw_data": raw_data, "annotations": annotations}


class BugTableEntry:
    def __init__(self, frb_report):
        self.binary = ""
        self.fuzzer = ""
        self.stats = defaultdict(list)  # bug_id -> list of BugDetails
        self.num_trials = None
        self.trial_time = None

        try:
            with open(frb_report, "r") as f:
                report_data = json.load(f)

            self.binary = report_data.get("Target", "Unknown")
            self.fuzzer = report_data.get("Fuzzer", "Unknown")
            self.num_trials = report_data.get("Number-Trials")
            self.trial_time = report_data.get("Trial-Time")

            if "Campaign" not in report_data:
                raise KeyError("Missing 'Campaign' key")

            for run, run_data in report_data["Campaign"].items():
                for bug in run_data:
                    bug_id = bug.get("bug_id")
                    if not bug_id:
                        continue

                    bug_detail = BugDetails(
                        self.fuzzer,
                        run,
                        bug.get("reached"),
                        bug.get("triggered"),
                        bug.get("detected"),
                    )
                    self.stats[bug_id].append(bug_detail)

        except Exception as e:
            print(f"Error processing {frb_report}: {e}")

    def _compute_median_with_censoring(self, values):
        if self.trial_time is None or not values:
            return None

        import numpy as np

        uncensored = [v for v in values if v is not None]
        censored_count = sum(1 for v in values if v is None)

        adjusted_values = uncensored + [float('inf')] * censored_count

        if len(adjusted_values) == 0:
            return None

        median_seconds = np.median(adjusted_values)

        if np.isinf(median_seconds):
            return None

        return float(median_seconds)

    def to_dict(self):
        return {
            "binary": self.binary,
            "fuzzer": self.fuzzer,
            "num_trials": self.num_trials,
            "trial_time": self.trial_time,
            "bugs": {
                bug_id: {
                    "runs": [detail.to_dict() for detail in details],
                    "meanReached": self._compute_median_with_censoring([d.bug_reached for d in details]),
                    "meanTriggered": self._compute_median_with_censoring([d.bug_triggered for d in details]),
                    "meanDetected": self._compute_median_with_censoring([d.bug_detected for d in details]),
                }
                for bug_id, details in self.stats.items()
            },
        }


class BugDetails:
    def __init__(self, fuzzer, run, reached, triggered, detected):
        self.bug_reached = reached
        self.bug_triggered = triggered
        self.bug_detected = detected
        self.fuzzer = fuzzer
        self.run = run

    def print(self):
        print(f"Fuzzer: {self.fuzzer}, Run: {self.run}, Reached: {self.bug_reached}, Triggered: {self.bug_triggered}, Detected: {self.bug_detected}")

    def to_dict(self):
        return {
            'fuzzer': self.fuzzer,
            'run': self.run,
            'reached': self.bug_reached,
            'triggered': self.bug_triggered,
            'detected': self.bug_detected
        }


def get_table_json(frb_reports):
    """
    Transform list of FRB reports into the structure expected by the frontend.

    Expected frontend structure:
    [
        {
            "binary": "binary_name",
            "bugs": [
                {
                    "bugId": "bug_1",
                    "fuzzerStats": {
                        "FuzzerA": {
                            "meanReached": xx,
                            "meanTriggered": xx,
                            "meanDetected": xx,
                            "runs": [...]
                        },
                        "FuzzerB": { ... }
                    }
                }
            ]
        }
    ]
    """
    table_entries = []
    for report_path in frb_reports:
        table_entry = BugTableEntry(report_path)
        table_entries.append(table_entry)

    binary_data = defaultdict(lambda: defaultdict(dict))

    for entry in table_entries:
        binary = entry.binary
        fuzzer = entry.fuzzer

        for bug_id, bug_stats in entry.to_dict()["bugs"].items():
            binary_data[binary][bug_id][fuzzer] = {
                "meanReached": bug_stats["meanReached"],
                "meanTriggered": bug_stats["meanTriggered"],
                "meanDetected": bug_stats["meanDetected"],
                "runs": bug_stats["runs"]
            }

    result = []
    for binary, bugs_dict in binary_data.items():
        bugs_list = []
        for bug_id, fuzzer_stats in bugs_dict.items():
            bugs_list.append({
                "bugId": bug_id,
                "fuzzerStats": fuzzer_stats
            })

        result.append({
            "binary": binary,
            "bugs": bugs_list
        })

    return result
