import json
import pandas as pd
import numpy as np
import argparse


def compute_median_survival(group, duration_col, event_col):
    uncensored_times = group.loc[group[event_col] == 1, duration_col].values
    censored_times = group.loc[group[event_col] == 0, duration_col].values

    uncensored_times = list(uncensored_times) + [float("inf")] * len(censored_times)

    if len(uncensored_times) == 0:
        return float("inf")

    return np.median(uncensored_times)


def summarize_data(json_file):
    # print(f"loading: {json_file}")
    with open(json_file, "r") as file:
        json_data = json.load(file)

    data = []
    total_ungrouped_crashes = []
    MAX_TRIAL_TIME = json_data.get("Trial-Time")

    trigger_runs = {}
    detected_runs = {}

    if "Campaign" not in json_data:
        raise KeyError("'Campaign' key not found in the JSON data.")

    for run, trials in json_data["Campaign"].items():
        for trial in trials:
            if "ungrouped_crashes" in trial or "multi_bugs_triggered" in trial:
                ungrouped_get = trial.get("ungrouped_crashes")
                if ungrouped_get is not None:
                    for crash in ungrouped_get:
                        total_ungrouped_crashes.append(crash)
                continue

            bug_id = trial.get("bug_id")
            if bug_id is None:
                continue

            if trial.get("triggered") is not None:
                triggered_event_observed = 1
                triggered_duration = trial["triggered"]
                if bug_id not in trigger_runs:
                    trigger_runs[bug_id] = set()
                trigger_runs[bug_id].add(run)
            else:
                triggered_event_observed = 0
                triggered_duration = MAX_TRIAL_TIME

            if trial.get("reached") is not None:
                reached_duration = trial["reached"]
                reached_event_observed = 1
            else:
                reached_duration = MAX_TRIAL_TIME
                reached_event_observed = 0

            if trial.get("detected") is not None:
                if bug_id not in detected_runs:
                    detected_runs[bug_id] = set()
                detected_runs[bug_id].add(run)

            data.append(
                {
                    "Binary": json_data["Target"],
                    "Fuzzer": json_data["Fuzzer"],
                    "BugID": bug_id,
                    "triggered_duration": triggered_duration,
                    "triggered_event_observed": triggered_event_observed,
                    "reached_duration": reached_duration,
                    "reached_event_observed": reached_event_observed,
                }
            )

    df = pd.DataFrame(data)

    if df.empty:
        return pd.DataFrame(
            columns=[
                "Binary",
                "Fuzzer",
                "BugID",
                "MedianDetectedTime",
                "DetectedCount",
                "MedianReachedTime",
                "MedianTriggeredTime",
                "TriggeredCount",
            ]
        )

    triggered_medians = df.groupby(["Binary", "Fuzzer", "BugID"]).apply(
        lambda x, **kwargs: compute_median_survival(
            x, "triggered_duration", "triggered_event_observed"
        ),
        include_groups=False,
    )

    reached_medians = df.groupby(["Binary", "Fuzzer", "BugID"]).apply(
        lambda x, **kwargs: compute_median_survival(
            x, "reached_duration", "reached_event_observed"
        ),
        include_groups=False,
    )

    medians_df = pd.DataFrame(
        {
            "Binary": triggered_medians.index.get_level_values("Binary"),
            "Fuzzer": triggered_medians.index.get_level_values("Fuzzer"),
            "BugID": triggered_medians.index.get_level_values("BugID"),
            "MedianReachedTime": reached_medians.values,
            "MedianDetectedTime": reached_medians.values,
            "MedianTriggeredTime": triggered_medians.values,
            "TriggeredCount": [
                len(trigger_runs.get(bug_id, set()))
                for bug_id in triggered_medians.index.get_level_values("BugID")
            ],
            "DetectedCount": [
                len(detected_runs.get(bug_id, set()))
                for bug_id in reached_medians.index.get_level_values("BugID")
            ],
        }
    )

    medians_df["MedianReachedTime"] = np.ceil(medians_df["MedianReachedTime"] / 60)
    medians_df["MedianDetectedTime"] = np.ceil(medians_df["MedianDetectedTime"] / 60)
    medians_df["MedianTriggeredTime"] = np.ceil(medians_df["MedianTriggeredTime"] / 60)

    binary = medians_df["Binary"].unique()
    fuzzer = medians_df["Fuzzer"].unique()
    if len(total_ungrouped_crashes) > 0:
        print(
            f"===WARNING: UNGROUPED CRASHES IN {fuzzer} FOR {binary} CHECK THE FRB REPORT==="
        )
    return medians_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Calculate bug statistics from JSON data."
    )
    parser.add_argument(
        "json_file", type=str, help="Path to the JSON file containing bug data."
    )

    args = parser.parse_args()

    print(summarize_data(args.json_file))
