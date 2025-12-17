import json
import pandas as pd
import numpy as np
import argparse


def compute_median_survival(group, duration_col, event_col):
    uncensored_times = group.loc[group[event_col] == 1, duration_col].values
    censored_times = group.loc[group[event_col] == 0, duration_col].values

    # Add `inf` to the uncensored times
    uncensored_times = list(uncensored_times) + [float("inf")] * len(censored_times)

    # If no uncensored events, return infinity
    if len(uncensored_times) == 0:
        return float("inf")  # No events happened, return infinity

    return np.median(uncensored_times)  # Compute median of the adjusted times


def summarize_data(json_file):
    # print(f"loading: {json_file}")
    with open(json_file, "r") as file:
        json_data = json.load(file)

    data = []
    total_ungrouped_crashes = []
    MAX_TRIAL_TIME = json_data.get("Trial-Time")

    trigger_count = {}

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
                continue  # Skip if bug_id is missing

            # For triggered events
            if trial.get("triggered") is not None:
                triggered_event_observed = 1  # Event occurred
                triggered_duration = trial["triggered"]
                trigger_count[bug_id] = (
                    trigger_count.get(bug_id, 0) + 1
                )  # Increment trigger count
            else:
                triggered_event_observed = 0  # Event not occurred (censored)
                triggered_duration = MAX_TRIAL_TIME  # Censoring at max trial time

            # For reached events
            if trial.get("reached") is not None:
                reached_duration = trial["reached"]
                reached_event_observed = 1  # Event occurred
            else:
                reached_duration = MAX_TRIAL_TIME  # Censoring at max trial time
                reached_event_observed = 0  # Event not reached (censored)

            # Append the data to the list
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

    # Create DataFrame from the collected data
    df = pd.DataFrame(data)

    # Compute manual median survival times for triggered and reached events
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

    # Create DataFrame with results
    medians_df = pd.DataFrame(
        {
            "Binary": triggered_medians.index.get_level_values("Binary"),
            "Fuzzer": triggered_medians.index.get_level_values("Fuzzer"),
            "BugID": triggered_medians.index.get_level_values("BugID"),
            "MedianReachedTime": reached_medians.values,
            "MedianTriggeredTime": triggered_medians.values,
            "TriggeredCount": [
                trigger_count.get(bug_id, 0)
                for bug_id in triggered_medians.index.get_level_values("BugID")
            ],
        }
    )

    medians_df["MedianReachedTime"] = np.ceil(medians_df["MedianReachedTime"] / 60)
    medians_df["MedianTriggeredTime"] = np.ceil(medians_df["MedianTriggeredTime"] / 60)

    # Check if ungrouped crashes exist
    binary = medians_df["Binary"].unique()
    fuzzer = medians_df["Fuzzer"].unique()
    if len(total_ungrouped_crashes) > 0:
        print(
            f"===WARNING: UNGROUPED CRASHES IN {fuzzer} FOR {binary} CHECK THE FRB REPORT==="
        )
    return medians_df


if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Calculate bug statistics from JSON data."
    )
    parser.add_argument(
        "json_file", type=str, help="Path to the JSON file containing bug data."
    )

    # Parse the arguments
    args = parser.parse_args()

    # Run the summarize_data function with the provided JSON file
    print(summarize_data(args.json_file))
