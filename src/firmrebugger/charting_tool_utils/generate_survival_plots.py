import json
import pandas as pd
import matplotlib.pyplot as plt
from lifelines import KaplanMeierFitter
import os
import argparse
from typing import List
from lifelines.utils import restricted_mean_survival_time as rmst
import warnings
import math
import glob
from matplotlib import gridspec


def calc_survival(
    ax, data: List[int], bug, trial_time: int, fuzzer_name, color="tab:blue"
):
    data = [x / 3600 if x is not None else None for x in data]
    # print(f"Plotting survival curve for {fuzzer_name} on {bug} with data:")
    # print(data)
    df = pd.DataFrame(data)
    T = df.fillna(trial_time)
    E = df.notnull()

    kmf = KaplanMeierFitter()
    kmf.fit(T, E)

    # Takes a long time to calculate the surv_time_var
    # surv_time_mean, surv_time_var = rmst(kmf, t=trial_time, return_variance=True)
    # surv_time_var = abs(surv_time_var)

    surv_time_mean = rmst(kmf, t=trial_time)
    kmf.plot_survival_function(
        ax=ax, ci_show=True, label=fuzzer_name, legend=False, color=color, linewidth=2
    )
    return ax.lines[-1]
    print(f"Survival time mean for {fuzzer_name} on {bug}: {surv_time_mean}")


def process_data(json_data):
    bug_survival_data = {}

    # Loop through the runs and gather survival times for each bug
    for run_name, run_data in json_data.get("Campaign", {}).items():
        for bug in run_data:
            if "ERROR" in bug.get("bug_id", ""):
                # print(f"Skipping bug with ERROR in ID: {bug.get('bug_id')}")
                continue
            if (
                isinstance(bug, dict)
                and "bug_id" in bug
                and bug["bug_id"] not in bug_survival_data
            ):
                bug_survival_data[bug["bug_id"]] = {"triggered": []}

            if isinstance(bug, dict) and "bug_id" in bug:
                bug_id = bug["bug_id"]
                bug_survival_data[bug_id]["triggered"].append(bug["triggered"])
    return bug_survival_data


def set_ax_visuals(ax, max_time, bug_id):
    ax.set_xscale("symlog", linthresh=2)
    ax.set_title(f"Bug: {bug_id}")
    ax.grid(True)
    ax.set_xlabel("")
    ax.set_xlim(0, max_time)
    ax.set_xlim(left=-0.1)
    ax.set_ylim(bottom=-0.03)
    ax.set_xticks([0, 1, 4, 8, 12, max_time])
    ax.set_xticklabels([str(int(x)) for x in [0, 1, 4, 8, 12, max_time]])

    for spine in ax.spines.values():
        spine.set_visible(False)
    # ax.spines['bottom'].set_visible(True)
    # ax.spines['left'].set_visible(True)
    return ax


def plot_survival(fuzzers_data, ax, fuzzer_colors, bug_count, max_time, legend_handles):
    line = None
    for fuzzer_group in fuzzers_data:
        for fuzzer, fuzzer_data in fuzzer_group.items():
            bug_id = list(fuzzer_data.keys())[bug_count]
            triggered_times = fuzzer_data[bug_id]["triggered"]
            color = fuzzer_colors.get(fuzzer, "tab:gray")
            line = calc_survival(
                ax, triggered_times, bug_id, max_time, fuzzer, color=color
            )
            if fuzzer not in legend_handles:
                legend_handles[fuzzer] = line
    set_ax_visuals(ax, max_time, bug_id)
    return legend_handles


def plot_grid_survival(fuzzers_data, max_time, output_dir, binary):
    fuzzers_data = sorted(fuzzers_data, key=lambda fuzzer: list(fuzzer.keys())[0])
    MAX_COLS = 5
    num_bugs = len(next(iter(fuzzers_data[0].values())))
    ncols = min(MAX_COLS, num_bugs)
    nrows = math.ceil(num_bugs / ncols)  # Calculate the number of rows required
    if ncols != 1:
        fig = plt.figure(figsize=(4 * ncols, 3 * nrows))
    else:
        fig = plt.figure(figsize=(8 * ncols, 4 * nrows))

    ngrid = ncols * 2 + 2
    spec = gridspec.GridSpec(ncols=ngrid, nrows=nrows, figure=fig)
    legend_handles = {}
    bug_count = 0
    colormap = plt.colormaps["tab10"]
    fuzzer_names = list(
        set(
            fuzzer
            for fuzzers_data_item in fuzzers_data
            for fuzzer in fuzzers_data_item.keys()
        )
    )
    fuzzer_names = sorted(fuzzer_names)
    fuzzer_colors = {
        fuzzer_name: colormap(i / 10) for i, fuzzer_name in enumerate(fuzzer_names)
    }

    remaining_plots = num_bugs - (MAX_COLS * (nrows - 1))
    for row in range(0, nrows, 1):
        for col in range(0, ngrid, 2):
            if row is nrows - 1 and row != 0 and remaining_plots < MAX_COLS:
                break
            if col + 3 < ngrid:
                # print(f"{row},{col+1}:{col + 3}")
                ax = fig.add_subplot(spec[row, col + 1 : col + 3])
                plot_survival(
                    fuzzers_data, ax, fuzzer_colors, bug_count, max_time, legend_handles
                )
                bug_count += 1

    start_col = int((ngrid / 2) - remaining_plots)
    end_col = start_col + 2  # The plot spans 2 columns
    for _ in range(remaining_plots):
        if nrows == 1 or remaining_plots == MAX_COLS:
            break
        ax = fig.add_subplot(spec[nrows - 1, start_col:end_col])
        plot_survival(
            fuzzers_data, ax, fuzzer_colors, bug_count, max_time, legend_handles
        )
        start_col += 2
        end_col += 2
        bug_count += 1

    plt.rc("font", size=14)
    fig_width, fig_height = fig.get_size_inches()
    fig.text(
        0.5, -0.2 / fig_height, "Time (hrs)", ha="center", va="center", fontsize=20
    )
    fig.text(
        0.9 / fig_width,
        0.5,
        "Survival Probability",
        ha="center",
        va="center",
        rotation="vertical",
        fontsize=20,
    )
    fig.text(
        1 - (0.9 / fig_width),
        0.5,
        "Survival Probability",
        ha="center",
        va="center",
        rotation="vertical",
        fontsize=20,
        color="white",
    )

    legend_position_y = -0.7 / fig_height
    legend_position_x = 0.5
    bbox_to_anchor = (legend_position_x, legend_position_y)

    fig.legend(
        legend_handles.values(),
        legend_handles.keys(),
        loc="center",
        ncol=len(fuzzers_data),
        bbox_to_anchor=bbox_to_anchor,
        frameon=False,
    )

    plt.tight_layout()
    plt.subplots_adjust(wspace=0.8)
    plt.rcParams["font.family"] = "Arial"

    if output_dir is None:
        output_dir = "survival_plots"
    output_dir_binary = os.path.join(output_dir, binary)
    os.makedirs(output_dir_binary, exist_ok=True)
    plt.savefig(f"{output_dir_binary}/survival_plots.pdf",backend='pgf', bbox_inches="tight")
    print(
        f"Survival plots generated successfully at {output_dir_binary}/survival_plots.pdf"
    )
    plt.close()


def process_binary(json_file):
    fuzzers_data = {}
    fuzzer_name = ""
    binary = ""
    with open(json_file, "r") as file:
        json_data = json.load(file)
        fuzzer_name = json_data["Fuzzer"]
        binary = json_data["Target"]
        fuzzers_data[fuzzer_name] = process_data(json_data)

    max_trial_time_hours = int(json_data["Trial-Time"]) / 3600
    return fuzzers_data, binary, max_trial_time_hours


def survival_plot(json_files, report_path, target=None, output_dir=None):
    if output_dir is None:
        output_dir = os.path.join(report_path, f"{target}", "survival_plots")
    else:
        output_dir = "./survival_plots"
    warnings.simplefilter("ignore")
    fuzzer_data_per_binary = {}
    max_trial_time_hours = 0
    for json_file in json_files:
        fuzzers_data, binary, max_trial_time_hours = process_binary(json_file)
        if binary not in fuzzer_data_per_binary:
            fuzzer_data_per_binary[binary] = []
        fuzzer_data_per_binary[binary].append(fuzzers_data)

    for binary, fuzzers_data_list in fuzzer_data_per_binary.items():
        print(f"Data for {binary}:")
        plot_grid_survival(fuzzers_data_list, max_trial_time_hours, output_dir, binary)


def main():
    warnings.simplefilter("ignore")
    parser = argparse.ArgumentParser(description="Suvival plots' bug data.")
    parser.add_argument(
        "json_folder", help="Path to folder of firmrebugger JSON reports"
    )
    args = parser.parse_args()
    json_files = glob.glob(os.path.join(args.json_folder, "*.json"))
    json_files = [os.path.abspath(file) for file in json_files]
    survival_plot(json_files, report_path="./report", target="custom")


if __name__ == "__main__":
    main()
