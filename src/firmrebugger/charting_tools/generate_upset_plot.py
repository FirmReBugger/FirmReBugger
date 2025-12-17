import argparse
import os
import pandas as pd
from collections import defaultdict
from firmrebugger.charting_tools.summarize_data import summarize_data
from matplotlib import cm
from matplotlib import pyplot as plt
from upsetplot import UpSet


def prep_data_for_upset_plot(all_bugs_triggered, bugs_triggered):
    ASTERISK_FUZZERS = {"SEmu-Fuzz", "Fuzzware", "SplITS"}
    fuzzer_rename = {
        f: (
            "Ember-IO"
            if f == "Ember-IO-Fuzzing"
            else (f + "*" if f in ASTERISK_FUZZERS else f)
        )
        for f in bugs_triggered.keys()
    }
    fuzzer_rename_map = {f: newf for f, newf in fuzzer_rename.items()}
    fuzzer_list = list(fuzzer_rename.values())

    bugs_triggered_new = {}
    for fuzzer, bug_list in bugs_triggered.items():
        new_fuzzer = fuzzer_rename_map[fuzzer]
        bugs_triggered_new[new_fuzzer] = bug_list

    rows = []
    for bug in all_bugs_triggered:
        bug_row = {
            fuzzer: bug in bugs_triggered_new.get(fuzzer, []) for fuzzer in fuzzer_list
        }
        bug_row["TP_FP"] = "FP" if bug.startswith("FP_") else "TP"
        bug_row["bugid"] = bug
        rows.append(bug_row)

    df = pd.DataFrame(rows)
    df = df.sort_values("bugid")
    df_upset = df.set_index(fuzzer_list)
    return df_upset


def list_all_triggered_bugs(dfs):
    bugs_triggered = defaultdict(list)
    all_bugs_triggered = set()
    all_fuzzers = set()

    for df in dfs:
        # Standardize column names just in case (strip spaces)
        df = df.rename(columns={c: c.strip() for c in df.columns})

        for _, row in df.iterrows():
            fuzzer = str(row["Fuzzer"])
            all_fuzzers.add(fuzzer)
            bugid = str(row["BugID"])
            if "ERROR" in bugid:
                continue
            all_bugs_triggered.add(bugid)
            try:
                triggered_count = float(row["TriggeredCount"])
            except Exception:
                triggered_count = 0
            if triggered_count > 0:
                fuzzer = str(row["Fuzzer"])
                bugs_triggered[fuzzer].append(bugid)
    # print(all_bugs_triggered)
    # print(bugs_triggered)
    # exit(1)
    for fuzzer in all_fuzzers:
        bugs_triggered.setdefault(fuzzer, [])
    return prep_data_for_upset_plot(all_bugs_triggered, bugs_triggered)


def upset_plot(df):
    upset_df = list_all_triggered_bugs([df])
    pastel_colors = cm.Pastel1.colors
    color_map = {"TP": pastel_colors[1], "FP": pastel_colors[0]}

    fig = plt.figure(figsize=(10, 3))
    upset = UpSet(upset_df, show_counts=True, intersection_plot_elements=0)
    upset.add_stacked_bars(
        by="TP_FP", colors=color_map, title="Intersection Size", elements=3
    )
    upset.plot(fig=fig)
    fig = plt.gcf()
    for ax in fig.axes:
        leg = ax.get_legend()
        if leg:
            # leg.remove()
            leg.set_bbox_to_anchor((0.2, 0.9), transform=fig.transFigure)

    fig.axes[2].set_xticks([])
    fig.axes[2].set_title(f"Total ({len(upset_df)})")
    fig.axes[2].spines["bottom"].set_visible(False)

    return fig


def generate_upset_plot(frb_reports, output_dir=None):
    full_upset_df = []
    for target, binaries in frb_reports.items():
        all_reports_df = []
        for binary, output_reports in binaries.items():
            for report in output_reports:
                result_df = summarize_data(report)
                full_upset_df.append(result_df)
                all_reports_df.append(result_df)

        combined_df = pd.concat(all_reports_df, ignore_index=True)
        all_combined_df = pd.concat(full_upset_df, ignore_index=True)

        # Generate UpSet plot per target
        upset_plot_target = upset_plot(combined_df.sort_values(by="Fuzzer"))
        full_upset_plot = upset_plot(all_combined_df.sort_values(by="Fuzzer"))

        upset_plot_target.savefig(
            f"{output_dir}/{target}/upset_plot.pdf",
            backend="pgf",
            dpi=300,
            bbox_inches="tight",
        )

        full_upset_plot.savefig(
            f"{output_dir}/full_upset_plot.pdf",
            backend="pgf",
            dpi=300,
            bbox_inches="tight",
        )

        print(
            f"UpSet plot successfully generated at {output_dir}/{target}/upset_plot.pdf"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Generate UpSet plot for FirmReBugger fuzzer bugs."
    )
    parser.add_argument("output_reports", help="Path to the output reports directory")
    args = parser.parse_args()

    output_reports = args.output_reports
    if not os.path.exists(output_reports):
        print(f"Output reports directory '{output_reports}' does not exist.")
        return

    generate_upset_plot(output_reports)


if __name__ == "__main__":
    main()
