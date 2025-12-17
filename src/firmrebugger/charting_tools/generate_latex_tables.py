import os
import subprocess
import pandas as pd
from firmrebugger.charting_tools.summarize_data import summarize_data


def value_to_color(value, min_value=0, max_value=10):
    value = max(min(value, max_value), min_value)
    color_map = [
        "#fcfcff",
        "#edf6f2",
        "#def0e5",
        "#cfead8",
        "#bfe4cb",
        "#b0ddbd",
        "#a1d7b0",
        "#91d1a3",
        "#82cb96",
        "#73c589",
        "#63be7b",
    ]
    num_colors = len(color_map)
    normalized_value = (value - min_value) / (max_value - min_value) * (num_colors - 1)
    color_index = int(normalized_value)
    color_index = max(0, min(color_index, num_colors - 1))
    hex_color = color_map[color_index]
    return (
        r"\cellcolor[HTML]{"
        + hex_color[1:].upper()
        + "}"
        + str(int((value / max_value) * 100))
        + r"\%"
    )


def minutes_to_hm(minutes):
    if minutes == "-" or minutes == float("inf"):
        return r"\missing"
    if isinstance(minutes, (int, float)):
        hours, remainder = divmod(int(minutes), 60)
        minutes = remainder
        return f"{hours:02}:{minutes:02}"
    return str(minutes)


def generate_table_pdf(output_report, table_code, table):
    # Define the output directory and file name
    output_dir = f"{output_report}/{table}/summary_table"
    tex_file = f"table{table}.tex"
    pdf_file = f"table{table}.pdf"
    os.makedirs(output_dir, exist_ok=True)
    tex_path = os.path.join(output_dir, tex_file)
    pdf_path = os.path.join(output_dir, pdf_file)
    latex_code = rf"""
\documentclass{{article}}
\usepackage{{graphicx}}
\usepackage[table,xcdraw]{{xcolor}}
\usepackage[a4paper,margin=1in]{{geometry}}
\pagestyle{{empty}}
\usepackage{{pdflscape}}
\newcommand{{\missing}}{{\makebox[2em][c]{{--}}}}
\begin{{document}}
%\begin{{landscape}}
    {table_code}
%\end{{landscape}}
\end{{document}}
"""
    with open(tex_path, "w") as f:
        f.write(latex_code)
    subprocess.run(
        ["pdflatex", "-output-directory", output_dir, tex_path],
        capture_output=True,
        text=True,
    )
    print(f"Latex tables generated successfully at: {pdf_path}")


def escape_latex(text):
    special_chars = {
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    for char, escaped in special_chars.items():
        text = text.replace(char, escaped)
    return text


def reshape_and_convert_to_latex(combined_df, expected_fuzzers=None):
    desired_order = [
        "Ember-IO-Fuzzing",
        "Fuzzware",
        "Fuzzware-Icicle",
        "SEmu-Fuzz",
        "SplITS",
        "Hoedur",
        "MultiFuzz",
    ]

    if expected_fuzzers is None:
        present_fuzzers = combined_df["Fuzzer"].unique()
        fuzzers = [f for f in desired_order if f in present_fuzzers]
    else:
        # Force expected_fuzzers into desired_order, only keeping those present in expected_fuzzers
        fuzzers = [f for f in desired_order if f in expected_fuzzers]

    latex_table = (
        r"\begin{table*}[t]"
        + "\n"
        + r"\centering"
        + "\n"
        + r"\resizebox{\textwidth}{!}{"
        + "\n"
        + r"\scriptsize"
        + "\n"
    )

    # First row: Fuzzer headers
    fuzzer_headers = " & ".join(
        [
            rf"\multicolumn{{3}}{{c}}{{{fuzzer}}}"
            if i == len(fuzzers) - 1
            else rf"\multicolumn{{3}}{{c|}}{{{fuzzer}}}"
            for i, fuzzer in enumerate(fuzzers)
        ]
    )

    # Second row: Single "Median R | Median T | Hit" under each fuzzer
    sub_headers = " & ".join(
        [r"\multicolumn{3}{c|}{{Med. R \textbar{} Med. T \textbar{} Hit}}"]
        * (len(fuzzers) - 1)
        + [r"\multicolumn{3}{c}{{Med. R \textbar{} Med. T \textbar{} Hit}}"]
    )

    column_structure = "l|l" + "|ccc" * len(fuzzers)
    latex_table += r"\begin{tabular}{" + column_structure + "}" + "\n" + r"\hline"

    latex_table += "\nBinary & Bug ID & " + fuzzer_headers + r" \\"
    latex_table += "\n & & " + sub_headers + r" \\ \hline"

    # Group data by Binary
    grouped_data = combined_df.groupby("Binary")
    grouped_data_list = list(grouped_data)  # Convert to list to check the last group

    first_row = True  # Track if this is the first row for any Binary

    for idx, (binary, group) in enumerate(grouped_data_list):
        for bug_id, bug_group in group.groupby("BugID"):
            if "ERROR" in bug_id:
                continue
            row_data = []

            # For each fuzzer, extract Reached, Triggered, Count
            # Calculate minimums only from non-missing values
            valid_reached = bug_group[bug_group["MedianReachedTime"] != "-"][
                "MedianReachedTime"
            ]
            valid_triggered = bug_group[bug_group["MedianTriggeredTime"] != "-"][
                "MedianTriggeredTime"
            ]

            min_reached = float("inf")
            min_triggered = float("inf")

            if not valid_reached.empty:
                min_reached = float(valid_reached.min())
            if not valid_triggered.empty:
                min_triggered = float(valid_triggered.min())

            # Process all expected fuzzers, not just those present in bug_group
            for fuzzer in fuzzers:
                fuzzer_row = bug_group[bug_group["Fuzzer"] == fuzzer]
                if not fuzzer_row.empty:
                    reached, triggered, count = fuzzer_row.iloc[0][
                        ["MedianReachedTime", "MedianTriggeredTime", "TriggeredCount"]
                    ]

                    # Convert reached and triggered times to HH:MM format
                    reached_hm = (
                        minutes_to_hm(float(reached)) if reached != "-" else r"\missing"
                    )
                    triggered_hm = (
                        minutes_to_hm(float(triggered))
                        if triggered != "-"
                        else r"\missing"
                    )

                    # Apply bolding if the time is equal to the minimum reached or triggered time
                    if (
                        reached != "-"
                        and float(reached) == min_reached
                        and min_reached != float("inf")
                    ):
                        reached_hm = r"\textbf{" + reached_hm + "}"
                    if (
                        triggered != "-"
                        and float(triggered) == min_triggered
                        and min_triggered != float("inf")
                    ):
                        triggered_hm = r"\textbf{" + triggered_hm + "}"

                    if reached_hm == str(float("inf")):
                        reached_hm = r"\missing"
                    if triggered_hm == str(float("inf")):
                        triggered_hm = r"\missing"

                    # Apply the color for the hit count (TriggeredCount)
                    hit_color = value_to_color(count)
                    count = hit_color

                else:
                    # Always provide 3 columns even when fuzzer data is missing
                    # Use a consistent format with background color for missing data
                    reached_hm, triggered_hm = r"\missing", r"\missing"
                    count = (
                        r"\cellcolor[HTML]{F5F5F5}N/A"  # Light gray for missing data
                    )

                # Add the formatted times and count to row_data
                row_data.extend([str(reached_hm), str(triggered_hm), str(count)])

            bug_id_cell = (
                r"\cellcolor{gray!20} " + str(bug_id)
                if r"FP\_" in str(bug_id)
                else str(bug_id)
            )
            if first_row:
                latex_table += (
                    f"\n{binary} & {bug_id_cell} & " + " & ".join(row_data) + r" \\"
                )
                first_row = False
            else:
                latex_table += f"\n & {bug_id_cell} & " + " & ".join(row_data) + r" \\"

        # Add \hline at the end of each binary group, but not after the last binary
        if idx != len(grouped_data_list) - 1:
            latex_table += r" \hline"

        first_row = True  # Reset for next binary

    # Close the table
    latex_table += (
        "\n"
        + r"\end{tabular}"
        + "\n"
        + r"}"
        + "\n"
        + r"\caption{Fuzzing Results}"
        + "\n"
        + r"\label{tab:fuzzing-results}"
        + "\n"
        + r"\end{table*}"
    )

    return latex_table


def generate_table(frb_reports, output_report):
    for target, binaries in frb_reports.items():
        all_reports_df = []
        for binary, output_reports in binaries.items():
            for report in output_reports:
                result_df = summarize_data(report)
                all_reports_df.append(result_df)

        if not all_reports_df:
            print(f"Warning: No data found for target {target}")
            continue

        combined_df = pd.concat(all_reports_df, ignore_index=True)
        combined_df = combined_df.applymap(
            lambda x: escape_latex(str(x)) if isinstance(x, str) else x
        )

        fuzzers = list(combined_df["Fuzzer"].drop_duplicates())
        latex_code = reshape_and_convert_to_latex(combined_df, fuzzers)
        generate_table_pdf(output_report, latex_code, target)
