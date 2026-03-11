import os
import subprocess
import pandas as pd
from firmrebugger.charting_tool_utils.summarize_data import summarize_data
import numpy as np
import scipy.stats as stats


def value_to_color(value, min_value=0, max_value=10):
    value = max(min(value, max_value), min_value)
    color_map = [
        "#fcfcff",
        "#edf6f2",
        "#def0e5",
        "#cfead8",
        "#bfe4cb",
        "#b0ddbe",
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
\usepackage[a4paper,margin=0.5in,landscape]{{geometry}}
\pagestyle{{empty}}
\usepackage{{pdflscape}}
\newcommand{{\missing}}{{\makebox[2em][c]{{--}}}}
\begin{{document}}
    {table_code}
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


def count_table_rows(combined_df):
    """Count the number of rows that will be in the final table."""
    row_count = 0
    for binary, group in combined_df.groupby("Binary"):
        for bug_id, bug_group in group.groupby("BugID"):
            if "ERROR" in bug_id:
                continue
            row_count += 1
    return row_count


def split_dataframe_by_binaries(combined_df, max_rows_per_table=25):
    """
    Split the dataframe into chunks, keeping binaries together.
    Returns a list of dataframes, each representing one table.
    """
    chunks = []
    current_chunk = []
    current_row_count = 0

    grouped_data = list(combined_df.groupby("Binary"))

    for binary, group in grouped_data:
        binary_row_count = 0
        for bug_id, bug_group in group.groupby("BugID"):
            if "ERROR" not in bug_id:
                binary_row_count += 1

        if (
            current_row_count > 0
            and current_row_count + binary_row_count > max_rows_per_table
        ):
            chunks.append(pd.concat(current_chunk, ignore_index=True))
            current_chunk = []
            current_row_count = 0

        current_chunk.append(group)
        current_row_count += binary_row_count

    if current_chunk:
        chunks.append(pd.concat(current_chunk, ignore_index=True))

    return chunks


def reshape_and_convert_to_latex(
    combined_df, expected_fuzzers=None, table_number=1, total_tables=1
):
    if expected_fuzzers is not None:
        fuzzers = list(expected_fuzzers)
    else:
        fuzzers = list(combined_df["Fuzzer"].unique())

    table_label = "fuzzing-results"
    caption_text = "Fuzzing Results"
    if total_tables > 1:
        table_label += f"-{table_number}"
        caption_text += f" (Part {table_number} of {total_tables})"

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

    grouped_data = combined_df.groupby("Binary")
    grouped_data_list = list(grouped_data)

    first_row = True

    for idx, (binary, group) in enumerate(grouped_data_list):
        for bug_id, bug_group in group.groupby("BugID"):
            if "ERROR" in bug_id:
                continue
            row_data = []

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

            for fuzzer in fuzzers:
                fuzzer_row = bug_group[bug_group["Fuzzer"] == fuzzer]
                if not fuzzer_row.empty:
                    reached, triggered, count = fuzzer_row.iloc[0][
                        ["MedianReachedTime", "MedianTriggeredTime", "TriggeredCount"]
                    ]

                    reached_hm = (
                        minutes_to_hm(float(reached)) if reached != "-" else r"\missing"
                    )
                    triggered_hm = (
                        minutes_to_hm(float(triggered))
                        if triggered != "-"
                        else r"\missing"
                    )

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

                    hit_color = value_to_color(count)
                    count = hit_color

                else:
                    reached_hm, triggered_hm = r"\missing", r"\missing"
                    count = r"\cellcolor[HTML]{F5F5F5}N/A"

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

        if idx != len(grouped_data_list) - 1:
            latex_table += r" \hline"

        first_row = True

    latex_table += (
        "\n"
        + r"\end{tabular}"
        + "\n"
        + r"}"
        + "\n"
        + rf"\caption{{{caption_text}}}"
        + "\n"
        + rf"\label{{tab:{table_label}}}"
        + "\n"
        + r"\end{table*}"
    )

    return latex_table


def generate_table(frb_reports, output_report, max_rows_per_table=40):
    for target, binaries in frb_reports.items():
        print(f"Processing target: {target} binarys: {list(binaries.keys())}")
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

        timeout = 24 * 60 * 60

        significant_wins = {}

        for binary, group in combined_df.groupby("Binary"):
            fuzzer_groups = group.groupby("Fuzzer")["MedianTriggeredTime"].apply(list)
            fuzzer_groups = fuzzer_groups[
                fuzzer_groups.apply(lambda times: any(t < timeout for t in times))
            ]
            if len(fuzzer_groups) < 2:
                continue

            medians = fuzzer_groups.apply(
                lambda times: np.median([t for t in times if t < timeout])
            )
            winner = medians.idxmin()
            winner_times = np.array([t for t in fuzzer_groups[winner] if t < timeout])

            win_significant = True
            for fuzzer, times in fuzzer_groups.items():
                if fuzzer == winner:
                    continue
                comp_times = np.array([t for t in times if t < timeout])
                if len(winner_times) < 2 or len(comp_times) < 2:
                    win_significant = False
                    break
                stat, p = stats.mannwhitneyu(
                    winner_times, comp_times, alternative="less"
                )
                if p >= 0.05:
                    win_significant = False
                    break
            if win_significant:
                significant_wins[winner] = significant_wins.get(winner, 0) + 1

        for fuzzer, count in sorted(
            significant_wins.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"{fuzzer}: {count}")

        fuzzers = list(combined_df["Fuzzer"].drop_duplicates())
        pd.set_option("display.max_rows", None)
        pd.set_option("display.max_columns", None)
        pd.set_option("display.width", None)
        pd.set_option("display.max_colwidth", None)
        print(combined_df)

        total_rows = count_table_rows(combined_df)
        print(f"Total rows in table: {total_rows}")

        if total_rows > max_rows_per_table:
            chunks = split_dataframe_by_binaries(combined_df, max_rows_per_table)
            total_tables = len(chunks)
            print(f"Splitting table into {total_tables} parts")

            all_latex_codes = []
            for i, chunk_df in enumerate(chunks, start=1):
                latex_code = reshape_and_convert_to_latex(
                    chunk_df, fuzzers, table_number=i, total_tables=total_tables
                )
                all_latex_codes.append(latex_code)

            combined_latex = "\n\n\\clearpage\n\n".join(all_latex_codes)
            generate_table_pdf(output_report, combined_latex, target)
        else:
            latex_code = reshape_and_convert_to_latex(combined_df, fuzzers)
            generate_table_pdf(output_report, latex_code, target)
