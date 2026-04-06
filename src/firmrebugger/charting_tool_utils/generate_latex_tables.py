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


def _safe_float(val):
    """Return float or None if val is NaN/inf/missing."""
    import math
    if val is None:
        return None
    try:
        f = float(val)
    except (TypeError, ValueError):
        return None
    return None if (math.isnan(f) or math.isinf(f)) else f


def count_heatmap_cell(count, max_count, time_str, bold=False):
    """Continuously interpolates RGB across Greens_3 (lighter max) based on count/max_count ratio.
    All tones pass WCAG AA with black text."""
    stops = [
        (255, 255, 255),  # white       (0 hits)
        (220, 240, 216),  # #dcf0d8    off-white tinted green
        (161, 217, 155),  # #a1d99b    white-green
        (116, 196, 118),  # #74c476    green (max)
    ]
    ratio = (count / max_count) if max_count > 0 and count > 0 else 0.0
    t = ratio * (len(stops) - 1)
    lo = min(int(t), len(stops) - 2)
    f = t - lo
    r = int(round(stops[lo][0] + f * (stops[lo + 1][0] - stops[lo][0])))
    g = int(round(stops[lo][1] + f * (stops[lo + 1][1] - stops[lo][1])))
    b = int(round(stops[lo][2] + f * (stops[lo + 1][2] - stops[lo][2])))
    hex_color = f"{r:02X}{g:02X}{b:02X}"
    if bold:
        time_str = r"\textbf{" + time_str + "}"
    return r"\cellcolor[HTML]{" + hex_color + "}" + time_str


def minutes_to_hm(minutes):
    import math
    if minutes is None:
        return None
    try:
        f = float(minutes)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    h, m = divmod(int(f), 60)
    return f"{h:02}:{m:02}"


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

    # Second row: R   T   D aligned to individual columns under each fuzzer
    rtd_group_mid   = r"R & T & D"                        # last fuzzer (no trailing |)
    rtd_group_sep   = r"R & T & \multicolumn{1}{c|}{D}"   # all other fuzzers (| after D)
    sub_headers = " & ".join(
        [rtd_group_sep] * (len(fuzzers) - 1) + [rtd_group_mid]
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

            def fmt_metric(time_val, count):
                """Return HH:MM when median is finite, -- otherwise.
                Colour is driven separately by count regardless."""
                hm = minutes_to_hm(time_val)
                return hm if hm is not None else r"\missing"

            valid_reached   = [_safe_float(v) for v in bug_group["MedianReachedTime"]   if _safe_float(v) is not None]
            valid_triggered = [_safe_float(v) for v in bug_group["MedianTriggeredTime"] if _safe_float(v) is not None]
            valid_detected  = [_safe_float(v) for v in bug_group["MedianDetectedTime"]  if _safe_float(v) is not None]

            min_reached   = min(valid_reached)   if valid_reached   else None
            min_triggered = min(valid_triggered) if valid_triggered else None
            min_detected  = min(valid_detected)  if valid_detected  else None

            def safe_int_col(series):
                cleaned = series.dropna()
                return int(cleaned.max()) if not cleaned.empty else 0

            max_r_count = safe_int_col(bug_group["ReachedCount"])
            max_t_count = safe_int_col(bug_group["TriggeredCount"])
            max_d_count = safe_int_col(bug_group["DetectedCount"])

            for fuzzer in fuzzers:
                fuzzer_row = bug_group[bug_group["Fuzzer"] == fuzzer]
                if not fuzzer_row.empty:
                    row0 = fuzzer_row.iloc[0]
                    r_t = _safe_float(row0["MedianReachedTime"])
                    t_t = _safe_float(row0["MedianTriggeredTime"])
                    d_t = _safe_float(row0["MedianDetectedTime"])
                    r_count = int(row0["ReachedCount"])   if _safe_float(row0["ReachedCount"])   is not None else 0
                    t_count = int(row0["TriggeredCount"]) if _safe_float(row0["TriggeredCount"]) is not None else 0
                    d_count = int(row0["DetectedCount"])  if _safe_float(row0["DetectedCount"])  is not None else 0
                    num_runs = int(row0["NumRuns"]) if _safe_float(row0["NumRuns"]) is not None else max_r_count

                    reached_str   = fmt_metric(r_t, r_count)
                    triggered_str = fmt_metric(t_t, t_count)
                    detected_str  = fmt_metric(d_t, d_count)

                    # Bold best (lowest) time across fuzzers for this bug
                    if r_t is not None and min_reached is not None and r_t == min_reached:
                        reached_str   = r"\textbf{" + reached_str   + "}"
                    if t_t is not None and min_triggered is not None and t_t == min_triggered:
                        triggered_str = r"\textbf{" + triggered_str + "}"
                    if d_t is not None and min_detected is not None and d_t == min_detected:
                        detected_str  = r"\textbf{" + detected_str  + "}"

                    reached_cell   = count_heatmap_cell(r_count, num_runs, reached_str)
                    triggered_cell = count_heatmap_cell(t_count, num_runs, triggered_str)
                    detected_cell  = count_heatmap_cell(d_count, num_runs, detected_str)

                else:
                    reached_cell   = r"\cellcolor[HTML]{F5F5F5}" + r"\missing"
                    triggered_cell = r"\cellcolor[HTML]{F5F5F5}" + r"\missing"
                    detected_cell  = r"\cellcolor[HTML]{F5F5F5}" + r"\missing"

                row_data.extend([str(reached_cell), str(triggered_cell), str(detected_cell)])

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

    gradient_boxes = (
        r"{\setlength{\fboxsep}{4pt}"
        + r"\colorbox[HTML]{FFFFFF}{\phantom{M}}"
        + r"\colorbox[HTML]{F2F9F0}{\phantom{M}}"
        + r"\colorbox[HTML]{E5F4E2}{\phantom{M}}"
        + r"\colorbox[HTML]{D5EDD0}{\phantom{M}}"
        + r"\colorbox[HTML]{BFE5BA}{\phantom{M}}"
        + r"\colorbox[HTML]{A8DCA3}{\phantom{M}}"
        + r"\colorbox[HTML]{96D492}{\phantom{M}}"
        + r"\colorbox[HTML]{85CC84}{\phantom{M}}"
        + r"\colorbox[HTML]{74C476}{\phantom{M}}"
        + "}"
    )
    heatmap_legend = (
        r"\begin{center}"
        + r"{\scriptsize\textbf{Cell colour (R\,/\,T\,/\,D):}\quad{}0 hits~"
        + gradient_boxes
        + r"~all runs hit.\qquad{}"
        + r"\textbf{R}\,=\,Reached\enspace{}"
        + r"\textbf{T}\,=\,Triggered\enspace{}"
        + r"\textbf{D}\,=\,Detected}"
        + r"\end{center}"
    )

    latex_table += (
        "\n"
        + r"\end{tabular}"
        + "\n"
        + r"}"
        + "\n"
        + heatmap_legend
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
