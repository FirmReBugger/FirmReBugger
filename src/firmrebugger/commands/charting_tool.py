from firmrebugger.common import menu, get_frb_base_dir
from firmrebugger.charting_tool_utils.generate_latex_tables import generate_table
from firmrebugger.charting_tool_utils.generate_survival_plots import survival_plot
from firmrebugger.charting_tool_utils.generate_upset_plot import generate_upset_plot
import glob
import sys
import os

FIRMREBUGGER_BASE_DIR = None


def multiple_results_check(candidate_dirs, label):
    if not candidate_dirs:
        return None
    if len(candidate_dirs) > 1:
        run_names = [os.path.basename(os.path.dirname(d)) for d in candidate_dirs]
        selected_run = menu(f"Select run for {label}", run_names)
        if not selected_run:
            print("No run selected, exiting.")
            sys.exit(1)
        return candidate_dirs[run_names.index(selected_run[0])]
    else:
        return candidate_dirs[0]


def check_frb_report_exists(output_path):
    frb_report_path = os.path.join(output_path, "frb_report.json")
    if os.path.exists(frb_report_path):
        return frb_report_path
    else:
        return None


def init_working_dirs(benchmark):
    benchmark_path = os.path.join(FIRMREBUGGER_BASE_DIR, benchmark)
    outputs_path = os.path.join(FIRMREBUGGER_BASE_DIR, "outputs")
    frb_reports = {}
    selected_targets = menu("Select binaries(s)", sorted(os.listdir(benchmark_path)))
    binary_collection = {}

    for binary in sorted(selected_targets):
        binary_path = os.path.join(benchmark_path, binary)
        fuzzer_names = sorted(
            item
            for item in os.listdir(binary_path)
            if os.path.isdir(os.path.join(binary_path, item))
        )
        report_paths = []
        for fuzzer in fuzzer_names:
            candidate_dirs = sorted(
                glob.glob(
                    os.path.join(outputs_path, "*", f"{benchmark}-{binary}-{fuzzer}")
                )
            )
            selected_dir = multiple_results_check(candidate_dirs, f"{binary}/{fuzzer}")
            if selected_dir:
                report_path = check_frb_report_exists(selected_dir)
                if report_path is not None:
                    report_paths.append(report_path)
        if report_paths:
            binary_collection[binary] = sorted(report_paths)
    if binary_collection:
        frb_reports[benchmark] = binary_collection
        return frb_reports


def run_charting_tool():
    global FIRMREBUGGER_BASE_DIR
    FIRMREBUGGER_BASE_DIR = get_frb_base_dir()
    selected_benchmarks = menu(
        "Select which Benchmark to visualize",
        ["FirmBench", "FirmBenchDMA", "FirmBenchX"],
    )
    for bench in selected_benchmarks:
        report_path = f"{FIRMREBUGGER_BASE_DIR}/frb_report/{bench}"
        frb_reports = init_working_dirs(bench)
        # Generate LaTeX tables for each target
        generate_table(frb_reports, report_path)
        # Generate upset plots for each target
        generate_upset_plot(frb_reports, report_path)
        # Generate survival plots for each binary
        for target, binaries in frb_reports.items():
            for binary, output_reports in binaries.items():
                if output_reports:
                    survival_plot(output_reports, report_path, target=target)


if __name__ == "__main__":
    run_charting_tool()
