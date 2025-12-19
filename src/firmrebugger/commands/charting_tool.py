from firmrebugger.common import menu, get_frb_base_dir
from firmrebugger.charting_tool_utils.generate_latex_tables import generate_table
from firmrebugger.charting_tool_utils.generate_survival_plots import survival_plot
from firmrebugger.charting_tool_utils.generate_upset_plot import generate_upset_plot
import sys
import os

FIRMREBUGGER_BASE_DIR = None


def multiple_results_check(fuzzing_out_path):
    if os.path.exists(fuzzing_out_path):
        folders = [
            item
            for item in os.listdir(fuzzing_out_path)
            if os.path.isdir(os.path.join(fuzzing_out_path, item))
        ]
        if len(folders) == 0:
            return None
        elif len(folders) > 1:
            selected_out_folder = menu(
                f"Select output folder for {fuzzing_out_path}", folders
            )
            if not selected_out_folder:
                print("No output folder selected, exiting.")
                sys.exit(1)
            return selected_out_folder[0]
        else:
            return folders[0]
    else:
        print(f"{fuzzing_out_path} does not exist")
        sys.exit(1)


def check_frb_report_exists(output_path):
    frb_report_path = os.path.join(output_path, "frb_report.json")
    if os.path.exists(frb_report_path):
        return frb_report_path
    else:
        # Skip silently if report doesn't exist
        return None


def init_working_dirs(benchmark):
    benchmark_path = os.path.join(FIRMREBUGGER_BASE_DIR, benchmark)
    frb_reports = {}
    selected_targets = menu("Select target(s)", sorted(os.listdir(benchmark_path)))

    for target in sorted(selected_targets):
        target_path = os.path.join(benchmark_path, target)
        binary_collection = {}
        for binary in sorted(os.listdir(target_path)):
            binary_path = os.path.join(target_path, binary)
            fuzzers_path = os.path.join(binary_path, "fuzzers")
            report_paths = []
            for fuzzer in sorted(os.listdir(fuzzers_path)):
                fuzzing_out_path = os.path.join(fuzzers_path, fuzzer, "fuzzing_out")
                selected_out = multiple_results_check(fuzzing_out_path)
                if selected_out:
                    report_path = check_frb_report_exists(
                        os.path.join(fuzzing_out_path, selected_out)
                    )
                    if report_path is not None:
                        report_paths.append(report_path)
            if report_paths:
                binary_collection[binary] = sorted(report_paths)
        if binary_collection:
            frb_reports[target] = binary_collection
    print(frb_reports)
    return frb_reports


def run_charting_tool():
    global FIRMREBUGGER_BASE_DIR
    FIRMREBUGGER_BASE_DIR = get_frb_base_dir()
    selected_benchmarks = menu(
        "Select which Benchmark to visualize",
        ["FirmBench", "FirmBenchDMA", "FirmBenchX"],
    )
    for bench in selected_benchmarks:
        report_path = f"{FIRMREBUGGER_BASE_DIR}/report/{bench}"
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
    main()
