import argparse
from firmrebugger.build_fuzzers.build_fuzzers import build_fuzzers_docker
from firmrebugger.fuzz.fuzz import fuzz
from firmrebugger.analysis_bench.bug_analyzer import bug_analyzer
from firmrebugger.analysis_bench.charting_tool import charting_tool
from firmrebugger.utils.common import parse_fuzzing_time
import sys


def print_help():
    help_text = """
FirmReBugger Benchmark Tool

Usage:
  firmrebugger <command> [<args>...]

Commands:
  fuzz            Fuzz using FirmReBugger Benchmarks.
  build           Build fuzzers with Docker.
  bug-analyzer    Generate FirmReBugger bug reports.
  charting-tool   Visualizes data from FirmReBugger reports. Output is saved in the 'report' folder.

Arguments for 'fuzz':
  time            Duration (s,m,h) to run the fuzzing (optional, positional, default: 24h)
  num_trials      Number of trials to run (optional, positional, default: 10)
  output_name     Name for the fuzzing output directory (optional, positional, default: fuzzing_results)

Arguments for 'build':
    --frb           Build FirmReBugger version of a fuzzer with Docker (optional, flag)

Arguments for 'bug-analyzer':
  fuzzing_results_dir  Directory containing the fuzzing results (Optional, positional, default: ./)

Note:
    It is recommended to build the FirmReBugger versions of the fuzzers locally, running the analyzer in docker is slow.

"""
    print(help_text)


def main():
    parser = argparse.ArgumentParser(
        description="FirmReBugger benchmarking tool.", add_help=False
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="FirmReBugger commands"
    )

    # Build fuzzers
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument(
        "--frb",
        action="store_true",
    )

    # Fuzz using bench
    fuzz_parser = subparsers.add_parser("fuzz")
    fuzz_parser.add_argument("fuzzing_time", type=str, nargs="?", default="24h")
    fuzz_parser.add_argument("num_trials", type=int, nargs="?", default=10)
    fuzz_parser.add_argument(
        "fuzzing_output_name", type=str, nargs="?", default="fuzzing_results"
    )

    # Bug analyzer
    bug_analyzer_parser = subparsers.add_parser("bug-analyzer")
    bug_analyzer_parser.add_argument(
        "fuzzing_results_dir", type=str, nargs="?", default="./"
    )

    # Charting tool
    subparsers.add_parser("charting-tool")

    # Show custom help if no arguments or if -h/--help is present
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "build":
        build_fuzzers_docker(args.frb)
    elif args.command == "fuzz":
        args.fuzzing_time = parse_fuzzing_time(args.fuzzing_time)
        fuzz(args.fuzzing_time, args.num_trials, args.fuzzing_output_name)
    elif args.command == "bug-analyzer":
        bug_analyzer(args.fuzzing_results_dir)
    elif args.command == "charting-tool":
        charting_tool()


if __name__ == "__main__":
    main()
