import os
import subprocess
import sys

import click

from firmrebugger.app_utils import check_fuzzers
from firmrebugger.commands.bug_analyzer import run_bug_analyzer
from firmrebugger.commands.build import build_fuzzers
from firmrebugger.commands.charting_tool import run_charting_tool
from firmrebugger.commands.fuzz import fuzz
from firmrebugger.commands.web_app import run_app
from firmrebugger.common import get_frb_base_dir, menu, parse_fuzzing_time

def check_docker_nosudo():
    """Check if Docker can be run without sudo."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if result.returncode == 0:
            click.echo("[+] Docker can be run without sudo.")
            return True
        else:
            click.echo("[!] Docker cannot be run without sudo.", err=True)
            click.echo(
                f"    To fix this, run: sudo usermod -aG docker $USER and restart your session.",
                err=True,
            )
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        click.echo("[!] Docker is not installed or not accessible.", err=True)
        return False


HELP_TEXT = """
FirmReBugger Benchmark Tool

\b
Commands:
  fuzz            Fuzz using FirmReBugger Benchmarks.
  build           Build fuzzers with Docker.
  bug-analyzer    Generate FirmReBugger bug reports.
  charting-tool   Visualizes data from FirmReBugger reports.
  app             Run the FirmReBugger web application.
Note:
  It is recommended to build the FirmReBugger versions locally.
"""


@click.group(help=HELP_TEXT, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.1.0")
def main():
    """FirmReBugger CLI"""
    pass


@main.command()
@click.option(
    "--time", "-t", default="24h", help="Duration (s,m,h) for this single fuzz run"
)
@click.option(
    "--num-trials",
    "-n",
    type=int,
    default=1,
    help="Number of trials (kept for API compatibility)",
)
@click.option(
    "--output-name", "-o", default="fuzzing_results", help="Name for output directory"
)
def fuzz_cmd(time, num_trials, output_name):
    """Fuzz using FirmReBugger Benchmarks."""
    fuzzing_time_seconds = parse_fuzzing_time(time)

    base_dir = get_frb_base_dir()
    benchmarks = ["FirmBench, FirmBenchDMA, FirmBenchX"]
    selected_bench = menu("Select benchmark", benchmarks)
    if not selected_bench:
        click.echo("No benchmark selected, aborting.")
        return
    benchmark = selected_bench[0]

    fuzzers = check_fuzzers(benchmark)
    selected_fuzzer = menu("Select fuzzer", fuzzers)
    if not selected_fuzzer:
        click.echo("No fuzzer selected, aborting.")
        return
    fuzzer = selected_fuzzer[0]

    # Gather binaries that contain this fuzzer
    binaries = []
    for item in os.listdir(os.path.join(base_dir, benchmark)):
        fuzzer_path = os.path.join(base_dir, benchmark, item, "fuzzers", fuzzer)
        if os.path.isdir(fuzzer_path):
            binaries.append(item)

    if not binaries:
        click.echo(f"No binaries found for fuzzer {fuzzer} in benchmark {benchmark}")
        return

    selected_binary = menu("Select binary", binaries)
    if not selected_binary:
        click.echo("No binary selected, aborting.")
        return
    binary = selected_binary[0]

    status = fuzz(
        fuzzing_time_seconds,
        num_trials,
        output_name,
        benchmark=benchmark,
        fuzzer=fuzzer,
        binary=binary,
    )
    click.echo(f"Fuzz run finished with status: {status}")


@main.command()
def build():
    """Build fuzzers with Docker."""
    if not check_docker_nosudo():
        sys.exit(1)

    build_fuzzers()


@main.command("bug-analyzer")
@click.argument("fuzzing_results_dir", default="./")
@click.argument("descriptor_path", default="./bug_descriptor.c")
def bug_analyzer(fuzzing_results_dir, descriptor_path):
    """
    Generate FirmReBugger bug reports.

    \b
    Arguments:
      FUZZING_RESULTS_DIR  Directory with fuzzing results [default: ./]
    """
    run_bug_analyzer(fuzzing_results_dir, descriptor_path)


@main.command("charting-tool")
def charting_tool():
    """Visualizes data from FirmReBugger reports."""
    run_charting_tool()


@main.command("backend")
@click.option("--port", "-p", default=5000, help="Port for backend")
def backend(port):
    """Run the FirmReBugger backend."""
    run_app(port)


@main.command("app")
@click.option("--port", "-p", default=5000, help="Port for backend")
def app(port):
    """Run the FirmReBugger web application."""
    base_dir = get_frb_base_dir()
    env_path = f"{base_dir}/src/firmrebugger-web/.env"

    env_vars = {}
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_vars[key] = value

    env_vars["VITE_API_URL"] = f"http://localhost:{port}"

    with open(env_path, 'w') as f:
        for key, value in env_vars.items():
            f.write(f"{key}={value}\n")

    run_app(port)

