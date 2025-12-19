import click
import subprocess
import sys
from firmrebugger.commands.charting_tool import run_charting_tool
from firmrebugger.commands.build import build_fuzzers
from firmrebugger.common import parse_fuzzing_time
from firmrebugger.commands.fuzz import fuzz
from firmrebugger.commands.bug_analyzer import run_bug_analyzer

def check_docker_nosudo():
    """Check if Docker can be run without sudo."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        if result.returncode == 0:
            click.echo("[+] Docker can be run without sudo.")
            return True
        else:
            click.echo("[!] Docker cannot be run without sudo.", err=True)
            click.echo(f"    To fix this, run: sudo usermod -aG docker $USER and restart your session.", err=True)
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

Note:
  It is recommended to build the FirmReBugger versions locally. 
"""

@click.group(
    help=HELP_TEXT,
    context_settings={"help_option_names": ["-h", "--help"]}
)
@click.version_option(version="0.1.0")
def main():
    """FirmReBugger CLI"""
    pass

@main.command()
@click.option('--time', '-t', default='24h', help='Duration (s,m,h) to run fuzzing')
@click.option('--num-trials', '-n', type=int, default=10, help='Number of trials to run')
@click.option('--output-name', '-o', default='fuzzing_results', help='Name for output directory')
@click.option('--full', is_flag=True, help='Run bug analyzer after fuzzing completes')
def fuzz_cmd(time, num_trials, output_name, full):
    """
    Fuzz using FirmReBugger Benchmarks. 
    
    \b
    Options:
      --time, -t         Duration (s,m,h) to run fuzzing [default: 24h]
      --num-trials, -n   Number of trials to run [default: 10]
      --output-name, -o  Name for output directory [default: fuzzing_results]
      --full             Run bug analyzer after fuzzing completes
    """
    fuzzing_time_seconds = parse_fuzzing_time(time)
    fuzz(fuzzing_time_seconds, num_trials, output_name, full)

@main.command()
@click.option('--frb', is_flag=True, help='Build FirmReBugger version')
def build(frb):
    """Build fuzzers with Docker."""
    if not check_docker_nosudo():
        sys.exit(1)
    
    if frb:
        build_fuzzers(frb=True)
    else:
        build_fuzzers(frb=False)

@main.command("bug-analyzer")
@click.argument('fuzzing_results_dir', default='./')
def bug_analyzer(fuzzing_results_dir):
    """
    Generate FirmReBugger bug reports. 
    
    \b
    Arguments:
      FUZZING_RESULTS_DIR  Directory with fuzzing results [default: ./]
    """
    run_bug_analyzer(fuzzing_results_dir)

@main.command("charting-tool")
def charting_tool():
    """Visualizes data from FirmReBugger reports."""
    run_charting_tool()