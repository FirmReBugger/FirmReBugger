from firmrebugger.common import get_frb_base_dir, menu
from firmrebugger.commands.build import check_docker_builds
from firmrebugger.common import parse_fuzzing_time
import os
import sys
import shutil
import subprocess
import time
import yaml
import glob
import select

FIRMREBUGGER_BASE_DIR = None
FUZZING_TIME = "24h"
FUZZING_OUTPUT_NAME = "fuzzing_results"
FUZZING_NUM_TRIALS = 10
SELECTED_BENCH = None
RUN_ANALYZER = False  # Only run analyzer if --full flag is set
# Check if fuzzing is active to not kill any active jobs
FUZZER_ACTIVE = False

jobs = []  # running jobs
job_queue = []  # queued jobs
completed_trials = {}  # Track completed trials per fuzzing group
analyzer_queued = set()  # Track which analyzer jobs have been queued


# Initialize the bench info file
def init_bench_info(
    bench_info_path,
    Fuzzer,
    Fuzzing_Target,
    Fuzzing_Trials,
    Planned_Fuzzing_Time,
    Start_Fuzzing_Time,
):
    data = {
        "Fuzzer": Fuzzer,
        "Target": os.path.splitext(os.path.basename(Fuzzing_Target))[0],
        "Num_Trials": int(Fuzzing_Trials),
        "Planned_Time": int(Planned_Fuzzing_Time),
        "Start_Time": int(round(Start_Fuzzing_Time)),
        "End_Time": None,
        "Total_Time": None,
        "Start_date": time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(Start_Fuzzing_Time)
        ),
    }
    try:
        with open(f"{os.path.dirname(bench_info_path)}/frb_bench_info.yml", "w") as f:
            yaml.dump(data, f, sort_keys=False)
    except Exception as e:
        print(f"Error writing bench info: {e}")


# Update the bench info with end time and total time
def end_write_bench_info(bench_info_path, ending_time, elapsed_time):
    try:
        with open(f"{os.path.dirname(bench_info_path)}/frb_bench_info.yml", "r") as f:
            data = yaml.safe_load(f)
        data["End_Time"] = int(round(ending_time))
        data["Total_Time"] = int(round(elapsed_time))
        with open(f"{os.path.dirname(bench_info_path)}/frb_bench_info.yml", "w") as f:
            yaml.dump(data, f, sort_keys=False)
    except Exception as e:
        print(f"Error updating bench info: {e}")


# Create a .bin file from an .elf file using arm-none-eabi-objcopy
def create_bin_from_elf(elf_path, result_dir):
    global FUZZER_ACTIVE
    objcopy_path = shutil.which("arm-none-eabi-objcopy")
    if objcopy_path is None:
        print(
            "arm-none-eabi-objcopy not found in PATH. Please install it or add it to your PATH."
        )
        if FUZZER_ACTIVE:
            return None
        else:
            return None
    bin_path = os.path.join(
        result_dir, os.path.splitext(os.path.basename(elf_path))[0] + ".bin"
    )
    try:
        subprocess.run([objcopy_path, "-O", "binary", elf_path, bin_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to create .bin from .elf: {e}")
        if FUZZER_ACTIVE:
            return None
        else:
            return None


# Print progress bar
def print_progress_bar(run_time_errors, bar_length=30):
    global jobs, job_queue, SELECTED_BENCH
    try:
        os.system("clear")
    except Exception:
        pass

    print("=== Running Jobs ===")
    
    # Separate fuzzing and analyzer jobs
    fuzzing_jobs = [j for j in jobs if j.get("job_type") != "analyzer"]
    analyzer_jobs = [j for j in jobs if j.get("job_type") == "analyzer"]
    
    # Display fuzzing jobs with progress bar
    if fuzzing_jobs:
        print("\n[FUZZING]")
        grouped = {}
        for job in fuzzing_jobs:
            fields = job["desc"].split(":")
            if len(fields) < 4:
                continue  # skip malformed desc
            fuzzer = fields[0]
            fuzzing_output_name = fields[2]
            binary = fields[3]
            key = (fuzzer, binary, fuzzing_output_name)
            if key not in grouped:
                grouped[key] = {"job": job, "count": 1}
            else:
                grouped[key]["count"] += 1

        for (fuzzer, binary, fuzzing_output_name), info in grouped.items():
            job = info["job"]
            count = info["count"]
            elapsed = time.time() - job["start_time"]
            total = job["timeout"]
            percent = min(elapsed / total, 1.0)
            arrow = "=" * int(percent * bar_length)
            spaces = " " * (bar_length - len(arrow))
            bar = f"[{arrow}{spaces}]"
            print(
                f"  {fuzzer}:{SELECTED_BENCH}:{binary}:{fuzzing_output_name} {bar} {int(percent * 100)}% ({int(elapsed)}/{int(total)} sec) x {count}"
            )
    
    # Display analyzer jobs with elapsed time only
    if analyzer_jobs:
        print("\n[ANALYZING]")
        for job in analyzer_jobs:
            elapsed = time.time() - job["start_time"]
            desc = job["desc"].replace("analyzer:", "")
            print(f"  {desc} (elapsed: {int(elapsed)} sec)")
    
    if not fuzzing_jobs and not analyzer_jobs:
        print("No jobs currently running.")

    print("\n=== Queued Jobs ===")
    if job_queue:
        group_counts = {}
        for queued_job in job_queue:
            fuzzer = queued_job.get("fuzzer", "?")
            target_bench = queued_job.get("target_bench", "?")
            target = queued_job.get("target", "?")
            fuzzing_output_name = queued_job.get("fuzzing_output_name", "?")
            key = (fuzzer, target_bench, fuzzing_output_name, target)
            group_counts[key] = group_counts.get(key, 0) + 1
        for (
            fuzzer,
            target_bench,
            fuzzing_output_name,
            target,
        ), count in group_counts.items():
            print(
                f"{fuzzer}:{SELECTED_BENCH}:{target_bench}:{fuzzing_output_name}:{target} [QUEUED] x {count}"
            )
    else:
        print("No jobs queued.")

    if run_time_errors:
        print("\n=== Errors in runs: ===")
        print(run_time_errors)

    print("\nPress Enter to add new jobs, Ctrl+C to quit fuzzing campaign.")


def check_target_has_fuzzer(target_bench, target, selected_fuzzers):
    target_path = (
        f"{FIRMREBUGGER_BASE_DIR}/{SELECTED_BENCH}/{target_bench}/{target}/fuzzers"
    )
    try:
        available_fuzzers = os.listdir(target_path)
    except FileNotFoundError:
        return False
    return any(f in available_fuzzers for f in selected_fuzzers)


def target_selection(selected_fuzzers):
    global SELECTED_BENCH
    try:
        SELECTED_BENCH = menu(
            "Select target bench", ["FirmBench", "FirmBenchX", "FirmBenchDMA"]
        )[0]
        benchmark_dir = os.listdir(f"{FIRMREBUGGER_BASE_DIR}/{SELECTED_BENCH}")
        targets = {}

        valid_bench_targets = []
        for bench in benchmark_dir:
            targets_dir = os.listdir(
                f"{FIRMREBUGGER_BASE_DIR}/{SELECTED_BENCH}/{bench}"
            )
            valid_targets = [
                t
                for t in targets_dir
                if check_target_has_fuzzer(bench, t, selected_fuzzers)
            ]
            if valid_targets:
                valid_bench_targets.append(bench)

        if not valid_bench_targets:
            print("No targets with selected fuzzers found.")
            return None

        selected_targets_bench = menu(
            "Select targets to run (Bench)", valid_bench_targets
        )
        for bench in selected_targets_bench:
            targets_dir = os.listdir(
                f"{FIRMREBUGGER_BASE_DIR}/{SELECTED_BENCH}/{bench}"
            )
            valid_targets = [
                t
                for t in targets_dir
                if check_target_has_fuzzer(bench, t, selected_fuzzers)
            ]
            if not valid_targets:
                continue
            selected_targets = menu(
                f"Select targets for {bench} (Bench)", valid_targets
            )
            filtered_targets = [
                t
                for t in selected_targets
                if check_target_has_fuzzer(bench, t, selected_fuzzers)
            ]
            if filtered_targets:
                targets[bench] = filtered_targets

        if not targets:
            print("No selected targets found with the chosen fuzzers.")
            return None

        return targets
    except Exception as e:
        print(f"Error in target selection: {e}")
        if FUZZER_ACTIVE:
            return None
        else:
            return None


# Prepare the output target fuzzing folder
def prep_target_folder(
    fuzzer, target_path, result_dir, output_path, result_output_path, start_time
):
    global FUZZER_ACTIVE
    result_dir = f"{target_path}/fuzzing_out/{result_dir}"
    try:
        if "output-01" in output_path:
            if os.path.exists(result_dir):
                print(f"Result Directory {result_dir} already exists. Exiting.")
                if FUZZER_ACTIVE:
                    return None
                else:
                    return None
            os.makedirs(result_dir, exist_ok=True)
            binary_path = os.path.dirname(os.path.dirname(target_path))
            binary_path = os.path.join(binary_path, "binary")
            elf_path = glob.glob(os.path.join(binary_path, "*.elf"))
            if not elf_path:
                print("No .elf file found in binary dir.")
                if FUZZER_ACTIVE:
                    return None
                else:
                    return None
            init_bench_info(
                result_output_path,
                fuzzer,
                elf_path[0],
                FUZZING_NUM_TRIALS,
                FUZZING_TIME,
                start_time,
            )
            if "SEmu-Fuzz" in fuzzer:
                try:
                    shutil.copy(f"{target_path}/rules.txt", result_dir)
                    shutil.copy(f"{target_path}/cortexm_memory.yml", result_dir)
                except Exception as e:
                    print(f"Error copying rules or cortexmconfig: {e}")
            if os.path.exists(f"{target_path}/seeds"):
                try:
                    shutil.copytree(f"{target_path}/seeds", f"{result_dir}/seeds")
                except Exception as e:
                    print(f"Error copying seeds: {e}")
            for config_file in glob.glob(f"{target_path}/config*"):
                try:
                    shutil.copy(
                        config_file, f"{result_dir}/{os.path.basename(config_file)}"
                    )
                except Exception as e:
                    print(f"Error copying config file {config_file}: {e}")
            try:
                shutil.copy(
                    f"{FIRMREBUGGER_BASE_DIR}/src/firmrebugger/fuzzer_runners/{fuzzer}-run.sh",
                    f"{result_dir}/{fuzzer}-run.sh",
                )
            except Exception as e:
                print(f"Error copying fuzzer runner script: {e}")
            elf_files = glob.glob(os.path.join(target_path, "../../binary/*.elf"))
            if elf_files:
                try:
                    shutil.copy(elf_files[0], result_dir)
                    bin_res = create_bin_from_elf(elf_files[0], result_dir)
                    if bin_res is None:
                        return None
                except Exception as e:
                    print(f"Error copying/creating .bin from .elf: {e}")
                    if FUZZER_ACTIVE:
                        return None
                    else:
                        return None
            else:
                print("No .elf file found.")
                if FUZZER_ACTIVE:
                    return None
                else:
                    return None
    except Exception as e:
        print(f"Error preparing target folder: {e}")
        if FUZZER_ACTIVE:
            return None
        else:
            return None


# Dynamically add new jobs to the job queue
def add_new_jobs():
    global FUZZER_ACTIVE, job_queue
    try:
        if select.select([sys.stdin], [], [], 0)[0]:
            line = sys.stdin.readline()
            if line == "\n":
                print("\nEnter pressed! Add a job here.")
                print(
                    "Enter fuzzing_time (24h, 3600m...), fuzzing_trial, fuzzing_output_name separated by spaces (or 'q' to exit):"
                )
                user_input = input("> ").strip()
                if user_input.lower() == "q":
                    print("Exiting...")
                    return
                args = user_input.split()
                if len(args) == 3:
                    fuzzing_time, fuzzing_trial, fuzzing_output_name = args
                    fuzzing_time = parse_fuzzing_time(fuzzing_time)
                    if fuzzing_time is None:
                        print("Invalid fuzzing_time format. Use 24h, 3600m, etc.")
                        return
                    try:
                        fuzzing_trial = int(fuzzing_trial)
                    except ValueError:
                        print("Invalid trial count: must be an integer.")
                        return
                    FUZZER_ACTIVE = True
                    enqueue_job(fuzzing_time, fuzzing_trial, fuzzing_output_name)
                else:
                    print(
                        "Invalid input. Please enter 3 arguments separated by spaces (or 'q' to exit)."
                    )
            else:
                print(f"\nInput received: {line.strip()}")
    except Exception as e:
        print(f"Error adding new jobs: {e}")


# Enqueue a job
def enqueue_job(fuzzing_time, fuzzing_num_trials, fuzzing_output_name):
    global job_queue
    global FIRMREBUGGER_BASE_DIR, FUZZING_TIME, FUZZING_OUTPUT_NAME, FUZZING_NUM_TRIALS
    try:
        FIRMREBUGGER_BASE_DIR = get_frb_base_dir()
        FUZZING_TIME = fuzzing_time
        FUZZING_OUTPUT_NAME = fuzzing_output_name
        FUZZING_NUM_TRIALS = fuzzing_num_trials

        fuzzer_docker_dirs = f"{FIRMREBUGGER_BASE_DIR}/docker/"
        fuzzer_docker_dirs = os.listdir(fuzzer_docker_dirs)
        selected_fuzzers = menu("Select fuzzers to run (Docker)", fuzzer_docker_dirs)
        check_docker_builds(selected_fuzzers)
        targets = target_selection(selected_fuzzers)
        if targets is None:
            print("No targets selected, exiting.")
            return
        for target_bench, target_list in targets.items():
            for fuzzer in selected_fuzzers:
                for target in target_list:
                    for trial in range(FUZZING_NUM_TRIALS):
                        job_queue.append(
                            {
                                "fuzzer": fuzzer,
                                "target_bench": target_bench,
                                "target": target,
                                "trial": trial,
                                "fuzzing_time": FUZZING_TIME,
                                "fuzzing_output_name": FUZZING_OUTPUT_NAME,
                            }
                        )
    except Exception as e:
        print(f"Error enqueuing job: {e}")


# Check if all trials for a fuzzing group are done, then queue analyzer
def check_and_queue_analyzer(job):
    global completed_trials, analyzer_queued
    
    # Extract fuzzing group key (fuzzer, target_bench, target, output_name)
    fuzzer = job.get("fuzzer")
    target_bench = job.get("target_bench")
    target = job.get("target")
    output_name = job.get("fuzzing_output_name")
    
    group_key = f"{fuzzer}:{target_bench}:{target}:{output_name}"
    
    # Initialize or increment completed count for this group
    if group_key not in completed_trials:
        completed_trials[group_key] = 0
    completed_trials[group_key] += 1
    
    print(f"\n[+] Completed trial {completed_trials[group_key]}/{FUZZING_NUM_TRIALS} for {group_key}")
    
    # Check if all trials are done and analyzer not yet queued
    if completed_trials[group_key] >= FUZZING_NUM_TRIALS and group_key not in analyzer_queued:
        # Only queue analyzer if --full flag was set
        if not RUN_ANALYZER:
            print(f"\n[+] All trials complete for {group_key} (analyzer skipped, use --full to enable)")
            analyzer_queued.add(group_key)  # Mark as processed so we don't check again
            return
        
        # Calculate the fuzzing_out directory path (parent of all output-XX dirs)
        # output_path is like: /path/to/target/fuzzers/Fuzzer/fuzzing_out/test/output-01
        # We want: /path/to/target/fuzzers/Fuzzer/fuzzing_out/test
        output_path = job["output_path"]
        fuzzing_out_dir = os.path.dirname(output_path)
        
        analyzer_job = {
            "job_type": "analyzer",
            "fuzzer": fuzzer,
            "target_bench": target_bench,
            "target": target,
            "fuzzing_out_dir": fuzzing_out_dir,
            "desc": f"analyzer:{fuzzer}:{target_bench}:{output_name}:{target}",
        }
        job_queue.append(analyzer_job)
        analyzer_queued.add(group_key)
        print(f"\n[+] All trials complete! Queued analyzer job for {group_key}")
        print(f"[+] Analyzer will run in: {fuzzing_out_dir}")


# Monitor and report job status
def monitor_and_report_jobs(run_time_errors):
    global completed_trials, analyzer_queued
    now = time.time()
    try:
        for job in jobs[:]:
            proc = job["proc"]
            elapsed = now - job["start_time"]
            # Skip timeout check for analyzer jobs
            if job.get("job_type") != "analyzer" and elapsed > job["timeout"]:
                try:
                    end_write_bench_info(job["output_path"], now, elapsed)
                    
                    # Track completed fuzzing jobs
                    if job.get("job_type") == "fuzzing":
                        check_and_queue_analyzer(job)

                except Exception as e:
                    print(f"Error writing bench info at timeout: {e}")
                print(
                    f"\nForce-killing container {job['container_name']} ({job['desc']}) after {job['timeout']} seconds"
                )
                try:
                    subprocess.run(["docker", "kill", job["container_name"]])
                except Exception as e:
                    print(f"Error killing docker container: {e}")
                jobs.remove(job)
            elif proc.poll() is not None:
                try:
                    # Close log file if this is an analyzer job
                    if job.get("job_type") == "analyzer" and "log_file" in job:
                        try:
                            job["log_file"].close()
                        except Exception as e:
                            print(f"Error closing log file: {e}")
                    
                    end_write_bench_info(job["output_path"], now, elapsed)
                    
                    # Track completed fuzzing jobs
                    if job.get("job_type") == "fuzzing":
                        check_and_queue_analyzer(job)
                    
                    # Report analyzer failures
                    if job.get("job_type") == "analyzer":
                        if proc.returncode != 0:
                            print(f"\n[!] Analyzer failed for {job['desc']} (exit code: {proc.returncode})")
                            print(f"[!] Log saved to: {job.get('log_file_path', 'unknown')}")
                        else:
                            print(f"\n[+] Analyzer completed successfully for {job['desc']}")
                        
                except Exception as e:
                    print(f"Error writing bench info at proc completion: {e}")
                jobs.remove(job)
                if proc.returncode != 0 and proc.returncode != 124:
                    run_time_errors.append(job["desc"])
        print_progress_bar(run_time_errors)
        add_new_jobs()
        time.sleep(1)
    except Exception as e:
        print(f"Error in monitor/report loop: {e}")


# Force-kill all jobs
def kill_all_jobs():
    global jobs
    for job in jobs:
        try:
            # Close log file if this is an analyzer job
            if job.get("job_type") == "analyzer" and "log_file" in job:
                try:
                    job["log_file"].close()
                except Exception as e:
                    print(f"Error closing log file: {e}")
            
            now = time.time()
            elapsed = now - job["start_time"]
            end_write_bench_info(job["output_path"], now, elapsed)
            subprocess.run(["docker", "kill", job["container_name"]])
            print(f"Force-killed container {job['container_name']} ({job['desc']})")
        except Exception as e:
            print(f"Error force-killing container {job['container_name']}: {e}")


# Main manager loop for fuzzing jobs
def manager_loop(num_cores):
    global jobs, job_queue
    run_time_errors = []
    try:
        while jobs or job_queue:
            # Launch new jobs if slots are available
            while len(jobs) < num_cores and job_queue:
                job_info = job_queue.pop(0)
                
                # Check if this is an analyzer job or fuzzing job
                if job_info.get("job_type") == "analyzer":
                    # Check if there's already an analyzer running
                    analyzer_running = any(j.get("job_type") == "analyzer" for j in jobs)
                    if analyzer_running:
                        # Put it back at the front of the queue and wait
                        job_queue.insert(0, job_info)
                        break
                    
                    # Handle analyzer job
                    fuzzer = job_info.get("fuzzer")
                    fuzzing_out_dir = job_info.get("fuzzing_out_dir")
                    abs_fuzzing_out_dir = os.path.abspath(fuzzing_out_dir)
                    
                    # Validate inputs
                    if not fuzzer:
                        print(f"[!] Warning: Analyzer job has no fuzzer name, skipping: {job_info.get('desc')}")
                        continue
                    if not fuzzing_out_dir:
                        print(f"[!] Warning: Analyzer job has no fuzzing_out_dir, skipping: {job_info.get('desc')}")
                        continue
                    
                    # Get the current working directory where the user ran the fuzz command
                    firmrebugger_src = os.getcwd()
                    
                    idx = find_available_idx(num_cores)
                    if idx is None:
                        break
                    container_name = f"frb_analyzer_{idx}"
                    
                    # Create log file path in the fuzzing_out directory
                    log_file_path = os.path.join(abs_fuzzing_out_dir, "frb_analyzer.log")
                    
                    # Calculate relative path from firmrebugger_src to fuzzing_out_dir
                    # This will be the path inside the container under /benchmark
                    rel_path = os.path.relpath(abs_fuzzing_out_dir, firmrebugger_src)
                    container_work_dir = f"/benchmark/{rel_path}"
                    
                    run_cmd = [
                        "docker",
                        "run",
                        "--rm",
                        "--name",
                        container_name,
                        "--mount",
                        f"type=bind,source={firmrebugger_src},target=/benchmark",
                        "-w",
                        container_work_dir,
                        f"frb:{fuzzer}",
                        "/bin/bash",
                        "-c",
                        f"cd /benchmark && uv run frb bug-analyzer {container_work_dir}",
                    ]
                    
                    try:
                        log_file = open(log_file_path, 'w')
                        
                        # Write job details header to log file
                        log_file.write("=" * 80 + "\n")
                        log_file.write("FirmReBugger Analyzer Job Log\n")
                        log_file.write("=" * 80 + "\n")
                        log_file.write(f"Job Description: {job_info.get('desc', 'N/A')}\n")
                        log_file.write(f"Fuzzer: {fuzzer}\n")
                        log_file.write(f"Fuzzing Output Dir: {fuzzing_out_dir}\n")
                        log_file.write(f"Container: {container_name}\n")
                        log_file.write(f"Docker Image: frb:{fuzzer}\n")
                        log_file.write(f"Start Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n")
                        log_file.write("=" * 80 + "\n\n")
                        log_file.flush()
                        
                        proc = subprocess.Popen(
                            run_cmd, 
                            stdout=log_file,
                            stderr=subprocess.STDOUT,
                            preexec_fn=os.setsid
                        )
                    except Exception as e:
                        print(f"Error starting analyzer container: {e}")
                        if 'log_file' in locals():
                            log_file.close()
                        continue
                    
                    job = {
                        "proc": proc,
                        "container_name": container_name,
                        "start_time": time.time(),
                        "timeout": float('inf'),  # No timeout for analyzer
                        "output_path": fuzzing_out_dir,  # Use fuzzing_out_dir for bench_info
                        "desc": job_info["desc"],
                        "job_type": "analyzer",
                        "fuzzer": fuzzer,
                        "log_file": log_file,
                        "log_file_path": log_file_path,
                    }
                    jobs.append(job)
                    
                    # Add delay between spawning analyzer jobs to avoid resource contention
                    time.sleep(1)
                else:
                    # Handle fuzzing job
                    fuzzer = job_info["fuzzer"]
                    target_bench = job_info["target_bench"]
                    target = job_info["target"]
                    trial = job_info["trial"]
                    fuzzing_time = job_info["fuzzing_time"]
                    fuzzing_output_name = job_info["fuzzing_output_name"]

                    target_path = f"{FIRMREBUGGER_BASE_DIR}/{SELECTED_BENCH}/{target_bench}/{target}/fuzzers/{fuzzer}"
                    output_path = f"output-{trial + 1:02d}"
                    start_time = time.time()
                    timeout = int(fuzzing_time) + 60
                    result_output_path = (
                        f"{target_path}/fuzzing_out/{fuzzing_output_name}/{output_path}"
                    )
                    idx = find_available_idx(num_cores)
                    if idx is None:
                        break
                    core_id = idx % num_cores
                    container_name = f"frb_job_{idx}"

                    prep_target_folder(
                        fuzzer,
                        target_path,
                        fuzzing_output_name,
                        output_path,
                        result_output_path,
                        start_time,
                    )
                    run_cmd = [
                        "docker",
                        "run",
                        "--cpus=1",
                        f"--cpuset-cpus={core_id}",
                        "--rm",
                        "--name",
                        container_name,
                        "--mount",
                        f"type=bind,source={target_path}/fuzzing_out/{fuzzing_output_name},target=/home/user/{fuzzer}/target",
                        "-w",
                        f"/home/user/{fuzzer}/target",
                        f"frb_original:{fuzzer}",
                        f"./{fuzzer}-run.sh",
                        str(fuzzing_time),
                        output_path,
                    ]
                    try:
                        proc = subprocess.Popen(run_cmd, preexec_fn=os.setsid)
                    except Exception as e:
                        print(f"Error starting fuzzing container: {e}")
                        continue
                    job = {
                        "proc": proc,
                        "container_name": container_name,
                        "start_time": start_time,
                        "timeout": timeout,
                        "output_path": result_output_path,
                        "desc": f"{fuzzer}:{target_bench}:{fuzzing_output_name}:{target}:trial{trial + 1}",
                        "job_type": "fuzzing",
                        "fuzzer": fuzzer,
                        "target_bench": target_bench,
                        "target": target,
                        "fuzzing_output_name": fuzzing_output_name,
                    }
                    jobs.append(job)
            monitor_and_report_jobs(run_time_errors)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt detected, force-killing all containers...")
        kill_all_jobs()
    except Exception as e:
        print(f"Error in manager_loop: {e}")


# Find avaliable core for job
def find_available_idx(max_idx):
    global jobs
    used_indices = {int(job["container_name"].split("_")[-1]) for job in jobs}
    for i in range(max_idx):
        if i not in used_indices:
            return i
    return None


# Start the fuzzing benchmark
def start_bench(fuzzers, targets, fuzzing_output_name):
    global job_queue, FUZZER_ACTIVE
    num_cores = (os.cpu_count() or 1) - 1
    if num_cores < 1:
        num_cores = 1

    for target_bench, target_list in targets.items():
        for fuzzer in fuzzers:
            for target in target_list:
                for trial in range(FUZZING_NUM_TRIALS):
                    job_queue.append(
                        {
                            "job_type": "fuzzing",
                            "fuzzer": fuzzer,
                            "target_bench": target_bench,
                            "target": target,
                            "trial": trial,
                            "fuzzing_time": FUZZING_TIME,
                            "fuzzing_output_name": fuzzing_output_name,
                        }
                    )
    if FUZZER_ACTIVE:
        return
    manager_loop(num_cores)


# Fuzzing
def fuzz(fuzzing_time, fuzzing_num_trials, fuzzing_output_name, run_analyzer=False):
    global FIRMREBUGGER_BASE_DIR
    try:
        FIRMREBUGGER_BASE_DIR = get_frb_base_dir()
        global FUZZING_TIME, FUZZING_OUTPUT_NAME, FUZZING_NUM_TRIALS, RUN_ANALYZER
        FUZZING_TIME = fuzzing_time
        RUN_ANALYZER = run_analyzer
        if FUZZING_TIME is None:
            if FUZZER_ACTIVE:
                return
            print("Invalid Format for fuzzing_time. Use 24h, 3600m, etc.")
            return

        FUZZING_OUTPUT_NAME = fuzzing_output_name
        FUZZING_NUM_TRIALS = fuzzing_num_trials
        fuzzer_docker_dirs = f"{FIRMREBUGGER_BASE_DIR}/docker/"
        fuzzer_docker_dirs = os.listdir(fuzzer_docker_dirs)
        selected_fuzzers = menu("Select fuzzers to run (Docker)", fuzzer_docker_dirs)
        check_docker_builds(selected_fuzzers)
        targets = target_selection(selected_fuzzers)
        if targets is None:
            print("No targets selected, exiting.")
            return
        start_bench(selected_fuzzers, targets, fuzzing_output_name)
    except Exception as e:
        print(f"Error in fuzz(): {e}")

