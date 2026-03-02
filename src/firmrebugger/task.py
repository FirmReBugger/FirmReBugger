import multiprocessing
import os
import threading
import time
from queue import Queue
from typing import List
from firmrebugger.common import get_frb_base_dir
import subprocess
import shutil

class Task:
    """Represents a single run of a fuzzing job."""
    def __init__(self, task_id, job_id, fuzzer, duration, binary, run_number, mode, benchmark , output_dir, runs, core_idx, container_name):
        self.task_id = task_id
        self.job_id = job_id
        self.fuzzer = fuzzer
        self.duration = duration
        self.binary = binary
        self.run_number = run_number
        self.mode = mode
        self.benchmark = benchmark
        self.status = "queued"
        self.process = None
        self.subprocess = None
        self.created_at = time.time()
        self.started_at = None
        self.completed_at = None
        self.output_dir = output_dir
        self.runs = runs
        self.core_idx = core_idx
        self.container_name = container_name

    def start(self):
        """Start the fuzzing task in a separate thread."""
        self.status = "running"
        self.started_at = time.time()
        
        def run_task():
            print(f"[Task {self.task_id}] Starting fuzzer '{self.fuzzer}' on binary '{self.binary}' (Run {self.run_number}) for {self.duration} seconds (Mode: {self.mode})")

            if self.mode == "Fuzzing":
                self.fuzz()
            elif self.mode == "Triaging":
                self.triage()

            if self.status not in ["error", "stopped"]:
                self.status = "completed"
            self.completed_at = time.time()
            print(f"[Task {self.task_id}] Completed with status: {self.status}.")
        
        self.process = threading.Thread(target=run_task)
        self.process.start()

    def is_running(self):
        """Check if the task is currently running."""
        return self.process is not None and self.process.is_alive()
    
    def docker_cp(self, source, destination):
        """Copy files to/from a Docker container."""
        docker_cp_cmd = [
            "docker", "cp",
            source,
            destination
        ]
        subprocess.run(docker_cp_cmd, check=True)
    
    def fuzz(self):
        base_dir = get_frb_base_dir()
        work_dir = os.path.join(base_dir, self.benchmark, self.binary, "fuzzers", self.fuzzer, "fuzzing_out", self.output_dir)

        run_cmd = [
            "docker", "run", "--cpus=1",
            f"--cpuset-cpus={self.core_idx}",
            "--rm",
            "-itd",
            "--name", self.container_name,
            f"frb_original:{self.fuzzer}"
        ]
        subprocess.run(run_cmd, check=True)

        print("the work dir is:", work_dir)

        self.docker_cp(work_dir, f"{self.container_name}:/home/user/target")

        os.makedirs(f"{work_dir}/fuzzing_logs", exist_ok=True)
        log_file = f"{work_dir}/fuzzing_logs/log-{self.run_number}.log"

        fuzz_start_time = time.time()
        
        with open(log_file, "w") as log:
            docker_exec_cmd = [
                "docker", "exec",
                "-w", "/home/user/target",
                self.container_name,
                f"./{self.fuzzer}-run.sh",
                str(self.duration),
                f"/home/user/target/output-{self.run_number}"
            ]

            self.subprocess = subprocess.Popen(
                docker_exec_cmd,
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                universal_newlines=True  
            )

            for line in self.subprocess.stdout:
                log.write(line)  
                log.flush()  

            self.subprocess.wait()

            if self.status != "stopped" and self.subprocess.returncode not in (0, None):
                warn_msg = f"Fuzzer process exited with non-zero status {self.subprocess.returncode}"
                print(f"[Task {self.task_id}] WARNING: {warn_msg}")
                log.write(f"\n\nWARNING: {warn_msg}\n")
                log.flush()

        fuzz_end_time = time.time()
        actual_duration = fuzz_end_time - fuzz_start_time
        expected_duration = max(0, self.duration - 5)
        
        if self.status != "stopped" and actual_duration < expected_duration:
            return_code = self.subprocess.returncode if self.subprocess is not None else "unknown"
            error_msg = (
                f"Task ended prematurely after {actual_duration:.1f}s "
                f"(expected at least {expected_duration}s; return code: {return_code})"
            )
            print(f"[Task {self.task_id}] ERROR: {error_msg}")
            self.status = "error"
            with open(log_file, "a") as log:
                log.write(f"\n\nERROR: {error_msg}\n")
        
        if self.status != "stopped":
            try:
                self.docker_cp(f"{self.container_name}:/home/user/target/output-{self.run_number}", work_dir)
                print(f"Fuzzing results copied to {work_dir}")
            except Exception as e:
                print(f"[Task {self.task_id}] Could not copy results: {e}")
        
        try:
            subprocess.run(["docker", "stop", self.container_name], check=False,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[Task {self.task_id}] Stopped docker container: {self.container_name}")
        except Exception as e:
            print(f"[Task {self.task_id}] Error stopping container {self.container_name}: {e}")

    def kill_task(self):
        """Force kill a task and its docker container."""
        print(f"[Scheduler] Force killing task {self.task_id}...")
        
        try:
            base_dir = get_frb_base_dir()
            work_dir = os.path.join(base_dir, self.benchmark, self.binary, "fuzzers", self.fuzzer, "fuzzing_out", self.output_dir)
            self.docker_cp(f"{self.container_name}:/home/user/target/output-{self.run_number}", work_dir)
            print(f"[Scheduler] Copied results from container {self.container_name} before killing")
        except Exception as e:
            print(f"[Scheduler] Could not copy results from container {self.container_name}: {e}")
        
        try:
            subprocess.run(["docker", "kill", self.container_name], check=False, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[Scheduler] Killed docker container: {self.container_name}")
        except Exception as e:
            print(f"[Scheduler] Error killing container {self.container_name}: {e}")
        
        self.stop()
        print(f"[Scheduler] Task {self.task_id} stopped.")

    def stop(self):
        """Stop the running task."""
        if self.process and self.process.is_alive():
            self.status = "stopped"
            self.completed_at = time.time()
            
            if self.subprocess and self.subprocess.poll() is None:
                try:
                    self.subprocess.terminate()
                    self.subprocess.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.subprocess.kill()
                except Exception as e:
                    print(f"[Task {self.task_id}] Error stopping subprocess: {e}")
            
            print(f"[Task {self.task_id}] Task stopped.")
    
    def triage(self):
        """Perform triaging on the fuzzing results."""
        container_name = f"frb_triage_{self.job_id}_{self.task_id}"
        base_dir = get_frb_base_dir()
        output_dir = os.path.join(base_dir, self.benchmark, self.binary, "fuzzers", self.fuzzer, "fuzzing_out", self.output_dir)

        bug_descriptor_path = os.path.join(base_dir, self.benchmark, self.binary, "bug_descriptor.c")
        shutil.copy(bug_descriptor_path, output_dir)

        os.makedirs(f"{output_dir}/fuzzing_logs", exist_ok=True)
        log_file = f"{output_dir}/fuzzing_logs/triage.log"

        core_str = ",".join(map(str, self.core_idx))
        print("log file:", log_file)
        
        with open(log_file, "w") as log:
            docker_exec_cmd = [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--mount",
                f"type=bind,source={output_dir},target=/firmrebugger/target",
                "--cpuset-cpus",
                core_str,
                f"frb:{self.fuzzer}"
            ]

            self.subprocess = subprocess.Popen(
                docker_exec_cmd,
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                universal_newlines=True  
            )

            for line in self.subprocess.stdout:
                log.write(line)  
                log.flush()  

            self.subprocess.wait()

            if self.status != "stopped" and self.subprocess.returncode not in (0, None):
                error_msg = f"Triaging process exited with non-zero status {self.subprocess.returncode}"
                print(f"[Task {self.task_id}] ERROR: {error_msg}")
                self.status = "error"
                log.write(f"\n\nERROR: {error_msg}\n")
                log.flush()



    



    

