import multiprocessing
import os
import time
from queue import Queue
from typing import List
from firmrebugger.task import Task
from firmrebugger.common import get_frb_base_dir
import shutil
import glob
import subprocess
import psutil
import json

class Job:
    """Represents a fuzzing job with multiple runs (tasks)."""
    def __init__(self, job_id, fuzzer, duration, binary, runs, mode, benchmark, progress, output_dir):
        self.job_id = job_id
        self.fuzzer = fuzzer
        self.duration = duration
        self.binary = binary
        self.runs = runs
        self.mode = mode
        self.benchmark = benchmark
        self.tasks = [] 
        self.created_at = time.time()
        self.started_at = None
        self.progress = progress
        self.elapsed_time = None
        self.output_dir = output_dir


        if mode == "Fuzzing":
            for run_num in range(1, runs + 1):
                task = Task(
                    task_id=f"{job_id}-run{run_num}",
                    job_id=job_id,
                    fuzzer=fuzzer,
                    duration=duration,
                    binary=binary,
                    run_number=str(run_num).zfill(2),
                    mode=mode,
                    benchmark=benchmark,
                    output_dir=output_dir,
                    runs=runs,
                    core_idx=None,  
                    container_name=f"{job_id}_run{run_num}_temp"  # Temporary name, will be updated
                )
                self.tasks.append(task)
            
            print(f"[Job {job_id}] Created with {runs} tasks.")

        elif mode == "Triaging":
            task = Task(
                task_id=f"{job_id}-triage",
                job_id=job_id,
                fuzzer=fuzzer,
                duration=duration,
                binary=binary,
                run_number=runs,
                mode=mode,
                benchmark=benchmark,
                output_dir=output_dir,
                runs=runs,
                core_idx=None,
                container_name=f"{job_id}_triage_temp"
            )
            self.tasks.append(task)
            print(f"[Job {job_id}] Created Triaging task.")

        
    @property
    def status(self):
        """Derive job status from tasks."""
        if not self.tasks:
            return "queued"
        if all(t.status == "completed" for t in self.tasks):
            return "completed"
        elif any(t.status == "running" for t in self.tasks):
            return "running"
        elif all(t.status == "queued" for t in self.tasks):
            return "queued"
        elif any(t.status == "stopped" for t in self.tasks):
            return "stopped"
        else:
            return "partial"
    
    def get_completed_runs(self):
        """Get the number of completed runs."""
        return sum(1 for t in self.tasks if t.status == "completed")
    
    def stop_all_tasks(self):
        """Stop all running tasks in this job."""
        for task in self.tasks:
            if task.is_running():
                task.kill_task()
            if task.status == "queued":
                task.status = "stopped"
        print(f"[Job {self.job_id}] All tasks stopped.")
    
    

class JobScheduler:
    """The Job Scheduler to manage jobs and tasks."""
    def __init__(self, reserved_cores=2):
        self.job_queue = Queue()  
        self.jobs = {} 
        self.running_tasks = []  
        self.scheduler_thread = None
        self.running = False
        self.reserved_cores = reserved_cores
        self.max_concurrent_tasks = max(1, multiprocessing.cpu_count() - reserved_cores)
        print(f"[Scheduler] Initialized with {multiprocessing.cpu_count()} total cores, reserving {reserved_cores} cores.")
        print(f"[Scheduler] Max concurrent tasks: {self.max_concurrent_tasks}")

    def add_job(self, job: Job):
        """Add a new job to the scheduler and queue all its tasks."""
        self.jobs[job.job_id] = job
        
        queued_count = 0
        for task in job.tasks:
            if task.status == "queued":
                self.job_queue.put(task)
                queued_count += 1
        
        if queued_count > 0:
            print(f"[Scheduler] Added Job {job.job_id} with {queued_count} tasks to the queue.")
        else:
            print(f"[Scheduler] Added Job {job.job_id} (status: {job.status}, no tasks queued).")

    def reorder_job(self, job_id):
        """Move a job's tasks up one position in the queue."""
        if job_id not in self.jobs:
            print(f"[Scheduler] Job {job_id} not found.")
            return
        
        tasks_list = []
        while not self.job_queue.empty():
            tasks_list.append(self.job_queue.get())
        
        job_tasks = [t for t in tasks_list if t.job_id == job_id]
        
        if not job_tasks:
            for task in tasks_list:
                self.job_queue.put(task)
            print(f"[Scheduler] Job {job_id} has no queued tasks.")
            return
        
        first_job_task_index = next(i for i, t in enumerate(tasks_list) if t.job_id == job_id)
        
        if first_job_task_index == 0:
            # Already at the top
            for task in tasks_list:
                self.job_queue.put(task)
            print(f"[Scheduler] Job {job_id} is already at the top of the queue.")
            return
        
        other_tasks = [t for t in tasks_list if t.job_id != job_id]
        
        new_position = max(0, first_job_task_index - 1)
        
        prev_job_id = None
        for i in range(new_position - 1, -1, -1):
            if other_tasks[i].job_id != job_id:
                prev_job_id = other_tasks[i].job_id
                break
        
        if prev_job_id:
            prev_job_start = next(i for i, t in enumerate(other_tasks) if t.job_id == prev_job_id)
            new_position = prev_job_start
        else:
            new_position = 0
        
        for i, task in enumerate(job_tasks):
            other_tasks.insert(new_position + i, task)
        
        for task in other_tasks:
            self.job_queue.put(task)
        
        print(f"[Scheduler] Moved Job {job_id} up one position in the queue.")
    
    def delete_job(self, job_id):
        """Delete a job and its tasks from the scheduler."""
        if job_id not in self.jobs:
            print(f"[Scheduler] Job {job_id} not found.")
            return
        
        full_path = os.path.join(get_frb_base_dir(), self.jobs[job_id].benchmark, self.jobs[job_id].binary, "fuzzers", self.jobs[job_id].fuzzer, "fuzzing_out", self.jobs[job_id].output_dir)
        shutil.rmtree(full_path)
        del self.jobs[job_id]
        
        print(f"[Scheduler] Deleted Job {job_id} and all its tasks.")

    def stop_job(self, job_id):
        """Stop a specific job (all its tasks)."""
        if job_id in self.jobs:
            self.jobs[job_id].stop_all_tasks()
            
            tasks_list = []
            while not self.job_queue.empty():
                task = self.job_queue.get()
                if task.job_id != job_id:
                    tasks_list.append(task)
                else:
                    print(f"[Scheduler] Removed task {task.task_id} from queue")
            
            for task in tasks_list:
                self.job_queue.put(task)
            
            print(f"[Scheduler] Job {job_id} has been stopped.")
        else:
            print(f"[Scheduler] Job {job_id} not found.")

    def update_triaging_progress(self):
        """Update progress for triaging jobs by reading their log files."""
        import re
        
        for job_id, job in self.jobs.items():
            if job.mode == "Triaging" and job.status == "running":
                base_dir = get_frb_base_dir()
                output_folder = os.path.join(
                    base_dir,
                    job.benchmark,
                    job.binary,
                    "fuzzers",
                    job.fuzzer,
                    "fuzzing_out",
                    job.output_dir
                )
                log_file = os.path.join(output_folder, "fuzzing_logs", "triage.log")
                
                if os.path.exists(log_file):
                    try:
                        output_folders = glob.glob(os.path.join(output_folder, "output-*"))
                        total_runs = len(output_folders)
                        
                        if total_runs == 0:
                            continue
                        
                        result = subprocess.run(
                            ['grep', '-oE', 'run-?[0-9]+', log_file],
                            capture_output=True,
                            text=True
                        )
                        
                        if result.returncode == 0 and result.stdout:
                            matches = re.findall(r'run-?(\d+)', result.stdout)
                            if matches:
                                current_run = max(int(m) for m in matches)
                                current_run = max(0, current_run-1) 
                                job.progress = min(100, round((current_run / total_runs) * 100, 2))
                                print(f"[Scheduler] Triaging job {job_id}: Run {current_run}/{total_runs} ({job.progress}%)")
                    except Exception as e:
                        print(f"[Scheduler] Error reading triage log for job {job_id}: {e}")

    def run_scheduler(self):
        """Run the job scheduler to process the task queue."""
        self.running = True
        GRACE_PERIOD = 30  # 30 seconds grace period after duration
        print("[Scheduler] Starting...")
        while self.running:
            self.update_triaging_progress()
            
            self.running_tasks = [task for task in self.running_tasks if task.is_running()]
            
            current_time = time.time()
            for task in self.running_tasks[:]:
                if task.started_at is not None:
                    elapsed = current_time - task.started_at
                    timeout_limit = task.duration + GRACE_PERIOD
                    
                    if elapsed > timeout_limit and task.mode != "Triaging":
                        print(f"[Scheduler] Task {task.task_id} exceeded timeout ({elapsed:.0f}s > {timeout_limit}s).")
                        task.kill_task()
                        self.running_tasks.remove(task)
            
            current_running = len(self.running_tasks)
            available_slots = self.max_concurrent_tasks - current_running
            
            cores_in_use = 0
            for task in self.running_tasks:
                if hasattr(task, 'core_idx') and task.core_idx is not None:
                    if isinstance(task.core_idx, list):
                        cores_in_use += len(task.core_idx)
                    else:
                        cores_in_use += 1
            
            available_cores = self.max_concurrent_tasks - cores_in_use
            print(f"[Scheduler] Current running tasks: {current_running}. Available slots: {available_slots}. Cores in use: {cores_in_use}/{self.max_concurrent_tasks}. Available cores: {available_cores}.")
            
            if available_slots > 0 and not self.job_queue.empty():
                tasks_list = []
                job_to_start = None
                
                while not self.job_queue.empty():
                    tasks_list.append(self.job_queue.get())
                
                if tasks_list:
                    first_job_id = tasks_list[0].job_id
                    job_tasks = [t for t in tasks_list if t.job_id == first_job_id and t.status == "queued"]
                    
                    if first_job_id in self.jobs:
                        job = self.jobs[first_job_id]
                        if job.mode == "Triaging":
                            cores_needed = job.runs
                        else:
                            cores_needed = len(job_tasks)
                    else:
                        cores_needed = len(job_tasks)
                    
                    if len(job_tasks) <= available_slots and cores_needed <= available_cores:
                        job_to_start = first_job_id
                        
                        if first_job_id in self.jobs:
                            job = self.jobs[first_job_id]
                            if not hasattr(job, 'started_at') or job.started_at is None:
                                job.started_at = time.time()
                        
                        if job.mode == "Fuzzing":
                            prep_target_folder(job)
                        
                        for i, job_task in enumerate(job_tasks):
                            combined_tasks = self.running_tasks + job_tasks[:i]
                            
                            if job.mode == "Triaging":
                                num_cores_needed = job.runs
                                core_indices = find_available_idx(
                                    multiprocessing.cpu_count() - self.reserved_cores, 
                                    combined_tasks,
                                    num_cores=num_cores_needed
                                )
                                if isinstance(core_indices, int):
                                    core_indices = [core_indices]
                                job_task.core_idx = core_indices
                                cores_str = ",".join(map(str, core_indices))
                                job_task.container_name = f"{job_task.job_id}_triage_cores{cores_str.replace(',', '-')}"
                                print(f"[Scheduler] Assigned {num_cores_needed} cores {core_indices} to triaging task {job_task.task_id}")
                            else:
                                core_idx = find_available_idx(
                                    multiprocessing.cpu_count() - self.reserved_cores, 
                                    combined_tasks,
                                    num_cores=1
                                )
                                job_task.core_idx = core_idx
                                job_task.container_name = f"{job_task.job_id}_run{job_task.run_number}_core{core_idx}"
                                print(f"[Scheduler] Assigned core {core_idx} to task {job_task.task_id}")
                            
                            print(f"[Scheduler] Starting Task {job_task.task_id}... ({current_running + 1}/{self.max_concurrent_tasks} slots used)")

                            job_task.start()
                            self.running_tasks.append(job_task)
                            current_running += 1
                            available_slots -= 1
                            tasks_list.remove(job_task)
                        
                        print(f"[Scheduler] Started all {len(job_tasks)} tasks for Job {job_to_start}")
                
                for task in tasks_list:
                    self.job_queue.put(task)
                
                if job_to_start is None and tasks_list:
                    next_job_id = tasks_list[0].job_id
                    next_job_task_count = sum(1 for t in tasks_list if t.job_id == next_job_id and t.status == "queued")
                    
                    if next_job_id in self.jobs:
                        next_job = self.jobs[next_job_id]
                        if next_job.mode == "Triaging":
                            next_cores_needed = next_job.runs
                        else:
                            next_cores_needed = next_job_task_count
                    else:
                        next_cores_needed = next_job_task_count
                    
                    print(f"[Scheduler] Next job ({next_job_id}) needs {next_job_task_count} task slots and {next_cores_needed} cores, but only {available_slots} slots and {available_cores} cores available. Waiting...")
            
            time.sleep(1)  
        print("[Scheduler] Stopped.")

    def stop_scheduler(self):
        """Stop the scheduler."""
        self.running = False
    
    def get_current_jobs(self):
        """Return a list of current jobs in queue order."""
        print("[Scheduler] Fetching current jobs...")
        jobs_to_remove = []
        
        for job_id, job in self.jobs.items():
            elapsed_time = 0
            prev_status = getattr(job, '_prev_status', None)
            
            if job.status == "running" and job.started_at is not None and job.mode != "Triaging":
                elapsed_time = round(time.time() - job.started_at, 0)
                job.progress = min(100, round((elapsed_time / job.duration) * 100, 2))

            elif job.status == "completed":
                if prev_status != "completed" and job.started_at is not None:
                    finalize_job(job)
                elapsed_time = job.duration
                job.progress = 100
                
                if job.mode == "Triaging":
                    jobs_to_remove.append(job_id)
                    print(f"[Scheduler] Marking triaged job {job_id} for removal (completed)")
                    
            elif job.status == "stopped" and job.started_at is not None:
                if prev_status not in ["stopped", "completed"] and job.started_at is not None:
                    finalize_job(job, stopped=True)
                stopped_times = [t.completed_at for t in job.tasks if t.completed_at is not None]
                if stopped_times:
                    elapsed_time = round(max(stopped_times) - job.started_at, 0)
                else:
                    elapsed_time = round(time.time() - job.started_at, 0)
                job.progress = min(100, round((elapsed_time / job.duration) * 100, 2))

                if job.mode == "Triaging":
                    jobs_to_remove.append(job_id)
                    print(f"[Scheduler] Marking triaged job {job_id} for removal (stopped)")
            
            elif job.status == "stopped" and job.started_at is None:
                jobs_to_remove.append(job_id)
                print(f"[Scheduler] Marking triaged job {job_id} for removal (stopped)")

            elif job.status == "running" and job.started_at is not None and job.mode == "Triaging":
                elapsed_time = round(time.time() - job.started_at, 0)
            else:  
                elapsed_time = 0
                job.progress = 0
            
            job.elapsed_time = elapsed_time
            job._prev_status = job.status
            print(f"  Job {job_id}: Status: {job.status}, Fuzzer: {job.fuzzer}, Runs: {job.runs}, Completed: {job.get_completed_runs()}/{job.runs}, Elapsed: {elapsed_time}, Progress: {job.progress}%")
        
        for job_id in jobs_to_remove:
            del self.jobs[job_id]
            print(f"[Scheduler] Removed triaged job {job_id} from queue")
        
        tasks_list = []
        temp_queue = []
        
        while not self.job_queue.empty():
            task = self.job_queue.get()
            tasks_list.append(task)
            temp_queue.append(task)
        
        for task in temp_queue:
            self.job_queue.put(task)
        
        seen_jobs = set()
        queued_jobs_ordered = []
        for task in tasks_list:
            if task.job_id not in seen_jobs and task.job_id in self.jobs:
                seen_jobs.add(task.job_id)
                queued_jobs_ordered.append(self.jobs[task.job_id])
        
        running_jobs = [job for job in self.jobs.values() if job.status == 'running']
        other_jobs = [job for job in self.jobs.values() if job.status not in ['queued', 'running']]
        
        print(f"[Scheduler] Returning jobs in order: {len(running_jobs)} running, {len(queued_jobs_ordered)} queued, {len(other_jobs)} other")
        return running_jobs + queued_jobs_ordered + other_jobs
    
    
    
def start_manager(scheduler):
    print("[Manager] Starting Job Scheduler...")
    scheduler.run_scheduler()


def finalize_job(job: Job, stopped=False):
    """Create/update the frb_info.json file with complete job and task information when job completes."""
    import json
    
    base_dir = get_frb_base_dir()
    output_folder = os.path.join(
        base_dir, 
        job.benchmark, 
        job.binary, 
        "fuzzers", 
        job.fuzzer, 
        "fuzzing_out", 
        job.output_dir
    )
    json_path = os.path.join(output_folder, "frb_info.json")

    if os.path.isfile(json_path):
        return
    
    try:
        if stopped:
            completed_times = [t.completed_at for t in job.tasks if t.completed_at is not None]
            end_time = max(completed_times) if completed_times else time.time()
        else:
            end_time = time.time()
        
        total_time = int(round(end_time - job.started_at))
        
        data = {
            "job_id": job.job_id,
            "fuzzer": job.fuzzer,
            "binary": job.binary,
            "benchmark": job.benchmark,
            "mode": job.mode,
            "duration": job.duration,
            "runs": job.runs,
        }

        data["output_dir"] = job.output_dir
        data["status"] = job.status
        data["created_at"] = job.created_at
        data["started_at"] = job.started_at
        data["ended_at"] = end_time
        data["progress"] = job.progress
        data["completed_runs"] = job.get_completed_runs()
        
        data["tasks"] = []
        for task in job.tasks:
            task_info = {
                "task_id": task.task_id,
                "run_number": task.run_number,
                "status": task.status,
                "created_at": task.created_at,
                "started_at": task.started_at,
                "completed_at": task.completed_at,
                "core_idx": task.core_idx,
                "container_name": task.container_name,
                "duration": task.duration
            }
            
            if task.started_at and task.completed_at:
                task_info["elapsed_time"] = round(task.completed_at - task.started_at, 2)
            
            data["tasks"].append(task_info)
        
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)
        
        print(f"[Job {job.job_id}] Finalized job info: Total time = {total_time}s")
        print(f"[Job {job.job_id}] Saved job info to {json_path}")
    
    except Exception as e:
        print(f"[Job {job.job_id}] Error finalizing job info: {e}")

def prep_target_folder(job: Job):
    base_dir = get_frb_base_dir()
    ouput_dir_path = f"{base_dir}/{job.benchmark}/{job.binary}/fuzzers/{job.fuzzer}/fuzzing_out/{job.output_dir}/"

    os.makedirs(ouput_dir_path, exist_ok=True)
    binary_dir_path = os.path.join(base_dir, job.benchmark, job.binary, "binary")
    elf_path = glob.glob(f"{binary_dir_path}/*.elf")[0]
    print("the elf path is:", elf_path)

    fuzzer_dir_path = os.path.join(base_dir, job.benchmark, job.binary, "fuzzers", job.fuzzer)

    for item in os.listdir(fuzzer_dir_path):
        item_path = os.path.join(fuzzer_dir_path, item)
        if item != "fuzzing_out":
            try:
                if os.path.isdir(item_path):
                    shutil.copytree(item_path, os.path.join(ouput_dir_path, item), dirs_exist_ok=True)
                else:
                    shutil.copy(item_path, ouput_dir_path)
            except Exception as e:
                print(f"Error copying {item} to output folder: {e}")

    try:
        shutil.copy(elf_path, ouput_dir_path)
        objcopy_path = shutil.which("arm-none-eabi-objcopy")
        if objcopy_path is None:
            print(
                "arm-none-eabi-objcopy not found in PATH. Please install it or add it to your PATH."
            )
        bin_path = os.path.join(
            ouput_dir_path, os.path.splitext(os.path.basename(elf_path))[0] + ".bin"
        )
        subprocess.run(
            [objcopy_path, "-O", "binary", elf_path, bin_path], check=True
        )   
    except Exception as e:
        print(f"Error copying binary to output folder: {e}")
    
    try:
        fuzzer_runner_path = os.path.join(base_dir,"src", "firmrebugger",  "fuzzer_runners", f"{job.fuzzer}-run.sh")
        shutil.copy(fuzzer_runner_path, ouput_dir_path)
    except Exception as e:
        print(f"Error copying fuzzer runner to output folder: {e}")

def find_available_idx(max_idx, existing_tasks, num_cores=1):
    if existing_tasks is None:
        existing_tasks = []
    
    used_cores = set()
    for task in existing_tasks:
        if hasattr(task, 'core_idx') and task.core_idx is not None:
            # Handle both single core (int) and multiple cores (list)
            if isinstance(task.core_idx, list):
                used_cores.update(task.core_idx)
            else:
                used_cores.add(task.core_idx)
    
    cpu_percent = psutil.cpu_percent(interval=0.1, percpu=True)
    
    available_cores = [i for i in range(min(max_idx, len(cpu_percent))) if i not in used_cores]
    
    if num_cores == 1:
        if available_cores:
            least_used = min(available_cores, key=lambda i: cpu_percent[i])
            print(f"Assigning to least used available core {least_used} with {cpu_percent[least_used]:.1f}% usage")
            return least_used
        
        if cpu_percent:
            least_used = min(range(min(max_idx, len(cpu_percent))), key=lambda i: cpu_percent[i])
            print(f"All cores assigned, reusing least used core {least_used} with {cpu_percent[least_used]:.1f}% usage")
            return least_used
        
        print("Unable to determine CPU usage, defaulting to core 0")
        return 0
    else:
        if len(available_cores) >= num_cores:
            selected_cores = sorted(available_cores, key=lambda i: cpu_percent[i])[:num_cores]
            usage_str = ", ".join([f"{c} ({cpu_percent[c]:.1f}%)" for c in selected_cores])
            print(f"Assigning {num_cores} cores: [{usage_str}]")
            return selected_cores
        else:
            print(f"Warning: Only {len(available_cores)} cores available, but {num_cores} requested")
            all_cores = list(range(min(max_idx, len(cpu_percent))))
            selected_cores = sorted(all_cores, key=lambda i: cpu_percent[i])[:num_cores]
            usage_str = ", ".join([f"{c} ({cpu_percent[c]:.1f}%)" for c in selected_cores])
            print(f"Assigning {num_cores} least-used cores (some may be shared): [{usage_str}]")
            return selected_cores


def list_finished_jobs() -> List[Job]:
    base_dir = get_frb_base_dir()
    finished_jobs = []
    
    search_pattern = os.path.join(base_dir, "**", "fuzzers", "**", "fuzzing_out", "**", "frb_info.json")
    frb_info_files = glob.glob(search_pattern, recursive=True)
    
    print(f"[list_finished_jobs] Found {len(frb_info_files)} frb_info.json files")
    
    for json_file_path in frb_info_files:
        try:
            with open(json_file_path, 'r') as f:
                data = json.load(f)
            
            job = Job(
                job_id=data.get("job_id"),
                fuzzer=data.get("fuzzer"),
                duration=data.get("duration"),
                binary=data.get("binary"),
                runs=data.get("runs"),
                mode=data.get("mode"),
                benchmark=data.get("benchmark"),
                progress=data.get("progress", 0),
                output_dir=data.get("output_dir")
            )
            
            job.created_at = data.get("created_at")
            job.started_at = data.get("started_at")
            job.elapsed_time = data.get("ended_at", 0) - data.get("started_at", 0) if data.get("started_at") else 0
            
            tasks_data = data.get("tasks", [])
            if tasks_data:
                job.tasks = []
                
                for task_data in tasks_data:
                    task = Task(
                        task_id=task_data.get("task_id"),
                        job_id=job.job_id,
                        fuzzer=job.fuzzer,
                        duration=job.duration,
                        binary=job.binary,
                        run_number=task_data.get("run_number"),
                        mode=job.mode,
                        benchmark=job.benchmark,
                        output_dir=job.output_dir,
                        runs=job.runs,
                        core_idx=task_data.get("core_idx"),
                        container_name=task_data.get("container_name")
                    )
                    
                    task.status = task_data.get("status", "completed")
                    task.created_at = task_data.get("created_at")
                    task.started_at = task_data.get("started_at")
                    task.completed_at = task_data.get("completed_at")
                    
                    job.tasks.append(task)
            
            finished_jobs.append(job)
            print(f"[list_finished_jobs] Loaded job {job.job_id} from {json_file_path}")
            
        except Exception as e:
            print(f"[list_finished_jobs] Error reading {json_file_path}: {e}")
            continue
    
    print(f"[list_finished_jobs] Successfully loaded {len(finished_jobs)} finished jobs")
    return finished_jobs
