import glob
import json
import multiprocessing
import os
import shutil
import subprocess
import threading
import time
import uuid
from queue import Queue
from typing import List

import psutil

from firmrebugger.common import get_frb_base_dir
from firmrebugger.task import Task


class Job:
    """Represents a fuzzing job with multiple runs (tasks)."""

    def __init__(
        self,
        job_id,
        fuzzer,
        duration,
        binary,
        runs,
        mode,
        benchmark,
        progress,
        output_dir,
        auto_queue_triaging=True,
    ):
        self.job_id = job_id
        self.fuzzer = fuzzer
        self.duration = int(duration)
        self.binary = binary
        self.runs = int(runs)
        self.mode = mode
        self.benchmark = benchmark
        self.tasks = []
        self.created_at = time.time()
        self.started_at = None
        self.progress = progress
        self.elapsed_time = None
        self.output_dir = output_dir
        self.auto_queue_triaging = bool(auto_queue_triaging)
        self.manually_stopped = False

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
                    container_name=f"{job_id}_run{run_num}_temp",  # Temporary name, will be updated
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
                container_name=f"{job_id}_triage_temp",
            )
            self.tasks.append(task)
            print(f"[Job {job_id}] Created Triaging task.")

    @property
    def status(self):
        """Derive job status from tasks."""
        if not self.tasks:
            return "queued"

        has_running = any(t.status == "running" for t in self.tasks)
        has_stopping = any(t.status == "stopping" for t in self.tasks)
        has_queued = any(t.status == "queued" for t in self.tasks)
        has_error = any(t.status == "error" for t in self.tasks)
        has_stopped = any(t.status == "stopped" for t in self.tasks)

        if all(t.status == "completed" for t in self.tasks):
            return "completed"
        elif has_stopping:
            return "stopping"
        elif has_running:
            return "running"
        elif all(t.status == "queued" for t in self.tasks):
            return "queued"
        elif has_error and not has_running and not has_queued:
            return "error"
        elif has_stopped and not has_running and not has_queued:
            return "stopped"
        else:
            return "partial"

    def get_completed_runs(self):
        """Get the number of completed runs."""
        return sum(1 for t in self.tasks if t.status == "completed")

    def stop_all_tasks(self):
        """Stop all running tasks in this job."""
        for task in self.tasks:
            if task.status == "running":
                task.status = "stopping"

        for task in self.tasks:
            if task.status == "stopping":
                if task.is_running() or (
                    task.subprocess is not None and task.subprocess.poll() is None
                ):
                    task.kill_task()
                else:
                    task.stop()
                # If the process wasn't alive, stop() won't have set the status,
                # so force it to stopped here to prevent re-queuing.
                if task.status not in ("stopped", "completed"):
                    task.status = "stopped"
            elif task.status == "queued":
                task.status = "stopped"
        print(f"[Job {self.job_id}] All tasks stopped.")


class JobManager:
    """The Job Manager to manage jobs and tasks."""

    def __init__(self, reserved_cores=2):
        self.job_queue = Queue()
        self.jobs = {}
        self.running_tasks = []
        self.manager_thread = None
        self.running = False
        self.queue_lock = threading.RLock()
        self.reserved_cores = reserved_cores
        self.max_concurrent_tasks = max(1, multiprocessing.cpu_count() - reserved_cores)
        print(
            f"[Manager] Initialized with {multiprocessing.cpu_count()} total cores, reserving {reserved_cores} cores."
        )
        print(f"[Manager] Max concurrent tasks: {self.max_concurrent_tasks}")

    @staticmethod
    def _rmtree_onerror(func, path, _exc_info):
        try:
            os.chmod(path, 0o777)
            func(path)
        except Exception:
            pass

    @staticmethod
    def _relax_permissions_with_docker(target_path):
        try:
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{target_path}:/target",
                    "alpine:3.20",
                    "sh",
                    "-lc",
                    "chmod -R a+rwX /target || true",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    def add_job(self, job: Job):
        """Add a new job to the manager and queue all its tasks."""
        self.jobs[job.job_id] = job

        queued_count = 0
        with self.queue_lock:
            for task in job.tasks:
                if task.status == "queued":
                    self.job_queue.put(task)
                    queued_count += 1

        if queued_count > 0:
            print(
                f"[Manager] Added Job {job.job_id} with {queued_count} tasks to the queue."
            )
        else:
            print(
                f"[Manager] Added Job {job.job_id} (status: {job.status}, no tasks queued)."
            )

    def _has_triage_report(self, job: Job) -> bool:
        report_path = os.path.join(
            get_frb_base_dir(),
            job.benchmark,
            job.binary,
            "fuzzers",
            job.fuzzer,
            "fuzzing_out",
            job.output_dir,
            "frb_report.json",
        )
        return os.path.exists(report_path)

    def _has_related_triaging_job(self, fuzzing_job: Job) -> bool:
        for candidate_job in self.jobs.values():
            if (
                candidate_job.mode == "Triaging"
                and candidate_job.benchmark == fuzzing_job.benchmark
                and candidate_job.binary == fuzzing_job.binary
                and candidate_job.fuzzer == fuzzing_job.fuzzer
                and candidate_job.output_dir == fuzzing_job.output_dir
            ):
                # If it was manually stopped, block re-queuing permanently
                if candidate_job.manually_stopped:
                    return True
                if candidate_job.status in ["queued", "running", "error", "stopped"]:
                    return True
        return False

    def enqueue_auto_triaging_jobs(self):
        """Automatically queue triaging jobs for eligible completed fuzzing jobs."""
        fuzzing_jobs = [
            job for job in list(self.jobs.values()) if job.mode == "Fuzzing"
        ]

        for fuzzing_job in fuzzing_jobs:
            if fuzzing_job.status != "completed":
                continue
            if not getattr(fuzzing_job, "auto_queue_triaging", True):
                continue
            if self._has_triage_report(fuzzing_job):
                continue
            if self._has_related_triaging_job(fuzzing_job):
                continue

            triage_job_id = f"AUTO-TRIAGE-{fuzzing_job.job_id}-{uuid.uuid4().hex[:8]}"
            triage_job = Job(
                job_id=triage_job_id,
                fuzzer=fuzzing_job.fuzzer,
                duration=fuzzing_job.duration,
                binary=fuzzing_job.binary,
                runs=fuzzing_job.runs,
                mode="Triaging",
                benchmark=fuzzing_job.benchmark,
                progress=0,
                output_dir=fuzzing_job.output_dir,
                auto_queue_triaging=False,
            )
            self.add_job(triage_job)
            print(
                f"[Manager] Auto-queued triaging job {triage_job_id} for completed fuzzing job {fuzzing_job.job_id}."
            )

    def reorder_job(self, job_id):
        """Move a job's tasks up one position in the queue."""
        if job_id not in self.jobs:
            print(f"[Manager] Job {job_id} not found.")
            return

        with self.queue_lock:
            tasks_list = []
            while not self.job_queue.empty():
                tasks_list.append(self.job_queue.get())

            job_tasks = [t for t in tasks_list if t.job_id == job_id]

            if not job_tasks:
                for task in tasks_list:
                    self.job_queue.put(task)
                print(f"[Manager] Job {job_id} has no queued tasks.")
                return

            first_job_task_index = next(
                i for i, t in enumerate(tasks_list) if t.job_id == job_id
            )

            if first_job_task_index == 0:
                for task in tasks_list:
                    self.job_queue.put(task)
                print(f"[Manager] Job {job_id} is already at the top of the queue.")
                return

            other_tasks = [t for t in tasks_list if t.job_id != job_id]

            new_position = max(0, first_job_task_index - 1)

            prev_job_id = None
            for i in range(new_position - 1, -1, -1):
                if other_tasks[i].job_id != job_id:
                    prev_job_id = other_tasks[i].job_id
                    break

            if prev_job_id:
                prev_job_start = next(
                    i for i, t in enumerate(other_tasks) if t.job_id == prev_job_id
                )
                new_position = prev_job_start
            else:
                new_position = 0

            for i, task in enumerate(job_tasks):
                other_tasks.insert(new_position + i, task)

            for task in other_tasks:
                self.job_queue.put(task)

        print(f"[Manager] Moved Job {job_id} up one position in the queue.")

    def reorder_job_to_top(self, job_id):
        """Move a job's queued tasks to the top of the queue."""
        if job_id not in self.jobs:
            print(f"[Manager] Job {job_id} not found.")
            return

        with self.queue_lock:
            tasks_list = []
            while not self.job_queue.empty():
                tasks_list.append(self.job_queue.get())

            job_tasks = [
                t for t in tasks_list if t.job_id == job_id and t.status == "queued"
            ]

            if not job_tasks:
                for task in tasks_list:
                    self.job_queue.put(task)
                print(f"[Manager] Job {job_id} has no queued tasks.")
                return

            other_tasks = [
                t for t in tasks_list if t.job_id != job_id or t.status != "queued"
            ]

            for task in job_tasks + other_tasks:
                self.job_queue.put(task)

        print(f"[Manager] Moved Job {job_id} to the top of the queue.")

    def delete_job(self, job_id):
        """Delete a job and its tasks from the manager."""
        if job_id not in self.jobs:
            print(f"[Manager] Job {job_id} not found.")
            return

        full_path = os.path.join(
            get_frb_base_dir(),
            self.jobs[job_id].benchmark,
            self.jobs[job_id].binary,
            "fuzzers",
            self.jobs[job_id].fuzzer,
            "fuzzing_out",
            self.jobs[job_id].output_dir,
        )
        if os.path.exists(full_path):
            try:
                shutil.rmtree(full_path, onerror=self._rmtree_onerror)
            except PermissionError:
                self._relax_permissions_with_docker(full_path)
                shutil.rmtree(full_path, onerror=self._rmtree_onerror)
        del self.jobs[job_id]

        print(f"[Manager] Deleted Job {job_id} and all its tasks.")

    def stop_job(self, job_id):
        """Stop a specific job (all its tasks)."""
        if job_id in self.jobs:
            self.jobs[job_id].manually_stopped = True
            self.jobs[job_id].stop_all_tasks()

            with self.queue_lock:
                tasks_list = []
                while not self.job_queue.empty():
                    task = self.job_queue.get()
                    if task.job_id != job_id:
                        tasks_list.append(task)
                    else:
                        print(f"[Manager] Removed task {task.task_id} from queue")

                for task in tasks_list:
                    self.job_queue.put(task)

            print(f"[Manager] Job {job_id} has been stopped.")
        else:
            print(f"[Manager] Job {job_id} not found.")

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
                    job.output_dir,
                )
                log_file = os.path.join(output_folder, "fuzzing_logs", "triage.log")

                if os.path.exists(log_file):
                    try:
                        output_folders = glob.glob(
                            os.path.join(output_folder, "output-*")
                        )
                        total_runs = len(output_folders)

                        if total_runs == 0:
                            continue

                        result = subprocess.run(
                            ["grep", "-oE", "run-?[0-9]+", log_file],
                            capture_output=True,
                            text=True,
                        )

                        if result.returncode == 0 and result.stdout:
                            matches = re.findall(r"run-?(\d+)", result.stdout)
                            if matches:
                                current_run = max(int(m) for m in matches)
                                current_run = max(0, current_run - 1)
                                job.progress = min(
                                    100, round((current_run / total_runs) * 100, 2)
                                )
                    except Exception as e:
                        print(
                            f"[Manager] Error reading triage log for job {job_id}: {e}"
                        )

    def run_manager(self):
        """Run the Job Manager to process the task queue."""
        self.running = True
        GRACE_PERIOD = 30  # 30 seconds grace period after duration
        print("[Manager] Starting...")
        while self.running:
            try:
                self.update_triaging_progress()
                self.enqueue_auto_triaging_jobs()
                tasks_list = []
                job_to_start = None

                self.running_tasks = [
                    task for task in self.running_tasks if task.is_running()
                ]

                current_time = time.time()
                for task in self.running_tasks[:]:
                    if task.started_at is not None:
                        elapsed = current_time - task.started_at
                        timeout_limit = task.duration + GRACE_PERIOD

                        if elapsed > timeout_limit and task.mode != "Triaging":
                            print(
                                f"[Manager] Task {task.task_id} exceeded timeout ({elapsed:.0f}s > {timeout_limit}s)."
                            )
                            task.kill_task(reason="grace_timeout")
                            self.running_tasks.remove(task)

                current_running = len(self.running_tasks)
                available_slots = self.max_concurrent_tasks - current_running

                cores_in_use = 0
                for task in self.running_tasks:
                    if hasattr(task, "core_idx") and task.core_idx is not None:
                        if isinstance(task.core_idx, list):
                            cores_in_use += len(task.core_idx)
                        else:
                            cores_in_use += 1

                available_cores = self.max_concurrent_tasks - cores_in_use

                if available_slots > 0:
                    with self.queue_lock:
                        if self.job_queue.empty():
                            tasks_list = []
                            job_to_start = None
                        else:
                            tasks_list = []
                            job_to_start = None

                            while not self.job_queue.empty():
                                tasks_list.append(self.job_queue.get())

                if tasks_list:
                    queued_job_ids = []
                    seen_job_ids = set()
                    for task in tasks_list:
                        if task.status == "queued" and task.job_id not in seen_job_ids:
                            queued_job_ids.append(task.job_id)
                            seen_job_ids.add(task.job_id)

                    selected_job = None
                    selected_job_tasks = []
                    selected_cores_needed = 0

                    for candidate_job_id in queued_job_ids:
                        candidate_job_tasks = [
                            t
                            for t in tasks_list
                            if t.job_id == candidate_job_id and t.status == "queued"
                        ]

                        if not candidate_job_tasks:
                            continue

                        if candidate_job_id in self.jobs:
                            candidate_job = self.jobs[candidate_job_id]
                            if candidate_job.mode == "Triaging":
                                candidate_cores_needed = min(
                                    candidate_job.runs, available_cores
                                )
                                candidate_tasks_to_start = candidate_job_tasks[:1]
                            else:
                                candidate_cores_needed = len(candidate_job_tasks)
                                candidate_tasks_to_start = candidate_job_tasks
                        else:
                            candidate_job = None
                            candidate_cores_needed = len(candidate_job_tasks)
                            candidate_tasks_to_start = candidate_job_tasks

                        if (
                            candidate_job is not None
                            and candidate_job.mode == "Triaging"
                        ):
                            can_schedule = (
                                len(candidate_tasks_to_start) > 0
                                and available_slots >= 1
                                and candidate_cores_needed <= available_cores
                            )
                        else:
                            can_schedule = (
                                candidate_cores_needed > 0
                                and candidate_cores_needed <= available_cores
                                and candidate_cores_needed <= available_slots
                            )

                        if can_schedule:
                            selected_job = candidate_job
                            selected_job_tasks = candidate_tasks_to_start
                            selected_cores_needed = candidate_cores_needed
                            break

                    if selected_job is not None and selected_job_tasks:
                        job_to_start = selected_job.job_id

                        if (
                            not hasattr(selected_job, "started_at")
                            or selected_job.started_at is None
                        ):
                            selected_job.started_at = time.time()

                        if selected_job.mode == "Fuzzing":
                            prep_target_folder(selected_job)

                        for i, job_task in enumerate(selected_job_tasks):
                            combined_tasks = self.running_tasks + selected_job_tasks[:i]

                            if selected_job.mode == "Triaging":
                                num_cores_needed = max(1, selected_cores_needed)
                                core_indices = find_available_idx(
                                    multiprocessing.cpu_count() - self.reserved_cores,
                                    combined_tasks,
                                    num_cores=num_cores_needed,
                                )
                                if isinstance(core_indices, int):
                                    core_indices = [core_indices]
                                job_task.core_idx = core_indices
                                cores_str = ",".join(map(str, core_indices))
                                job_task.container_name = f"{job_task.job_id}_triage_cores{cores_str.replace(',', '-')}"
                            else:
                                core_idx = find_available_idx(
                                    multiprocessing.cpu_count() - self.reserved_cores,
                                    combined_tasks,
                                    num_cores=1,
                                )
                                job_task.core_idx = core_idx
                                job_task.container_name = f"{job_task.job_id}_run{job_task.run_number}_core{core_idx}"

                            job_task.start()
                            self.running_tasks.append(job_task)
                            current_running += 1
                            available_slots -= 1
                            tasks_list.remove(job_task)

                        print(
                            f"[Manager] Started all {len(selected_job_tasks)} tasks for Job {job_to_start} "
                            f"(needed {selected_cores_needed} cores)"
                        )

                with self.queue_lock:
                    for task in tasks_list:
                        self.job_queue.put(task)

                time.sleep(1)
            except Exception as e:
                print(f"[Manager] Loop error: {e}")
                time.sleep(1)
        print("[Manager] Stopped.")

    def run_scheduler(self):
        """Backward-compatible alias for run_manager."""
        self.run_manager()

    def stop_manager(self):
        """Stop the job manager."""
        self.running = False

    def stop_scheduler(self):
        """Backward-compatible alias for stop_manager."""
        self.stop_manager()

    def get_job(self, job_id):
        return self.jobs.get(job_id)

    def find_task(self, task_id):
        for job in self.jobs.values():
            if hasattr(job, "tasks"):
                for task in job.tasks:
                    if task.task_id == task_id:
                        return task
        return None

    def get_current_jobs(self):
        """Return a list of current jobs in queue order."""
        jobs_to_remove = []

        for job_id, job in self.jobs.items():
            elapsed_time = 0
            prev_status = getattr(job, "_prev_status", None)

            if (
                job.status == "running"
                and job.started_at is not None
                and job.mode != "Triaging"
            ):
                elapsed_time = round(time.time() - job.started_at, 0)
                job.progress = min(100, round((elapsed_time / job.duration) * 100, 2))

            elif job.status == "completed":
                if prev_status != "completed" and job.started_at is not None:
                    finalize_job(job)
                elapsed_time = job.duration
                job.progress = 100

                if job.mode == "Triaging" and not getattr(
                    job, "manually_stopped", False
                ):
                    jobs_to_remove.append(job_id)

            elif job.status == "stopped" and job.started_at is not None:
                if (
                    prev_status not in ["stopped", "completed"]
                    and job.started_at is not None
                ):
                    finalize_job(job, stopped=True)
                stopped_times = [
                    t.completed_at for t in job.tasks if t.completed_at is not None
                ]
                if stopped_times:
                    elapsed_time = round(max(stopped_times) - job.started_at, 0)
                else:
                    elapsed_time = round(time.time() - job.started_at, 0)
                job.progress = min(100, round((elapsed_time / job.duration) * 100, 2))

                if job.mode == "Triaging" and not getattr(
                    job, "manually_stopped", False
                ):
                    jobs_to_remove.append(job_id)

            elif job.status == "stopped" and job.started_at is None:
                if job.mode == "Triaging" and not getattr(
                    job, "manually_stopped", False
                ):
                    jobs_to_remove.append(job_id)

            elif job.status == "error":
                if prev_status != "error" and job.started_at is not None:
                    finalize_job(job, stopped=True, force_status="error")

                if job.started_at is not None:
                    finished_times = [
                        t.completed_at for t in job.tasks if t.completed_at is not None
                    ]
                    if finished_times:
                        elapsed_time = round(max(finished_times) - job.started_at, 0)
                    else:
                        if job.elapsed_time is not None:
                            elapsed_time = round(job.elapsed_time, 0)
                        else:
                            elapsed_time = round(time.time() - job.started_at, 0)
                else:
                    elapsed_time = 0

                if job.duration and job.duration > 0:
                    job.progress = min(
                        100, round((elapsed_time / job.duration) * 100, 2)
                    )
                else:
                    job.progress = 0

                if job.mode == "Triaging":
                    pass

            elif (
                job.status == "running"
                and job.started_at is not None
                and job.mode == "Triaging"
            ):
                elapsed_time = round(time.time() - job.started_at, 0)
            else:
                elapsed_time = 0
                job.progress = 0

            job.elapsed_time = elapsed_time
            job._prev_status = job.status

        for job_id in jobs_to_remove:
            del self.jobs[job_id]

        with self.queue_lock:
            with self.job_queue.mutex:
                tasks_list = list(self.job_queue.queue)

        running_jobs = [job for job in self.jobs.values() if job.status == "running"]
        running_job_ids = {job.job_id for job in running_jobs}

        seen_jobs = set()
        queued_jobs_ordered = []
        for task in tasks_list:
            if (
                task.job_id not in seen_jobs
                and task.job_id in self.jobs
                and task.job_id not in running_job_ids
            ):
                seen_jobs.add(task.job_id)
                queued_jobs_ordered.append(self.jobs[task.job_id])

        other_jobs = [
            job for job in self.jobs.values() if job.status not in ["queued", "running"]
        ]

        return running_jobs + queued_jobs_ordered + other_jobs


def start_manager(manager):
    print("[Manager] Starting Job Manager...")
    manager.run_manager()


def finalize_job(job: Job, stopped=False, force_status=None):
    """Create/update the frb_info.json file with complete job and task information when job completes."""

    base_dir = get_frb_base_dir()
    output_folder = os.path.join(
        base_dir,
        job.benchmark,
        job.binary,
        "fuzzers",
        job.fuzzer,
        "fuzzing_out",
        job.output_dir,
    )
    json_path = os.path.join(output_folder, "frb_info.json")

    if os.path.isfile(json_path):
        return

    try:
        if stopped:
            completed_times = [
                t.completed_at for t in job.tasks if t.completed_at is not None
            ]
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
        data["auto_queue_triaging"] = bool(getattr(job, "auto_queue_triaging", True))
        data["status"] = force_status if force_status is not None else job.status
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
                "duration": task.duration,
            }

            if task.started_at and task.completed_at:
                task_info["elapsed_time"] = round(
                    task.completed_at - task.started_at, 2
                )

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

    fuzzer_dir_path = os.path.join(
        base_dir, job.benchmark, job.binary, "fuzzers", job.fuzzer
    )

    for item in os.listdir(fuzzer_dir_path):
        item_path = os.path.join(fuzzer_dir_path, item)
        if item != "fuzzing_out":
            try:
                if os.path.isdir(item_path):
                    shutil.copytree(
                        item_path,
                        os.path.join(ouput_dir_path, item),
                        dirs_exist_ok=True,
                    )
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
        subprocess.run([objcopy_path, "-O", "binary", elf_path, bin_path], check=True)
    except Exception as e:
        print(f"Error copying binary to output folder: {e}")

    try:
        local_fuzzer_runner_path = os.path.join(fuzzer_dir_path, f"{job.fuzzer}-run.sh")
        default_fuzzer_runner_path = os.path.join(
            base_dir, "src", "firmrebugger", "fuzzer_runners", f"{job.fuzzer}-run.sh"
        )

        fuzzer_runner_path = (
            local_fuzzer_runner_path
            if os.path.exists(local_fuzzer_runner_path)
            else default_fuzzer_runner_path
        )

        shutil.copy(fuzzer_runner_path, ouput_dir_path)
    except Exception as e:
        print(f"Error copying fuzzer runner to output folder: {e}")


def find_available_idx(max_idx, existing_tasks, num_cores=1):
    if existing_tasks is None:
        existing_tasks = []

    max_idx = max(1, int(max_idx))

    used_cores = set()
    for task in existing_tasks:
        if hasattr(task, "core_idx") and task.core_idx is not None:
            # Handle both single core (int) and multiple cores (list)
            if isinstance(task.core_idx, list):
                used_cores.update(task.core_idx)
            else:
                used_cores.add(task.core_idx)

    cpu_percent = psutil.cpu_percent(interval=0.1, percpu=True)

    core_limit = min(max_idx, len(cpu_percent)) if cpu_percent else 0
    if core_limit <= 0:
        return [0] if num_cores > 1 else 0

    available_cores = [i for i in range(core_limit) if i not in used_cores]

    if num_cores == 1:
        if available_cores:
            least_used = min(available_cores, key=lambda i: cpu_percent[i])
            return least_used

        if cpu_percent and core_limit > 0:
            least_used = min(range(core_limit), key=lambda i: cpu_percent[i])
            return least_used

        return 0
    else:
        if len(available_cores) >= num_cores:
            selected_cores = sorted(available_cores, key=lambda i: cpu_percent[i])[
                :num_cores
            ]
            return selected_cores
        else:
            print(
                f"Warning: Only {len(available_cores)} cores available, but {num_cores} requested"
            )
            all_cores = list(range(core_limit))
            selected_cores = sorted(all_cores, key=lambda i: cpu_percent[i])[:num_cores]
            return selected_cores


def list_finished_jobs() -> List[Job]:
    base_dir = get_frb_base_dir()
    finished_jobs = []

    search_pattern = os.path.join(
        base_dir, "**", "fuzzers", "**", "fuzzing_out", "**", "frb_info.json"
    )
    frb_info_files = glob.glob(search_pattern, recursive=True)

    for json_file_path in frb_info_files:
        try:
            with open(json_file_path, "r") as f:
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
                output_dir=data.get("output_dir"),
                auto_queue_triaging=data.get("auto_queue_triaging", True),
            )

            job.created_at = data.get("created_at")
            job.started_at = data.get("started_at")
            job.elapsed_time = (
                data.get("ended_at", 0) - data.get("started_at", 0)
                if data.get("started_at")
                else 0
            )

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
                        container_name=task_data.get("container_name"),
                    )

                    task.status = task_data.get("status", "completed")
                    task.created_at = task_data.get("created_at")
                    task.started_at = task_data.get("started_at")
                    task.completed_at = task_data.get("completed_at")

                    job.tasks.append(task)

            finished_jobs.append(job)

        except Exception as e:
            print(f"[list_finished_jobs] Error reading {json_file_path}: {e}")
            continue

    return finished_jobs
