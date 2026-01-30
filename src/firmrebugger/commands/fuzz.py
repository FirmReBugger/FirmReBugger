import time
import uuid
from typing import List
from firmrebugger.manager import Job, prep_target_folder, finalize_job
from firmrebugger.app_utils import check_output_name
from firmrebugger.common import get_frb_base_dir
from firmrebugger.commands.bug_analyzer import run_bug_analyzer
import os
from firmrebugger.task import Task


def fuzz(fuzzing_time, num_trials, fuzzing_output_name, benchmark='FirmBench', fuzzer=None, binary=None):
    if not fuzzer or not binary:
        raise RuntimeError("Both fuzzer and binary must be specified for fuzz")

    base_dir = get_frb_base_dir()
    print(f"[CLI fuzz] Base dir: {base_dir}, Benchmark: {benchmark}")

    if not check_output_name(benchmark, binary, [fuzzer], fuzzing_output_name):
        raise RuntimeError(f"Output path already exists: {os.path.join(base_dir, benchmark, binary, 'fuzzers', fuzzer, 'fuzzing_out', fuzzing_output_name)}")

    job_id = f"cli-{benchmark}-{binary}-{fuzzer}-{uuid.uuid4().hex[:8]}"
    job = Job(
        job_id=job_id,
        fuzzer=fuzzer,
        duration=fuzzing_time,
        binary=binary,
        runs=int(num_trials),
        mode='Fuzzing',
        benchmark=benchmark,
        progress=0,
        output_dir=fuzzing_output_name,
    )

    # Prepare the target folder once for all runs
    print(f"[CLI fuzz] Preparing target folder for job {job_id}...")
    prep_target_folder(job)

    final_status = None
    for run_idx in range(1, int(num_trials) + 1):
        run_str = str(run_idx).zfill(2)

        task = Task(
            task_id=f"{job_id}-run{run_str}",
            job_id=job_id,
            fuzzer=fuzzer,
            duration=fuzzing_time,
            binary=binary,
            run_number=run_str,
            mode='Fuzzing',
            benchmark=benchmark,
            output_dir=fuzzing_output_name,
            runs=int(num_trials),
            core_idx=1, # Changes later 
            container_name=f"tmp-name"
        )

        print(f"[CLI fuzz] Starting task {task.task_id} (core={core_idx})...")
        task.start()
        if task.process:
            task.process.join()

        print(f"[CLI fuzz] Task {task.task_id} finished with status: {task.status}")
        final_status = task.status
        job.tasks.append(task)

        if task.status != 'completed':
            print(f"[CLI fuzz] Run {run_idx} ended with status {task.status}, stopping further runs.")
            break

    try:
        finalize_job(job)
    except Exception as e:
        print(f"[CLI fuzz] Warning: failed to finalize job info: {e}")

    return final_status


