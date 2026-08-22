import uuid
from firmrebugger.manager import Job, prep_target_folder, finalize_job
from firmrebugger.app_utils import check_run_name_available
from firmrebugger.common import get_frb_base_dir, get_run_output_dir
from firmrebugger.task import Task


def fuzz(
    fuzzing_time,
    num_trials,
    fuzzing_output_name,
    benchmark="FirmBench",
    fuzzer=None,
    binary=None,
):
    if not fuzzer or not binary:
        raise RuntimeError("Both fuzzer and binary must be specified for fuzz")

    base_dir = get_frb_base_dir()
    print(f"[CLI fuzz] Base dir: {base_dir}, Benchmark: {benchmark}")

    if not check_run_name_available(benchmark, binary, [fuzzer], fuzzing_output_name):
        raise RuntimeError(
            f"Output path already exists: "
            f"{get_run_output_dir(base_dir, fuzzing_output_name, benchmark, binary, fuzzer)}"
        )

    job_id = f"cli-{benchmark}-{binary}-{fuzzer}-{uuid.uuid4().hex[:8]}"
    job = Job(
        job_id=job_id,
        fuzzer=fuzzer,
        duration=fuzzing_time,
        binary=binary,
        runs=int(num_trials),
        mode="Fuzzing",
        benchmark=benchmark,
        progress=0,
        run_name=fuzzing_output_name,
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
            mode="Fuzzing",
            benchmark=benchmark,
            run_name=fuzzing_output_name,
            runs=int(num_trials),
            core_idx=1,  # Changes later
            container_name="tmp-name",
        )

        print(f"[CLI fuzz] Starting task {task.task_id}")
        task.start()
        if task.process:
            task.process.join()

        print(f"[CLI fuzz] Task {task.task_id} finished with status: {task.status}")
        final_status = task.status
        job.tasks.append(task)

        if task.status != "completed":
            print(
                f"[CLI fuzz] Run {run_idx} ended with status {task.status}, stopping further runs."
            )
            break

    try:
        finalize_job(job)
    except Exception as e:
        print(f"[CLI fuzz] Warning: failed to finalize job info: {e}")

    return final_status
