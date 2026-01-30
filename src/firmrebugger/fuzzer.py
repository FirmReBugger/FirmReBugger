import os
import time

import yaml

from firmrebugger.common import get_frb_base_dir
from firmrebugger.task import Task


def init_bench_info(
    bench_info_path,
    fuzzer,
    target,
    runs,
    duration,
    Start_Fuzzing_Time,
):
    data = {
        "Fuzzer": fuzzer,
        "Target": target,
        "Num_Trials": int(runs),
        "Planned_Time": int(duration),
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


def prep_target_folder(task: Task):
    base_dir = get_frb_base_dir()
    ouput_dir_path = f"{base_dir}/{task.benchmark}/{task.binary}/fuzzers/{task.fuzzer}/fuzzing_out/{task.output_dir}"

    os.makedirs(ouput_dir_path, exist_ok=True)
    binary_path = os.path.join(
        base_dir, task.benchmark, task.binary, f"{task.binary}.elf"
    )

    init_bench_info(
        ouput_dir_path,
        task.fuzzer,
        task.binary,
        task.runs,
        task.duration,
        task.started_at,
    )

    fuzzer_dir_path = os.path.join(
        base_dir, task.benchmark, task.binary, "fuzzers", task.fuzzer
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
        shutil.copy(binary_path, ouput_dir_path)
        objcopy_path = shutil.which("arm-none-eabi-objcopy")
        if objcopy_path is None:
            print(
                "arm-none-eabi-objcopy not found in PATH. Please install it or add it to your PATH."
            )
        bin_path = os.path.join(ouput_dir_path, f"{task.binary}.bin")
        subprocess.run(
            [objcopy_path, "-O", "binary", binary_path, bin_path], check=True
        )
    except Exception as e:
        print(f"Error copying binary to output folder: {e}")


def fuzz(task: Task, core_idx):
    if task.mode == "Fuzzing":
        print(f"[Task {task.task_id}] Preparing target folder for fuzzing...")
        prep_target_folder(task)
