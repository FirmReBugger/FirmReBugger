import os
import re
import shutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from firmrebugger.bug_analyzer_utils.common import (
    get_available_cpu_count,
    periodic_printer,
    run_command,
    update_bug_data,
)


def _extract_elf_name_from_cmdline(output_path):
    cmdline_path = os.path.join(output_path, "outputs", "cmdline")
    if not os.path.isfile(cmdline_path):
        return None

    try:
        with open(cmdline_path, "r") as file:
            for line in file:
                token = line.strip()
                if token.endswith(".elf"):
                    return os.path.basename(token)
    except Exception:
        return None

    return None


def _extract_elf_name_from_cfg(output_path):
    cfg_path = os.path.join(output_path, "mi-f429.cfg")
    if not os.path.isfile(cfg_path):
        return None

    try:
        with open(cfg_path, "r") as file:
            for line in file:
                stripped = line.strip()
                if stripped.startswith("img") and "=" in stripped:
                    value = stripped.split("=", 1)[1].strip()
                    if value.endswith(".elf"):
                        return os.path.basename(value)
    except Exception:
        return None

    return None


def _extract_elf_name_from_run_script(output_path):
    run_script = os.path.join(output_path, "run_fw.py")
    if not os.path.isfile(run_script):
        return None

    try:
        with open(run_script, "r") as file:
            content = file.read()
        match = re.search(r"/home/user/target/([^'\"\s]+\.elf)", content)
        if match:
            return os.path.basename(match.group(1))
    except Exception:
        return None

    return None


def _prepare_dice_compat_paths(output_path):
    expected_root = "/home/user/target"
    output_name = os.path.basename(output_path)
    expected_output_path = os.path.join(expected_root, output_name)

    try:
        os.makedirs(expected_root, exist_ok=True)
    except Exception as e:
        print(f"Warning: Could not create {expected_root}: {e}")
        return

    try:
        if os.path.lexists(expected_output_path):
            if os.path.islink(expected_output_path):
                current_target = os.readlink(expected_output_path)
                if os.path.abspath(current_target) != os.path.abspath(output_path):
                    os.remove(expected_output_path)
                    os.symlink(output_path, expected_output_path)
            elif os.path.abspath(expected_output_path) != os.path.abspath(output_path):
                print(
                    f"Warning: {expected_output_path} exists and is not a symlink; using existing path"
                )
        else:
            os.symlink(output_path, expected_output_path)
    except Exception as e:
        print(f"Warning: Could not prepare output symlink {expected_output_path}: {e}")

    elf_name = _extract_elf_name_from_cmdline(output_path)
    if not elf_name:
        elf_name = _extract_elf_name_from_cfg(output_path)
    if not elf_name:
        elf_name = _extract_elf_name_from_run_script(output_path)
    if not elf_name:
        parent_dir = os.path.dirname(output_path)
        try:
            elf_files = [f for f in os.listdir(parent_dir) if f.endswith(".elf")]
            if len(elf_files) == 1:
                elf_name = elf_files[0]
        except Exception:
            pass
    if not elf_name:
        print("Warning: Could not determine DICE ELF name; run_fw.py may fail")
        return

    expected_elf_path = os.path.join(expected_root, elf_name)
    if os.path.exists(expected_elf_path):
        return

    elf_candidates = [
        os.path.join(output_path, elf_name),
        os.path.join(os.path.dirname(output_path), elf_name),
        os.path.join(os.path.dirname(os.path.dirname(output_path)), elf_name),
    ]

    source_elf = None
    for candidate in elf_candidates:
        if os.path.isfile(candidate):
            source_elf = candidate
            break

    if source_elf is None:
        print(
            f"Warning: Could not find ELF '{elf_name}' near output path; run_fw.py may fail"
        )
        return

    try:
        os.symlink(source_elf, expected_elf_path)
    except Exception:
        try:
            shutil.copy2(source_elf, expected_elf_path)
        except Exception as e:
            print(f"Warning: Could not place ELF at {expected_elf_path}: {e}")


def final_model(path="."):
    max_num = None
    for name in os.listdir(path):
        folder_path = os.path.join(path, name)
        if os.path.isdir(folder_path) and name.isdigit():
            n = int(name)
            if (max_num is None) or (n > max_num):
                max_num = n
    return max_num


def get_time_input(seed_path, fuzzer_stats_path="outputs/fuzzer_stats"):
    try:
        file_mtime = int(os.path.getmtime(seed_path))
    except Exception as e:
        raise RuntimeError(f"Could not get mtime for {seed_path}: {e}")

    try:
        with open(fuzzer_stats_path, "r") as f:
            for line in f:
                if line.startswith("start_time"):
                    match = re.search(r"\d+", line)
                    if match:
                        start_time = int(match.group())
                        break
            else:
                raise RuntimeError(f"start_time not found in {fuzzer_stats_path}")
    except Exception as e:
        raise RuntimeError(f"Could not read {fuzzer_stats_path}: {e}")

    return file_mtime - start_time


def get_run_parameters(output_path):
    file_info = ""
    file_return = []

    cmdline_path = os.path.join(output_path, "outputs", "cmdline")
    if not os.path.isfile(cmdline_path):
        raise FileNotFoundError(f"The 'cmdline' file does not exist at: {cmdline_path}")

    with open(cmdline_path, "r") as file:
        filename = ""
        for line in file:
            line = line.strip()
            if line.endswith(".elf"):
                filename = line.rsplit("/", 1)[-1]
            elif filename == "":
                sys.exit(f"Error: No ELF file found in cmdline at {cmdline_path}")
            else:
                if "@@" in line:
                    file_return.append(filename)
                    file_return.append(file_info)
                    return file_return
                file_info += line + " "


def _get_dice_working_folder(output_path, crash):
    folder_name = "crashes" if crash else "queue"
    candidates = [
        os.path.join(output_path, "outputs", "default", folder_name),
        os.path.join(output_path, "output", "default", folder_name),
        os.path.join(output_path, "outputs", folder_name),
        os.path.join(output_path, "default", folder_name),
    ]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate

    label = "Crashes" if crash else "Queue"
    raise FileNotFoundError(
        f"The '{label}' folder does not exist; checked: {', '.join(candidates)}"
    )


def _get_dice_fuzzer_stats_path(output_path, working_folder):
    candidates = [
        os.path.join(os.path.dirname(working_folder), "fuzzer_stats"),
        os.path.join(output_path, "outputs", "fuzzer_stats"),
        os.path.join(output_path, "fuzzer_stats"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return candidates[0]


def dice_analyzer(
    bench_info,
    output_path,
    run_data=None,
    Crash=False,
    run_name=None,
    descriptor_path=None,
):
    os.environ["FIRMREBUGGER_CONFIG"] = descriptor_path
    execution_times = []
    working_folder = _get_dice_working_folder(output_path, Crash)
    fuzzer_stats_path = _get_dice_fuzzer_stats_path(output_path, working_folder)

    seeds = [
        os.path.join(working_folder, seed)
        for seed in sorted(os.listdir(working_folder))
        if "README" not in seed and os.path.basename(seed).startswith("id")
    ]
    num_workers = max(1, min(len(seeds), get_available_cpu_count()))

    progress = {
        "completed": 0,
        "total": len(seeds),
        "run_name": run_name,
        "ungrouped_crashes": 0,
        "Fuzzer": bench_info["fuzzer"],
        "Target": bench_info["target"],
        "failed": False,
        "failure_message": None,
    }
    stop_event = threading.Event()

    printer_thread = threading.Thread(
        target=periodic_printer, args=(run_data, stop_event, progress, Crash)
    )
    printer_thread.start()
    original_dir = os.getcwd()

    failure_exc = None
    failure_tb = None
    try:
        _prepare_dice_compat_paths(output_path)

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            # change dir
            os.chdir(output_path)
            model = final_model()
            for seed_path in seeds:
                command = f"stdbuf -oL -eL ./run_fw.py {model} {seed_path}"
                futures.append(
                    executor.submit(
                        run_command,
                        command,
                        seed_path,
                        get_time_input(seed_path, fuzzer_stats_path),
                        Crash,
                        10,
                    )
                )

            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    continue
                seed_path, bugs_triggered, bugs_reached, time_val, elapsed, errors = (
                    result
                )
                execution_times.append(elapsed)

                run_data = update_bug_data(
                    run_data,
                    time_val,
                    seed_path,
                    bugs_triggered=bugs_triggered,
                    bugs_reached=bugs_reached,
                    Crash=Crash,
                )

                progress["completed"] += 1
                progress["ungrouped_crashes"] = len(run_data[0]["ungrouped_crashes"])
    except Exception as exc:
        progress["failed"] = True
        progress["failure_message"] = str(exc)
        failure_exc = exc
        failure_tb = exc.__traceback__
    finally:
        stop_event.set()
        printer_thread.join()
        os.chdir(original_dir)

    if failure_exc is not None:
        print(
            "\n[ERROR DICE Triaging] Triaging aborted due to replay error.\n"
            f"{progress['failure_message']}\n",
            file=sys.stderr,
            flush=True,
        )
        raise failure_exc.with_traceback(failure_tb)

    return run_data, execution_times
