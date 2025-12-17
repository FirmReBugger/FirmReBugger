import os
import sys
import zstandard
import tarfile
import yaml
import io
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed
from firmrebugger.bug_analyzer.common import (
    update_bug_data,
    run_command,
    periodic_printer,
)
import threading


def get_hoedur_env():
    if "HOEDUR_BASE_DIR" not in os.environ:
        raise EnvironmentError("The environment variable 'HOEDUR_BASE_DIR' is not set.")
        sys.exit(1)

    hoedur_env = os.environ["HOEDUR_BASE_DIR"]
    return hoedur_env


def get_timestamp_from_tar(tar_bytes):
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        for member in tar.getmembers():
            if member.name.endswith("meta.yml"):
                f = tar.extractfile(member)
                if f is not None:
                    meta_data = yaml.safe_load(f.read().decode())
                    return meta_data.get("timestamp")
    return None


def get_corpus_tar_zst(path):
    pattern = os.path.join(path, "output*.corpus.tar.zst")
    try:
        glob.glob(pattern)[0]
    except IndexError:
        pattern = os.path.join(path, "Hoedur*.corpus.tar.zst")
        glob.glob(pattern)[0]

    return glob.glob(pattern)[0]


def get_seeds(zst_path):
    queue = []
    crashes = []
    meta_time = None

    tmp_dir = os.path.join(os.path.dirname(zst_path), "tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    with open(zst_path, "rb") as compressed:
        dctx = zstandard.ZstdDecompressor()
        decompressed = dctx.stream_reader(compressed)
        tar_bytes = decompressed.read()

    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        for member in tar.getmembers():
            if "meta.yml" in member.name:
                meta_time = get_timestamp_from_tar(tar_bytes)
                break

    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if meta_time is None:
                print("Meta timestamp not found in the tar file.")
                sys.exit(1)
            if member.name.startswith("input/") or member.name.startswith("crash/"):
                relative_time = member.mtime - meta_time
                # Ensure the directories exist
                extract_path = os.path.join(tmp_dir, member.name)
                os.makedirs(os.path.dirname(extract_path), exist_ok=True)
                with tar.extractfile(member) as src, open(extract_path, "wb") as dst:
                    dst.write(src.read())
                if member.name.startswith("input/"):
                    queue.append((extract_path, relative_time))
                elif member.name.startswith("crash/"):
                    crashes.append((extract_path, relative_time))
    return queue, crashes


def check_env_setup():
    if "FIRMREBUGGER_CONFIG" not in os.environ:
        raise EnvironmentError(
            "The environment variable 'FIRMREBUGGER_CONFIG' is not set."
        )
        sys.exit(1)

    if "LD_LIBRARY_PATH" not in os.environ:
        raise EnvironmentError("The environment variable 'LD_LIBRARY_PATH' is not set.")
        sys.exit(1)

    if "HOEDUR_BASE_DIR" not in os.environ:
        raise EnvironmentError("The environment variable 'HOEDUR_BASE_DIR' is not set.")
        sys.exit(1)


def hoedur_analyzer(
    bench_info,
    output_path,
    run_data=None,
    Crash=False,
    run_name=None,
    descriptor_path=None,
):
    # Set bug descriptor path
    os.environ["FIRMREBUGGER_CONFIG"] = descriptor_path
    os.environ["LD_LIBRARY_PATH"] = os.path.expanduser("~/.cargo/bin/")
    execution_times = []

    check_env_setup()
    corpus_path = get_corpus_tar_zst(output_path)
    if Crash:
        working_folder = get_seeds(corpus_path)[1]
    else:
        working_folder = get_seeds(corpus_path)[0]
    num_cores = os.cpu_count()
    num_workers = max(1, int(num_cores) - 1)

    progress = {
        "completed": 0,
        "total": len(working_folder),
        "run_name": run_name,
        "ungrouped_crashes": 0,
        "Fuzzer": bench_info["fuzzer"],
        "Target": bench_info["target"],
    }

    stop_event = threading.Event()
    printer_thread = threading.Thread(
        target=periodic_printer, args=(run_data, stop_event, progress, Crash)
    )
    printer_thread.start()

    # Begin bug analysis on seeds
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        hoedur_base_dir = get_hoedur_env()
        for seed, time_val in sorted(working_folder):
            seed_path = os.path.abspath(seed)
            if "README" in seed_path:
                continue
            command = f"{hoedur_base_dir}/target/release/hoedur-arm --import-config {corpus_path} run {seed_path}"
            futures.append(
                executor.submit(run_command, command, seed_path, time_val, Crash)
            )

        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            seed_path, bugs_triggered, bugs_reached, time_val, elapsed, errors = result
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

    stop_event.set()
    printer_thread.join()
    # shutil.rmtree(os.path.join(os.path.dirname(corpus_path), "tmp"))

    return run_data, execution_times
