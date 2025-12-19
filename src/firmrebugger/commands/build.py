from firmrebugger.common import get_frb_base_dir, menu
import docker
from docker.errors import ImageNotFound
import sys
import os
import concurrent.futures
import subprocess

FIRMREBUGGER_BASE_DIR = None


def get_fuzzers(fuzzers_dir):
    fuzzers = []
    try:
        if not os.path.isdir(fuzzers_dir):
            raise FileNotFoundError(f"Directory not found: {fuzzers_dir}")
        for fuzzer in os.listdir(fuzzers_dir):
            fuzzers.append(fuzzer)
        return fuzzers
    except Exception as e:
        print(f"Error listing fuzzers in {fuzzers_dir}: {e}")
        sys.exit(1)


def build_fuzzer_docker(fuzzer, frb=False):
    """Build a single fuzzer and return success status"""
    print(f"Building Docker image for {fuzzer}...")
    if frb:
        builder_path = os.path.join(
            FIRMREBUGGER_BASE_DIR, "docker", fuzzer, "frb", "build_image.sh"
        )
    else:
        builder_path = os.path.join(
            FIRMREBUGGER_BASE_DIR, "docker", fuzzer, "original", "build_image.sh"
        )

    cmd = f"{builder_path}"
    print(f"Running command: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"{fuzzer} built successfully.")
        return True, None
    except subprocess. CalledProcessError as e: 
        error_msg = f"Return code: {e.returncode}, Command: {e.cmd}"
        print(f"Error building {fuzzer}. {error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = str(e)
        print(f"Unexpected error building {fuzzer}: {e}")
        return False, error_msg


def build_fuzzers(frb=False):
    global FIRMREBUGGER_BASE_DIR
    FIRMREBUGGER_BASE_DIR = get_frb_base_dir()
    fuzzer_docker_dir = f"{FIRMREBUGGER_BASE_DIR}/docker"
    fuzzers = get_fuzzers(fuzzer_docker_dir)
    if not fuzzers:
        print(f"No fuzzers found in directory: {fuzzer_docker_dir}")
        sys.exit(1)

    selected_fuzzers = menu("Select fuzzers to build", fuzzers)
    if not selected_fuzzers:
        print("No fuzzers selected.")
        sys.exit(1)

    results = {}

    def safe_build(fuzzer):
        success, error = build_fuzzer_docker(fuzzer, frb=frb)
        return fuzzer, success, error

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor. submit(safe_build, fuzzer) for fuzzer in selected_fuzzers]
        for future in concurrent.futures.as_completed(futures):
            fuzzer, success, error = future.result()
            results[fuzzer] = {"success": success, "error": error}

    # Print summary
    print("\n" + "="*60)
    print("BUILD SUMMARY")
    print("="*60)

    successful = [f for f, r in results.items() if r["success"]]
    failed = [f for f, r in results.items() if not r["success"]]

    if successful: 
        print(f"\nSuccessfully built ({len(successful)}):")
        for fuzzer in successful:
            print(f"  - {fuzzer}")

    if failed:
        print(f"\nFailed to build ({len(failed)}):")
        for fuzzer in failed:
            print(f"  - {fuzzer}")
            if results[fuzzer]["error"]:
                print(f"    Error: {results[fuzzer]['error']}")

    print("="*60)

    if failed:
        sys.exit(1)
    else:
        print("\nAll fuzzers built successfully.")

def check_docker_builds(fuzzers, frb=False):
    client = docker.from_env()
    version = "frb" if frb else "frb_original"
    for fuzzer in fuzzers:
        image_name = f"{version}:{fuzzer}"
        try:
            client.images.get(image_name)
        except ImageNotFound:
            print(f"Image {image_name} not found.")
            build_fuzzer_docker(fuzzer, frb=frb)
    print("All selected fuzzers docker images have been built.")
