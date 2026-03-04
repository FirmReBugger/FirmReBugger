from firmrebugger.common import get_frb_base_dir, menu
import sys
import os
import subprocess
import json


def remove_local_image(image_name):
    """Best-effort removal of a local Docker image tag."""
    try:
        result = subprocess.run(
            ["docker", "image", "rm", "-f", image_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def cleanup_existing_images(fuzzer, registry_prefix):
    """Remove potentially stale local images before build/pull.

    Order is GHCR-prefixed local tags first, then local runtime tags.
    """
    images_to_remove = [
        f"{registry_prefix}/frb:{fuzzer}",
        f"{registry_prefix}/frb_original:{fuzzer}",
        f"frb:{fuzzer}",
        f"frb_original:{fuzzer}",
    ]

    removed_any = False
    for image_name in images_to_remove:
        if remove_local_image(image_name):
            removed_any = True
            print(f"Removed local image: {image_name}")

    if not removed_any:
        print(f"No existing local images to remove for {fuzzer}")


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


def build_fuzzer_docker(fuzzer):
    print(f"Building Docker images for {fuzzer}...")

    # Paths for the build scripts
    non_frb_builder_path = os.path.join(
        FIRMREBUGGER_BASE_DIR, "docker", fuzzer, "original", "build_image.sh"
    )
    frb_builder_path = os.path.join(
        FIRMREBUGGER_BASE_DIR, "docker", fuzzer, "frb", "build_image.sh"
    )

    # Helper to build a Docker image and handle errors
    def run_build(build_script, version):
        cmd = f"{build_script}"
        print(f"Building {version} version: Running command: {cmd}")
        try:
            subprocess.run(
                cmd,
                shell=True,
                check=True,
                cwd=FIRMREBUGGER_BASE_DIR,
                env={**os.environ, "FIRMREBUGGER_BASE_DIR": FIRMREBUGGER_BASE_DIR},
            )
            print(f"{version} version of {fuzzer} built successfully.")
            return True, None
        except subprocess.CalledProcessError as e:
            error_msg = f"Return code: {e.returncode}, Command: {e.cmd}"
            print(f"Error building {version} version of {fuzzer}. {error_msg}")
            return False, error_msg
        except Exception as e:
            error_msg = str(e)
            print(f"Unexpected error building {version} version of {fuzzer}: {e}")
            return False, error_msg

    non_frb_success, non_frb_error = run_build(non_frb_builder_path, "Original")
    if not non_frb_success:
        return False, f"Error in original build: {non_frb_error}"

    # Build the FRB version next
    frb_success, frb_error = run_build(frb_builder_path, "FRB")
    if not frb_success:
        return False, f"Error in FRB build: {frb_error}"

    # Both builds succeeded
    return True, None


def pull_prebuilt_fuzzer_images(fuzzer, registry_prefix):
    print(f"Pulling prebuilt Docker images for {fuzzer} from {registry_prefix}...")

    remote_frb_image = f"{registry_prefix}/frb:{fuzzer}"
    local_frb_image = f"frb:{fuzzer}"

    remote_original_image = f"{registry_prefix}/frb_original:{fuzzer}"
    local_original_image = f"frb_original:{fuzzer}"

    def docker_manifest_config_digest(image):
        try:
            result = subprocess.run(
                ["docker", "manifest", "inspect", image],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            manifest = json.loads(result.stdout)
            config = manifest.get("config", {}) if isinstance(manifest, dict) else {}
            digest = config.get("digest")
            return (
                digest
                if isinstance(digest, str) and digest.startswith("sha256:")
                else None
            )
        except Exception:
            return None

    def docker_local_image_id(image):
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            image_id = result.stdout.strip()
            return image_id if image_id.startswith("sha256:") else None
        except Exception:
            return None

    def should_pull(remote_image, local_image):
        remote_digest = docker_manifest_config_digest(remote_image)
        local_digest = docker_local_image_id(local_image)

        if remote_digest and local_digest and remote_digest == local_digest:
            print(
                f"{local_image} already matches remote digest {remote_digest}; skipping pull"
            )
            return False
        return True

    def docker_pull(image):
        try:
            subprocess.run(["docker", "pull", image], check=True)
            return True, None
        except subprocess.CalledProcessError as e:
            return False, f"Return code: {e.returncode}, Command: {e.cmd}"
        except Exception as e:
            return False, str(e)

    def docker_tag(source, target):
        try:
            subprocess.run(["docker", "tag", source, target], check=True)
            return True, None
        except subprocess.CalledProcessError as e:
            return False, f"Return code: {e.returncode}, Command: {e.cmd}"
        except Exception as e:
            return False, str(e)

    if should_pull(remote_frb_image, local_frb_image):
        frb_success, frb_error = docker_pull(remote_frb_image)
        if not frb_success:
            return False, f"Error pulling FRB image '{remote_frb_image}': {frb_error}"

        tag_success, tag_error = docker_tag(remote_frb_image, local_frb_image)
        if not tag_success:
            return False, f"Error tagging FRB image to '{local_frb_image}': {tag_error}"

    if should_pull(remote_original_image, local_original_image):
        original_success, original_error = docker_pull(remote_original_image)
        if not original_success:
            return (
                False,
                f"Error pulling original image '{remote_original_image}': {original_error}. "
                "Prebuilt mode requires both distinct images: frb:<fuzzer> and frb_original:<fuzzer>.",
            )

        tag_success, tag_error = docker_tag(remote_original_image, local_original_image)
        if not tag_success:
            return (
                False,
                f"Error tagging original image to '{local_original_image}': {tag_error}",
            )

    print(
        f"Prebuilt images ready for {fuzzer}: {local_frb_image}, {local_original_image}"
    )
    return True, None


def build_fuzzers(use_prebuilt=False, registry_prefix=None):
    global FIRMREBUGGER_BASE_DIR
    FIRMREBUGGER_BASE_DIR = get_frb_base_dir()
    fuzzer_docker_dir = f"{FIRMREBUGGER_BASE_DIR}/docker"
    fuzzers = get_fuzzers(fuzzer_docker_dir)
    user_id = os.environ.get("USERID", "1000")
    print(f"[+] Using USERID={user_id} for Docker builds")
    if not fuzzers:
        print(f"No fuzzers found in directory: {fuzzer_docker_dir}")
        sys.exit(1)

    selected_fuzzers = menu("Select fuzzers to build", fuzzers)
    if not selected_fuzzers:
        print("No fuzzers selected.")
        sys.exit(1)

    results = {}

    def safe_build(fuzzer):
        if use_prebuilt:
            # Keep local tags for digest comparison to skip unchanged pulls.
            success, error = pull_prebuilt_fuzzer_images(fuzzer, registry_prefix)
        else:
            cleanup_existing_images(fuzzer, registry_prefix)
            success, error = build_fuzzer_docker(fuzzer)
        return fuzzer, success, error

    if use_prebuilt:
        total = len(selected_fuzzers)
        print(f"Processing prebuilt images for ({total} fuzzers)")
        completed = 0
        for fuzzer in selected_fuzzers:
            fuzzer, success, error = safe_build(fuzzer)
            completed += 1
            print(f"[{completed}/{total}] Prepared prebuilt images for {fuzzer}")
            results[fuzzer] = {"success": success, "error": error}
    else:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(safe_build, fuzzer) for fuzzer in selected_fuzzers
            ]
            for future in concurrent.futures.as_completed(futures):
                fuzzer, success, error = future.result()
                results[fuzzer] = {"success": success, "error": error}


    # Print summary
    print("\n" + "=" * 60)
    print("BUILD SUMMARY")
    print("=" * 60)

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

    print("=" * 60)

    if failed:
        sys.exit(1)
    else:
        print("\nAll fuzzers built successfully.")
