import os
import shutil
import subprocess
import threading
import time

from firmrebugger.common import (
    get_binary_dir,
    get_frb_base_dir,
    get_fuzzer_meta,
    get_run_output_dir,
)


def get_runtime_docker_env():
    """Return runtime env vars to keep Python caches in writable locations."""
    cache_root = "/tmp/frb-cache"
    return {
        "HOME": "/home/user",
        "XDG_CACHE_HOME": cache_root,
        "XDG_DATA_HOME": cache_root,
        "PYTHON_EGG_CACHE": f"{cache_root}/Python-Eggs",
        "UV_CACHE_DIR": f"{cache_root}/uv",
        "UV_PYTHON_INSTALL_DIR": f"{cache_root}/uv/python",
        "UV_PROJECT_ENVIRONMENT": "/tmp/frb-venv",
    }


def get_runtime_docker_ulimits():
    nofile_soft = os.getenv("FRB_ULIMIT_NOFILE_SOFT", "524288")
    nofile_hard = os.getenv("FRB_ULIMIT_NOFILE_HARD", nofile_soft)
    core_soft = os.getenv("FRB_ULIMIT_CORE_SOFT", "0")
    core_hard = os.getenv("FRB_ULIMIT_CORE_HARD", core_soft)
    return {
        "nofile": f"{nofile_soft}:{nofile_hard}",
        "core": f"{core_soft}:{core_hard}",
    }


def _ensure_writable_directory(
    path, repair_image=None, verify_with_image=None, verify_user=None
):
    import uuid as _uuid

    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        return False, f"Failed to create directory {path}: {e}"

    # Use a unique suffix per call so concurrent triage jobs probing the same
    # directory never collide on the same probe filename.
    probe_suffix = _uuid.uuid4().hex
    probe_file = os.path.join(path, f".frb_write_probe_{probe_suffix}")

    def can_write():
        try:
            with open(probe_file, "w"):
                pass
            os.remove(probe_file)
            return True, None
        except Exception as e:
            return False, str(e)

    writable, write_error = can_write()

    # If the host can already write we skip the container write-probe entirely.
    # The directory was produced by a fuzzer container that already ran fine, so
    # there is no need to spin up another Docker container just to verify it.
    # This also avoids a second race window where the container probe command
    # could collide with a concurrent triage's probe in the same directory.
    if writable:
        return True, None

    if not repair_image:
        return False, f"Directory is not writable: {path}. Error: {write_error}"

    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                "0:0",
                "--mount",
                f"type=bind,source={path},target=/target",
                "--entrypoint",
                "/bin/sh",
                repair_image,
                "-lc",
                "chmod -R a+rwX /target",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        return (
            False,
            f"Directory is not writable and auto-repair failed for {path}: {e}",
        )

    # Re-probe with a fresh unique filename after the repair attempt.
    probe_file = os.path.join(path, f".frb_write_probe_{_uuid.uuid4().hex}")
    writable, write_error = can_write()

    if writable:
        return True, None

    return (
        False,
        f"Directory remains non-writable on host after repair: {path}. Error: {write_error}",
    )


class Task:
    """Represents a single run of a fuzzing job."""

    def __init__(
        self,
        task_id,
        job_id,
        fuzzer,
        duration,
        binary,
        run_number,
        mode,
        benchmark,
        run_name,
        runs,
        core_idx,
        container_name,
    ):
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
        self.run_name = run_name
        self.runs = runs
        self.core_idx = core_idx
        self.container_name = container_name
        self.stop_reason = None

    def start(self):
        """Start the fuzzing task in a separate thread."""
        self.status = "running"
        self.started_at = time.time()

        def run_task():
            print(
                f"[Task {self.task_id}] Starting fuzzer '{self.fuzzer}' on binary '{self.binary}' (Run {self.run_number}) for {self.duration} seconds (Mode: {self.mode})"
            )

            try:
                if self.mode == "Fuzzing":
                    self.fuzz()
                elif self.mode == "Triaging":
                    self.triage()
            except Exception as e:
                print(f"[Task {self.task_id}] ERROR: unhandled exception: {e}")
                if self.status != "stopped":
                    self.status = "error"
                    self.stop_reason = str(e)

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
        docker_cp_cmd = ["docker", "cp", source, destination]
        subprocess.run(docker_cp_cmd, check=True)

    def fuzz(self):
        base_dir = get_frb_base_dir()
        work_dir = get_run_output_dir(
            base_dir, self.run_name, self.benchmark, self.binary, self.fuzzer
        )
        ok, err = _ensure_writable_directory(
            work_dir,
            repair_image=f"frb_original:{self.fuzzer}",
        )
        if not ok:
            print(f"[Task {self.task_id}] ERROR: {err}")
            self.status = "error"
            return

        image_name = f"frb_original:{self.fuzzer}"
        image_check = subprocess.run(
            ["docker", "image", "inspect", image_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if image_check.returncode != 0:
            print(
                f"[Task {self.task_id}] ERROR: Docker image '{image_name}' not found. "
                f"Run 'uv run frb build' or 'uv run frb build --use-prebuilt' first."
            )
            self.status = "error"
            self.stop_reason = f"Docker image '{image_name}' not found."
            return

        runtime_env = get_runtime_docker_env()
        runtime_ulimits = get_runtime_docker_ulimits()

        # Fuzzers opt into bind-mounting their output dir (instead of the
        # default docker-cp in/out) via `bind_mount: true` in
        # Fuzzers/<fuzzer>/fuzzer.yml — e.g. MultiFuzz uses it so output
        # streams to the host live while the run is in progress, and so
        # hail-fuzz's baked-in absolute paths (settings.json) resolve
        # correctly on the host.
        bind_mount = bool(get_fuzzer_meta(base_dir, self.fuzzer).get("bind_mount"))

        run_cmd = [
            "docker",
            "run",
            "--cpus=1",
            f"--cpuset-cpus={self.core_idx}",
            "--rm",
            "-itd",
            "--name",
            self.container_name,
        ]
        for ulimit_name, ulimit_value in runtime_ulimits.items():
            run_cmd.extend(["--ulimit", f"{ulimit_name}={ulimit_value}"])
        for env_name, env_value in runtime_env.items():
            run_cmd.extend(["-e", f"{env_name}={env_value}"])
        if bind_mount:
            run_cmd.extend(["--mount", f"type=bind,source={work_dir},target={work_dir}"])
        run_cmd.extend([f"frb_original:{self.fuzzer}"])
        subprocess.run(run_cmd, check=True)

        if bind_mount:
            # Bind mount already makes work_dir's contents visible inside the
            # container at the same path, host-writable, no copy or chown needed.
            exec_cwd = work_dir
            runner_target_dir = f"{work_dir}/output-{self.run_number}"
        else:
            self.docker_cp(work_dir, f"{self.container_name}:/home/user/target")

            try:
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        "--user",
                        "0:0",
                        self.container_name,
                        "sh",
                        "-lc",
                        "chown -R user:user /home/user/target && chmod -R u+rwX /home/user/target",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                print(
                    f"[Task {self.task_id}] Warning: failed to normalize /home/user/target permissions: {e}"
                )

            exec_cwd = "/home/user/target"
            runner_target_dir = f"/home/user/target/output-{self.run_number}"

        os.makedirs(f"{work_dir}/fuzzing_logs", exist_ok=True)
        log_file = f"{work_dir}/fuzzing_logs/log-{self.run_number}.log"

        fuzz_start_time = time.time()

        with open(log_file, "w") as log:
            docker_exec_cmd = [
                "docker",
                "exec",
                "-w",
                exec_cwd,
            ]
            for env_name, env_value in runtime_env.items():
                docker_exec_cmd.extend(["--env", f"{env_name}={env_value}"])
            docker_exec_cmd.extend(
                [
                    self.container_name,
                    "./runner.sh",
                    str(self.duration),
                    runner_target_dir,
                ]
            )

            self.subprocess = subprocess.Popen(
                docker_exec_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
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
            return_code = (
                self.subprocess.returncode if self.subprocess is not None else "unknown"
            )
            error_msg = (
                f"Task ended prematurely after {actual_duration:.1f}s "
                f"(expected at least {expected_duration}s; return code: {return_code})"
            )
            print(f"[Task {self.task_id}] ERROR: {error_msg}")
            self.status = "error"
            with open(log_file, "a") as log:
                log.write(f"\n\nERROR: {error_msg}\n")

        if self.status != "stopped" and not bind_mount:
            # MultiFuzz results are already on the host live via the bind mount.
            try:
                self.docker_cp(
                    f"{self.container_name}:/home/user/target/output-{self.run_number}",
                    work_dir,
                )
            except Exception as e:
                print(f"[Task {self.task_id}] Could not copy results: {e}")

        try:
            subprocess.run(
                ["docker", "stop", self.container_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(
                f"[Task {self.task_id}] Error stopping container {self.container_name}: {e}"
            )

    def kill_task(self, reason="user_stop"):
        """Force kill a task and its docker container."""
        print(f"[Manager] Force killing task {self.task_id}...")

        base_dir = get_frb_base_dir()
        bind_mount = bool(get_fuzzer_meta(base_dir, self.fuzzer).get("bind_mount"))

        if not bind_mount:
            # Bind-mounted fuzzers' results are already on the host live;
            # there's nothing at that container path to copy.
            try:
                work_dir = get_run_output_dir(
                    base_dir, self.run_name, self.benchmark, self.binary, self.fuzzer
                )
                self.docker_cp(
                    f"{self.container_name}:/home/user/target/output-{self.run_number}",
                    work_dir,
                )
            except Exception as e:
                print(
                    f"[Manager] Could not copy results from container {self.container_name}: {e}"
                )

        try:
            subprocess.run(
                ["docker", "kill", self.container_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"[Manager] Error killing container {self.container_name}: {e}")

        self.stop(reason=reason)
        if self.status == "completed":
            print(
                f"[Manager] Task {self.task_id} completed after grace-period termination."
            )
        else:
            print(f"[Manager] Task {self.task_id} stopped.")

    def stop(self, reason="user_stop"):
        """Stop the running task."""
        if self.process and self.process.is_alive():
            self.stop_reason = reason
            elapsed = None
            if self.started_at is not None:
                elapsed = time.time() - self.started_at

            if (
                reason == "grace_timeout"
                and elapsed is not None
                and elapsed >= self.duration
            ):
                self.status = "completed"
            else:
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

            if self.status == "completed":
                print(
                    f"[Task {self.task_id}] Task completed after grace-period termination."
                )
            else:
                print(f"[Task {self.task_id}] Task stopped.")

    def triage(self):
        """Perform triaging on the fuzzing results."""
        container_name = f"frb_triage_{self.job_id}_{self.task_id}"
        base_dir = get_frb_base_dir()
        output_dir = get_run_output_dir(
            base_dir, self.run_name, self.benchmark, self.binary, self.fuzzer
        )
        ok, err = _ensure_writable_directory(
            output_dir,
            repair_image=f"frb:{self.fuzzer}",
            verify_with_image=f"frb:{self.fuzzer}",
            verify_user=None,
        )
        if not ok:
            print(f"[Task {self.task_id}] ERROR: {err}")
            self.status = "error"
            return

        runtime_env = get_runtime_docker_env()
        runtime_ulimits = get_runtime_docker_ulimits()
        persistent_worker_settings = {
            "Fuzzware": (
                "/usr/bin/python3 -m fuzzware_harness.persistent_worker",
                "FUZZWARE_REPLAY_WORKERS",
            ),
            "Fuzzware-Icicle": (
                "/usr/bin/python3 -m fuzzware_harness.persistent_worker",
                "FUZZWARE_REPLAY_WORKERS",
            ),
            "SplITS": (
                "/usr/bin/python3 -m fuzzware_harness.persistent_worker",
                "FUZZWARE_REPLAY_WORKERS",
            ),
            "MultiFuzz": (
                "/home/user/multifuzz/MultiFuzz/target/release/hail-fuzz",
                "MULTIFUZZ_REPLAY_WORKERS",
            ),
            "Hoedur": ("/home/user/.cargo/bin/hoedur-dict-arm", None),
        }.get(self.fuzzer)
        if persistent_worker_settings:
            persistent_worker_command, worker_count_env = persistent_worker_settings
            worker_count = (
                len(self.core_idx) if isinstance(self.core_idx, list) else 1
            )
            if worker_count_env:
                runtime_env[worker_count_env] = str(max(1, worker_count))
            runtime_env["FRB_REPLAY_WORKER_COMMAND"] = persistent_worker_command

        bug_descriptor_path = os.path.join(
            get_binary_dir(base_dir, self.benchmark, self.binary), "bug_descriptor.c"
        )
        shutil.copy(bug_descriptor_path, output_dir)

        try:
            subprocess.run(
                ["chmod", "-R", "a+rwX", output_dir],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(
                f"[Task {self.task_id}] Warning: failed to relax permissions on {output_dir}: {e}"
            )

        os.makedirs(f"{output_dir}/fuzzing_logs", exist_ok=True)
        log_file = f"{output_dir}/fuzzing_logs/triage.log"

        core_str = ",".join(map(str, self.core_idx))

        with open(log_file, "w") as log:
            docker_exec_cmd = [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--mount",
                f"type=bind,source={output_dir},target=/home/user/firmrebugger/target",
                "--mount",
                f"type=bind,source={os.path.join(base_dir, 'src')},target=/home/user/firmrebugger/src",
                "--mount",
                f"type=bind,source={os.path.join(base_dir, 'Fuzzers')},target=/home/user/firmrebugger/Fuzzers",
                "--cpuset-cpus",
                core_str,
            ]
            for ulimit_name, ulimit_value in runtime_ulimits.items():
                docker_exec_cmd.extend(["--ulimit", f"{ulimit_name}={ulimit_value}"])
            for env_name, env_value in runtime_env.items():
                docker_exec_cmd.extend(["-e", f"{env_name}={env_value}"])
            docker_exec_cmd.extend([f"frb:{self.fuzzer}"])

            self.subprocess = subprocess.Popen(
                docker_exec_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
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
