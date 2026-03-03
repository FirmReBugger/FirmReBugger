import os
import threading
import time
from firmrebugger.common import get_frb_base_dir
import subprocess
import shutil


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


def _ensure_writable_directory(
    path, repair_image=None, verify_with_image=None, verify_user=None
):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        return False, f"Failed to create directory {path}: {e}"

    probe_file = os.path.join(path, ".frb_write_probe")

    def can_write():
        try:
            with open(probe_file, "w"):
                pass
            os.remove(probe_file)
            return True, None
        except Exception as e:
            return False, str(e)

    writable, write_error = can_write()

    def container_can_write(image, user):
        cmd = [
            "docker",
            "run",
            "--rm",
            "--mount",
            f"type=bind,source={path},target=/target",
            "--entrypoint",
            "/bin/sh",
        ]
        if user:
            cmd.extend(["--user", user])
        cmd.extend(
            [
                image,
                "-lc",
                "touch /target/.frb_container_write_probe && rm -f /target/.frb_container_write_probe",
            ]
        )
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.returncode == 0, (result.stderr or result.stdout or "").strip()

    container_writable = True
    container_error = None
    if verify_with_image:
        container_writable, container_error = container_can_write(
            verify_with_image, verify_user
        )

    if writable and container_writable:
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

    writable, write_error = can_write()
    if verify_with_image:
        container_writable, container_error = container_can_write(
            verify_with_image, verify_user
        )
    else:
        container_writable = True
        container_error = None

    if writable and container_writable:
        return True, None

    if not writable:
        return (
            False,
            f"Directory remains non-writable on host after repair: {path}. Error: {write_error}",
        )
    return (
        False,
        f"Directory is writable on host but not in container user context: {path}. Error: {container_error}",
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
        output_dir,
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
        self.output_dir = output_dir
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

            if self.mode == "Fuzzing":
                self.fuzz()
            elif self.mode == "Triaging":
                self.triage()

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
        work_dir = os.path.join(
            base_dir,
            self.benchmark,
            self.binary,
            "fuzzers",
            self.fuzzer,
            "fuzzing_out",
            self.output_dir,
        )
        ok, err = _ensure_writable_directory(
            work_dir,
            repair_image=f"frb_original:{self.fuzzer}",
        )
        if not ok:
            print(f"[Task {self.task_id}] ERROR: {err}")
            self.status = "error"
            return

        runtime_env = get_runtime_docker_env()

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
        for env_name, env_value in runtime_env.items():
            run_cmd.extend(["-e", f"{env_name}={env_value}"])
        run_cmd.extend([f"frb_original:{self.fuzzer}"])
        subprocess.run(run_cmd, check=True)

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

        os.makedirs(f"{work_dir}/fuzzing_logs", exist_ok=True)
        log_file = f"{work_dir}/fuzzing_logs/log-{self.run_number}.log"

        fuzz_start_time = time.time()

        with open(log_file, "w") as log:
            docker_exec_cmd = [
                "docker",
                "exec",
                "-w",
                "/home/user/target",
            ]
            for env_name, env_value in runtime_env.items():
                docker_exec_cmd.extend(["--env", f"{env_name}={env_value}"])
            docker_exec_cmd.extend(
                [
                    self.container_name,
                    f"./{self.fuzzer}-run.sh",
                    str(self.duration),
                    f"/home/user/target/output-{self.run_number}",
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

        if self.status != "stopped":
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

        try:
            base_dir = get_frb_base_dir()
            work_dir = os.path.join(
                base_dir,
                self.benchmark,
                self.binary,
                "fuzzers",
                self.fuzzer,
                "fuzzing_out",
                self.output_dir,
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
        output_dir = os.path.join(
            base_dir,
            self.benchmark,
            self.binary,
            "fuzzers",
            self.fuzzer,
            "fuzzing_out",
            self.output_dir,
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

        bug_descriptor_path = os.path.join(
            base_dir, self.benchmark, self.binary, "bug_descriptor.c"
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
                f"type=bind,source={output_dir},target=/firmrebugger/target",
                "--cpuset-cpus",
                core_str,
            ]
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
