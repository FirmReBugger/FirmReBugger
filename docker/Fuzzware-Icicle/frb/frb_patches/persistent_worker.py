"""Persistent Fuzzware-Icicle replay worker.

Icicle does not expose a whole-VM snapshot API through its Python binding.
The worker therefore initializes one VM parent and forks a disposable child
for each replay.  The parent is the clean native snapshot; child CPU, memory,
device, translation-cache, and FirmReBugger mutations are discarded when the
child exits.
"""

from __future__ import annotations

import ctypes
import json
import os
import signal
import sys
import tempfile
import time
import traceback


PREFIX = "FRB_WORKER\t"


def send(payload):
    sys.stdout.write(PREFIX + json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


class CaptureNativeOutput:
    """Capture Python, C, and Rust output without corrupting the protocol."""

    def __enter__(self):
        sys.stdout.flush()
        sys.stderr.flush()
        self.saved_stdout = os.dup(1)
        self.saved_stderr = os.dup(2)
        self.stdout_file = tempfile.TemporaryFile(mode="w+b")
        self.stderr_file = tempfile.TemporaryFile(mode="w+b")
        os.dup2(self.stdout_file.fileno(), 1)
        os.dup2(self.stderr_file.fileno(), 2)
        return self

    def __exit__(self, exc_type, exc, tb):
        ctypes.CDLL(None).fflush(None)
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(self.saved_stdout, 1)
        os.dup2(self.saved_stderr, 2)
        os.close(self.saved_stdout)
        os.close(self.saved_stderr)

    def read(self):
        self.stdout_file.seek(0)
        self.stderr_file.seek(0)
        stdout = self.stdout_file.read().decode("utf-8", "replace")
        stderr = self.stderr_file.read().decode("utf-8", "replace")
        self.stdout_file.close()
        self.stderr_file.close()
        return stdout, stderr


class IcicleSession:
    def __init__(self):
        self.uc = None
        self.native = None
        self.harness = None
        self.config_path = None

    def _resolve_config(self, seed_path, request):
        pinned_config = request.get("config_path") or os.environ.get(
            "FRB_REPLAY_CONFIG"
        )
        from fuzzware_pipeline.naming_conventions import config_for_input_path

        seed_config = os.path.abspath(config_for_input_path(seed_path))
        if pinned_config:
            pinned_config = os.path.abspath(pinned_config)
            if pinned_config != seed_config:
                raise RuntimeError(
                    "Fuzzware-Icicle worker received a seed for a different config: "
                    f"{seed_config} != {pinned_config}"
                )
            return pinned_config
        return seed_config

    def initialize(self, seed_path, request):
        requested_config = self._resolve_config(seed_path, request)
        if self.uc is not None:
            if requested_config != self.config_path:
                raise RuntimeError(
                    "Fuzzware-Icicle worker received a seed for a different config: "
                    f"{requested_config} != {self.config_path}"
                )
            return

        for key, value in (request.get("env") or {}).items():
            os.environ[str(key)] = str(value)

        from fuzzware_harness import harness, native

        self.harness = harness
        self.native = native
        self.config_path = requested_config

        parser = __import__("argparse").ArgumentParser(add_help=False)
        harness.populate_parser(parser)
        args = parser.parse_args([seed_path, "-c", self.config_path])
        args.print_exit_info = True
        os.environ.setdefault("FRB_REPLAY_WORKER", "1")
        self.uc = harness.configure_unicorn(args)
        harness.globs.uc = self.uc

    @staticmethod
    def _read_file(file):
        file.seek(0)
        return file.read().decode("utf-8", "replace")

    def _replay_child(self, seed_path, prefix_path, timeout):
        stdout_file = tempfile.TemporaryFile(mode="w+b")
        stderr_file = tempfile.TemporaryFile(mode="w+b")
        pid = os.fork()
        if pid == 0:
            try:
                os.dup2(stdout_file.fileno(), 1)
                os.dup2(stderr_file.fileno(), 2)
                try:
                    self.native.emulate(self.uc, seed_path, prefix_path)
                except BaseException:
                    traceback.print_exc()
                    os._exit(1)
                ctypes.CDLL(None).fflush(None)
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(0)
            except BaseException:
                os._exit(1)

        started = time.monotonic()
        status = None
        timed_out = False
        deadline = started + timeout
        while True:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                break
            if time.monotonic() >= deadline:
                timed_out = True
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status = os.waitpid(pid, 0)
                break
            # Keep completion latency below the duration of short replays.
            time.sleep(0.001)

        stdout = self._read_file(stdout_file)
        stderr = self._read_file(stderr_file)
        stdout_file.close()
        stderr_file.close()

        if timed_out:
            return {
                "status": "timeout",
                "timed_out": True,
                "returncode": None,
                "elapsed": time.monotonic() - started,
                "stdout": stdout,
                "stderr": stderr,
            }

        if os.WIFEXITED(status):
            returncode = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            returncode = 128 + os.WTERMSIG(status)
        else:
            returncode = 1
        return {
            "status": "ok" if returncode == 0 else "error",
            "returncode": returncode,
            "elapsed": time.monotonic() - started,
            "stdout": stdout,
            "stderr": stderr,
        }

    def reset(self, request):
        # The parent VM is never replayed. Its address space is the clean
        # snapshot, so no in-process Icicle reset is needed here.
        with CaptureNativeOutput() as captured:
            self.initialize(request["seed_path"], request)
        stdout, stderr = captured.read()
        return stdout, stderr

    def replay(self, request):
        self.initialize(request["seed_path"], request)
        return {
            "op": "result",
            **self._replay_child(
                request["seed_path"],
                request.get("prefix_input_path"),
                float(request.get("timeout", 10)),
            ),
        }

    def close(self):
        close = getattr(self.uc, "close", None)
        if close:
            close()
        self.uc = None


def main():
    session = IcicleSession()
    try:
        for line in sys.stdin:
            if not line.startswith(PREFIX):
                continue
            request = json.loads(line[len(PREFIX) :])
            operation = request.get("op")
            try:
                if operation == "start":
                    send({"op": "ready", "status": "ok"})
                elif operation == "reset":
                    stdout, stderr = session.reset(request)
                    send(
                        {
                            "op": "result",
                            "status": "ok",
                            "stdout": stdout,
                            "stderr": stderr,
                        }
                    )
                elif operation == "replay":
                    send(session.replay(request))
                elif operation == "shutdown":
                    session.close()
                    send({"op": "result", "status": "ok"})
                    return 0
            except BaseException as exc:
                send(
                    {
                        "op": "error",
                        "status": "error",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                return 1
    finally:
        session.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
