from __future__ import annotations

import json
import os
import selectors
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any


PROTOCOL_PREFIX = "FRB_WORKER\t"


def _decode_output(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return _decode_output(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


class ReplayWorkerError(RuntimeError):
    """Base class for worker/session failures."""


class ReplayWorkerResetError(ReplayWorkerError):
    """The native worker could not restore its clean state."""


class ReplayWorkerTimeoutError(ReplayWorkerError):
    """The native worker stopped responding during a replay."""


@dataclass
class ReplayResult:
    # Result returned for one replay request

    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    elapsed: float = 0.0
    timed_out: bool = False
    worker_error: str | None = None
    restart_worker: bool = False
    status: str = "ok"
    reached_ids: list[str] | None = None
    triggered_ids: list[str] | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any], elapsed: float) -> "ReplayResult":
        status = str(payload.get("status", "ok"))
        return cls(
            stdout=str(payload.get("stdout", "") or ""),
            stderr=str(payload.get("stderr", "") or ""),
            returncode=payload.get("returncode"),
            elapsed=float(payload.get("elapsed", elapsed) or elapsed),
            timed_out=bool(payload.get("timed_out", False) or status == "timeout"),
            worker_error=payload.get("worker_error") or payload.get("error"),
            restart_worker=bool(payload.get("restart_worker", False)),
            status=status,
            reached_ids=list(payload.get("reached_ids", []) or []),
            triggered_ids=list(payload.get("triggered_ids", []) or []),
        )


def _kill_process_group(proc: subprocess.Popen, pgid: int | None = None) -> None:
    # Terminate a worker and everything it spawned

    try:
        os.killpg(pgid if pgid is not None else os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def _send_protocol(stream, payload: dict[str, Any]) -> None:
    stream.write(
        PROTOCOL_PREFIX
        + json.dumps(payload, separators=(",", ":"), default=_json_default)
        + "\n"
    )
    stream.flush()


def _run_compat_replay(request: dict[str, Any]) -> ReplayResult:

    env = os.environ.copy()
    env.update(request.get("env") or {})
    env["FRB_REPLAY_WORKER"] = "1"
    env["FRB_REPLAY_SEED"] = str(request.get("seed_path", ""))
    env["FRB_REPLAY_RESET"] = "1"

    reset_command = request.get("reset_command")
    if reset_command:
        reset = subprocess.run(
            reset_command,
            shell=True,
            cwd=request.get("cwd") or None,
            env=env,
            text=True,
            capture_output=True,
        )
        if reset.returncode != 0:
            return ReplayResult(
                stdout=reset.stdout or "",
                stderr=reset.stderr or "",
                returncode=reset.returncode,
                status="reset_error",
                worker_error="emulator reset failed",
                restart_worker=True,
            )

    started = time.monotonic()
    proc = subprocess.Popen(
        request["command"],
        shell=isinstance(request["command"], str),
        cwd=request.get("cwd") or None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=request.get("timeout"))
    except subprocess.TimeoutExpired as exc:
        _kill_process_group(proc)
        return ReplayResult(
            stdout=_decode_output(exc.stdout),
            stderr=_decode_output(exc.stderr),
            elapsed=time.monotonic() - started,
            timed_out=True,
            status="timeout",
            restart_worker=True,
        )

    return ReplayResult(
        stdout=_decode_output(stdout),
        stderr=_decode_output(stderr),
        returncode=proc.returncode,
        elapsed=time.monotonic() - started,
        status="ok" if proc.returncode == 0 else "crash",
        restart_worker=proc.returncode is not None and proc.returncode < 0,
    )


def _compat_worker_main() -> int:

    for line in sys.stdin:
        if not line.startswith(PROTOCOL_PREFIX):
            continue
        try:
            request = json.loads(line[len(PROTOCOL_PREFIX) :])
            operation = request.get("op")
            if operation == "start":
                _send_protocol(sys.stdout, {"op": "ready", "status": "ok"})
            elif operation == "reset":
                reset_command = request.get("reset_command")
                if reset_command:
                    result = subprocess.run(
                        reset_command,
                        shell=True,
                        cwd=request.get("cwd") or None,
                        env=os.environ.copy(),
                        text=True,
                        capture_output=True,
                    )
                    if result.returncode:
                        _send_protocol(
                            sys.stdout,
                            {
                                "op": "result",
                                "status": "reset_error",
                                "error": "emulator reset failed",
                                "stdout": result.stdout or "",
                                "stderr": result.stderr or "",
                            },
                        )
                        return 1
                _send_protocol(sys.stdout, {"op": "result", "status": "ok"})
            elif operation == "replay":
                result = _run_compat_replay(request)
                _send_protocol(sys.stdout, {"op": "result", **result.__dict__})
                if result.restart_worker:
                    return 1
            elif operation == "shutdown":
                _send_protocol(sys.stdout, {"op": "result", "status": "ok"})
                return 0
        except BaseException as exc:
            _send_protocol(
                sys.stdout,
                {"op": "error", "error": f"{type(exc).__name__}: {exc}"},
            )
            return 1
    return 0


class _NativeSlot:
    def __init__(
        self,
        slot_id: int,
        command: str | list[str],
        env: dict[str, str] | None,
        startup_timeout: float,
        descriptor_path: str | None,
    ):
        self.slot_id = slot_id
        self.command = command
        self.env = env or {}
        self.startup_timeout = startup_timeout
        self.descriptor_path = descriptor_path
        self.process: subprocess.Popen | None = None
        self._pgid: int | None = None
        self._stderr_file = None
        self.start_count = 0
        self.start()

    @property
    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def _read_response(self, timeout: float) -> dict[str, Any]:
        if not self.process or not self.process.stdout:
            raise ReplayWorkerError(f"replay worker {self.slot_id} has no stdout")
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + max(0.0, timeout)
        try:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("worker response timeout")
                line = self.process.stdout.readline()
                if not line:
                    diagnostics = self._read_stderr()
                    detail = f"; worker stderr: {diagnostics}" if diagnostics else ""
                    raise ReplayWorkerError(
                        f"replay worker {self.slot_id} exited before its response{detail}"
                    )
                if not line.startswith(PROTOCOL_PREFIX):
                    continue
                payload = json.loads(line[len(PROTOCOL_PREFIX) :])
                if payload.get("op") in {"ready", "result", "error"}:
                    return payload
        finally:
            selector.close()

    def _read_stderr(self) -> str:
        if self._stderr_file is None:
            return ""
        try:
            self._stderr_file.seek(0)
            return self._stderr_file.read().strip()
        except (OSError, ValueError):
            return ""

    def _request(self, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        if not self.alive:
            diagnostics = self._read_stderr()
            detail = f"; worker stderr: {diagnostics}" if diagnostics else ""
            returncode = self.process.poll() if self.process is not None else None
            raise ReplayWorkerError(
                f"replay worker {self.slot_id} is not alive"
                f" (returncode={returncode}){detail}"
            )
        assert self.process is not None and self.process.stdin is not None
        _send_protocol(self.process.stdin, payload)
        try:
            response = self._read_response(timeout)
        except TimeoutError as exc:
            self.close(force=True)
            raise ReplayWorkerTimeoutError(
                f"replay worker {self.slot_id} became unresponsive"
            ) from exc
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.close(force=True)
            raise ReplayWorkerError(
                f"invalid response from replay worker {self.slot_id}: {exc}"
            ) from exc
        if response.get("op") == "error":
            self.close(force=True)
            raise ReplayWorkerError(response.get("error", "replay worker failed"))
        return response

    def start(self) -> None:
        self.close(force=True)
        worker_env = os.environ.copy()
        worker_env.update(self.env)
        worker_env.update(
            {
                "FRB_REPLAY_WORKER": "1",
                "FRB_REPLAY_PROTOCOL": "1",
                "FRB_REPLAY_SLOT": str(self.slot_id),
            }
        )
        self._stderr_file = tempfile.TemporaryFile(mode="w+")
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=isinstance(self.command, str),
                env=worker_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._stderr_file,
                text=True,
                start_new_session=True,
                bufsize=1,
            )
        except Exception:
            self._stderr_file.close()
            self._stderr_file = None
            raise
        self._pgid = self.process.pid
        self.start_count += 1
        try:
            response = self._request(
                {
                    "op": "start",
                    "slot_id": self.slot_id,
                    "descriptor_path": self.descriptor_path,
                },
                self.startup_timeout,
            )
            if response.get("status", "ok") not in {"ok", "ready"}:
                raise ReplayWorkerError(response.get("error", "worker start failed"))
        except Exception:
            self.close(force=True)
            raise

    def reset(self, request: dict[str, Any], timeout: float) -> None:
        response = self._request({"op": "reset", **request}, timeout)
        if response.get("status", "ok") not in {"ok", "ready"}:
            self.close(force=True)
            raise ReplayWorkerResetError(
                response.get("error", "native emulator reset failed")
            )

    def replay(self, request: dict[str, Any], timeout: float) -> ReplayResult:
        started = time.monotonic()
        try:
            response = self._request({"op": "replay", **request}, timeout)
        except ReplayWorkerTimeoutError:
            return ReplayResult(
                elapsed=time.monotonic() - started,
                timed_out=True,
                status="timeout",
                restart_worker=True,
            )
        except ReplayWorkerError:
            # A transport/process failure is not a target crash. Let the pool
            # restart the worker and retry this seed once; if recovery also
            # fails, abort triage instead of silently accepting an empty
            # replay result.
            raise
        if response.get("status") not in {None, "ok", "crash", "timeout", "error"}:
            self.close(force=True)
            raise ReplayWorkerError(
                response.get("error", "unknown native replay status")
            )
        result = ReplayResult.from_payload(response, time.monotonic() - started)
        if result.status == "error" and result.returncode not in {None, 0}:
            result.status = "crash"
        if result.status == "error":
            self.close(force=True)
            detail = result.worker_error or "native replay failed"
            if result.stderr:
                detail = f"{detail}; stderr: {result.stderr[-2000:]}"
            raise ReplayWorkerError(detail)
        if result.timed_out or result.restart_worker:
            self.close(force=True)
        return result

    def close(self, force: bool = False) -> None:
        process = self.process
        if process is None:
            return
        if not force and self.alive and process.stdin:
            try:
                _send_protocol(process.stdin, {"op": "shutdown"})
                self._read_response(5)
            except (OSError, ReplayWorkerError, TimeoutError, ValueError):
                pass
        # Kill the recorded process group even if the worker leader already
        # acknowledged shutdown. Native emulators may outlive their parent.
        _kill_process_group(process, self._pgid)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        if self._stderr_file is not None:
            self._stderr_file.close()
        self._stderr_file = None
        self.process = None
        self._pgid = None


def _default_worker_command() -> list[str]:
    return [
        sys.executable,
        "-m",
        "firmrebugger.bug_analyzer_utils.replay_worker",
        "--compat-worker",
    ]


class PersistentReplayPool:
    _RESTART_ATTEMPTS = 3

    def __init__(
        self,
        workers: int,
        descriptor_path: str | None = None,
        reset_command: str | None = None,
        worker_command: str | list[str] | None = None,
        worker_env: dict[str, str] | None = None,
        startup_timeout: float = 30,
    ):
        self._descriptor = _DescriptorResetter(descriptor_path)
        configured = worker_command or os.environ.get("FRB_REPLAY_WORKER_COMMAND")
        if worker_command is None and isinstance(configured, str):
            # Image-provided native commands are simple argv strings. Avoid a
            # permanently resident shell wrapper around every emulator.
            configured = shlex.split(configured)
        self._worker_command = configured or _default_worker_command()
        self._worker_env = worker_env or {}
        self._reset_command = reset_command or os.environ.get(
            "FRB_REPLAY_RESET_COMMAND"
        )
        self._slots = []
        for slot_id in range(max(1, workers)):
            last_error = None
            for attempt in range(self._RESTART_ATTEMPTS):
                try:
                    self._slots.append(
                        _NativeSlot(
                            slot_id,
                            self._worker_command,
                            self._worker_env,
                            startup_timeout,
                            self._descriptor.path,
                        )
                    )
                    break
                except Exception as exc:
                    last_error = exc
                    if attempt + 1 < self._RESTART_ATTEMPTS:
                        time.sleep(0.1 * (attempt + 1))
            else:
                for slot in self._slots:
                    slot.close(force=True)
                raise last_error
        self._condition = threading.Condition()
        self._idle = list(self._slots)
        self._closed = False

    def _restart_slot(self, slot: _NativeSlot) -> None:
        last_error = None
        for attempt in range(self._RESTART_ATTEMPTS):
            try:
                slot.start()
                return
            except Exception as exc:
                last_error = exc
                if attempt + 1 < self._RESTART_ATTEMPTS:
                    time.sleep(0.1 * (attempt + 1))
        if last_error is not None:
            raise last_error

    @property
    def start_count(self) -> int:
        return sum(slot.start_count for slot in self._slots)

    def _acquire(self) -> _NativeSlot:
        with self._condition:
            while not self._idle:
                if self._closed:
                    raise ReplayWorkerError("replay pool is closed")
                self._condition.wait()
            return self._idle.pop()

    def _release(self, slot: _NativeSlot) -> None:
        with self._condition:
            if not self._closed:
                self._idle.append(slot)
            self._condition.notify_all()

    def replay(
        self,
        command,
        seed_path: str,
        timeout: float = 10,
        *,
        env: dict | None = None,
        cwd: str | None = None,
        mode: str = "queue",
        timing: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> ReplayResult:
        slot = self._acquire()
        request_started = time.monotonic()
        recovery_attempted = False
        try:
            while True:
                try:
                    self._descriptor.reset()
                    slot.reset(
                        {
                            "seed_path": seed_path,
                            "descriptor_path": self._descriptor.path,
                            "reset_command": self._reset_command,
                            "cwd": cwd,
                            "env": env or {},
                            "mode": mode,
                            "timing": timing,
                            "metadata": metadata or {},
                        },
                        min(30.0, max(1.0, timeout)),
                    )
                    result = slot.replay(
                        {
                            "seed_path": seed_path,
                            "mode": mode,
                            "timing": timing,
                            "metadata": metadata or {},
                            "command": command,
                            "env": env or {},
                            "cwd": cwd,
                            "timeout": timeout,
                        },
                        timeout + 2,
                    )
                    # Worker payloads may expose emulator-only timing. Report
                    # the complete per-seed cost, including descriptor restore,
                    # TinyCC reset/recompile, snapshot/fork reset, and replay.
                    result.elapsed = time.monotonic() - request_started
                    return result
                except ReplayWorkerResetError:
                    # A native reset failure is a failed replay request. The
                    # worker is still discarded and restarted by the outer
                    # handler, but this seed is not silently replayed.
                    raise
                except ReplayWorkerError:
                    # A worker can die between two requests. Recover that
                    # slot and retry the current seed once so one native crash
                    # does not abort an entire triage run.
                    if recovery_attempted:
                        raise
                    recovery_attempted = True
                    slot.close(force=True)
                    self._restart_slot(slot)
        except ReplayWorkerResetError:
            slot.close(force=True)
            self._restart_slot(slot)
            raise
        except ReplayWorkerError:
            slot.close(force=True)
            self._restart_slot(slot)
            raise
        finally:
            if not slot.alive and not self._closed:
                self._restart_slot(slot)
            self._release(slot)

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
        for slot in self._slots:
            slot.close()
        with self._condition:
            self._condition.notify_all()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


class _DescriptorResetter:
    def __init__(self, path: str | None):
        self.path = os.path.abspath(path) if path else None
        self._lock = threading.Lock()
        self._contents = None
        self._mode = None
        if self.path:
            with open(self.path, "rb") as descriptor:
                self._contents = descriptor.read()
            self._mode = os.stat(self.path).st_mode & 0o777

    def reset(self) -> None:
        if not self.path:
            return

        # Native replays mutate descriptor *runtime* state, not the source
        # file. Avoid serializing every worker on an atomic write + fsync when
        # the canonical source is already present. The locked path below is
        # retained for recovery if a backend or external process did change
        # the file.
        try:
            with open(self.path, "rb") as descriptor:
                if descriptor.read() == self._contents:
                    return
        except FileNotFoundError:
            pass

        with self._lock:
            # Another replay may already have repaired it while this caller
            # was waiting for the recovery lock.
            try:
                with open(self.path, "rb") as descriptor:
                    if descriptor.read() == self._contents:
                        return
            except FileNotFoundError:
                pass

            directory = os.path.dirname(self.path) or "."
            fd, temporary = tempfile.mkstemp(prefix=".frb-descriptor-", dir=directory)
            try:
                with os.fdopen(fd, "wb") as descriptor:
                    descriptor.write(self._contents)
                    descriptor.flush()
                    os.fsync(descriptor.fileno())
                os.chmod(temporary, self._mode)
                os.replace(temporary, self.path)
            except Exception:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                raise


def replay_as_tuple(
    pool,
    command,
    seed_path,
    time_val,
    crash,
    timeout=10,
    *,
    env=None,
    cwd=None,
    metadata=None,
):

    from firmrebugger.bug_analyzer_utils.common import parse_replay_output

    result = pool.replay(
        command,
        seed_path,
        timeout,
        env=env,
        cwd=cwd,
        mode="crash" if crash else "queue",
        timing=time_val,
        metadata=metadata,
    )
    if result.timed_out:
        print(
            f"[replay_worker] Timeout ({timeout}s) exceeded for seed: {seed_path} — skipping."
        )
        return seed_path, [], [], time_val, result.elapsed, []
    return parse_replay_output(
        seed_path,
        result.stdout,
        result.stderr,
        time_val,
        result.elapsed,
        crash,
        result.returncode,
        result.reached_ids,
        result.triggered_ids,
    )


if __name__ == "__main__" and "--compat-worker" in sys.argv:
    raise SystemExit(_compat_worker_main())
