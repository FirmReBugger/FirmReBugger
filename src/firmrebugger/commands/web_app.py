import os
import time
import json
from pathlib import Path
from flask import (
    Flask,
    jsonify,
    request,
    send_from_directory,
    Response,
    stream_with_context,
)
from flask_cors import CORS
from firmrebugger.common import get_frb_base_dir
from firmrebugger.app_utils import (
    check_binaries,
    check_binaries_with_support,
    check_fuzzers,
    check_output_name,
    cpu_usage,
    all_cpu_usage,
    get_reports,
    get_table_json,
)
from firmrebugger.manager import start_manager, Job, JobManager, list_finished_jobs
import threading


STATIC_FOLDER = ""
app = Flask(__name__, static_folder=STATIC_FOLDER, static_url_path="/static")
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        }
    },
)

FIRMREBUGGER_BASE_DIR = ""
job_manager = None
jobs_snapshot = {
    "version": 0,
    "jobs": [],
    "count": 0,
    "updated_at": 0,
    "fingerprint": "",
}
jobs_snapshot_lock = threading.Lock()


def serialize_jobs(jobs_list):
    jobs_data = []
    for job in jobs_list:
        full_output_dir = os.path.join(
            get_frb_base_dir(),
            job.benchmark,
            job.binary,
            "fuzzers",
            job.fuzzer,
            "fuzzing_out",
            job.output_dir,
        )

        report_path = os.path.join(full_output_dir, "frb_report.json")
        has_been_triaged = os.path.exists(report_path)

        jobs_data.append(
            {
                "id": job.job_id,
                "mode": job.mode,
                "benchmark": getattr(job, "benchmark", "FirmBench"),
                "fuzzer": job.fuzzer,
                "binary": job.binary,
                "runs": job.runs,
                "completedRuns": job.get_completed_runs(),
                "time": job.duration,
                "status": job.status,
                "progress": job.progress,
                "createdAt": job.created_at,
                "startedAt": job.started_at,
                "elapsedTime": job.elapsed_time,
                "output_dir": job.output_dir,
                "output_path": full_output_dir,
                "autoQueueTriaging": bool(
                    getattr(job, "auto_queue_triaging", True)
                ),
                "triaged": has_been_triaged,
            }
        )

    return jobs_data


def refresh_jobs_snapshot(force=False):
    global jobs_snapshot

    if not job_manager:
        return

    jobs_list = job_manager.get_current_jobs()
    jobs_data = serialize_jobs(jobs_list)
    fingerprint = json.dumps(jobs_data, sort_keys=True, separators=(",", ":"))

    with jobs_snapshot_lock:
        has_changed = force or (fingerprint != jobs_snapshot.get("fingerprint", ""))
        if has_changed:
            jobs_snapshot["version"] = jobs_snapshot.get("version", 0) + 1
            jobs_snapshot["jobs"] = jobs_data
            jobs_snapshot["count"] = len(jobs_data)
            jobs_snapshot["updated_at"] = time.time()
            jobs_snapshot["fingerprint"] = fingerprint


def get_jobs_snapshot():
    with jobs_snapshot_lock:
        return {
            "version": jobs_snapshot["version"],
            "jobs": list(jobs_snapshot["jobs"]),
            "count": jobs_snapshot["count"],
            "updated_at": jobs_snapshot["updated_at"],
        }


def jobs_snapshot_worker():
    while True:
        try:
            if job_manager:
                refresh_jobs_snapshot()
        except Exception as e:
            print(f"[Snapshot] Error refreshing jobs snapshot: {e}")
        time.sleep(1)


def task_to_dict(task):
    cpu_percent = None
    core_idx_value = getattr(task, "core_idx", None)

    if core_idx_value is not None and task.status == "running":
        try:
            if isinstance(core_idx_value, list):
                cpu_percent = [cpu_usage(idx) for idx in core_idx_value]
            else:
                cpu_percent = cpu_usage(core_idx_value)
        except Exception as e:
            print(f"Error getting CPU usage for core {core_idx_value}: {e}")
            cpu_percent = None

    return {
        "task_id": task.task_id,
        "job_id": task.job_id,
        "fuzzer": task.fuzzer,
        "duration": task.duration,
        "binary": task.binary,
        "run_number": task.run_number,
        "mode": task.mode,
        "benchmark": task.benchmark,
        "status": task.status,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "completed_at": task.completed_at,
        "output_dir": task.output_dir,
        "runs": task.runs,
        "core_idx": core_idx_value,
        "container_name": getattr(task, "container_name", None),
        "cpu_usage": cpu_percent,
    }


@app.route("/api/fuzzers/list")
def list_fuzzers_folder():
    try:
        docker_path = Path(FIRMREBUGGER_BASE_DIR) / "docker"

        if not docker_path.exists():
            return jsonify(
                {"error": "Docker directory not found", "path": str(docker_path)}
            ), 404

        if not docker_path.is_dir():
            return jsonify(
                {"error": "Path is not a directory", "path": str(docker_path)}
            ), 400

        items = []
        for item in sorted(docker_path.iterdir()):
            items.append(
                {
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "path": str(item.relative_to(FIRMREBUGGER_BASE_DIR)),
                }
            )

        return jsonify(
            {
                "base_dir": FIRMREBUGGER_BASE_DIR,
                "path": "docker",
                "items": items,
                "count": len(items),
            }
        )

    except PermissionError:
        return jsonify({"error": "Permission denied", "path": str(docker_path)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/table/generate", methods=["POST"])
def generate_table():
    try:
        data = request.json

        if not data:
            return jsonify({"error": "No data provided"}), 400

        report_paths = data.get("report_paths", [])
        if not report_paths:
            return jsonify({"error": "No report paths provided"}), 400

        table_data = get_table_json(report_paths)

        if not table_data:
            return jsonify({"error": "No bug data to visualize"}), 400

        response = {
            "table_data": table_data,
        }

        return jsonify(response), 200

    except Exception as e:
        print(f"Error in generate_table: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/jobs/add", methods=["POST"])
def add_job():
    """Add jobs to the job manager"""
    try:
        global job_manager
        data = request.json

        if not data:
            return jsonify({"error": "No data provided"}), 400

        jobs_data = data.get("jobs", [])

        if not jobs_data:
            return jsonify({"error": "At least one job is required"}), 400

        job_ids = []
        for job_data in jobs_data:
            job_id = job_data["job_id"]
            fuzzer = job_data["fuzzer"]
            benchmark = job_data["benchmark"]
            duration = int(job_data["duration"])
            binary = job_data["binary"]
            runs = int(job_data["runs"])
            mode = job_data["mode"]
            output_dir = job_data.get("output_dir", "")
            auto_queue_triaging = job_data.get("autoQueueTriaging", True)

            if runs < 1:
                return jsonify(
                    {"error": f"Invalid runs value for job {job_id}: must be >= 1"}
                ), 400
            if duration < 0:
                return jsonify(
                    {"error": f"Invalid duration value for job {job_id}: must be >= 0"}
                ), 400

            try:
                job = Job(
                    job_id=job_id,
                    fuzzer=fuzzer,
                    duration=duration,
                    binary=binary,
                    runs=runs,
                    mode=mode,
                    benchmark=benchmark,
                    progress=0,
                    output_dir=output_dir,
                    auto_queue_triaging=auto_queue_triaging,
                )
                job_manager.add_job(job)
                job_ids.append(job_id)
                print(f"Successfully added job {job_id}")
            except Exception as e:
                print(f"ERROR adding job: {e}")
                raise

        refresh_jobs_snapshot(force=True)

        return jsonify(
            {
                "success": True,
                "jobs_added": len(job_ids),
                "job_ids": job_ids,
                "message": f"Added {len(job_ids)} job(s)",
            }
        ), 201

    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/jobs/list", methods=["GET"])
def get_jobs():
    """Get all current jobs from the job manager"""
    try:
        global job_manager

        if not job_manager:
            return jsonify({"jobs": [], "count": 0})

        snapshot = get_jobs_snapshot()
        if snapshot["count"] == 0 and job_manager is not None:
            refresh_jobs_snapshot(force=True)
            snapshot = get_jobs_snapshot()

        return jsonify(
            {
                "jobs": snapshot["jobs"],
                "count": snapshot["count"],
                "version": snapshot["version"],
                "updatedAt": snapshot["updated_at"],
            }
        )

    except Exception as e:
        return jsonify({"error": str(e), "jobs": [], "count": 0}), 500


@app.route("/api/jobs/stop", methods=["POST"])
def stop_job():
    """Stop a specific job"""
    try:
        global job_manager

        if not job_manager:
            return jsonify(
                {"error": "Job manager not initialized", "success": False}
            ), 500

        data = request.json
        job_id = data.get("job_id", None)

        if not job_id:
            return jsonify({"error": "job_id is required", "success": False}), 400

        job = job_manager.get_job(job_id)
        if not job:
            return (
                jsonify({"error": f"Job {job_id} not found", "success": False}),
                404,
            )

        for task in job.tasks:
            if task.status == "running":
                task.status = "stopping"

        refresh_jobs_snapshot(force=True)
        job_manager.stop_job(job_id)
        refresh_jobs_snapshot(force=True)

        return jsonify(
            {
                "success": True,
                "message": f"Job {job_id} stop requested",
                "job_id": job_id,
            }
        )

    except Exception as e:
        print(f"ERROR in stop_job: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/jobs/auto-triage", methods=["POST"])
def set_job_auto_triage():
    """Enable/disable auto-triaging for a specific fuzzing job."""
    try:
        global job_manager

        if not job_manager:
            return jsonify(
                {"error": "Job manager not initialized", "success": False}
            ), 500

        data = request.json or {}
        job_id = data.get("job_id")
        enabled = data.get("enabled")

        if not job_id:
            return jsonify({"error": "job_id is required", "success": False}), 400
        if not isinstance(enabled, bool):
            return jsonify(
                {"error": "enabled must be a boolean", "success": False}
            ), 400

        job = job_manager.get_job(job_id)
        if not job:
            return jsonify(
                {"error": f"Job {job_id} not found", "success": False}
            ), 404

        if job.mode != "Fuzzing":
            return jsonify(
                {
                    "error": "Auto-triage setting can only be changed for Fuzzing jobs",
                    "success": False,
                }
            ), 400

        job.auto_queue_triaging = enabled
        refresh_jobs_snapshot(force=True)

        return jsonify(
            {
                "success": True,
                "job_id": job_id,
                "autoQueueTriaging": enabled,
            }
        )

    except Exception as e:
        print(f"ERROR in set_job_auto_triage: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/jobs/reorder", methods=["POST"])
def reorder_jobs():
    """Move a queued job up one position in the queue"""
    try:
        global job_manager

        if not job_manager:
            return jsonify(
                {"error": "Job manager not initialized", "success": False}
            ), 500

        data = request.json
        job_id = data.get("job_id", None)

        if not job_id:
            return jsonify({"error": "job_id is required", "success": False}), 400

        job_manager.reorder_job(job_id)
        refresh_jobs_snapshot(force=True)

        return jsonify(
            {
                "success": True,
                "message": f"Job {job_id} moved up one position",
                "job_id": job_id,
            }
        )

    except Exception as e:
        print(f"ERROR in reorder_jobs: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/jobs/reorder-top", methods=["POST"])
def reorder_jobs_to_top():
    """Move a queued job to the top of the queue"""
    try:
        global job_manager

        if not job_manager:
            return jsonify(
                {"error": "Job manager not initialized", "success": False}
            ), 500

        data = request.json
        job_id = data.get("job_id", None)

        if not job_id:
            return jsonify({"error": "job_id is required", "success": False}), 400

        job_manager.reorder_job_to_top(job_id)
        refresh_jobs_snapshot(force=True)

        return jsonify(
            {
                "success": True,
                "message": f"Job {job_id} moved to top of queue",
                "job_id": job_id,
            }
        )

    except Exception as e:
        print(f"ERROR in reorder_jobs_to_top: {e}")
        return jsonify({"error": str(e), "success": False}), 500


@app.route("/api/jobs/delete", methods=["POST"])
def delete_job():
    """Delete a completed or stopped job"""
    try:
        global job_manager

        if not job_manager:
            return jsonify(
                {"error": "Job manager not initialized", "success": False}
            ), 500

        data = request.json
        job_id = data.get("job_id", None)

        if not job_id:
            return jsonify({"error": "job_id is required", "success": False}), 400

        job_manager.delete_job(job_id)
        refresh_jobs_snapshot(force=True)

        return jsonify(
            {"success": True, "message": f"Job {job_id} deleted", "job_id": job_id}
        )

    except Exception as e:
        print(f"ERROR in delete_job: {e}")
        return jsonify({"error": str(e), "success": False}), 500


# for a job get the task details
@app.route("/api/tasks/list", methods=["GET"])
def get_task_details():
    """Get all task details for a specific job or all jobs"""
    try:
        global job_manager

        if not job_manager:
            return jsonify({"tasks": [], "count": 0})

        job_id = request.args.get("job_id", None)

        all_tasks = []
        if job_id:
            job = job_manager.get_job(job_id)
            if job and hasattr(job, "tasks"):
                for task in job.tasks:
                    all_tasks.append(task_to_dict(task))
        else:
            jobs_list = job_manager.get_current_jobs()
            for job in jobs_list:
                if hasattr(job, "tasks"):
                    for task in job.tasks:
                        all_tasks.append(task_to_dict(task))

        return jsonify({"tasks": all_tasks, "count": len(all_tasks), "job_id": job_id})

    except Exception as e:
        print(f"ERROR in get_task_details: {e}")
        return jsonify({"error": str(e), "tasks": [], "count": 0}), 500


@app.route("/api/tasks/logs", methods=["GET"])
def get_task_logs():
    """Get logs for a specific task"""
    try:
        global job_manager

        task_id = request.args.get("task_id", None)

        if not task_id:
            return jsonify({"error": "task_id is required"}), 400

        if not job_manager:
            return jsonify({"error": "Job manager not initialized"}), 500

        task_found = job_manager.find_task(task_id)

        if not task_found:
            return jsonify({"error": f"Task {task_id} not found"}), 404

        if task_found.mode == "Triaging":
            log_filename = "triage.log"
        else:
            log_filename = f"log-{task_found.run_number}.log"

        normalized_output_dir = task_found.output_dir or ""
        if os.path.isabs(normalized_output_dir):
            marker = f"{os.sep}fuzzing_out{os.sep}"
            if marker in normalized_output_dir:
                normalized_output_dir = normalized_output_dir.split(marker, 1)[1].strip(
                    os.sep
                )
            else:
                normalized_output_dir = os.path.basename(
                    normalized_output_dir.rstrip(os.sep)
                )

        log_path = os.path.join(
            FIRMREBUGGER_BASE_DIR,
            task_found.benchmark,
            task_found.binary,
            "fuzzers",
            task_found.fuzzer,
            "fuzzing_out",
            normalized_output_dir,
            "fuzzing_logs",
            log_filename,
        )

        if not os.path.exists(log_path):
            return jsonify(
                {
                    "error": f"Log file not found: {log_path}",
                    "content": "",
                    "exists": False,
                }
            ), 404

        try:
            with open(log_path, "r") as f:
                log_content = f.read()

            return jsonify(
                {
                    "content": log_content,
                    "path": log_path,
                    "exists": True,
                    "task_id": task_id,
                    "run_number": task_found.run_number,
                }
            )

        except Exception as e:
            return jsonify(
                {
                    "error": f"Error reading log file: {str(e)}",
                    "content": "",
                    "exists": True,
                }
            ), 500

    except Exception as e:
        print(f"ERROR in get_task_logs: {e}")
        return jsonify({"error": str(e), "content": ""}), 500


@app.route("/api/jobs/triage-log", methods=["GET"])
def get_triage_log_by_job():
    """Get triage.log by job coordinates even if triaging task is no longer active."""
    try:
        benchmark = request.args.get("benchmark", None)
        binary = request.args.get("binary", None)
        fuzzer = request.args.get("fuzzer", None)
        output_dir = request.args.get("output_dir", None)

        if not benchmark or not binary or not fuzzer or not output_dir:
            return jsonify(
                {
                    "error": "benchmark, binary, fuzzer, and output_dir are required",
                    "content": "",
                }
            ), 400

        normalized_output_dir = output_dir
        if os.path.isabs(normalized_output_dir):
            marker = f"{os.sep}fuzzing_out{os.sep}"
            if marker in normalized_output_dir:
                normalized_output_dir = normalized_output_dir.split(marker, 1)[1].strip(
                    os.sep
                )
            else:
                normalized_output_dir = os.path.basename(
                    normalized_output_dir.rstrip(os.sep)
                )

        log_path = os.path.join(
            FIRMREBUGGER_BASE_DIR,
            benchmark,
            binary,
            "fuzzers",
            fuzzer,
            "fuzzing_out",
            normalized_output_dir,
            "fuzzing_logs",
            "triage.log",
        )

        if not os.path.exists(log_path):
            return jsonify(
                {
                    "error": f"Triage log file not found: {log_path}",
                    "content": "",
                    "exists": False,
                }
            ), 404

        with open(log_path, "r") as f:
            log_content = f.read()

        return jsonify(
            {
                "content": log_content,
                "path": log_path,
                "exists": True,
                "benchmark": benchmark,
                "binary": binary,
                "fuzzer": fuzzer,
                "output_dir": normalized_output_dir,
            }
        )

    except Exception as e:
        print(f"ERROR in get_triage_log_by_job: {e}")
        return jsonify({"error": str(e), "content": ""}), 500


@app.route("/api/check_fuzzers", methods=["GET"])
def check_fuzzers_endpoint():
    """Get valid fuzzers for a given benchmark"""
    try:
        benchmark = request.args.get("benchmark", "FirmBench")
        valid_fuzzers = check_fuzzers(benchmark)

        return jsonify({"valid_fuzzers": valid_fuzzers, "benchmark": benchmark})

    except Exception as e:
        print(f"ERROR in check_fuzzers: {e}")
        return jsonify({"error": str(e), "valid_fuzzers": []}), 500


@app.route("/api/jobs/stream", methods=["GET"])
def stream_jobs():
    """Stream job manager updates via Server-Sent Events."""

    def event_stream():
        last_version = -1
        while True:
            try:
                snapshot = get_jobs_snapshot()
                if snapshot["version"] != last_version:
                    payload = {
                        "jobs": snapshot["jobs"],
                        "count": snapshot["count"],
                        "version": snapshot["version"],
                        "updatedAt": snapshot["updated_at"],
                    }
                    yield f"event: jobs\ndata: {json.dumps(payload)}\n\n"
                    last_version = snapshot["version"]
                else:
                    yield "event: ping\ndata: {}\n\n"
                time.sleep(1)
            except GeneratorExit:
                break
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                time.sleep(1)

    response = Response(
        stream_with_context(event_stream()), mimetype="text/event-stream"
    )
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Connection"] = "keep-alive"
    response.headers["X-Accel-Buffering"] = "no"
    return response


@app.route("/api/check_binaries", methods=["POST"])
def check_binaries_endpoint():
    """Get valid binaries for a given benchmark and fuzzers"""
    try:
        data = request.json
        benchmark = data.get("benchmark", "FirmBench")
        fuzzers = data.get("fuzzers", [])

        valid_binaries = check_binaries(benchmark, fuzzers)
        binary_support = check_binaries_with_support(benchmark, fuzzers)

        return jsonify(
            {
                "valid_binaries": valid_binaries,
                "binary_support": binary_support,
                "benchmark": benchmark,
                "fuzzers": fuzzers,
            }
        )

    except Exception as e:
        print(f"ERROR in check_binaries: {e}")
        return jsonify({"error": str(e), "valid_binaries": []}), 500


@app.route("/api/get_reports", methods=["POST"])
def get_reports_endpoint():
    try:
        data = request.json
        benchmark = data.get("benchmark", "FirmBench")
        fuzzers = data.get("fuzzers", [])

        valid_reports = get_reports(benchmark, fuzzers)
        report_durations = {}

        for report_path in valid_reports:
            try:
                with open(report_path, "r") as f:
                    report_json = json.load(f)
                report_durations[report_path] = report_json.get("Trial-Time", None)
            except Exception:
                report_durations[report_path] = None

        return jsonify(
            {
                "valid_reports": valid_reports,
                "report_durations": report_durations,
                "benchmark": benchmark,
                "fuzzers": fuzzers,
            }
        )

    except Exception as e:
        print(f"ERROR in get_reports: {e}")
        return jsonify({"error": str(e), "valid_reports": []}), 500


@app.route("/api/check_output_name", methods=["POST"])
def check_output_name_endpoint():
    """Check if output name already exists"""
    try:
        data = request.json
        benchmark = data.get("benchmark", "FirmBench")
        binary_name = data.get("binary_name", "")
        fuzzers_selected = data.get("fuzzers_selected", [])
        output_name = data.get("output_name", "")

        is_valid = check_output_name(
            benchmark, binary_name, fuzzers_selected, output_name
        )

        return jsonify({"is_valid": is_valid, "exists": not is_valid})

    except Exception as e:
        print(f"ERROR in check_output_name: {e}")
        return jsonify({"error": str(e), "is_valid": False}), 500


@app.route("/api/system/cpu", methods=["GET"])
def get_system_cpu():
    """Get CPU usage for all cores"""
    try:
        cpu_usage_list = all_cpu_usage()

        return jsonify({"cpu_usage": cpu_usage_list, "core_count": len(cpu_usage_list)})

    except Exception as e:
        print(f"ERROR in get_system_cpu: {e}")
        return jsonify({"error": str(e), "cpu_usage": [], "core_count": 0}), 500


@app.route("/api/system/cpu/stream", methods=["GET"])
def stream_system_cpu():
    """Stream CPU usage updates via Server-Sent Events."""

    def event_stream():
        while True:
            try:
                cpu_usage_list = all_cpu_usage()
                payload = {
                    "cpu_usage": cpu_usage_list,
                    "core_count": len(cpu_usage_list),
                    "updatedAt": time.time(),
                }
                yield f"event: cpu\ndata: {json.dumps(payload)}\n\n"
                time.sleep(2)
            except GeneratorExit:
                break
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                time.sleep(2)

    response = Response(
        stream_with_context(event_stream()), mimetype="text/event-stream"
    )
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Connection"] = "keep-alive"
    response.headers["X-Accel-Buffering"] = "no"
    return response


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react_app(path):
    """Serve the React application"""
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        # Serve the requested static file
        return send_from_directory(app.static_folder, path)
    else:
        # Serve index.html for all other routes (SPA routing)
        return send_from_directory(app.static_folder, "index.html")


def run_flask(port=5000):
    app.run(debug=False, port=port, host="0.0.0.0")


def run_app(port):
    global FIRMREBUGGER_BASE_DIR, STATIC_FOLDER, app, job_manager

    FIRMREBUGGER_BASE_DIR = get_frb_base_dir()
    STATIC_FOLDER = f"{FIRMREBUGGER_BASE_DIR}/src/firmrebugger-web/dist"

    app.static_folder = STATIC_FOLDER

    job_manager = JobManager()

    print("[Startup] Loading finished jobs from disk...")
    try:
        finished_jobs = list_finished_jobs()
        for job in finished_jobs:
            job_manager.add_job(job)
        print(f"[Startup] Loaded {len(finished_jobs)} finished jobs")
    except Exception as e:
        print(f"[Startup] Error loading finished jobs: {e}")

    refresh_jobs_snapshot(force=True)

    snapshot_thread = threading.Thread(target=jobs_snapshot_worker, daemon=True)
    snapshot_thread.start()

    flask_thread = threading.Thread(target=run_flask, args=(port,))
    flask_thread.start()

    start_manager(job_manager)
