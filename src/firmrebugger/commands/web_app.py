import json
import base64
import io
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pandas as pd

from flask import (
    Flask,
    Response,
    jsonify,
    request,
    send_from_directory,
    stream_with_context,
)
from flask_cors import CORS

from firmrebugger.app_utils import (
    all_cpu_usage,
    check_binaries,
    check_binaries_with_support,
    check_fuzzers,
    check_run_name_available,
    cpu_usage,
    get_benchmark_binaries,
    get_binary_bug_ids,
    get_reports,
    get_table_json,
)
from firmrebugger.charting_tool_utils.generate_latex_tables import (
    escape_latex,
    reshape_and_convert_to_latex,
)
from firmrebugger.charting_tool_utils.generate_upset_plot import upset_plot
from firmrebugger.charting_tool_utils.summarize_data import summarize_data
from firmrebugger.commands.bug_registry import (
    _ID_RE,
    _parse_detail_file,
    _scan_bug_descriptor_ids,
)
from firmrebugger.common import get_binary_dir, get_frb_base_dir, get_run_output_dir
from firmrebugger.manager import Job, JobManager, list_finished_jobs, start_manager

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

# The coverage-summary route is hit every few seconds per job and would
# otherwise flood the werkzeug access log with routine 200s.
class _SuppressCoveragePollLogs(logging.Filter):
    def filter(self, record):
        return "/coverage-summary" not in record.getMessage()


logging.getLogger("werkzeug").addFilter(_SuppressCoveragePollLogs())

FIRMREBUGGER_BASE_DIR = ""
APP_PORT = 5000
job_manager = None
jobs_snapshot = {
    "version": 0,
    "jobs": [],
    "count": 0,
    "updated_at": 0,
    "fingerprint": "",
}
jobs_snapshot_lock = threading.Lock()
# Set whenever job state mutates so the snapshot worker wakes immediately
# instead of waiting for the next 1-second tick.
_jobs_dirty = threading.Event()

DEFAULT_LOG_CHUNK_BYTES = 256 * 1024
MAX_LOG_CHUNK_BYTES = 2 * 1024 * 1024


def _parse_int_query_arg(name, default=None, minimum=None, maximum=None):
    raw = request.args.get(name, None)
    if raw is None or raw == "":
        return default

    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")

    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")

    return value


def _read_log_chunk(log_path, before_offset=None, chunk_bytes=None):
    file_size = os.path.getsize(log_path)

    if chunk_bytes is None:
        chunk_bytes = DEFAULT_LOG_CHUNK_BYTES
    chunk_bytes = max(1, min(chunk_bytes, MAX_LOG_CHUNK_BYTES))

    if before_offset is None:
        end_offset = file_size
    else:
        end_offset = max(0, min(before_offset, file_size))

    start_offset = max(0, end_offset - chunk_bytes)

    with open(log_path, "rb") as f:
        f.seek(start_offset)
        raw = f.read(end_offset - start_offset)

    return {
        "content": raw.decode("utf-8", errors="replace"),
        "file_size": file_size,
        "start_offset": start_offset,
        "end_offset": end_offset,
        "has_more_before": start_offset > 0,
    }


def serialize_jobs(jobs_list):
    jobs_data = []
    for job in jobs_list:
        full_output_dir = get_run_output_dir(
            get_frb_base_dir(), job.run_name, job.benchmark, job.binary, job.fuzzer
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
                "run_name": job.run_name,
                "run_path": full_output_dir,
                "autoQueueTriaging": bool(getattr(job, "auto_queue_triaging", True)),
                "triaged": has_been_triaged,
            }
        )

    return jobs_data


def notify_jobs_changed():
    """Signal the snapshot worker that something has changed."""
    _jobs_dirty.set()


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
        # Block until something signals a change, or at most 2 seconds so
        # progress updates from the manager loop still flow through.
        _jobs_dirty.wait(timeout=2)
        _jobs_dirty.clear()
        try:
            if job_manager:
                refresh_jobs_snapshot()
        except Exception as e:
            print(f"[Snapshot] Error refreshing jobs snapshot: {e}")


def _load_combined_reports_dataframe(report_paths):
    report_dfs = []
    for report_path in report_paths:
        report_dfs.append(summarize_data(report_path))

    if not report_dfs:
        return None

    return report_dfs[0] if len(report_dfs) == 1 else pd.concat(report_dfs, ignore_index=True)


def _collect_unique_fuzzers(combined_df):
    return [
        fuzzer
        for fuzzer in combined_df["Fuzzer"].drop_duplicates()
        if isinstance(fuzzer, str) and fuzzer
    ]


def _add_missing_binary_rows(combined_df, benchmark, selected_binaries):
    """Add bug rows for selected binaries that have no report at all.

    The empty fuzzer value deliberately does not match any expected fuzzer,
    causing the LaTeX renderer to emit grey N/A cells for the whole binary.
    """
    selected_binaries = list(dict.fromkeys(selected_binaries or []))
    if not selected_binaries:
        return combined_df

    existing_binaries = set()
    if combined_df is not None and not combined_df.empty and "Binary" in combined_df:
        existing_binaries = set(combined_df["Binary"].dropna())

    rows = []
    for binary in selected_binaries:
        if binary in existing_binaries:
            continue
        for bug_id in get_binary_bug_ids(benchmark, binary):
            rows.append(
                {
                    "Binary": binary,
                    "Fuzzer": "",
                    "BugID": bug_id,
                    "NumRuns": None,
                    "MedianReachedTime": None,
                    "MedianTriggeredTime": None,
                    "MedianDetectedTime": None,
                    "ReachedCount": None,
                    "TriggeredCount": None,
                    "DetectedCount": None,
                }
            )

    if not rows:
        return combined_df

    placeholder_df = pd.DataFrame(rows)
    if combined_df is None or combined_df.empty:
        return placeholder_df
    return pd.concat([combined_df, placeholder_df], ignore_index=True, sort=False)


def _render_latex_table_to_pdf_bytes(table_code):
    latex_code = rf"""
\documentclass{{article}}
\usepackage{{graphicx}}
\usepackage[table,xcdraw]{{xcolor}}
\usepackage[a4paper,margin=0.5in,landscape]{{geometry}}
\pagestyle{{empty}}
\usepackage{{pdflscape}}
\newcommand{{\missing}}{{\makebox[2em][c]{{--}}}}
\begin{{document}}
    {table_code}
\end{{document}}
"""

    with tempfile.TemporaryDirectory(prefix="frb-latex-") as tmpdir:
        tex_path = os.path.join(tmpdir, "table.tex")
        pdf_path = os.path.join(tmpdir, "table.pdf")

        with open(tex_path, "w") as f:
            f.write(latex_code)

        result = subprocess.run(
            [
                "pdflatex",
                "-interaction=nonstopmode",
                "-halt-on-error",
                "-output-directory",
                tmpdir,
                tex_path,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0 or not os.path.exists(pdf_path):
            output_tail = "\n".join((result.stdout or "").splitlines()[-30:])
            err_tail = "\n".join((result.stderr or "").splitlines()[-30:])
            raise RuntimeError(
                "Failed to render LaTeX table to PDF. "
                f"stdout:\n{output_tail}\n\nstderr:\n{err_tail}"
            )

        with open(pdf_path, "rb") as f:
            return f.read()


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
        "run_name": task.run_name,
        "runs": task.runs,
        "core_idx": core_idx_value,
        "container_name": getattr(task, "container_name", None),
        "cpu_usage": cpu_percent,
    }


@app.route("/api/fuzzers/list")
def list_fuzzers_folder():
    try:
        fuzzers_path = Path(FIRMREBUGGER_BASE_DIR) / "Fuzzers"

        if not fuzzers_path.exists():
            return jsonify(
                {"error": "Fuzzers directory not found", "path": str(fuzzers_path)}
            ), 404

        if not fuzzers_path.is_dir():
            return jsonify(
                {"error": "Path is not a directory", "path": str(fuzzers_path)}
            ), 400

        items = []
        for item in sorted(fuzzers_path.iterdir()):
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
                "path": "Fuzzers",
                "items": items,
                "count": len(items),
            }
        )

    except PermissionError:
        return jsonify({"error": "Permission denied", "path": str(fuzzers_path)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/table/generate", methods=["POST"])
def generate_table():
    try:
        data = request.json

        if not data:
            return jsonify({"error": "No data provided"}), 400

        report_paths = data.get("report_paths", [])
        selected_binaries = data.get("selected_binaries", [])
        fuzzers = data.get("fuzzers", [])
        benchmark = data.get("benchmark", "FirmBench")
        if not selected_binaries:
            return jsonify({"error": "No binaries selected"}), 400

        table_data = get_table_json(
            report_paths,
            benchmark=benchmark,
            selected_binaries=selected_binaries,
        )

        if not table_data:
            return jsonify({"error": "No bug data to visualize"}), 400

        response = {
            "table_data": table_data,
            "fuzzers": fuzzers,
        }

        return jsonify(response), 200

    except Exception as e:
        print(f"Error in generate_table: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/export-latex", methods=["POST"])
def export_latex_table():
    try:
        data = request.json or {}
        benchmark = data.get("benchmark", "Report")
        report_paths = data.get("report_paths", [])
        selected_binaries = data.get("selected_binaries", [])
        expected_fuzzers = data.get("fuzzers", [])

        if not selected_binaries:
            return jsonify({"error": "No binaries selected"}), 400

        combined_df = _load_combined_reports_dataframe(report_paths)
        combined_df = _add_missing_binary_rows(
            combined_df, benchmark, selected_binaries
        )
        if combined_df is None or combined_df.empty:
            return jsonify({"error": "No bug data to export"}), 400

        combined_df = combined_df.applymap(
            lambda x: escape_latex(str(x)) if isinstance(x, str) else x
        )
        fuzzers = expected_fuzzers or _collect_unique_fuzzers(combined_df)
        latex_code = reshape_and_convert_to_latex(combined_df, fuzzers)

        pdf_b64 = ""
        pdf_error = None
        try:
            pdf_bytes = _render_latex_table_to_pdf_bytes(latex_code)
            pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
        except Exception as render_err:
            pdf_error = str(render_err)

        return jsonify(
            {
                "benchmark": benchmark,
                "preview_pdf_base64": pdf_b64,
                "pdf_base64": pdf_b64,
                "pdf_error": pdf_error,
                "latex_code": latex_code,
                "filename": f"{benchmark.lower()}_summary_table.pdf",
                "report_count": len(report_paths),
            }
        )
    except Exception as e:
        print(f"Error in export_latex_table: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/export-csv", methods=["POST"])
def export_csv_table():
    try:
        data = request.json or {}
        benchmark = str(data.get("benchmark", "Report"))
        report_paths = data.get("report_paths", [])
        selected_binaries = data.get("selected_binaries", [])

        if not selected_binaries:
            return jsonify({"error": "No binaries selected"}), 400

        combined_df = _load_combined_reports_dataframe(report_paths)
        combined_df = _add_missing_binary_rows(
            combined_df, benchmark, selected_binaries
        )
        if combined_df is None or combined_df.empty:
            return jsonify({"error": "No bug data to export"}), 400

        safe_benchmark = re.sub(r"[^A-Za-z0-9_-]+", "_", benchmark).strip("_")
        filename = f"{(safe_benchmark or 'report').lower()}_summary_table.csv"
        return Response(
            combined_df.to_csv(index=False),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        print(f"Error in export_csv_table: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/export-upset", methods=["POST"])
def export_upset_preview():
    try:
        data = request.json or {}
        benchmark = data.get("benchmark", "Report")
        metric = str(data.get("metric", "triggered")).lower()
        if metric not in {"reached", "triggered", "detected"}:
            metric = "triggered"
        report_paths = data.get("report_paths", [])

        if not report_paths:
            return jsonify({"error": "No report paths provided"}), 400

        combined_df = _load_combined_reports_dataframe(report_paths)
        if combined_df is None or combined_df.empty:
            return jsonify({"error": "No bug data to export"}), 400

        figure = upset_plot(combined_df.sort_values(by="Fuzzer"), metric=metric)

        png_buffer = io.BytesIO()
        pdf_buffer = io.BytesIO()
        figure.savefig(png_buffer, format="png", dpi=180, bbox_inches="tight")
        figure.savefig(pdf_buffer, format="pdf", bbox_inches="tight")

        png_b64 = base64.b64encode(png_buffer.getvalue()).decode("ascii")
        pdf_b64 = base64.b64encode(pdf_buffer.getvalue()).decode("ascii")

        try:
            import matplotlib.pyplot as plt

            plt.close(figure)
        except Exception:
            pass

        return jsonify(
            {
                "benchmark": benchmark,
                "metric": metric,
                "preview_png_base64": png_b64,
                "pdf_base64": pdf_b64,
                "filename": f"{benchmark.lower()}_{metric}_upset_plot.pdf",
                "report_count": len(report_paths),
            }
        )
    except Exception as e:
        print(f"Error in export_upset_preview: {str(e)}")
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
            run_name = job_data.get("run_name", "")
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
                    run_name=run_name,
                    auto_queue_triaging=auto_queue_triaging,
                )
                job_manager.add_job(job)
                job_ids.append(job_id)
                print(f"Successfully added job {job_id}")
            except Exception as e:
                print(f"ERROR adding job: {e}")
                raise

        notify_jobs_changed()

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

        notify_jobs_changed()
        job_manager.stop_job(job_id)
        notify_jobs_changed()

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
            return jsonify({"error": f"Job {job_id} not found", "success": False}), 404

        if job.mode != "Fuzzing":
            return jsonify(
                {
                    "error": "Auto-triage setting can only be changed for Fuzzing jobs",
                    "success": False,
                }
            ), 400

        job.auto_queue_triaging = enabled
        notify_jobs_changed()

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
        notify_jobs_changed()

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
        notify_jobs_changed()

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
        notify_jobs_changed()

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

        log_path = os.path.join(
            get_run_output_dir(
                FIRMREBUGGER_BASE_DIR,
                task_found.run_name,
                task_found.benchmark,
                task_found.binary,
                task_found.fuzzer,
            ),
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
            chunk_bytes = _parse_int_query_arg(
                "chunk_bytes",
                default=DEFAULT_LOG_CHUNK_BYTES,
                minimum=1,
                maximum=MAX_LOG_CHUNK_BYTES,
            )
            before_offset = _parse_int_query_arg(
                "before_offset",
                default=None,
                minimum=0,
            )
            chunk = _read_log_chunk(
                log_path,
                before_offset=before_offset,
                chunk_bytes=chunk_bytes,
            )

            return jsonify(
                {
                    "content": chunk["content"],
                    "path": log_path,
                    "exists": True,
                    "task_id": task_id,
                    "run_number": task_found.run_number,
                    "file_size": chunk["file_size"],
                    "start_offset": chunk["start_offset"],
                    "end_offset": chunk["end_offset"],
                    "has_more_before": chunk["has_more_before"],
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
        run_name = request.args.get("run_name", None)

        if not benchmark or not binary or not fuzzer or not run_name:
            return jsonify(
                {
                    "error": "benchmark, binary, fuzzer, and run_name are required",
                    "content": "",
                }
            ), 400

        log_path = os.path.join(
            get_run_output_dir(
                FIRMREBUGGER_BASE_DIR, run_name, benchmark, binary, fuzzer
            ),
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

        chunk_bytes = _parse_int_query_arg(
            "chunk_bytes",
            default=DEFAULT_LOG_CHUNK_BYTES,
            minimum=1,
            maximum=MAX_LOG_CHUNK_BYTES,
        )
        before_offset = _parse_int_query_arg(
            "before_offset",
            default=None,
            minimum=0,
        )
        chunk = _read_log_chunk(
            log_path,
            before_offset=before_offset,
            chunk_bytes=chunk_bytes,
        )

        return jsonify(
            {
                "content": chunk["content"],
                "path": log_path,
                "exists": True,
                "benchmark": benchmark,
                "binary": binary,
                "fuzzer": fuzzer,
                "run_name": run_name,
                "file_size": chunk["file_size"],
                "start_offset": chunk["start_offset"],
                "end_offset": chunk["end_offset"],
                "has_more_before": chunk["has_more_before"],
            }
        )

    except Exception as e:
        print(f"ERROR in get_triage_log_by_job: {e}")
        return jsonify({"error": str(e), "content": ""}), 500


@app.route("/api/config", methods=["GET"])
def config():
    """Return runtime configuration for the frontend."""
    return jsonify(
        {
            "apiUrl": f"http://localhost:{APP_PORT}",
        }
    )


def _read_latest_coverage_blocks(output_dir):
    """Read the most recent 'blocks' value (column 8, no header) from a live
    MultiFuzz run's stats.csv, without loading the whole file — it grows
    continuously during a run and can reach tens of MB. Reads only the last
    few KB and finds the last complete row, tolerating a partial trailing
    line if the writer is mid-append."""
    stats_path = os.path.join(output_dir, "stats.csv")
    try:
        with open(stats_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return None
            chunk_size = min(size, 8192)
            f.seek(size - chunk_size)
            tail = f.read(chunk_size)
    except OSError:
        return None

    for line in reversed(tail.split(b"\n")):
        if not line.strip():
            continue
        fields = line.decode(errors="ignore").split(",")
        if len(fields) < 8:
            continue
        try:
            return int(fields[7])
        except ValueError:
            continue
    return None


_FUNC_SIG_RE = re.compile(r"^[A-Za-z_][\w \*]*?\b\w+\s*\([^)]*\)\s*\{", re.MULTILINE)


def _extract_function_containing(content, offset):
    """Return the source text of the top-level function containing the given
    character offset, by walking back to the nearest preceding function
    signature and forward to its matching closing brace."""
    sig_match = None
    for sig in _FUNC_SIG_RE.finditer(content):
        if sig.start() > offset:
            break
        sig_match = sig
    if sig_match is None:
        return None

    depth = 0
    for i in range(sig_match.end() - 1, len(content)):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return content[sig_match.start() : i + 1]
    return None


def _find_ravens_for_bug(base_dir, bug_id):
    """Find the raven(s) — the bug_descriptor.c function containing the
    report_reached/report_detected_triggered call — for this bug_id, across
    every (benchmark, binary) location it actually appears in code. Ground
    truth is the code scan, not the bug_analysis frontmatter's claimed
    locations, since those can drift out of sync."""
    id_match = _ID_RE.match(bug_id)
    if not id_match:
        return []
    prefix, number = id_match.group(1), int(id_match.group(2))
    locations = _scan_bug_descriptor_ids(base_dir).get((prefix, number), [])

    call_re = re.compile(
        r'report_(?:detected_triggered|reached)\(\s*"(FP_)?' + re.escape(bug_id) + r'"'
    )

    ravens = []
    seen_code = set()
    for benchmark, binary in sorted(set(locations)):
        path = os.path.join(base_dir, benchmark, binary, "bug_descriptor.c")
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read()
        except OSError:
            continue

        call_match = call_re.search(content)
        if not call_match:
            continue

        code = _extract_function_containing(content, call_match.start())
        if not code or code in seen_code:
            continue
        seen_code.add(code)

        ravens.append(
            {
                "benchmark": benchmark,
                "binary": binary,
                "reported_id": ("FP_" if call_match.group(1) else "") + bug_id,
                "code": code,
            }
        )

    return ravens


@app.route("/api/bug_analysis/<bug_id>", methods=["GET"])
def bug_analysis_detail(bug_id):
    """Serve a single bug_analysis/bugs/<BUG_ID>.md entry (frontmatter + body,
    plus its raven(s) from bug_descriptor.c) as JSON, reusing the same parser
    as the bug-registry CLI tooling."""
    base_dir = get_frb_base_dir()
    bugs_dir = os.path.realpath(os.path.join(base_dir, "bug_analysis", "bugs"))
    path = os.path.realpath(os.path.join(bugs_dir, f"{bug_id}.md"))
    if not path.startswith(bugs_dir + os.sep) or not os.path.isfile(path):
        return jsonify({"error": "not_found"}), 404

    entry, error = _parse_detail_file(path)
    if error:
        return jsonify({"error": error}), 500

    entry["ravens"] = _find_ravens_for_bug(base_dir, bug_id)

    return jsonify(entry)


def _read_full_coverage_series(output_dir):
    """Read the full (elapsed_ms, blocks) time series from a run's stats.csv.
    Tolerates a partial trailing line if the writer is mid-append."""
    stats_path = os.path.join(output_dir, "stats.csv")
    series = []
    try:
        with open(stats_path, "r") as f:
            for line in f:
                fields = line.strip().split(",")
                if len(fields) < 8:
                    continue
                try:
                    series.append((int(fields[0]), int(fields[7])))
                except ValueError:
                    continue
    except OSError:
        return []
    return series


def _read_total_valid_blocks(base_dir, benchmark, binary):
    """Total statically-valid basic block count for a binary, if known.

    Populated ahead of time in <Benchmark>/<Binary>/valid_basic_blocks.txt
    (one block address per line). Returns None when the file doesn't exist
    for this binary — not every benchmark has one.
    """
    path = os.path.join(
        get_binary_dir(base_dir, benchmark, binary), "valid_basic_blocks.txt"
    )
    try:
        with open(path, "r") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return None


@app.route("/api/jobs/<job_id>/coverage-summary", methods=["GET"])
def job_coverage_summary(job_id):
    """Live MultiFuzz coverage across a job's runs, read directly from each
    run's stats.csv on disk — no external tool involved. Aggregated
    server-side so the browser issues one request per job instead of one per
    run, regardless of how many runs the job has."""
    if not job_manager:
        return jsonify({"avg_blocks": None, "total_blocks": None, "runs": []})

    job = next(
        (j for j in job_manager.get_current_jobs() if j.job_id == job_id), None
    )
    if job is None or job.fuzzer != "MultiFuzz":
        return jsonify({"avg_blocks": None, "total_blocks": None, "runs": []})

    base_dir = get_frb_base_dir()
    work_dir = get_run_output_dir(
        base_dir, job.run_name, job.benchmark, job.binary, job.fuzzer
    )
    total_blocks = _read_total_valid_blocks(base_dir, job.benchmark, job.binary)

    runs = []
    for run_num in range(1, job.runs + 1):
        run_number = str(run_num).zfill(2)
        output_dir = os.path.join(work_dir, f"output-{run_number}")
        blocks = _read_latest_coverage_blocks(output_dir)
        runs.append(
            {
                "run_number": run_number,
                "blocks": blocks,
                "coverage_pct": (
                    round(100 * blocks / total_blocks, 2)
                    if blocks is not None and total_blocks
                    else None
                ),
            }
        )

    values = [r["blocks"] for r in runs if r["blocks"] is not None]
    avg_blocks = sum(values) / len(values) if values else None
    avg_coverage_pct = (
        round(100 * avg_blocks / total_blocks, 2)
        if avg_blocks is not None and total_blocks
        else None
    )

    return jsonify(
        {
            "avg_blocks": avg_blocks,
            "total_blocks": total_blocks,
            "avg_coverage_pct": avg_coverage_pct,
            "runs": runs,
        }
    )


COVERAGE_TIMESERIES_MAX_BUCKETS = 200


@app.route("/api/jobs/<job_id>/coverage-timeseries", methods=["GET"])
def job_coverage_timeseries(job_id):
    """Coverage-over-time for a MultiFuzz job, averaged across a chosen subset
    of its runs. Reads each selected run's full stats.csv (not just the tail),
    downsamples into a fixed number of time buckets, and returns per-bucket
    mean/min/max blocks (and coverage %) across the selected runs so the
    frontend can draw a single averaged coverage curve with a spread band."""
    if not job_manager:
        return jsonify({"buckets": [], "total_blocks": None, "runs_included": []})

    job = next(
        (j for j in job_manager.get_current_jobs() if j.job_id == job_id), None
    )
    if job is None or job.fuzzer != "MultiFuzz":
        return jsonify({"buckets": [], "total_blocks": None, "runs_included": []})

    runs_param = request.args.get("runs")
    if runs_param:
        try:
            selected_runs = sorted(
                {int(r) for r in runs_param.split(",") if r.strip()}
            )
        except ValueError:
            return jsonify({"error": "invalid runs parameter"}), 400
    else:
        selected_runs = list(range(1, job.runs + 1))

    base_dir = get_frb_base_dir()
    work_dir = get_run_output_dir(
        base_dir, job.run_name, job.benchmark, job.binary, job.fuzzer
    )
    total_blocks = _read_total_valid_blocks(base_dir, job.benchmark, job.binary)

    series_by_run = {}
    max_elapsed_ms = 0
    for run_num in selected_runs:
        if run_num < 1 or run_num > job.runs:
            continue
        run_number = str(run_num).zfill(2)
        output_dir = os.path.join(work_dir, f"output-{run_number}")
        series = _read_full_coverage_series(output_dir)
        if series:
            series_by_run[run_num] = series
            max_elapsed_ms = max(max_elapsed_ms, series[-1][0])

    runs_included = sorted(series_by_run.keys())
    if not runs_included or max_elapsed_ms <= 0:
        return jsonify(
            {
                "buckets": [],
                "total_blocks": total_blocks,
                "runs_included": runs_included,
            }
        )

    num_buckets = min(COVERAGE_TIMESERIES_MAX_BUCKETS, max(1, max_elapsed_ms // 1000))
    bucket_ms = max_elapsed_ms / num_buckets

    per_run_bucketed = {}
    for run_num, series in series_by_run.items():
        values = [None] * (int(num_buckets) + 1)
        for elapsed_ms, blocks in series:
            idx = min(int(num_buckets), int(elapsed_ms // bucket_ms))
            if values[idx] is None or blocks > values[idx]:
                values[idx] = blocks
        # Forward-fill gaps: coverage is monotonic, so a bucket with no
        # samples holds the last known value rather than reading as a dip.
        last = None
        for i, value in enumerate(values):
            if value is None:
                values[i] = last
            else:
                last = value
        per_run_bucketed[run_num] = values

    buckets = []
    for i in range(int(num_buckets) + 1):
        vals = [
            per_run_bucketed[r][i]
            for r in runs_included
            if per_run_bucketed[r][i] is not None
        ]
        if not vals:
            continue
        mean_blocks = sum(vals) / len(vals)
        min_blocks = min(vals)
        max_blocks = max(vals)
        buckets.append(
            {
                "elapsed_seconds": round(i * bucket_ms / 1000, 1),
                "mean_blocks": mean_blocks,
                "min_blocks": min_blocks,
                "max_blocks": max_blocks,
                "mean_pct": (
                    round(100 * mean_blocks / total_blocks, 2)
                    if total_blocks
                    else None
                ),
                "min_pct": (
                    round(100 * min_blocks / total_blocks, 2) if total_blocks else None
                ),
                "max_pct": (
                    round(100 * max_blocks / total_blocks, 2) if total_blocks else None
                ),
                "num_runs": len(vals),
            }
        )

    return jsonify(
        {
            "buckets": buckets,
            "total_blocks": total_blocks,
            "runs_included": runs_included,
        }
    )


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

        report_details = get_reports(benchmark, fuzzers)
        valid_reports = [r["reportPath"] for r in report_details]
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
                "report_details": report_details,
                "report_durations": report_durations,
                "binaries": get_benchmark_binaries(benchmark),
                "benchmark": benchmark,
                "fuzzers": fuzzers,
            }
        )

    except Exception as e:
        print(f"ERROR in get_reports: {e}")
        return jsonify({"error": str(e), "valid_reports": []}), 500


@app.route("/api/check_run_name", methods=["POST"])
def check_run_name_endpoint():
    """Check if a run name already exists for this benchmark+binary+fuzzer combo"""
    try:
        data = request.json
        benchmark = data.get("benchmark", "FirmBench")
        binary_name = data.get("binary_name", "")
        fuzzers_selected = data.get("fuzzers_selected", [])
        run_name = data.get("run_name", "")

        is_valid = check_run_name_available(
            benchmark, binary_name, fuzzers_selected, run_name
        )

        return jsonify({"is_valid": is_valid, "exists": not is_valid})

    except Exception as e:
        print(f"ERROR in check_run_name: {e}")
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


def run_flask(port=5000, host="127.0.0.1"):
    app.run(debug=False, port=port, host=host)


def run_app(port, host="127.0.0.1"):
    global FIRMREBUGGER_BASE_DIR, STATIC_FOLDER, APP_PORT, app, job_manager

    APP_PORT = port

    FIRMREBUGGER_BASE_DIR = get_frb_base_dir()
    STATIC_FOLDER = f"{FIRMREBUGGER_BASE_DIR}/src/firmrebugger-web/dist"

    app.static_folder = STATIC_FOLDER

    job_manager = JobManager()

    def _shutdown(signum, frame):
        sig_name = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
        print(f"\n[Shutdown] {sig_name} received — stopping all jobs and exiting...")
        job_manager.shutdown_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

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

    flask_thread = threading.Thread(target=run_flask, args=(port, host))
    flask_thread.start()

    start_manager(job_manager)
