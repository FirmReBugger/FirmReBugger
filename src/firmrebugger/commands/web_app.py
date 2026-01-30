import os
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory 
from flask_cors import CORS
from firmrebugger.common import get_frb_base_dir
from firmrebugger.app_utils import check_binaries, check_fuzzers, check_output_name, cpu_usage, all_cpu_usage, get_reports, get_table_json
from firmrebugger.manager import start_manager, Job, JobScheduler, list_finished_jobs
import threading


STATIC_FOLDER = ''
app = Flask(__name__, static_folder=STATIC_FOLDER, static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]}})

FIRMREBUGGER_BASE_DIR = ""
job_scheduler = None


def task_to_dict(task):
    cpu_percent = None
    core_idx_value = getattr(task, 'core_idx', None)

    if core_idx_value is not None and task.status == 'running':
        try:
            if isinstance(core_idx_value, list):
                cpu_percent = [cpu_usage(idx) for idx in core_idx_value]
            else:
                cpu_percent = cpu_usage(core_idx_value)
        except Exception as e:
            print(f"Error getting CPU usage for core {core_idx_value}: {e}")
            cpu_percent = None

    return {
        'task_id': task.task_id,
        'job_id': task.job_id,
        'fuzzer': task.fuzzer,
        'duration': task.duration,
        'binary': task.binary,
        'run_number': task.run_number,
        'mode': task.mode,
        'benchmark': task.benchmark,
        'status': task.status,
        'created_at': task.created_at,
        'started_at': task.started_at,
        'completed_at': task.completed_at,
        'output_dir': task.output_dir,
        'runs': task.runs,
        'core_idx': core_idx_value,
        'container_name': getattr(task, 'container_name', None),
        'cpu_usage': cpu_percent,
    }

@app.route('/api/fuzzers/list')
def list_fuzzers_folder():
    try:
        docker_path = Path(FIRMREBUGGER_BASE_DIR) / 'docker'

        if not docker_path.exists():
            return jsonify({
                'error': 'Docker directory not found',
                'path': str(docker_path)
            }), 404

        if not docker_path.is_dir():
            return jsonify({
                'error': 'Path is not a directory',
                'path': str(docker_path)
            }), 400

        items = []
        for item in sorted(docker_path.iterdir()):
            items.append({
                'name': item.name,
                'type': 'directory' if item.is_dir() else 'file',
                'path': str(item.relative_to(FIRMREBUGGER_BASE_DIR))
            })

        return jsonify({
            'base_dir': FIRMREBUGGER_BASE_DIR,
            'path': 'docker',
            'items': items,
            'count': len(items)
        })

    except PermissionError:
        return jsonify({
            'error': 'Permission denied',
            'path': str(docker_path)
        }), 403
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/api/table/generate', methods=['POST'])
def generate_table():
    try:
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        report_paths = data.get('report_paths', [])
        if not report_paths:
            return jsonify({'error': 'No report paths provided'}), 400

        table_data = get_table_json(report_paths)

        if not table_data:
            return jsonify({'error': 'No bug data to visualize'}), 400

        response = {
            'table_data': table_data,
        }

        return jsonify(response), 200

    except Exception as e:
        print(f"Error in generate_table: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/jobs/add', methods=['POST'])
def add_job():
    """Add jobs to the scheduler"""
    try:
        global job_scheduler
        data = request.json

        if not data:
            return jsonify({
                'error': 'No data provided'
            }), 400

        jobs_data = data.get('jobs', [])

        if not jobs_data:
            return jsonify({
                'error': 'At least one job is required'
            }), 400

        job_ids = []
        for job_data in jobs_data:
            job_id = job_data['job_id']
            fuzzer = job_data['fuzzer']
            benchmark = job_data['benchmark']
            duration = job_data['duration']
            binary = job_data['binary']
            runs = job_data['runs']
            mode = job_data['mode']
            output_dir = job_data.get('output_dir', '')

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
                    output_dir=output_dir
                )
                job_scheduler.add_job(job)
                job_ids.append(job_id)
                print(f"Successfully added job {job_id}")
            except Exception as e:
                print(f"ERROR adding job: {e}")
                raise

        return jsonify({
            'success': True,
            'jobs_added': len(job_ids),
            'job_ids': job_ids,
            'message': f'Added {len(job_ids)} job(s)'
        }), 201

    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@app.route('/api/jobs/list', methods=['GET'])
def get_jobs():
    """Get all current jobs from the scheduler"""
    try:
        global job_scheduler

        if not job_scheduler:
            return jsonify({
                'jobs': [],
                'count': 0
            })

        jobs_list = job_scheduler.get_current_jobs()

        jobs_data = []
        for job in jobs_list:
            full_output_dir = os.path.join(
                get_frb_base_dir(),
                job.benchmark,
                job.binary,
                "fuzzers",
                job.fuzzer,
                "fuzzing_out",
                job.output_dir
            )

            report_path = os.path.join(full_output_dir, "frb_report.json")
            has_been_triaged = os.path.exists(report_path)

            job_dict = {
                'id': job.job_id,
                'mode': job.mode,
                'benchmark': getattr(job, 'benchmark', 'FirmBench'),
                'fuzzer': job.fuzzer,
                'binary': job.binary,
                'runs': job.runs,
                'completedRuns': job.get_completed_runs(),
                'time': job.duration,
                'status': job.status,
                'progress': job.progress,
                'createdAt': job.created_at,
                'startedAt': job.started_at,
                'elapsedTime': job.elapsed_time,
                'output_dir': full_output_dir,
                'triaged': has_been_triaged,
            }
            jobs_data.append(job_dict)

        return jsonify({
            'jobs': jobs_data,
            'count': len(jobs_data)
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'jobs': [],
            'count': 0
        }), 500


@app.route('/api/jobs/stop', methods=['POST'])
def stop_job():
    """Stop a specific job"""
    try:
        global job_scheduler

        if not job_scheduler:
            return jsonify({
                'error': 'Job scheduler not initialized',
                'success': False
            }), 500

        data = request.json
        job_id = data.get('job_id', None)

        if not job_id:
            return jsonify({
                'error': 'job_id is required',
                'success': False
            }), 400

        job_scheduler.stop_job(job_id)

        return jsonify({
            'success': True,
            'message': f'Job {job_id} stop requested',
            'job_id': job_id
        })

    except Exception as e:
        print(f"ERROR in stop_job: {e}")
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@app.route('/api/jobs/reorder', methods=['POST'])
def reorder_jobs():
    """Move a queued job up one position in the queue"""
    try:
        global job_scheduler

        if not job_scheduler:
            return jsonify({
                'error': 'Job scheduler not initialized',
                'success': False
            }), 500

        data = request.json
        job_id = data.get('job_id', None)

        if not job_id:
            return jsonify({
                'error': 'job_id is required',
                'success': False
            }), 400

        job_scheduler.reorder_job(job_id)

        return jsonify({
            'success': True,
            'message': f'Job {job_id} moved up one position',
            'job_id': job_id
        })

    except Exception as e:
        print(f"ERROR in reorder_jobs: {e}")
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@app.route('/api/jobs/delete', methods=['POST'])
def delete_job():
    """Delete a completed or stopped job"""
    try:
        global job_scheduler

        if not job_scheduler:
            return jsonify({
                'error': 'Job scheduler not initialized',
                'success': False
            }), 500

        data = request.json
        job_id = data.get('job_id', None)

        if not job_id:
            return jsonify({
                'error': 'job_id is required',
                'success': False
            }), 400

        job_scheduler.delete_job(job_id)

        return jsonify({
            'success': True,
            'message': f'Job {job_id} deleted',
            'job_id': job_id
        })

    except Exception as e:
        print(f"ERROR in delete_job: {e}")
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


# for a job get the task details
@app.route('/api/tasks/list', methods=['GET'])
def get_task_details():
    """Get all task details for a specific job or all jobs"""
    try:
        global job_scheduler

        if not job_scheduler:
            return jsonify({
                'tasks': [],
                'count': 0
            })

        job_id = request.args.get('job_id', None)

        all_tasks = []
        jobs_list = job_scheduler.get_current_jobs()

        for job in jobs_list:
            if job_id and job.job_id != job_id:
                continue

            if hasattr(job, 'tasks'):
                tasks = job.tasks

            for task in tasks:
                all_tasks.append(task_to_dict(task))

        return jsonify({
            'tasks': all_tasks,
            'count': len(all_tasks),
            'job_id': job_id
        })

    except Exception as e:
        print(f"ERROR in get_task_details: {e}")
        return jsonify({
            'error': str(e),
            'tasks': [],
            'count': 0
        }), 500


@app.route('/api/tasks/logs', methods=['GET'])
def get_task_logs():
    """Get logs for a specific task"""
    try:
        global job_scheduler

        task_id = request.args.get('task_id', None)

        if not task_id:
            return jsonify({
                'error': 'task_id is required'
            }), 400

        if not job_scheduler:
            return jsonify({
                'error': 'Job scheduler not initialized'
            }), 500

        jobs_list = job_scheduler.get_current_jobs()
        task_found = None

        for job in jobs_list:
            if hasattr(job, 'tasks'):
                for task in job.tasks:
                    if task.task_id == task_id:
                        task_found = task
                        break
            if task_found:
                break

        if not task_found:
            return jsonify({
                'error': f'Task {task_id} not found'
            }), 404

        if task_found.mode == 'Triaging':
            log_filename = "triage.log"
        else:
            log_filename = f"log-{task_found.run_number}.log"

        log_path = os.path.join(
            FIRMREBUGGER_BASE_DIR,
            task_found.benchmark,
            task_found.binary,
            "fuzzers",
            task_found.fuzzer,
            "fuzzing_out",
            task_found.output_dir,
            "fuzzing_logs",
            log_filename
        )

        if not os.path.exists(log_path):
            return jsonify({
                'error': f'Log file not found: {log_path}',
                'content': '',
                'exists': False
            }), 404

        try:
            with open(log_path, 'r') as f:
                log_content = f.read()

            return jsonify({
                'content': log_content,
                'path': log_path,
                'exists': True,
                'task_id': task_id,
                'run_number': task_found.run_number
            })

        except Exception as e:
            return jsonify({
                'error': f'Error reading log file: {str(e)}',
                'content': '',
                'exists': True
            }), 500

    except Exception as e:
        print(f"ERROR in get_task_logs: {e}")
        return jsonify({
            'error': str(e),
            'content': ''
        }), 500


@app.route('/api/check_fuzzers', methods=['GET'])
def check_fuzzers_endpoint():
    """Get valid fuzzers for a given benchmark"""
    try:
        benchmark = request.args.get('benchmark', 'FirmBench')
        valid_fuzzers = check_fuzzers(benchmark)

        return jsonify({
            'valid_fuzzers': valid_fuzzers,
            'benchmark': benchmark
        })

    except Exception as e:
        print(f"ERROR in check_fuzzers: {e}")
        return jsonify({
            'error': str(e),
            'valid_fuzzers': []
        }), 500

@app.route('/api/check_binaries', methods=['POST'])
def check_binaries_endpoint():
    """Get valid binaries for a given benchmark and fuzzers"""
    try:
        data = request.json
        benchmark = data.get('benchmark', 'FirmBench')
        fuzzers = data.get('fuzzers', [])
        print(f"Received fuzzers: {fuzzers}")

        valid_binaries = check_binaries(benchmark, fuzzers)

        return jsonify({
            'valid_binaries': valid_binaries,
            'benchmark': benchmark,
            'fuzzers': fuzzers
        })

    except Exception as e:
        print(f"ERROR in check_binaries: {e}")
        return jsonify({
            'error': str(e),
            'valid_binaries': []
        }), 500

@app.route('/api/get_reports', methods=['POST'])
def get_reports_endpoint():
    try:
        data = request.json
        benchmark = data.get('benchmark', 'FirmBench')
        fuzzers = data.get('fuzzers', [])

        valid_reports = get_reports(benchmark, fuzzers)

        return jsonify({
            'valid_reports': valid_reports,
            'benchmark': benchmark,
            'fuzzers': fuzzers
        })

    except Exception as e:
        print(f"ERROR in get_reports: {e}")
        return jsonify({
            'error': str(e),
            'valid_reports': []
        }), 500

@app.route('/api/check_output_name', methods=['POST'])
def check_output_name_endpoint():
    """Check if output name already exists"""
    try:
        data = request.json
        benchmark = data.get('benchmark', 'FirmBench')
        binary_name = data.get('binary_name', '')
        fuzzers_selected = data.get('fuzzers_selected', [])
        output_name = data.get('output_name', '')

        print(f"Checking output name: benchmark={benchmark}, binary={binary_name}, fuzzers={fuzzers_selected}, output={output_name}")

        is_valid = check_output_name(benchmark, binary_name, fuzzers_selected, output_name)

        return jsonify({
            'is_valid': is_valid,
            'exists': not is_valid
        })

    except Exception as e:
        print(f"ERROR in check_output_name: {e}")
        return jsonify({
            'error': str(e),
            'is_valid': False
        }), 500

@app.route('/api/system/cpu', methods=['GET'])
def get_system_cpu():
    """Get CPU usage for all cores"""
    try:
        cpu_usage_list = all_cpu_usage()

        return jsonify({
            'cpu_usage': cpu_usage_list,
            'core_count': len(cpu_usage_list)
        })

    except Exception as e:
        print(f"ERROR in get_system_cpu: {e}")
        return jsonify({
            'error': str(e),
            'cpu_usage': [],
            'core_count': 0
        }), 500

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react_app(path):
    """Serve the React application"""
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        # Serve the requested static file
        return send_from_directory(app.static_folder, path)
    else:
        # Serve index.html for all other routes (SPA routing)
        return send_from_directory(app.static_folder, 'index.html')


def run_flask(port=5000):
    app.run(debug=False, port=port, host='0.0.0.0')

def run_app(port):
    global FIRMREBUGGER_BASE_DIR, STATIC_FOLDER, app, job_scheduler
    
    FIRMREBUGGER_BASE_DIR = get_frb_base_dir()
    STATIC_FOLDER = f"{FIRMREBUGGER_BASE_DIR}/src/firmrebugger-web/dist"
    
    app.static_folder = STATIC_FOLDER
    
    job_scheduler = JobScheduler()

    print("[Startup] Loading finished jobs from disk...")
    try:
        finished_jobs = list_finished_jobs()
        for job in finished_jobs:
            job_scheduler.add_job(job)
        print(f"[Startup] Loaded {len(finished_jobs)} finished jobs")
    except Exception as e:
        print(f"[Startup] Error loading finished jobs: {e}")

    flask_thread = threading.Thread(target=run_flask, args=(port,))
    flask_thread.start()

    start_manager(job_scheduler)