"""Bounded local worker jobs. Run the server with one worker process."""
import json
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
import history
from settings import AnalysisError, JOB_TIMEOUT, MAX_JOBS

SLOTS = threading.BoundedSemaphore(MAX_JOBS)

def execute(data, metadata, progress=lambda *args: None):
    with tempfile.TemporaryDirectory(prefix="firmguard-job-") as directory:
        root = Path(directory)
        (root / "input").write_bytes(data)
        (root / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("worker.py")), directory],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        last = None
        try:
            started = time.monotonic()
            while process.poll() is None:
                if time.monotonic() - started > JOB_TIMEOUT:
                    raise AnalysisError("Analysis exceeded its 180-second time limit. Submit a smaller input.", 422)
                try:
                    state = json.loads((root / "progress.json").read_text(encoding="utf-8"))
                    if state != last:
                        progress(state["stage"], state["progress"]); last = state
                except (FileNotFoundError, PermissionError, json.JSONDecodeError): pass
                time.sleep(0.1)
            if process.returncode or not (root / "result.json").exists():
                raise AnalysisError("Analysis worker stopped before completion. The input may exceed resource limits.", 422)
            response = json.loads((root / "result.json").read_text(encoding="utf-8"))
            if not response["ok"]: raise AnalysisError(response["error"], response["status"])
            return response["result"]
        finally:
            if process.poll() is None: process.kill()
            process.wait(timeout=10)

def saved_job(scan_id, data, metadata):
    try:
        history.update_scan(scan_id, "running", "Starting analysis", 5)
        result = execute(data, metadata, lambda stage, percent: history.update_scan(scan_id, "running", stage, percent))
        history.update_scan(scan_id, "completed", "Completed", 100, result)
    except AnalysisError as error:
        history.update_scan(scan_id, "failed", "Failed", 0, error=error.message)
    except Exception:
        history.update_scan(scan_id, "failed", "Failed", 0, error="The analysis could not be saved. Check local storage and submit the input again.")
    finally: SLOTS.release()
