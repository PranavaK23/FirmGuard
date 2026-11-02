"""Disposable analysis process with atomic status/result files."""
import json
import os
import sys
import time
from pathlib import Path
from settings import AnalysisError

def atomic(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    # On Windows a reader may momentarily hold the destination without delete sharing.
    for attempt in range(50):
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 49: raise
            time.sleep(0.01)

def run(directory):
    try:
        if sys.platform != "win32":
            import resource
            resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_CPU, (150, 150))
        from analysis import analyse
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
        def progress(stage, percent): atomic(directory / "progress.json", {"stage": stage, "progress": percent})
        result = analyse((directory / "input").read_bytes(), **metadata, progress=progress)
        atomic(directory / "result.json", {"ok": True, "result": result})
    except AnalysisError as error:
        atomic(directory / "result.json", {"ok": False, "error": error.message, "status": error.status})
    except Exception:
        atomic(directory / "result.json", {"ok": False, "error": "Analysis could not complete. The input may be malformed or exceed parser limits.", "status": 422})

if __name__ == "__main__": run(Path(sys.argv[1]))
