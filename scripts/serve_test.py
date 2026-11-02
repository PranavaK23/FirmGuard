"""Isolated database for browser integration tests."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="firmguard-browser-") as directory:
        env=os.environ.copy();env["FIRMGUARD_DB"]=str(Path(directory)/"scans.db")
        env.pop("FIRMGUARD_BINWALK_IMAGE",None)
        result=subprocess.run([sys.executable,"-m","uvicorn","main:app","--host","127.0.0.1","--port","8765","--workers","1"],
            cwd=Path(__file__).resolve().parents[1]/"backend",env=env)
        sys.exit(result.returncode)
