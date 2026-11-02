"""Optional Binwalk v3 extraction in Docker, never through host extractors."""
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from settings import AnalysisError, BINWALK_TIMEOUT, MAX_EXPANDED, ROOT
from unpack import Unpacker

def image():
    value = os.environ.get("FIRMGUARD_BINWALK_IMAGE", "")
    if value and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}", value):
        raise AnalysisError("The configured Binwalk image name is invalid.", 503)
    return value

def available():
    try: configured = bool(image())
    except AnalysisError: configured = False
    return {"configured": configured, "docker_cli": bool(shutil.which("docker")),
        "mode": "isolated Docker Binwalk v3", "note": "Requires a running Linux Docker engine and a locally built image; no automatic downloads."}

def extract(data):
    selected = image()
    if not selected or not shutil.which("docker"):
        raise AnalysisError("Binwalk extraction is unavailable. Configure the documented Docker image first, or scan without Binwalk.", 503)
    name = "firmguard-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="firmguard-binwalk-") as directory:
        source = Path(directory) / "firmware.bin"
        source.write_bytes(data)
        runner = ROOT / "tools" / "binwalk" / "container_runner.py"
        command = ["docker", "run", "--rm", "--name", name, "--pull=never", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=1536m", "--memory-swap=1536m",
            "--cpus=1", "--pids-limit=64", "--user=65534:65534", "--log-driver=none",
            "--tmpfs", "/work:rw,noexec,nosuid,nodev,size=384m,mode=1777",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
            "--mount", f"type=bind,source={source},target=/input/firmware.bin,readonly",
            "--mount", f"type=bind,source={runner},target=/runner.py,readonly",
            "--env", "HOME=/tmp", "--entrypoint", "python3", selected, "/runner.py"]
        with tempfile.TemporaryFile() as output:
            proc = subprocess.Popen(command, stdout=output, stderr=subprocess.DEVNULL)
            try:
                start = time.monotonic()
                while proc.poll() is None:
                    if time.monotonic() - start > BINWALK_TIMEOUT:
                        raise AnalysisError("Binwalk exceeded its 120-second time limit.", 422)
                    if os.fstat(output.fileno()).st_size > MAX_EXPANDED + 8 * 1024 * 1024:
                        raise AnalysisError("Binwalk output exceeds the size limit.", 413)
                    time.sleep(0.1)
                if proc.returncode:
                    raise AnalysisError("Binwalk container could not extract this input. Check Docker/image setup with scripts/doctor.py.", 422)
                output.seek(0)
                payload = output.read(MAX_EXPANDED + 8 * 1024 * 1024 + 1)
                if len(payload) > MAX_EXPANDED + 8 * 1024 * 1024:
                    raise AnalysisError("Binwalk output exceeds the size limit.", 413)
            finally:
                if proc.poll() is None: proc.kill()
                proc.wait(timeout=10)
                subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        unpacker = Unpacker()
        items = unpacker.unpack(payload, "binwalk-output.tar")
        metadata = next((i for i in items if i.path == "firmguard-metadata.json"), None)
        if metadata is None: raise AnalysisError("Binwalk returned invalid output.", 422)
        info = json.loads(metadata.data)
        items = [i for i in items if i is not metadata]
        if not items: raise AnalysisError("Binwalk did not produce regular extracted files. Try a supported filesystem image.", 422)
        return items, info
