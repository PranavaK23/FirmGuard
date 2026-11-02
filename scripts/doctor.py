"""Read-only tool and environment checks; never pulls or builds Docker images."""
import importlib.metadata
import os
import shutil
import subprocess
import sys
from pathlib import Path

def main():
    print("FirmGuard environment check")
    print("Python:", sys.version.split()[0], sys.executable)
    for package in ["fastapi","uvicorn","python-multipart","pyelftools","reportlab"]:
        try: print(package + ":",importlib.metadata.version(package))
        except importlib.metadata.PackageNotFoundError: print(package + ": MISSING")
    root=Path(__file__).resolve().parents[1]
    print("Built interface:", "ready" if (root/'frontend/dist/index.html').exists() else "missing; run npm ci and npm run build in frontend")
    image=os.environ.get("FIRMGUARD_BINWALK_IMAGE","")
    print("Binwalk Docker image:", image or "not configured (optional)")
    if not image: return
    if not shutil.which("docker"): print("Docker command: MISSING"); return
    try:
        for args in [["docker","info","--format","{{.OSType}}"],
                     ["docker","image","inspect","--format","{{.Id}}",image],
                     ["docker","run","--rm","--pull=never","--network=none","--read-only","--cap-drop=ALL",
                      "--security-opt=no-new-privileges","--user=65534:65534","--entrypoint","binwalk",image,"--version"]]:
            result=subprocess.run(args,capture_output=True,text=True,timeout=20)
            print(" ".join(args[:3])+":",result.stdout.strip() if result.returncode == 0 else "FAILED; check local Docker engine and image")
    except (OSError,subprocess.TimeoutExpired): print("Docker check failed or timed out.")

if __name__ == "__main__": main()
