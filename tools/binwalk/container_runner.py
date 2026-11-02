"""Trusted container entrypoint. Only regular files leave the disposable tmpfs."""
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

def run():
    version = subprocess.run(["binwalk", "--version"], capture_output=True, text=True, timeout=10)
    if version.returncode or not version.stdout.lower().startswith("binwalk 3."): return 2
    result = subprocess.run(["binwalk", "--quiet", "--extract", "--matryoshka", "--threads", "1",
        "--directory", "/work/extracted", "/input/firmware.bin"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=105)
    if result.returncode: return 3
    root = Path("/work/extracted")
    files, total, skipped, count = [], 0, 0, 0
    for base, directories, names in os.walk(root, followlinks=False):
        count += len(directories) + len(names)
        if count > 4096: return 4
        for directory in list(directories):
            if (Path(base) / directory).is_symlink(): directories.remove(directory); skipped += 1
        for name in sorted(names):
            path = Path(base) / name
            meta = path.lstat()
            if not stat.S_ISREG(meta.st_mode): skipped += 1; continue
            if meta.st_size > 64 * 1024 * 1024: return 4
            total += meta.st_size
            if total > 256 * 1024 * 1024: return 4
            files.append((path, meta))
    # Tar members are subsequently validated by the host virtual extractor.
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
        content = json.dumps({"tool": version.stdout.strip(), "skipped_links_or_special": skipped,
            "notice": "Links and special files were excluded. Extractor support and vendor format determine coverage."}).encode()
        header = tarfile.TarInfo("firmguard-metadata.json"); header.size = len(content)
        archive.addfile(header, io.BytesIO(content))
        for path, meta in files:
            header = tarfile.TarInfo("binwalk/" + path.relative_to(root).as_posix())
            header.size, header.mode = meta.st_size, stat.S_IMODE(meta.st_mode)
            with path.open("rb") as source: archive.addfile(header, source)
    return 0

if __name__ == "__main__":
    try: sys.exit(run())
    except Exception: sys.exit(5)
