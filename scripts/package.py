"""Build a clean downloadable release with per-file and whole-ZIP checksums."""
import argparse
import hashlib
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
EXCLUDED={".venv","node_modules","__pycache__",".git",".test-tmp","test-results","playwright-report","data"}

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--output",type=Path,default=ROOT.parent/"FirmGuard_Final.zip")
    args=parser.parse_args();target=args.output.resolve()
    if target.is_relative_to(ROOT): raise SystemExit("Place the release ZIP outside the project directory.")
    files=sorted(p for p in ROOT.rglob("*") if p.is_file() and not EXCLUDED.intersection(p.relative_to(ROOT).parts)
        and p.name!="RELEASE_MANIFEST.sha256" and p.suffix not in {".pyc",".log",".db",".tmp"})
    required=[ROOT/"frontend/dist/index.html",ROOT/"README.md",ROOT/"docs/VERIFICATION.md",ROOT/"backend/requirements-lock.txt"]
    if any(p not in files for p in required): raise SystemExit("Missing required release files. Build and verify the project first.")
    manifest=ROOT/"RELEASE_MANIFEST.sha256"
    manifest.write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ROOT).as_posix()}\n" for p in files),encoding="utf-8")
    target.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(target,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for path in [*files,manifest]:archive.write(path,"FirmGuard/"+path.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None:raise SystemExit("ZIP validation failed.")
    digest=hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_suffix(target.suffix+".sha256").write_text(digest+"  "+target.name+"\n",encoding="utf-8")
    print(f"Created {target.name}: {len(files)+1} files, {target.stat().st_size:,} bytes")
    print("SHA-256:",digest)

if __name__=="__main__":main()
