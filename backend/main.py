"""Local FirmGuard API and built frontend. Start with one Uvicorn worker."""
import json
import re
import tempfile
from contextlib import asynccontextmanager
from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Query, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.concurrency import run_in_threadpool
import history
from binwalk_adapter import available, image
from integrity import check_integrity
from jobs import SLOTS, execute, saved_job
from settings import AnalysisError, APP_VERSION, MAX_UPLOAD, ROOT
from unpack import safe_name

@asynccontextmanager
async def lifespan(app):
    history.interrupt_unfinished()
    yield

app = FastAPI(title="FirmGuard", version=APP_VERSION, lifespan=lifespan)

class RequestGuard:
    """Bound the actual body before multipart parsing, even without Content-Length."""
    def __init__(self, app): self.app = app
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http": return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        method = scope["method"]
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = headers.get(b"origin", b"").decode("latin1")
            same_origin = scope.get("scheme", "http") + "://" + headers.get(b"host", b"").decode("latin1")
            if origin and origin != same_origin and origin not in {"http://127.0.0.1:5173", "http://localhost:5173"}:
                return await JSONResponse({"detail": "This local API does not accept requests from that origin."}, status_code=403)(scope, receive, send)
        if method != "POST": return await self.app(scope, receive, send)
        limit = MAX_UPLOAD + 1024 * 1024
        try:
            length = int(headers.get(b"content-length", b"0"))
            if length < 0: raise ValueError
        except ValueError:
            return await JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)(scope, receive, send)
        if length > limit:
            return await JSONResponse({"detail": "Request exceeds the 65 MiB body limit."}, status_code=413)(scope, receive, send)
        with tempfile.SpooledTemporaryFile(max_size=1024*1024) as body:
            total = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect": return
                chunk = message.get("body", b""); total += len(chunk)
                if total > limit:
                    return await JSONResponse({"detail": "Request exceeds the 65 MiB body limit."}, status_code=413)(scope, receive, send)
                body.write(chunk)
                if not message.get("more_body", False): break
            body.seek(0)
            replayed = False
            async def replay():
                nonlocal replayed
                if replayed:
                    return await receive()
                chunk = body.read(65536)
                more = body.tell() < total
                replayed = not more
                return {"type": "http.request", "body": chunk, "more_body": more}
            await self.app(scope, replay, send)

app.add_middleware(RequestGuard)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])

@app.exception_handler(RequestValidationError)
async def invalid_request(request, error):
    # FastAPI's default errors can echo submitted input, including secrets.
    return JSONResponse(status_code=422, content={"detail": "Invalid or missing request fields. Check file, labels, hashes and numeric IDs."})

@app.exception_handler(AnalysisError)
async def invalid_analysis(request, error):
    return JSONResponse(status_code=error.status, content={"detail": error.message})

@app.get("/api/health")
def health():
    return {"status": "ok", "version": APP_VERSION, "max_upload_bytes": MAX_UPLOAD, "binwalk": available()}

def label(value, maximum, field):
    value = value.strip()
    if not 1 <= len(value) <= maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise HTTPException(400, f"{field} must contain 1 to {maximum} printable characters.")
    return value

async def read_upload(file, expected_sha256, use_binwalk):
    try:
        filename = (file.filename or "upload.bin").replace("\\", "/").rsplit("/", 1)[-1]
        if len(filename) > 200: raise HTTPException(400, "Filename exceeds 200 characters.")
        safe_name(filename)
        try: check_integrity(b"", expected_sha256)
        except ValueError as error: raise HTTPException(400, str(error)) from None
        if use_binwalk and (not available()["configured"] or not available()["docker_cli"]):
            raise HTTPException(503, "Binwalk is unavailable. Follow docs/BINWALK.md before enabling it.")
        data = await file.read(MAX_UPLOAD + 1)
        if not data: raise HTTPException(400, "The uploaded file is empty.")
        if len(data) > MAX_UPLOAD: raise HTTPException(413, "File exceeds the 64 MiB upload limit.")
        return data, {"filename": filename, "expected_sha256": expected_sha256, "use_binwalk": use_binwalk}
    finally: await file.close()

@app.post("/api/scans", status_code=202)
async def start_scan(background_tasks: BackgroundTasks, file: UploadFile,
    device: str = Form(...), version: str = Form(...), expected_sha256: str = Form(""), use_binwalk: bool = Form(False)):
    device, version = label(device, 80, "Device"), label(version, 40, "Version")
    data, metadata = await read_upload(file, expected_sha256, use_binwalk)
    if not SLOTS.acquire(blocking=False): raise HTTPException(429, "Two analyses are already active. Try again after one finishes.")
    try:
        scan_id = history.create_scan(device, version, {"filename": metadata["filename"], "size_bytes": len(data), "findings": [], "finding_count": 0})
        background_tasks.add_task(saved_job, scan_id, data, metadata)
        return {"id": scan_id, "status": "queued"}
    except Exception:
        SLOTS.release(); raise

@app.post("/api/scan")
async def immediate_scan(file: UploadFile, expected_sha256: str = Form(""), use_binwalk: bool = Form(False)):
    data, metadata = await read_upload(file, expected_sha256, use_binwalk)
    if not SLOTS.acquire(blocking=False): raise HTTPException(429, "Two analyses are already active. Try again later.")
    try: return await run_in_threadpool(execute, data, metadata)
    finally: SLOTS.release()

@app.get("/api/scans")
def saved_scans(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0), device: str = Query("", max_length=80)):
    return history.list_scans(limit, offset, device)

def record(scan_id):
    value = history.get_scan(scan_id)
    if value is None: raise HTTPException(404, "Scan not found.")
    return value

@app.get("/api/scans/{scan_id}")
def saved_scan(scan_id: int): return record(scan_id)

@app.delete("/api/scans/{scan_id}", status_code=204)
def remove_scan(scan_id: int):
    value = record(scan_id)
    if value["status"] in {"queued", "running"}: raise HTTPException(409, "An active scan cannot be deleted.")
    if not history.delete_scan(scan_id): raise HTTPException(409, "Scan could not be deleted.")
    return Response(status_code=204)

def completed(scan_id):
    value = record(scan_id)
    if value["status"] != "completed": raise HTTPException(409, "Scan must be completed first.")
    return value

@app.get("/api/scans/{scan_id}/export")
def export_scan(scan_id: int):
    value = completed(scan_id)
    return Response(json.dumps(value, indent=2), media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="firmguard-scan-{scan_id}.json"'})

@app.get("/api/scans/{scan_id}/report.pdf")
def report(scan_id: int):
    from reporting import scan_pdf
    return Response(scan_pdf(completed(scan_id)), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="firmguard-scan-{scan_id}.pdf"'})

def comparison(baseline, candidate):
    if baseline == candidate: raise HTTPException(400, "Choose two different scans.")
    old, new = completed(baseline), completed(candidate)
    if old["device"] != new["device"]: raise HTTPException(400, "Choose scans with the same device label.")
    a, b = old["result"], new["result"]
    if a.get("scanner_version") != b.get("scanner_version") or a.get("advisory_revision") != b.get("advisory_revision"):
        raise HTTPException(400, "Scanner or advisory rules differ. Rescan both inputs with the current rules.")
    if "extraction" not in a or "extraction" not in b: raise HTTPException(400, "Rescan older records with the current analyser.")
    if (a["extraction"]["scope"], a["extraction"]["method"]) != (b["extraction"]["scope"], b["extraction"]["method"]):
        raise HTTPException(400, "Compare scans with the same input scope and extraction method.")
    return history.compare_scans(old, new)

@app.get("/api/compare")
def compare(baseline: int = Query(..., ge=1), candidate: int = Query(..., ge=1)):
    return comparison(baseline, candidate)

@app.get("/api/compare/report.pdf")
def compare_report(baseline: int = Query(..., ge=1), candidate: int = Query(..., ge=1)):
    from reporting import comparison_pdf
    return Response(comparison_pdf(comparison(baseline, candidate)), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="firmguard-comparison-{baseline}-{candidate}.pdf"'})

if (ROOT / "frontend" / "dist").is_dir():
    app.mount("/", StaticFiles(directory=ROOT / "frontend" / "dist", html=True), name="frontend")
