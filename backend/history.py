"""Append-only analysis revisions in SQLite. No uploaded bytes are retained here."""
import json
import os
import sqlite3
from collections import defaultdict
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.environ.get("FIRMGUARD_DB", Path(__file__).parent / "data" / "scans.db"))

def now(): return datetime.now(timezone.utc).isoformat()

@contextmanager
def connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH, timeout=15)) as db, db:
        db.row_factory = sqlite3.Row
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
          id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL, version TEXT NOT NULL,
          created_at TEXT NOT NULL, status TEXT NOT NULL, stage TEXT NOT NULL,
          progress INTEGER NOT NULL, result_json TEXT NOT NULL, events_json TEXT NOT NULL,
          error TEXT, revision INTEGER NOT NULL DEFAULT 1)""")
        if "revision" not in {row[1] for row in db.execute("PRAGMA table_info(scans)")}:
            db.execute("ALTER TABLE scans ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")
        db.execute("CREATE INDEX IF NOT EXISTS scans_device_id ON scans(device,id)")
        db.execute("CREATE TABLE IF NOT EXISTS revisions (device TEXT, version TEXT, last INTEGER, PRIMARY KEY(device,version))")
        yield db

def interrupt_unfinished():
    with connection() as db:
        db.execute("""UPDATE scans SET status='interrupted', stage='Interrupted',
          error='Server stopped during analysis. Submit the input again.' WHERE status IN ('queued','running')""")

def create_scan(device, version, result):
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT last FROM revisions WHERE device=? AND version=?", (device, version)).fetchone()
        revision = (row[0] if row else db.execute("SELECT COALESCE(MAX(revision),0) FROM scans WHERE device=? AND version=?", (device, version)).fetchone()[0]) + 1
        db.execute("INSERT INTO revisions VALUES (?,?,?) ON CONFLICT(device,version) DO UPDATE SET last=excluded.last", (device, version, revision))
        cursor = db.execute("""INSERT INTO scans (device,version,revision,created_at,status,stage,progress,result_json,events_json)
          VALUES (?,?,?,?,'queued','Queued',0,?,?)""", (device, version, revision, now(), json.dumps(result),
          json.dumps([{"stage": "Queued", "progress": 0, "at": now()}])))
        return cursor.lastrowid

def update_scan(scan_id, status, stage, progress, result=None, error=None):
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT events_json,result_json FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None: return
        events = json.loads(row["events_json"])
        if not events or events[-1]["stage"] != stage:
            events.append({"stage": stage, "progress": progress, "at": now()})
        # Bound event storage even for thousands of files.
        if len(events) > 120: events = events[:4] + events[-116:]
        db.execute("UPDATE scans SET status=?,stage=?,progress=?,result_json=?,events_json=?,error=? WHERE id=?",
          (status, stage, progress, json.dumps(result) if result is not None else row["result_json"], json.dumps(events), error, scan_id))

def get_scan(scan_id):
    with connection() as db: row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if row is None: return None
    record = dict(row)
    record["result"] = json.loads(record.pop("result_json"))
    record["events"] = json.loads(record.pop("events_json"))
    return record

def list_scans(limit=50, offset=0, device=""):
    with connection() as db:
        where, args = ("WHERE device=?", [device]) if device else ("", [])
        total = db.execute("SELECT COUNT(*) FROM scans " + where, args).fetchone()[0]
        rows = db.execute("""SELECT id,device,version,revision,created_at,status,stage,progress,
          json_extract(result_json,'$.filename') AS filename,
          json_extract(result_json,'$.finding_count') AS finding_count FROM scans """ + where +
          " ORDER BY id DESC LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall()
    return {"items": [dict(row) for row in rows], "total": total, "limit": limit, "offset": offset}

def delete_scan(scan_id):
    with connection() as db:
        return db.execute("DELETE FROM scans WHERE id=? AND status NOT IN ('queued','running')", (scan_id,)).rowcount > 0

def compare_scans(old, new):
    def groups(record):
        grouped = defaultdict(list)
        single = record["result"]["extraction"]["scope"] == "single-file"
        for f in record["result"]["findings"]:
            grouped[("<single>" if single else f["filename"], f["rule_id"], f.get("key", ""), f.get("product", ""))].append(f)
        return grouped
    a, b = groups(old), groups(new)
    buckets = {"new": [], "still_present": [], "no_longer_detected": []}
    for key in sorted(a.keys() | b.keys()):
        shared = min(len(a[key]), len(b[key]))
        buckets["still_present"].extend(b[key][:shared]); buckets["new"].extend(b[key][shared:])
        buckets["no_longer_detected"].extend(a[key][shared:])
    def files(record):
        single = record["result"]["extraction"]["scope"] == "single-file"
        return {"<single>" if single else f["path"]: f for f in record["result"]["manifest"]}
    a_files, b_files = files(old), files(new)
    changed, same = [], []
    for path in sorted(a_files.keys() & b_files.keys()):
        left, right = a_files[path], b_files[path]
        if left["sha256"] != right["sha256"] or left["mode"] != right["mode"]:
            changed.append({"path": path, "baseline_sha256": left["sha256"], "candidate_sha256": right["sha256"],
                "baseline_mode": left["mode"], "candidate_mode": right["mode"]})
        else: same.append(path)
    file_delta = {"added": sorted(b_files.keys() - a_files.keys()), "removed": sorted(a_files.keys() - b_files.keys()), "changed": changed, "unchanged": same}
    def software(record):
        grouped = defaultdict(set)
        for c in record["result"]["components"]: grouped[c["product"]].add(c["version"])
        return grouped
    a_sw, b_sw = software(old), software(new)
    sw_delta = [{"product": p, "baseline_versions": sorted(a_sw[p]), "candidate_versions": sorted(b_sw[p])}
        for p in sorted(a_sw.keys() | b_sw.keys()) if a_sw[p] != b_sw[p]]
    return {"baseline_id": old["id"], "candidate_id": new["id"], "device": old["device"],
        "baseline_version": old["version"], "candidate_version": new["version"],
        "counts": {key: len(value) for key, value in buckets.items()}, **buckets,
        "files": file_delta, "file_counts": {k: len(v) for k,v in file_delta.items()}, "software_changes": sw_delta,
        "identical_upload": old["result"]["integrity"]["sha256"] == new["result"]["integrity"]["sha256"],
        "notice": "No longer detected means absent from this scan, not a verified fix. Paths, rule IDs and occurrence counts identify findings; secret values and line shifts are ignored. File hashes detect byte changes. Compare equivalent extraction coverage; partial scans may hide differences."}
