# Design and explanation

## Request to report

1. React sends a multipart upload with device/version labels, optional reference SHA-256 and a Binwalk option. The API validates fields and bytes before admitting a job.
2. A SQLite record is created with queued status and an incremented revision. A two-slot semaphore bounds active jobs within the single server process.
3. A background thread starts a disposable Python analysis process. Temporary upload bytes are separate from the history database. The parent observes atomic progress files and enforces a wall timeout.
4. The worker hashes the upload, detects its format, unpacks supported archives in memory, and constructs regular-file records. Optional embedded filesystem extraction uses a restricted Docker container.
5. Each regular file receives a SHA-256 hash. UTF-8 content receives credential/configuration rules; other content receives bounded ASCII-string rules. ELF files also receive metadata checks. Supported version evidence is mapped to the curated advisory set.
6. The worker writes masked JSON; the parent saves it transactionally and marks the scan completed. Failure and interrupted states never masquerade as successful complete scans.
7. React polls status and displays paginated tables. ReportLab generates PDF reports from saved results, without needing uploaded bytes again.

## Main modules

| File | Responsibility |
|---|---|
| `backend/main.py` | HTTP routes, request/field validation, local-use boundaries, built interface |
| `backend/jobs.py`, `worker.py` | Concurrency, disposable process, timeout and progress |
| `backend/unpack.py` | Signature detection, virtual archive paths, quotas |
| `backend/binwalk_adapter.py`, `tools/binwalk/container_runner.py` | Optional isolated external extraction and regular-file export |
| `backend/scanner.py` | Credential and configuration rules |
| `backend/elfcheck.py` | ELF metadata and hardening evidence |
| `backend/inventory.py`, `data_rules/advisories.json` | Supported component evidence and offline advisory ranges |
| `backend/integrity.py` | Exact-byte SHA-256/reference matching |
| `backend/history.py` | SQLite history, revision counters, file/finding/software comparison |
| `backend/reporting.py` | Scan and comparison PDFs |
| `frontend/src/App.jsx` | Conventional upload/history/compare/help pages and result tables |

## Finding identity and comparison

Matching uses relative path, rule ID, recognized credential key and product, with occurrence counts. Line shifts and secret values are ignored. Individual-file scans use one stable comparison path, so renamed individual uploads can compare. Filesystem releases use their actual virtual paths. A secret rotation may leave the same finding while the file's SHA-256 changes. Duplicate occurrences remain counted. No secret hash is retained for guessing or rotation tracking.

Native ZIP and TAR inputs share the same filesystem scope. Compression wrappers around a root TAR do not alter inner paths. Nested archive boundaries are shown as `!/`. Comparisons reject differing extraction methods, scopes or rule revisions. Binwalk-generated paths can change when image layouts change; moved/renamed files appear as removal/addition. Different partial coverage can also make findings disappear. No longer detected is not a verified repair.

## Boundaries

This is a local single-user application, not a hosted scanner. A single Uvicorn worker is required because capacity and restart handling belong to one process. SQLite uses parameterized statements and short transactions. Results are never edited through the API; re-analysis creates a new revision. User-entered version labels are not semantically sorted or inferred from a vendor image. Report generation escapes labels/paths to prevent markup injection. API validation errors suppress raw invalid values.

Native parsing is bounded and separated into a disposable process, but it is not a full operating-system sandbox on Windows. External filesystem parsing is containerized. No uploaded code is intentionally executed. The parser/library/kernel trust boundary still matters; use a disposable VM when handling hostile samples. Resource caps may reject valid images rather than claiming partial success without notice.
