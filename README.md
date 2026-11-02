# FirmGuard

FirmGuard is a local static firmware security analyser with a conventional React interface and a Python/FastAPI backend. Upload a firmware image, filesystem archive, ELF file or configuration, review explained findings, save device releases, compare versions and download PDF reports.

## Quick start on Windows

Install **Python 3.11 or newer** from [python.org](https://www.python.org/downloads/). Extract this entire project to a writable folder. Keep the folder structure intact. The release ZIP contains a built interface; Node.js is not needed for normal use.

Open PowerShell in the extracted `FirmGuard` folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Open [FirmGuard](http://127.0.0.1:8000). Keep the terminal open and stop with Ctrl+C. Setup downloads Python packages once into `.venv`; subsequent launches use `start.ps1`. Do not move an existing virtual environment: rerun setup if you move the project. If your institution prevents scripts, use the equivalent manual commands below.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements-lock.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000 --workers 1
```

The API and interface use one server and one address. API documentation is at [API docs](http://127.0.0.1:8000/docs). There is no account, cloud upload, paid service or database server to configure. Keep the server on **127.0.0.1** and use **one worker**. The app has no authentication or multi-user authorization.

## Linux and macOS

```sh
sh setup.sh
sh start.sh
```

Use Python 3.11+ with `venv`/pip support. On Debian/Ubuntu, your Python installation may need the distribution's `python3-venv` package. The Python/React code is portable, but this delivery was executed on Windows; Linux/macOS scripts and POSIX resource limits are supplied and have not been executed here.

## Included capabilities

| Capability | Actual behaviour |
|---|---|
| Firmware unpacking | Reads ZIP and TAR archives plus gzip, bzip2 and XZ compression, including bounded nesting. File signatures determine type, so supported archives also work with a `.bin` extension. Native extraction is virtual: entries never become host filesystem paths. |
| Binwalk integration | Optional Binwalk **v3 in a local Docker Linux container**, with helper extractors for embedded filesystems/vendor images. It is explicitly enabled per scan. See [Binwalk setup](docs/BINWALK.md). Host Binwalk is not used for extraction. |
| Credential scan | Literal password/Wi-Fi/token assignments and private-key headers in text or bounded ASCII binary strings. Values are masked; source lines are not returned. |
| Configuration scan | Explicit SSH settings, Telnet, TLS verification, debug mode, default SNMP communities, anonymous FTP, forwarding, empty account fields, hashes in passwd, and dangerous archive permission bits. Includes/defaults/runtime policy are not resolved. |
| ELF checks | Architecture/endianness/type; GNU_STACK NX; executable PIE; RELRO and immediate binding; recognized stack-check/FORTIFY symbols. Unknown, missing-symbol and not-applicable states are preserved. Never executes ELF files. |
| Software inventory | Recognizes OpenSSL, BusyBox, Dropbear, dnsmasq, OpenSSH, curl, zlib and uClibc version banners; recognized package names in dpkg/opkg-style `status`/`available` records. This is evidence inventory, not a complete SBOM. |
| Software checks | Two offline upstream version ranges: OpenSSL CVE-2014-0160 and dnsmasq CVE-2017-14491. Matches are **potential** matches. Vendor suffixes are left unmapped rather than silently treated as exact upstream releases. See [rules and sources](docs/RULES.md). |
| Integrity | SHA-256 over the exact upload plus every regular extracted file. Optional expected digest yields match/mismatch/not compared. Equality does not establish origin or security. |
| History/version tracking | SQLite metadata/results, UTC timestamps, scan status and monotonic revision numbers per device/version label. Repeat submissions create new records. Existing results are never overwritten. Restart marks unfinished records interrupted. |
| Firmware comparison | Finding occurrence changes, added/removed/changed files including permission differences, component-version sets, whole-upload equality. Matching device, scanner/advisory rules and extraction scope/method are required. ZIP and TAR releases can compare by relative paths. |
| Reporting | Download paginated scan/comparison PDFs and complete masked scan JSON. Reports include coverage notes, hashes, findings, actions, software and ELF results. UI tables paginate large lists. |
| Validation | Bounded requests and uploads, label/hash validation, sanitized error responses, safe archive names, no cross-origin writes, local host restriction, two-job capacity and worker timeouts. |

## Try the complete workflow

1. Open **Scan**, expand **Try the supplied samples**, choose **Firmware sample 1.0**, and run analysis. It should report six files, 13 findings, an unhardened ELF fixture, and three recognized software versions.
2. Choose **Firmware sample 2.0** and run analysis. It should report six files and two credential findings. Its ELF fixture requests NX, PIE and full RELRO; canary/FORTIFY remain unknown because the fixture has no symbol table.
3. Open **History**. Both records use device `Sample router` with versions `1.0` and `2.0`. Repeating the same label creates another revision without replacing the earlier scan.
4. Open **Compare**, choose 1.0 as baseline and 2.0 as candidate. Expect one added file, one removed file, five changed files and three software-version changes. Findings: one new, one still present, 12 no longer detected. A missing pattern is not a verified fix.
5. Download the scan/comparison PDF or masked JSON. `docs/example-report.pdf` is an actual generated report for the synthetic 1.0 sample.
6. The original safe/unsafe configuration samples remain available: unsafe yields three credential findings; safe yields none. To test integrity, compute a reference digest with `Get-FileHash samples\safe_config.txt -Algorithm SHA256`, supply it, then compare the safe sample and its modified copy.

Samples are synthetic test archives, not commercial device firmware or evidence of detection accuracy. Regenerate the two archive samples with `python scripts/make_samples.py`.

## Limits and supported scope

| Resource | Limit |
|---|---|
| Upload / total HTTP body | 64 MiB / 65 MiB including multipart overhead |
| Regular extracted file | 64 MiB |
| Cumulative expanded bytes | 256 MiB, counting intermediate decompression layers |
| Entries / nesting | 4096 entries / four archive or compression layers |
| Text / ASCII strings | First 8 MiB per file; full-file hashes are retained |
| Findings or component evidence | 20,000; exceeding a limit fails clearly, without silently truncating the result |
| Active analyses / analysis timeout | Two jobs / 180 seconds per job |
| Binwalk | 120-second host timeout; 1.5 GiB container memory; bounded tmpfs and export |
| Native worker on POSIX | 1.5 GiB address space and 150 CPU seconds |
| Native worker on Windows | Bounded data/parsers and process wall timeout; **no OS-enforced worker memory quota** |

Native archives reject traversal/absolute paths, ambiguous Windows names, case-colliding files, encryption, links, sparse files and special entries. Some legitimate firmware filesystem archives contain links: these archives are rejected by the strict native reader. The optional container exports only regular files and reports omitted links/special files. Very large, encrypted, unsupported, corrupted or heavily nested firmware can fail. Unsupported raw binaries receive **partial** string/hash coverage, not a claim that a filesystem was extracted. Binwalk results are also marked partial because extractor output cannot establish full firmware coverage.

An UTF-8 file under the text budget uses line-based rules. Other inputs use bounded ASCII-string rules with byte offsets. Non-UTF-8 configurations can therefore lose contextual checks. Encoded/obfuscated secrets, custom software, dynamic configuration, runtime exploits, malware classification, firmware signature verification and exhaustive CVE analysis are outside these static checks. Stripped binaries may hide hardening evidence. Reports use built-in PDF fonts; characters outside WinAnsi are replaced with `?` in PDFs while the UI/JSON preserve Unicode.

## Storage and privacy

`backend/data/scans.db` is created automatically. Set `FIRMGUARD_DB` before startup to use another path. It contains labels, original filenames, relative file paths, hashes, rule versions, manifests, findings and status events, but not uploaded file bytes or detected credential values. Labels and paths may themselves be sensitive. SQLite records are not signed or tamper-proof. Deletion in History removes a completed/failed/interrupted record; it does not guarantee forensic erasure from SQLite pages or backups. Revision counters survive deletion.

Each worker uses a private temporary directory for its input and status files and deletes it after normal completion/failure. Sudden termination can leave `firmguard-job-*` or `firmguard-binwalk-*` folders in the operating system's temporary directory; inspect and remove stale folders while the server is stopped. Multipart parsers may also spool temporarily. No raw firmware is offered for later download, and interrupted analyses must be re-uploaded. History can grow until records are deleted; back up the database while the server is stopped.

## Development and tests

Node.js **22.12+** with npm is needed to rebuild or change the interface. The release includes `frontend/dist` for normal startup. Rebuild after changing source; the backend serves the built files, not live source.

```powershell
.\setup.ps1 -RebuildFrontend
.\test.ps1
```

Backend tests can also run directly:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Browser tests (requires Chromium download; activate the Python environment first):

```powershell
.\.venv\Scripts\Activate.ps1
cd frontend
npm.cmd ci
npx.cmd playwright install chromium
npm.cmd run build
npm.cmd run test:e2e
```

The browser tests start their own server on 127.0.0.1:8765 with an isolated temporary database. They cover real uploads, report downloads, history, comparison, sample selection and a small-screen layout. If local certificate inspection affects npm, configure the institution's trusted CA; do not disable certificate verification.

For development, start the backend on 8000, then `npm run dev` inside `frontend` and open 127.0.0.1:5173. Vite proxies `/api` to the backend. The local origin allowlist uses these standard ports. Use `scripts/doctor.py` for environment checks and the CLI for headless scans:

```powershell
.\.venv\Scripts\python.exe scripts\analyse.py samples\firmware_v1.zip --output scan.json
```

See [verification](docs/VERIFICATION.md) for actual test results and untested dependencies, [design](docs/DESIGN.md) for student explanation, [requirements mapping](docs/REQUIREMENTS.md), and [source control](docs/SOURCE_CONTROL.md). The direct Python dependencies are in `backend/requirements.txt`; the tested resolved set is pinned in `backend/requirements-lock.txt`. npm uses its committed lockfile. No credentials, virtual environments or node_modules are included in the release ZIP.
