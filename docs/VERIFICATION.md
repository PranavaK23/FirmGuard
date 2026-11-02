# Verification record

Verified on 2 November 2026 with Windows, Python 3.14.7, Node.js 24.19.0 and Chromium from Playwright 1.64.1. Tests use synthetic files and ELF metadata fixtures. These results establish implemented behaviour, not real-world detection accuracy or universal vendor-image compatibility.

| Check | Observed result |
|---|---|
| Backend/API/security suite | 57 discovered: **56 passed, 1 skipped**. The skipped test is the explicitly optional live SquashFS/Binwalk integration. See `backend-tests.txt`. |
| Browser integration | **2 passed**: full upload/results/PDF/history/comparison workflow; safe sample selection and 390-pixel layout. No browser page errors in the complete workflow. |
| Frontend production build | Passed with Vite 7.3.7; 33 modules transformed. Built assets included in the release. |
| Dependency consistency | `pip check` passed; `npm ls --depth=0` matched the committed direct dependency versions. npm reported zero audit findings when installing the browser-test dependency; this is not a separate full security audit. |
| Native archive formats | ZIP, TAR, gzip, bzip2 and XZ decoded actual contents. Signature detection also handled an archive named `.bin`. |
| Extraction abuse cases | Traversal/absolute/Windows names, links and special files, encrypted ZIP flags, duplicate/case-colliding paths, decompression collisions, expansion/file/entry/nesting limits and damaged archives rejected. |
| ELF checks | 32/64-bit, little/big-endian, executable/shared-object, NX/PIE/RELRO, canary/FORTIFY symbols, missing stack headers and malformed metadata tested. |
| History and worker behaviour | Immutable revisions, revision preservation after delete, concurrent revision allocation, older schema migration, restart interruption, active deletion rejection, observable running status, capacity and timeout cleanup tested. |
| Credential privacy | A unique secret absent from saved result JSON, SQLite bytes, JSON export and parsed PDF text. No raw source lines returned. Labels/paths are not secret-redacted. |
| CLI | `scripts/analyse.py` produced six files and 13 findings for the synthetic 1.0 archive. |
| Windows setup/start scripts | Fresh project-local `.venv` installation from the pinned requirements succeeded. The supplied startup script served the built interface, accepted a real sample archive, saved a 13-finding analysis and delivered a PDF over local HTTP. |
| PDF | Generated scan report reopened and checked with pypdf; all three pages rendered with Poppler and visually inspected after pagination correction. Scan and comparison report downloads also tested in Chromium. |
| Interface review | Conventional form/table layout inspected from the actual browser run; screenshot in `interface.png`. |

## Expected sample evaluation

`sample-evaluation.json` contains actual pipeline results for the delivered sample bytes.

- Release 1.0: 6 regular files, 13 findings, 3 component versions, 1 ELF fixture.
- Release 2.0: 6 regular files, 2 findings, 3 component versions, 1 ELF fixture.
- Comparison: 1 added file, 1 removed file, 5 changed files, 0 unchanged files; 3 software-version changes; 1 new finding, 1 still present, 12 no longer detected.

## Explicitly unverified dependencies and limits

- **Docker/Binwalk were not installed/configured on this host.** Container argument construction, hardened options, returned-TAR validation, missing-tool errors and timeout cleanup were unit tested with mocked processes. Live embedded filesystem extraction was **not** executed. `tests/test_binwalk_live.py` provides an opt-in real SquashFS test for an equipped machine. No successful live Binwalk extraction is claimed for this delivery.
- No commercial router image, embedded device or real firmware corpus was provided for validation. Native filesystem archives contain actual bytes, but supplied releases and ELF files are generated fixtures rather than executable device builds.
- Linux/macOS launch scripts and POSIX process memory/CPU enforcement were not executed here. Windows workers have a wall timeout and parser/data limits but no OS memory quota.
- No exhaustive CVE feed, online vulnerability query, firmware signature verification, dynamic execution, fuzz campaign or independent penetration test was performed. The two curated advisory rules are intentionally limited and documented.
- The pinned Starlette test client currently emits an httpx deprecation warning. The tests pass; it is a dependency notice, not a hidden test failure.

Repeat the backend suite with `test.ps1` / `test.sh`, and the browser tests with the README instructions. Rebuild the interface when changing frontend source, and update rule revisions when changing scanner/advisory semantics.
