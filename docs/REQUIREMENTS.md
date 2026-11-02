# Requirements coverage

Baseline: the supplied FirmGuard synopsis plus the requested complete feature scope. The final implementation retains React/Vite/plain CSS, Python/FastAPI, masked credential scanning and SHA-256, and supplies the broader analysis/reporting capabilities in the request.

| Requirement | Delivered implementation | Verification |
|---|---|---|
| Actual unpacking | Native ZIP/TAR and gzip/bzip2/XZ with nesting; optional Binwalk v3 Docker extractor | Native archive/security tests; adapter unit tests; opt-in SquashFS integration test |
| Credentials/configuration | Explained rule IDs, file locations, masking, action text | Credential/configuration/negative/privacy tests |
| ELF analysis | Class/architecture/endian, NX/PIE/RELRO, canary/FORTIFY evidence | 32/64-bit, endian, hardening, shared-object, malformed fixtures |
| Software versions | Eight supported families, package/banner evidence, curated offline CVE ranges | Inventory/advisory boundary/vendor-suffix tests |
| Firmware comparison | File hash/permission changes, finding changes, software-version sets | Two full sample-release comparison tests and browser workflow |
| Integrity | Exact-upload and regular-file SHA-256, optional reference | Digest/reference/manifest tests |
| PDF reports | Complete scan and comparison reports with coverage/limits | PDF parsing/content/privacy tests and rendered visual inspection |
| API validation | Body/file bounds, safe paths/archives, labels/hashes, IDs, no raw validation echo, capacity | Validation, unsafe archives, missing records and concurrency tests |
| History/version control | SQLite persistence, device/version revisions, immutable results, restart interruption, pagination/filter/delete | Revision, deletion, list, state and comparison tests |
| Simple frontend | Upload form, tables, history, comparisons and help; responsive CSS | Build and browser workflow/small-screen tests |
| Runnable delivery | Built frontend, pinned dependencies, setup/start/test scripts, CLI, environment checker | Build, CLI, API, browser and package verification |

Scope is bounded static analysis, not universal firmware extraction, exhaustive vulnerability identification, digital-signature authentication or runtime testing. Live Binwalk extraction requires a separately configured toolchain; its integration test is explicitly skipped when unavailable. See VERIFICATION.md for observed results.
