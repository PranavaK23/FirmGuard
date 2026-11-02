"""One reproducible static analysis pipeline shared by API and CLI."""
import hashlib
import re
from collections import Counter
from pathlib import PurePosixPath
from binwalk_adapter import extract
from elfcheck import analyse_elf
from integrity import check_integrity
from inventory import check_versions, inventory
from scanner import preliminary_risk, scan_configuration, scan_credentials
from settings import AnalysisError, MAX_FINDINGS, MAX_TEXT, SCANNER_VERSION
from unpack import Unpacker, kind

NOTICE = "Static pattern and metadata analysis only. No findings does not prove security. Hash equality does not establish authenticity. Version matches require vendor verification."

def analyse(data, filename, expected_sha256="", use_binwalk=False, progress=lambda *args: None):
    progress("Hashing upload", 10)
    integrity = check_integrity(data, expected_sha256)
    fmt = kind(data, filename)
    if fmt == "file" and PurePosixPath(filename).suffix.lower() in {".zip", ".tar", ".gz", ".tgz", ".xz", ".bz2"}:
        raise AnalysisError("Archive header is invalid or unsupported.")
    progress("Unpacking input", 20)
    unpacker = Unpacker()
    items = unpacker.unpack(data, filename)
    method, binwalk_info = "native", None
    warnings = []
    if use_binwalk:
        if fmt in {"zip", "tar", "gzip", "xz", "bzip2"}:
            raise AnalysisError("Use Binwalk for raw filesystem/vendor images. Common archives are unpacked directly.")
        items, binwalk_info = extract(data)
        method = "binwalk-docker"
        warnings.append(binwalk_info["notice"])
    scope = "filesystem" if unpacker.containers or use_binwalk else "single-file"
    if len({i.path.casefold() for i in items}) != len(items):
        raise AnalysisError("Expanded files contain duplicate or case-colliding paths.")
    findings, components, binaries, manifest = [], [], [], []
    text_count = binary_count = 0
    partial = False
    for index, item in enumerate(items, 1):
        payload, path = item.data, item.path
        file_kind = kind(payload, path)
        entry = {"path": path, "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
            "mode": oct(item.mode), "kind": file_kind, "coverage": []}
        text = None
        if len(payload) <= MAX_TEXT:
            try:
                decoded = payload.decode("utf-8-sig")
                if not any(ord(c) < 32 and c not in "\t\r\n" for c in decoded): text = decoded
            except UnicodeDecodeError: pass
        if text is not None:
            text_count += 1; entry["coverage"].append("text rules")
            findings.extend(scan_credentials(text, path))
            findings.extend(scan_configuration(text, path, item.mode))
            components.extend(inventory(text, path))
        else:
            binary_count += 1
            entry["coverage"].append("ASCII strings (first 8 MiB)")
            if len(payload) > MAX_TEXT:
                partial = True; warnings.append(f"File {index}: only ASCII credential/version strings in the first 8 MiB were checked; contextual configuration checks were skipped. Full file hashing retained.")
            # Bounded fragments; locations are byte offsets rather than invented line numbers.
            for match in re.finditer(rb"[\x20-\x7e]{4,1024}", payload[:MAX_TEXT]):
                fragment = match[0].decode("ascii")
                found = scan_credentials(fragment, path)
                for f in found: f["line"] = None; f["offset"] = match.start(); f["evidence"] = "binary string"
                findings.extend(found)
                for component in inventory(fragment, path):
                    component["location"] = match.start(); component["source"] = "binary string"
                    components.append(component)
                if len(findings) > MAX_FINDINGS: raise AnalysisError("Finding limit exceeded; submit a smaller input.", 413)
            findings.extend(scan_configuration("", path, item.mode))
        if file_kind == "elf":
            try:
                metadata, found = analyse_elf(payload, path)
                binaries.append(metadata); findings.extend(found); entry["coverage"].append("ELF metadata")
            except Exception:
                partial = True
                binaries.append({"filename": path, "status": "unreadable", "notice": "Malformed or unsupported ELF metadata; ELF checks were skipped."})
                warnings.append(f"File {index}: ELF metadata could not be fully analysed.")
        manifest.append(entry)
        if len(findings) > MAX_FINDINGS or len(components) > MAX_FINDINGS:
            raise AnalysisError("Finding or inventory limit exceeded; submit a smaller input.", 413)
        progress(f"Analysed file {index} of {len(items)}", 30 + int(55 * index / len(items)))
    # Repeated version banners in a file produce one component evidence record.
    components = list({(c["product"], c["version"], c["filename"], c["source"]): c for c in components}.values())
    version_findings, revision = check_versions(components)
    findings.extend(version_findings)
    if len(findings) > MAX_FINDINGS: raise AnalysisError("Finding limit exceeded; submit a smaller input.", 413)
    if fmt == "file" and text_count == 0 and not use_binwalk:
        partial = True
        warnings.append("Raw image: no filesystem was extracted. Only bounded ASCII strings and whole-file hashing were checked. Enable configured Binwalk to unpack supported embedded filesystems.")
    if use_binwalk:
        partial = True  # Binwalk cannot certify extraction of every embedded filesystem.
    progress("Saving results", 95)
    return {"filename": filename, "size_bytes": len(data), "scanner_version": SCANNER_VERSION,
        "integrity": integrity, "files_scanned": len(items), "text_files": text_count, "binary_files": binary_count,
        "manifest": manifest, "containers": unpacker.containers, "findings": findings, "finding_count": len(findings),
        "severity_counts": dict(Counter(f["severity"] for f in findings)), "risk": preliminary_risk(findings),
        "components": components, "elf": binaries, "extraction": {"method": method, "input_format": fmt, "scope": scope,
        "binwalk": binwalk_info}, "coverage": "partial" if partial else "supported checks completed",
        "warnings": list(dict.fromkeys(warnings)), "advisory_revision": revision, "notice": NOTICE}
