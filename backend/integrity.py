"""SHA-256 integrity of the exact upload, with optional reference comparison."""

import hashlib
import hmac
import re


def check_integrity(data: bytes, expected_sha256: str = "") -> dict:
    reference = expected_sha256.strip().lower()
    if reference and not re.fullmatch(r"[0-9a-f]{64}", reference):
        raise ValueError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")

    # Hash the exact uploaded bytes, rather than decoded text or ZIP entries.
    digest = hashlib.sha256(data).hexdigest()
    status = "not_compared"
    if reference:
        status = "match" if hmac.compare_digest(digest, reference) else "mismatch"
    return {
        "algorithm": "SHA-256",
        "sha256": digest,
        "expected_sha256": reference or None,
        "status": status,
    }
