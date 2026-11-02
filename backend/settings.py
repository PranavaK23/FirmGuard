"""Shared fixed limits; all byte limits use binary MiB."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
APP_VERSION = "1.0.0"
SCANNER_VERSION = "firmguard-1.0-rules-1"
MAX_UPLOAD = 64 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_DEPTH = 4
MAX_TEXT = 8 * 1024 * 1024
MAX_FINDINGS = 20000
JOB_TIMEOUT = 180
BINWALK_TIMEOUT = 120
MAX_JOBS = 2

class AnalysisError(Exception):
    """Fixed user-facing message; never include uploaded contents."""
    def __init__(self, message, status=400):
        self.message, self.status = message, status
        super().__init__(message)
