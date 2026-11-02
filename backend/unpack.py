"""Bounded virtual extraction; never use extractall or trust archive paths."""
import bz2
import gzip
import hashlib
import io
import lzma
import re
import stat
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import PurePosixPath
from settings import AnalysisError, MAX_DEPTH, MAX_ENTRIES, MAX_EXPANDED, MAX_FILE

@dataclass
class Item:
    path: str
    data: bytes
    mode: int = 0

def safe_name(name):
    name = name.replace("\\", "/")
    parts = name.rstrip("/").split("/")
    if (not name or len(name) > 512 or name.startswith("/") or
        any(p in ("", ".", "..") or p.endswith((".", " ")) for p in parts) or
        any(ord(c) < 32 or ord(c) == 127 or c in ':<>"|?*!' for c in name) or
        any(re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?", p) for p in parts)):
        raise AnalysisError("Archive contains an unsafe or ambiguous path.")
    return "/".join(parts)

def kind(data, name=""):
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")): return "zip"
    if data.startswith(b"\x1f\x8b"): return "gzip"
    if data.startswith(b"BZh"): return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"): return "xz"
    if len(data) >= 512:
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:"): return "tar"
        except tarfile.TarError: pass
    return "elf" if data.startswith(b"\x7fELF") else "file"

class Unpacker:
    def __init__(self):
        self.bytes, self.entries = 0, 0
        self.containers = []

    def bounded(self, stream, expected=None):
        allowance = min(MAX_FILE, MAX_EXPANDED - self.bytes)
        if expected is not None and expected > allowance:
            raise AnalysisError("Expanded content exceeds the file or total size limit.", 413)
        data = stream.read(allowance + 1)
        if len(data) > allowance:
            raise AnalysisError("Expanded content exceeds the file or total size limit.", 413)
        self.bytes += len(data)
        return data

    def count(self):
        self.entries += 1
        if self.entries > MAX_ENTRIES: raise AnalysisError("Archive exceeds the 4096-entry limit.", 413)

    def unpack(self, data, name, depth=0, mode=0, root=True):
        fmt = kind(data, name)
        if fmt not in {"zip", "tar", "gzip", "xz", "bzip2"}: return [Item(name, data, mode)]
        if depth >= MAX_DEPTH: raise AnalysisError("Archive nesting exceeds the four-layer limit.", 413)
        self.containers.append({"path": name, "format": fmt, "sha256": hashlib.sha256(data).hexdigest()})
        files, seen = [], set()
        def child(path, stream, size, child_mode):
            path = safe_name(path)
            if path.casefold() in seen: raise AnalysisError("Archive contains duplicate or case-colliding paths.")
            seen.add(path.casefold())
            payload = self.bounded(stream, size)
            relative = path if root else name + "!/" + path
            files.extend(self.unpack(payload, relative, depth + 1, child_mode, root=False))
        try:
            if fmt == "zip":
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    for entry in archive.infolist():
                        self.count(); safe_name(entry.filename)
                        m = entry.external_attr >> 16
                        if stat.S_IFMT(m) not in (0, stat.S_IFREG, stat.S_IFDIR):
                            raise AnalysisError("Archive links and special files are not accepted.")
                        if entry.flag_bits & 1: raise AnalysisError("Encrypted archives are not supported.")
                        if entry.is_dir(): continue
                        with archive.open(entry) as source: child(entry.filename, source, entry.file_size, m & 0o7777)
            elif fmt == "tar":
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                    for entry in archive:
                        self.count()
                        path = entry.name
                        while path.startswith("./"): path = path[2:]
                        if entry.isdir() and path in ("", "."): continue
                        safe_name(path)
                        if entry.isdir(): continue
                        if not entry.isfile() or entry.sparse is not None:
                            raise AnalysisError("Archive links, sparse files and special files are not accepted.")
                        with archive.extractfile(entry) as source: child(path, source, entry.size, entry.mode & 0o7777)
            else:
                opener = {"gzip": gzip.open, "xz": lzma.LZMAFile, "bzip2": bz2.BZ2File}[fmt]
                with opener(io.BytesIO(data), mode="rb") as source: payload = self.bounded(source)
                self.count()
                stem = str(PurePosixPath(name).with_suffix(""))
                if name.lower().endswith(".tgz"): stem += ".tar"
                files.extend(self.unpack(payload, stem, depth + 1, mode, root=root))
        except AnalysisError: raise
        except (ValueError, OSError, EOFError, RuntimeError, zipfile.BadZipFile, tarfile.TarError, lzma.LZMAError, zlib.error, NotImplementedError):
            raise AnalysisError("Archive is damaged or uses unsupported compression.") from None
        if not files: raise AnalysisError("Archive contains no regular files.")
        return files
