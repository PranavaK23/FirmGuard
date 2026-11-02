"""Offline evidence-based component inventory and narrowly scoped advisory checks."""
import json
import re
from pathlib import Path, PurePosixPath
from scanner import finding

ALIASES = {"openssl": "OpenSSL", "libssl": "OpenSSL", "busybox": "BusyBox", "dropbear": "Dropbear",
    "dnsmasq": "dnsmasq", "openssh": "OpenSSH", "openssh-server": "OpenSSH", "curl": "curl",
    "libcurl": "curl", "zlib": "zlib", "zlib1g": "zlib", "uclibc": "uClibc"}
BANNERS = [
 ("OpenSSL", r"\bOpenSSL[ /](\d+\.\d+\.\d+[a-z]?(?:[-+][\w.]+)?)"),
 ("BusyBox", r"\bBusyBox\s+v?(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)"),
 ("Dropbear", r"\b[Dd]ropbear(?:[_ /]|\s+v)(\d{4}\.\d+(?:\.\d+)?)"),
 ("dnsmasq", r"\bdnsmasq(?:[- /]|\s+version\s+)(\d+\.\d+(?:\.\d+)?)"),
 ("OpenSSH", r"\bOpenSSH[_ /](\d+\.\d+(?:p\d+)?)"),
 ("curl", r"\bcurl[ /](\d+\.\d+\.\d+)"),
 ("zlib", r"\bzlib[ /](\d+\.\d+(?:\.\d+)?)"),
 ("uClibc", r"\buClibc(?:-ng)?[ /](\d+\.\d+(?:\.\d+)?)"),
]
RULES_PATH = Path(__file__).parent / "data_rules" / "advisories.json"

def inventory(text, path):
    found = {}
    def add(product, version, source, location):
        if re.fullmatch(r"[0-9][0-9A-Za-z.+~:_-]{0,63}", version):
            key = product, version, source
            found.setdefault(key, {"product": product, "version": version, "filename": path,
                "source": source, "location": location, "confidence": "package metadata" if source == "package" else "version string"})
    for product, pattern in BANNERS:
        for match in re.finditer(pattern, text): add(product, match[1], "banner", match.start())
    if PurePosixPath(path).name in {"status", "available"}:
        for block in re.split(r"\n\s*\n", text):
            package = re.search(r"(?m)^Package:\s*(\S+)\s*$", block)
            version = re.search(r"(?m)^Version:\s*(\S+)\s*$", block)
            if package and version:
                name = package[1].split(":")[0].lower()
                if name in ALIASES: add(ALIASES[name], version[1], "package", None)
    return list(found.values())

def version_key(version):
    # Only unmodified upstream releases can be mapped to these curated ranges.
    m = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?([a-z]?)", version)
    if not m: return None
    return int(m[1]), int(m[2]), int(m[3] or 0), ord(m[4]) - 96 if m[4] else 0

def check_versions(components):
    db = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    found = []
    for component in components:
        rules = [r for r in db["advisories"] if r["product"] == component["product"]]
        key = version_key(component["version"])
        component["check_status"] = "not_covered" if not rules else "unmapped_version" if key is None else "no_curated_match"
        component["advisory_ids"] = []
        for rule in rules:
            if key is not None and version_key(rule["introduced"]) <= key < version_key(rule["fixed"]):
                component["check_status"] = "potential_match"
                component["advisory_ids"].append(rule["id"])
                found.append(finding("SW-" + rule["id"], "Potential " + rule["id"] + " version match", component["filename"], rule["severity"],
                    f"Detected {component['product']} {component['version']}; the upstream range is {rule['introduced']} to before {rule['fixed']}. Vendor backports and build options require verification.",
                    "Check the vendor advisory and update to a supported, patched build.", category="Software", cve=rule["id"],
                    product=component["product"], detected_version=component["version"], reference=rule["reference"]))
    return found, db["revision"]
